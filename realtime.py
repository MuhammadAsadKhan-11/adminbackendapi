"""realtime.py — Firestore on_snapshot listeners => WebSocket "refresh" broadcast.

Flow:
  Firestore me koi bhi change (consumer / case / flag / naya reading)
      -> listener callback (background thread)
      -> cache clear + asyncio loop ko notify
      -> 1 second debounce
      -> sab connected apps ko {"type": "refresh", "changed": [...]} bhejo
      -> app apni REST API dobara call kar ke fresh data le leti hai
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, List, Optional, Set

from fastapi import WebSocket
from firebase_admin import firestore

from core import get_db, get_settings
from services import cache

log = logging.getLogger("electraguard.realtime")

DEBOUNCE_SECONDS = 1.0


class LiveUpdates:
    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._watches: List[Any] = []
        self._pending: Set[str] = set()
        self._flush_task: Optional[asyncio.Task] = None

    # ── lifecycle ─────────────────────────────────────────────
    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Blocking call — startup par asyncio.to_thread ke zariye chalao."""
        self._loop = loop
        s = get_settings()
        db = get_db()

        targets = {
            "consumers": db.collection(s.consumers_collection),
            "cases": db.collection(s.cases_collection),
            # consumptions mai bade csvRaw strings hote hain, is liye sirf sab se naya upload
            # watch hota hai (sasta change-detector). Naya CSV upload => refresh.
            "uploads": db.collection(s.consumptions_collection)
            .order_by("uploadedAt", direction=firestore.Query.DESCENDING)
            .limit(1),
        }
        # System Alerts (admin ke manual alerts) — naya alert aate hi apps refresh hon
        targets["alerts"] = (
            db.collection(s.alerts_collection).order_by("createdAt", direction=firestore.Query.DESCENDING).limit(1)
        )
        # extra notification collections (agar .env mai set hon) — sirf sab se naya doc watch hota hai
        for extra in [x.strip() for x in s.notification_extra_collections.split(",") if x.strip()]:
            targets[f"extra:{extra}"] = (
                db.collection(extra).order_by("createdAt", direction=firestore.Query.DESCENDING).limit(1)
            )
        for name, target in targets.items():
            try:
                self._watches.append(target.on_snapshot(self._make_callback(name)))
            except Exception as exc:  # listener fail ho to API phir bhi chalti rahe
                log.warning("Could not attach listener for %s: %s", name, exc)
        log.info("Realtime listeners attached: %d", len(self._watches))

    def stop(self) -> None:
        for w in self._watches:
            try:
                w.unsubscribe()
            except Exception:
                pass
        self._watches.clear()

    # ── firestore side (background thread) ────────────────────
    def _make_callback(self, name: str):
        state = {"initial": True}

        def callback(docs, changes, read_time) -> None:
            if state["initial"]:  # pehla callback existing data ka snapshot hota hai
                state["initial"] = False
                return
            cache.invalidate()
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._notify, name)

        return callback

    # ── asyncio side ──────────────────────────────────────────
    def _notify(self, name: str) -> None:
        self._pending.add(name)
        if self._flush_task is None or self._flush_task.done():
            self._flush_task = asyncio.create_task(self._flush())

    async def _flush(self) -> None:
        await asyncio.sleep(DEBOUNCE_SECONDS)
        changed = sorted(self._pending)
        self._pending.clear()
        await self.broadcast(
            {
                "type": "refresh",
                "changed": changed,
                "at": datetime.now(timezone.utc).isoformat(),
            }
        )

    async def connect(self, ws: WebSocket) -> None:
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        dead: List[WebSocket] = []
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


live = LiveUpdates()
