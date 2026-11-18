"""seed_reports_demo.py — demo data for the Admin Dashboard + Reports charts.

Writes documents in the SAME shape the app already uses (no new collections):
  consumptions : 100 detection records (CSV upload results) — 50 low / 30 medium / 20 high,
                 each with 14 consecutive days of readings (csvRaw) ending today
  cases        : 34 theft cases — G-10: 12, G-11: 7, G-13: 4, I-8: 9, F-10: 2

Every document has  isDemo: true  and  seedBatchId: "electraguard-reports-demo-v1",
and a fixed document id (demo-v1-...), so running it again never creates duplicates.
It refuses to write if any of those ids already holds a non-demo (genuine) document.

Run from electraguard_admin_api/ (uses the Firebase Admin credentials from .env):
    venv\\Scripts\\python seed_reports_demo.py --dry-run     # show what would be written
    venv\\Scripts\\python seed_reports_demo.py               # seed (skips if already seeded)
    venv\\Scripts\\python seed_reports_demo.py --refresh     # rewrite the demo batch with today's dates
    venv\\Scripts\\python seed_reports_demo.py --remove      # delete ONLY this demo batch
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from core import get_db, get_settings, local_tz

SEED_BATCH_ID = "electraguard-reports-demo-v1"
ID_PREFIX = "demo-v1"
DAYS = 14
RISK_PLAN = {"low": 50, "medium": 30, "high": 20}
AREA_PLAN = {"G-10": 12, "G-11": 7, "G-13": 4, "I-8": 9, "F-10": 2}
CASE_CATEGORIES = ["Meter Tampering", "Power Theft Suspected", "Illegal Connection", "Billing Fraud"]
TARIFF_APP = 20  # the consumer app estimates the bill as units x 20 PKR
DEMO_MARK = {"isDemo": True, "seedBatchId": SEED_BATCH_ID}


def _score_range(level: str, s) -> Tuple[int, int]:
    # inside the EXISTING thresholds (MEDIUM_RISK_THRESHOLD / HIGH_RISK_THRESHOLD)
    med, high = int(s.medium_risk_threshold), int(s.high_risk_threshold)
    return {"low": (3, med - 5), "medium": (med, high - 1), "high": (high, 99)}[level]


def _readings(level: str, rng: random.Random) -> List[float]:
    base = rng.uniform(6.5, 12.5)
    out = []
    for _ in range(DAYS):
        v = base * rng.uniform(0.88, 1.12)
        if level == "medium" and rng.random() < 0.3:
            v *= rng.uniform(0.25, 0.5)          # occasional sharp drops
        if level == "high":
            r = rng.random()
            if r < 0.25:
                v = 0.0                           # zero-consumption days
            elif r < 0.6:
                v *= rng.uniform(0.15, 0.4)       # far below the usual pattern
        out.append(round(v, 2))
    return out


def build_documents() -> Dict[str, Dict[str, Dict[str, Any]]]:
    s = get_settings()
    rng = random.Random(20261118)  # same data every run
    tz = local_tz()
    now = datetime.now(timezone.utc)
    today = now.astimezone(tz).date()
    days = [today - timedelta(days=DAYS - 1 - i) for i in range(DAYS)]
    header = ",".join(d.strftime("%m/%d/%Y") for d in days)
    date_range = f"{days[0].strftime('%m/%d/%Y')} – {days[-1].strftime('%m/%d/%Y')}"

    levels = [lvl for lvl, n in RISK_PLAN.items() for _ in range(n)]
    rng.shuffle(levels)
    consumptions: Dict[str, Dict[str, Any]] = {}
    suspects: List[Tuple[str, str]] = []  # (consumerId, name) of medium/high consumers
    for i, level in enumerate(levels, start=1):
        cid = f"DEMO-C{i:03d}"
        name = f"Demo Consumer {i:03d}"
        lo, hi = _score_range(level, s)
        score = rng.randint(lo, hi)
        values = _readings(level, rng)
        total = round(sum(values), 1)
        positive = [v for v in values if v > 0]
        uploaded = now - timedelta(days=rng.uniform(0, DAYS / 2 - 1), hours=rng.uniform(0, 6))
        consumptions[f"{ID_PREFIX}-consumption-{i:03d}"] = {
            "consumerId": cid,
            "consumerName": name,
            "email": "",
            "uid": None,
            "dateRange": date_range,
            "totalUnits": total,
            "avgUnits": round(sum(positive) / len(positive), 1) if positive else 0.0,
            "estimatedBill": round(total * TARIFF_APP),
            "riskScore": score,
            "riskLevel": level,
            "probability": round(score / 100 + rng.uniform(0, 0.009), 4),
            "prediction": "Theft Detected" if score >= s.medium_risk_threshold else "No Theft",
            "csvRaw": header + "\n" + ",".join(str(v) for v in values) + "\n",
            "dailyReadings": [{"label": d.strftime("%m/%d/%Y"), "value": v, "flag": None} for d, v in zip(days, values)],
            "uploadedAt": uploaded,
            **DEMO_MARK,
        }
        if level in ("medium", "high"):
            suspects.append((cid, name))

    cases: Dict[str, Dict[str, Any]] = {}
    n = 0
    for area, count in AREA_PLAN.items():
        for _ in range(count):
            n += 1
            cid, name = suspects[(n - 1) % len(suspects)]
            category = CASE_CATEGORIES[(n - 1) % len(CASE_CATEGORIES)]
            created = now - timedelta(days=rng.uniform(0.1, DAYS / 2 - 1))
            closed = n % 4 == 0
            status = "Closed" if closed else ("In Progress" if n % 3 == 0 else "Open")
            local = created.astimezone(tz)
            doc = {
                "caseId": f"DEMO-{n:04d}",
                "consumerId": cid,
                "consumerDocId": "",
                "uid": "",
                "consumerEmail": "",
                "consumerName": name,
                "description": f"{category} suspected after abnormal consumption pattern (demo data).",
                "title": category,
                "issueType": category,
                "issueValue": category.lower().replace(" ", "_"),
                "category": category,
                "location": area,
                "area": area,
                "riskLevel": "High" if n % 3 else "Medium",
                "priority": "High" if n % 2 else "Normal",
                "assignedInspector": "Demo Inspector" if status != "Open" else "",
                "currentStatus": status,
                "status": status,
                "escalated": False,
                "resolution": "Resolved during demo" if closed else "",
                "meterNumber": cid,
                "evidence": [],
                "hasImage": False,
                "timeline": [{"action": f"Case created — {category}", "date": local.date().isoformat(), "time": local.strftime("%H:%M")}],
                "createdAt": created,
                "updatedAt": created,
                "createdBy": "seed_reports_demo",
                **DEMO_MARK,
            }
            if closed:
                doc["resolvedAt"] = created + timedelta(hours=rng.uniform(6, 60))
            cases[f"{ID_PREFIX}-case-{n:03d}"] = doc

    s_ = get_settings()
    return {s_.consumptions_collection: consumptions, s_.cases_collection: cases}


def _is_ours(d: Dict[str, Any]) -> bool:
    return d.get("isDemo") is True and d.get("seedBatchId") == SEED_BATCH_ID


def seed(refresh: bool, dry_run: bool) -> int:
    db = get_db()
    plan = build_documents()
    existing_ours = 0
    for col, docs in plan.items():
        refs = [db.collection(col).document(doc_id) for doc_id in docs]
        for snap in db.get_all(refs):  # one batched read instead of 1 request per document
            if snap.exists:
                if not _is_ours(snap.to_dict() or {}):
                    print(f"ABORT: {col}/{snap.id} exists and is NOT demo data — nothing written.")
                    return 2
                existing_ours += 1
    total = sum(len(d) for d in plan.values())
    if existing_ours and not refresh:
        print(f"Demo batch '{SEED_BATCH_ID}' is already seeded ({existing_ours} documents). "
              "Nothing written. Use --refresh to rewrite it with today's dates.")
        return 0
    for col, docs in plan.items():
        print(f"{'would write' if dry_run else 'writing'} {len(docs)} documents to '{col}'")
    if dry_run:
        return 0
    for col, docs in plan.items():
        items = list(docs.items())
        for i in range(0, len(items), 400):
            batch = db.batch()
            for doc_id, data in items[i : i + 400]:
                batch.set(db.collection(col).document(doc_id), data)
            batch.commit()
    print(f"Seeded {total} demo documents (batch '{SEED_BATCH_ID}').")
    return 0


def remove(dry_run: bool) -> int:
    db = get_db()
    s = get_settings()
    removed = 0
    for col in (s.consumptions_collection, s.cases_collection):
        snaps = [sn for sn in db.collection(col).where("seedBatchId", "==", SEED_BATCH_ID).stream()]
        ours = [sn for sn in snaps if _is_ours(sn.to_dict() or {})]  # isDemo == true AND batch id
        print(f"{'would delete' if dry_run else 'deleting'} {len(ours)} demo documents from '{col}'")
        if dry_run:
            continue
        for i in range(0, len(ours), 400):
            batch = db.batch()
            for sn in ours[i : i + 400]:
                batch.delete(sn.reference)
            batch.commit()
        removed += len(ours)
    if not dry_run:
        print(f"Removed {removed} demo documents. Genuine records were not touched.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Seed or remove the ElectraGuard reports demo data.")
    ap.add_argument("--remove", action="store_true", help="delete only documents of this demo batch")
    ap.add_argument("--refresh", action="store_true", help="rewrite the demo batch (new dates)")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen, write nothing")
    a = ap.parse_args()
    sys.exit(remove(a.dry_run) if a.remove else seed(a.refresh, a.dry_run))
