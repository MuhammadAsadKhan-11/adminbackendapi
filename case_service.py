"""case_service.py — case management, S3 evidence and consumer notifications.

Same "cases" collection that services.py reads for the dashboard, so anything
created here shows up in KPIs, consumer profiles and admin notifications.

* Evidence files live in AWS S3 (evidence_storage.py). The case document keeps
  only metadata in its "evidence" array.
* Every admin action the consumer should know about writes ONE document to
  consumerNotifications (id derived from the event, so retries never duplicate).
* Consumer ("me") functions are always scoped to the signed-in Firebase uid.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
from firebase_admin import firestore as _fb_firestore
from google.api_core.exceptions import AlreadyExists

import evidence_storage
from core import get_db, get_settings, local_tz
from services import (
    CASE_STATUSES,
    _STATUS_ALIASES,
    _cases,
    _normalize_case_status,
    cache,
    first,
    fmt_date,
    to_dt,
    to_local_day,
    today_local,
)

try:
    import requests  # Expo push notifications ke liye
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

log = logging.getLogger("electraguard.cases")


# ─────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────
def _find_consumer_doc(consumer_id: str) -> Optional[Dict[str, Any]]:
    """consumerId, uid, or Firestore doc id. Returns {"docId", "data"}."""
    s = get_settings()
    col = get_db().collection(s.consumers_collection)
    raw = (consumer_id or "").strip()
    if not raw:
        return None

    candidates = []
    for value in dict.fromkeys([raw, raw.upper(), raw.lower()]):
        candidates.extend(list(col.where("consumerId", "==", value).limit(1).stream()))
        if candidates:
            break
    if not candidates:
        snap = col.document(raw).get()
        if snap.exists:
            candidates = [snap]
    if not candidates:
        candidates = list(col.where("uid", "==", raw).limit(1).stream())
    if not candidates and "@" in raw:
        candidates = list(col.where("email", "==", raw.lower()).limit(1).stream())

    if not candidates:
        return None
    snap = candidates[0]
    return {"docId": snap.id, "data": snap.to_dict() or {}}


def _consumer_uid(consumer: Optional[Dict[str, Any]]) -> str:
    if not consumer:
        return ""
    return str(consumer["data"].get("uid") or consumer["docId"]).strip()


def _send_expo_push(push_token: str, title: str, body: str, data: Optional[Dict[str, Any]] = None) -> None:
    """Best-effort Expo push; never raises."""
    if not get_settings().send_push_notifications:
        return
    if not push_token or not str(push_token).startswith("ExponentPushToken"):
        return
    if requests is None:
        return
    try:
        requests.post(
            "https://exp.host/--/api/v2/push/send",
            json={"to": push_token, "title": title, "body": body, "data": data or {}, "sound": "default"},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=8,
        )
    except Exception as exc:  # push fail ho to case action fail nahi honi chahiye
        log.warning("Expo push failed: %s", type(exc).__name__)


def _now_parts() -> Tuple[datetime, str, str]:
    now = datetime.now(timezone.utc)
    local = now.astimezone(local_tz())
    return now, local.date().isoformat(), local.strftime("%H:%M")


def _timeline_entry(action: str) -> Dict[str, str]:
    _, d, t = _now_parts()
    return {"action": action, "date": d, "time": t}


def _case_title(d: Dict[str, Any]) -> str:
    return str(first(d, "title", "category", "issueType", default="Case")).strip() or "Case"


def _case_number(d: Dict[str, Any], doc_id: str) -> str:
    return str(first(d, "caseId", "caseNumber", default=doc_id))


def _file_word(n: int) -> str:
    return f"{n} evidence file{'s' if n != 1 else ''}"


def _evidence_brief(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "id": str(it.get("id") or ""),
            "name": str(it.get("originalFileName") or it.get("name") or ""),
            "category": str(it.get("category") or ""),
            "fileType": str(it.get("fileType") or ""),
            "size": int(it.get("size") or 0),
        }
        for it in items
        if it.get("visibleToConsumer", True)
    ]


def _evidence_items(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evidence array with a stable id on every entry (old entries had none)."""
    out = []
    for i, ev in enumerate(d.get("evidence") or []):
        if not isinstance(ev, dict):
            continue
        item = dict(ev)
        if not item.get("id"):
            item["id"] = f"legacy-{i}"
        out.append(item)
    return out


def _timeline(d: Dict[str, Any]) -> List[Dict[str, str]]:
    return [
        {"action": str(t.get("action", "")), "date": str(t.get("date", "")), "time": str(t.get("time", ""))}
        for t in (d.get("timeline") or [])
        if isinstance(t, dict)
    ]


def _iso(v: Any) -> Optional[str]:
    dt = to_dt(v)
    return dt.astimezone(timezone.utc).isoformat() if dt else None


# ─────────────────────────────────────────────────────────────
# consumer notifications (single source of truth)
# ─────────────────────────────────────────────────────────────
def _notify_consumer(
    consumer: Optional[Dict[str, Any]],
    *,
    event_key: str,
    ntype: str,
    title: str,
    message: str,
    case_doc_id: Optional[str] = None,
    case_data: Optional[Dict[str, Any]] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
    admin_uid: str = "",
) -> Optional[str]:
    """Writes ONE consumerNotifications document (idempotent by event_key) and
    sends an Expo push if the consumer has a token. None if consumer unknown."""
    uid = _consumer_uid(consumer)
    if not uid:
        return None
    s = get_settings()
    d = case_data or {}
    nid = hashlib.sha1(event_key.encode()).hexdigest()[:24]
    payload = {
        "recipientUid": uid,
        "consumerDocId": consumer["docId"],
        "consumerId": str(consumer["data"].get("consumerId") or ""),
        "type": ntype,
        "title": title,
        "message": message,
        "caseDocId": case_doc_id or None,
        "caseId": (_case_number(d, case_doc_id or "") or None) if (d or case_doc_id) else None,
        "caseTitle": _case_title(d) if d else None,
        "caseStatus": _normalize_case_status(str(first(d, "currentStatus", "status", default=""))) if d else None,
        "evidence": _evidence_brief(evidence or []),
        "read": False,
        "readAt": None,
        "createdAt": datetime.now(timezone.utc),
        "createdBy": admin_uid or None,
        "eventKey": event_key,
    }
    try:
        get_db().collection(s.consumer_notifications_collection).document(nid).create(payload)
    except AlreadyExists:
        return nid  # same event already delivered — no duplicate
    except Exception as exc:
        log.error("Consumer notification write failed (%s): %s", ntype, type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="The case was saved, but the consumer notification could not be written. Please retry.",
        )
    log.info("Consumer notified: type=%s case=%s", ntype, case_doc_id or "-")

    push_token = str(consumer["data"].get("pushToken") or "").strip()
    if push_token:
        _send_expo_push(push_token, title, message, {"notificationId": nid, "caseId": case_doc_id, "type": ntype})
    return nid


# ─────────────────────────────────────────────────────────────
# admin views
# ─────────────────────────────────────────────────────────────
def _case_doc_to_summary(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    status_raw = _normalize_case_status(str(first(d, "currentStatus", "status", default="Open")))
    created = to_dt(first(d, "createdAt", "created_at"))
    return {
        "id": doc_id,
        "caseNumber": _case_number(d, doc_id),
        "consumerId": str(first(d, "consumerId", default="")).strip(),
        "consumerName": str(first(d, "consumerName", default="")).strip(),
        "area": str(first(d, "area", "location", default="")).strip(),
        "status": status_raw,
        "riskLevel": str(first(d, "riskLevel", default="Low")).strip() or "Low",
        "category": str(first(d, "category", "issueType", default="")).strip(),
        "description": str(first(d, "description", "title", default="")).strip(),
        "inspector": (str(d.get("assignedInspector")).strip() or None) if d.get("assignedInspector") else None,
        "createdAt": fmt_date(to_local_day(created)) if created else "—",
        "evidences": len(d.get("evidence") or []) + (1 if d.get("hasImage") else 0),
    }


def _case_doc_to_detail(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    summary = _case_doc_to_summary(doc_id, d)
    evidence = []
    for item in _evidence_items(d):
        view = evidence_storage.public_view(item)
        # Old Firebase-Storage entries keep their stored URL; S3 entries are
        # fetched through /evidence/{id}/url (presigned, short-lived).
        view["url"] = "" if item.get("storage") == "s3" else str(item.get("url") or "")
        evidence.append(view)
    summary.update(
        {
            "priority": str(first(d, "priority", default="Normal")).strip() or "Normal",
            "meterNumber": str(first(d, "meterNumber", default="") or summary["consumerId"]) or None,
            "timeline": _timeline(d),
            "evidence": evidence,
        }
    )
    return summary


def list_cases(status: Optional[str] = None, search: Optional[str] = None) -> Dict[str, Any]:
    rows = _cases()

    counts = {st: 0 for st in CASE_STATUSES}
    for c in rows:
        counts[c["status"]] = counts.get(c["status"], 0) + 1

    items = list(rows)
    if status and status.strip():
        items = [c for c in items if c["status"] == status.strip()]
    if search and search.strip():
        q = search.strip().lower()
        items = [
            c
            for c in items
            if q in " ".join([c["consumerName"], c["consumerId"], c["caseNumber"], c["location"]]).lower()
        ]

    floor = datetime.min.replace(tzinfo=timezone.utc)
    items.sort(key=lambda c: c["createdAt"] or floor, reverse=True)

    def to_summary(c: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": c["id"],
            "caseNumber": c["caseNumber"],
            "consumerId": c["consumerId"],
            "consumerName": c["consumerName"],
            "area": c["location"],
            "status": c["status"],
            "riskLevel": c["riskLevel"] or "Low",
            "category": c["issueType"],
            "description": c["fullDescription"] or c["description"],
            "inspector": c["assignedInspector"] or None,
            "createdAt": fmt_date(to_local_day(c["createdAt"])) if c["createdAt"] else "—",
            "evidences": c["evidenceCount"],
        }

    return {"total": len(rows), "counts": counts, "items": [to_summary(c) for c in items]}


def _load_case(case_id: str):
    """Case by Firestore doc id or by its caseId field. Snapshot or None."""
    s = get_settings()
    col = get_db().collection(s.cases_collection)
    raw = (case_id or "").strip()
    if not raw or "/" in raw:
        return None
    snap = col.document(raw).get()
    if snap.exists:
        return snap
    rows = list(col.where("caseId", "==", raw).limit(1).stream())
    return rows[0] if rows else None


def get_case_detail(case_id: str) -> Optional[Dict[str, Any]]:
    snap = _load_case(case_id)
    if snap is None:
        return None
    return _case_doc_to_detail(snap.id, snap.to_dict() or {})


def _consumer_for_case(d: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Owner of a case: stored doc id first, then consumerId / uid / email."""
    s = get_settings()
    doc_id = str(d.get("consumerDocId") or "").strip()
    if doc_id and "/" not in doc_id:
        snap = get_db().collection(s.consumers_collection).document(doc_id).get()
        if snap.exists:
            return {"docId": snap.id, "data": snap.to_dict() or {}}
    for key in ("consumerId", "uid", "consumerUid", "consumerEmail"):
        val = str(d.get(key) or "").strip()
        if val:
            found = _find_consumer_doc(val)
            if found:
                return found
    return None


def _upload_files(
    files: List[Tuple[str, bytes, str]],
    *,
    case_doc_id: str,
    case_number: str,
    consumer_id: str,
    consumer_uid: str,
    admin_uid: str,
) -> List[Dict[str, Any]]:
    """Validates ALL files first, then uploads. Any failure removes what was already uploaded."""
    if not files:
        return []
    validated = evidence_storage.validate_files(files)
    if not evidence_storage.s3_configured():
        raise HTTPException(
            status_code=503,
            detail="Evidence storage (AWS S3) is not configured on the server, so files cannot be uploaded.",
        )
    batch_id = uuid.uuid4().hex[:12]
    uploaded: List[Dict[str, Any]] = []
    try:
        for vf in validated:
            uploaded.append(
                evidence_storage.upload_evidence(
                    vf,
                    case_doc_id=case_doc_id,
                    case_number=case_number,
                    consumer_id=consumer_id,
                    consumer_uid=consumer_uid,
                    admin_uid=admin_uid,
                    batch_id=batch_id,
                )
            )
    except Exception:
        evidence_storage.delete_objects([u["s3Key"] for u in uploaded])
        raise
    for u in uploaded:
        u["date"] = fmt_date(today_local())
    return uploaded


# ─────────────────────────────────────────────────────────────
# admin mutations
# ─────────────────────────────────────────────────────────────
def create_case(
    *,
    consumer_id: str,
    consumer_name: str,
    area: str,
    risk_level: str,
    category: str,
    description: str,
    inspector: Optional[str],
    priority: str,
    files: List[Tuple[str, bytes, str]],  # (filename, content, content_type)
    admin_uid: str,
) -> Dict[str, Any]:
    db = get_db()
    settings = get_settings()

    consumer = _find_consumer_doc(consumer_id)
    consumer_email = ""
    if consumer:
        consumer_email = str(first(consumer["data"], "email", default="")).strip()
        consumer_name = consumer_name or str(first(consumer["data"], "fullName", "name", default=""))
    consumer_uid = _consumer_uid(consumer)

    doc_ref = db.collection(settings.cases_collection).document()
    case_number = f"CASE{int(datetime.now(timezone.utc).timestamp() * 1000) % 1000000:06d}"

    evidence = _upload_files(
        files,
        case_doc_id=doc_ref.id,
        case_number=case_number,
        consumer_id=consumer_id,
        consumer_uid=consumer_uid,
        admin_uid=admin_uid,
    )

    now, _, _ = _now_parts()
    status_val = "In Progress" if inspector else "Open"
    timeline = [_timeline_entry(f"Case created — {category}")]
    if inspector:
        timeline.append(_timeline_entry(f"Case assigned to {inspector}"))
    if evidence:
        timeline.append(_timeline_entry(f"{_file_word(len(evidence))} uploaded"))

    data = {
        "caseId": case_number,
        "consumerId": consumer_id,
        "consumerDocId": consumer["docId"] if consumer else "",
        "uid": consumer_uid,
        "consumerEmail": consumer_email,
        "consumerName": consumer_name,
        "description": description,
        "title": category,
        "issueType": category,
        "issueValue": category,
        "category": category,
        "location": area,
        "area": area,
        "riskLevel": risk_level,
        "priority": priority,
        "assignedInspector": inspector or "",
        "currentStatus": status_val,
        "status": status_val,
        "escalated": False,
        "resolution": "",
        "meterNumber": consumer_id,
        "evidence": evidence,
        "hasImage": False,  # legacy base64 flag; S3 evidence is counted from the array
        "timeline": timeline,
        "createdAt": now,
        "updatedAt": now,
        "createdBy": admin_uid,
    }
    try:
        doc_ref.set(data)
    except Exception:
        evidence_storage.delete_objects([e["s3Key"] for e in evidence])
        raise
    cache.invalidate()
    log.info("Case created: %s (%d evidence files)", case_number, len(evidence))

    notified = False
    if consumer:
        msg = f"Case {case_number} ({category}) was opened on your account. Priority: {priority}."
        if evidence:
            msg += f" {_file_word(len(evidence))} attached."
        notified = bool(
            _notify_consumer(
                consumer,
                event_key=f"{doc_ref.id}:created",
                ntype="case_created",
                title="New case on your account",
                message=msg,
                case_doc_id=doc_ref.id,
                case_data=data,
                evidence=evidence,
                admin_uid=admin_uid,
            )
        )

    detail = _case_doc_to_detail(doc_ref.id, data)
    detail["notified"] = notified
    return detail


def add_evidence(case_id: str, files: List[Tuple[str, bytes, str]], note: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    """Attach more evidence/documents to an existing case and notify the consumer."""
    snap = _load_case(case_id)
    if snap is None:
        return None
    if not files:
        raise HTTPException(status_code=400, detail="Choose at least one file to upload.")
    d = snap.to_dict() or {}
    consumer = _consumer_for_case(d)
    case_number = _case_number(d, snap.id)
    evidence = _upload_files(
        files,
        case_doc_id=snap.id,
        case_number=case_number,
        consumer_id=str(d.get("consumerId") or ""),
        consumer_uid=_consumer_uid(consumer),
        admin_uid=admin_uid,
    )
    now, _, _ = _now_parts()
    note = (note or "").strip()
    action = f"{_file_word(len(evidence))} uploaded" + (f" — {note}" if note else "")
    try:
        snap.reference.update(
            {
                "evidence": (d.get("evidence") or []) + evidence,
                "timeline": (d.get("timeline") or []) + [_timeline_entry(action)],
                "updatedAt": now,
            }
        )
    except Exception:
        evidence_storage.delete_objects([e["s3Key"] for e in evidence])
        raise
    cache.invalidate()

    if consumer:
        names = ", ".join(e["originalFileName"] for e in evidence[:3]) + ("…" if len(evidence) > 3 else "")
        msg = f"New evidence was added to case {case_number}: {names}."
        if note:
            msg += f" Note: {note}"
        _notify_consumer(
            consumer,
            event_key=f"{snap.id}:evidence:{evidence[0]['uploadBatchId']}",
            ntype="evidence_uploaded",
            title="Evidence uploaded to your case",
            message=msg,
            case_doc_id=snap.id,
            case_data=d,
            evidence=evidence,
            admin_uid=admin_uid,
        )
    return get_case_detail(snap.id)


def assign_inspector(case_id: str, inspector: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    snap = _load_case(case_id)
    if snap is None:
        return None
    inspector = (inspector or "").strip()
    if not inspector:
        raise HTTPException(status_code=400, detail="Inspector name is required.")

    d = snap.to_dict() or {}
    if str(d.get("assignedInspector") or "").strip() == inspector:
        return get_case_detail(snap.id)  # no change => no duplicate notification
    now, _, _ = _now_parts()
    current_status = _normalize_case_status(str(first(d, "currentStatus", "status", default="Open")))
    new_status = "In Progress" if current_status == "Open" else current_status

    snap.reference.update(
        {
            "assignedInspector": inspector,
            "currentStatus": new_status,
            "status": new_status,
            "updatedAt": now,
            "timeline": (d.get("timeline") or []) + [_timeline_entry(f"Case assigned to {inspector}")],
        }
    )
    cache.invalidate()

    consumer = _consumer_for_case(d)
    if consumer:
        case_number = _case_number(d, snap.id)
        d.update({"currentStatus": new_status, "assignedInspector": inspector})
        _notify_consumer(
            consumer,
            event_key=f"{snap.id}:assign:{inspector}:{int(now.timestamp())}",
            ntype="case_assigned",
            title="Inspector assigned to your case",
            message=f"An inspector ({inspector}) has been assigned to case {case_number}. Status: {new_status}.",
            case_doc_id=snap.id,
            case_data=d,
            admin_uid=admin_uid,
        )
    return get_case_detail(snap.id)


def update_case_status(case_id: str, new_status: str, note: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    raw = (new_status or "").strip()
    if raw.lower() not in _STATUS_ALIASES and raw.title() not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of: {', '.join(CASE_STATUSES)}")
    snap = _load_case(case_id)
    if snap is None:
        return None
    target = _normalize_case_status(raw)
    note = (note or "").strip()

    d = snap.to_dict() or {}
    current = _normalize_case_status(str(first(d, "currentStatus", "status", default="Open")))
    if current == target and not note:
        return get_case_detail(snap.id)  # nothing changed => no notification

    now, _, _ = _now_parts()
    action = f"Status changed to {target}" if current != target else f"Status confirmed as {target}"
    if note:
        action += f" — {note}"
    update: Dict[str, Any] = {
        "currentStatus": target,
        "status": target,
        "updatedAt": now,
        "timeline": (d.get("timeline") or []) + [_timeline_entry(action)],
    }
    if target in ("Closed", "Rejected"):
        update["resolvedAt"] = now
        if note:
            update["resolution"] = note
    snap.reference.update(update)
    cache.invalidate()

    consumer = _consumer_for_case(d)
    if consumer:
        case_number = _case_number(d, snap.id)
        d.update({"currentStatus": target})
        closed = target == "Closed"
        msg = (
            f"Your case ({case_number}) has been closed."
            if closed
            else f"The status of case {case_number} changed from {current} to {target}."
        )
        if note:
            msg += f" Admin note: {note}"
        _notify_consumer(
            consumer,
            event_key=f"{snap.id}:status:{target}:{int(now.timestamp())}",
            ntype="case_closed" if closed else "case_status_changed",
            title="Case closed" if closed else "Case status updated",
            message=msg,
            case_doc_id=snap.id,
            case_data=d,
            admin_uid=admin_uid,
        )
    return get_case_detail(snap.id)


def close_case(case_id: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    return update_case_status(case_id, "Closed", "", admin_uid)


def add_case_remark(case_id: str, message: str, notify: bool, admin_uid: str) -> Optional[Dict[str, Any]]:
    """Admin remark / instruction on the case timeline, optionally sent to the consumer."""
    snap = _load_case(case_id)
    if snap is None:
        return None
    text = (message or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Remark text is required.")
    if len(text) > 2000:
        raise HTTPException(status_code=400, detail="Remark is too long (2000 characters max).")
    d = snap.to_dict() or {}
    now, _, _ = _now_parts()
    remark = {"message": text, "by": admin_uid, "at": now, "sharedWithConsumer": bool(notify)}
    snap.reference.update(
        {
            "remarks": (d.get("remarks") or []) + [remark],
            "timeline": (d.get("timeline") or []) + [_timeline_entry(f"Admin remark: {text[:120]}")],
            "updatedAt": now,
        }
    )
    cache.invalidate()
    if notify:
        consumer = _consumer_for_case(d)
        if consumer:
            case_number = _case_number(d, snap.id)
            _notify_consumer(
                consumer,
                event_key=f"{snap.id}:remark:{hashlib.sha1(text.encode()).hexdigest()[:10]}:{int(now.timestamp())}",
                ntype="case_remark",
                title=f"Update on case {case_number}",
                message=text,
                case_doc_id=snap.id,
                case_data=d,
                admin_uid=admin_uid,
            )
    return get_case_detail(snap.id)


def escalate_case(
    case_id: str,
    *,
    escalation_level: str,
    reason: str,
    description: str,
    files: List[Tuple[str, bytes, str]],
    admin_uid: str,
) -> Optional[Dict[str, Any]]:
    snap = _load_case(case_id)
    if snap is None:
        return None

    d = snap.to_dict() or {}
    consumer = _consumer_for_case(d)
    case_number = _case_number(d, snap.id)
    new_evidence = _upload_files(
        files,
        case_doc_id=snap.id,
        case_number=case_number,
        consumer_id=str(d.get("consumerId") or ""),
        consumer_uid=_consumer_uid(consumer),
        admin_uid=admin_uid,
    )
    now, _, _ = _now_parts()
    try:
        snap.reference.update(
            {
                "escalated": True,
                "riskLevel": "Critical",
                "priority": "Urgent",
                "resolution": f"Escalated to {escalation_level}: {reason} — {description}",
                "evidence": (d.get("evidence") or []) + new_evidence,
                "updatedAt": now,
                "timeline": (d.get("timeline") or [])
                + [_timeline_entry(f"Case escalated to {escalation_level} — {reason}")],
            }
        )
    except Exception:
        evidence_storage.delete_objects([e["s3Key"] for e in new_evidence])
        raise
    cache.invalidate()

    if consumer:
        msg = f"Your case ({case_number}) has been escalated to {escalation_level} for further review."
        if new_evidence:
            msg += f" {_file_word(len(new_evidence))} attached."
        _notify_consumer(
            consumer,
            event_key=f"{snap.id}:escalate:{int(now.timestamp())}",
            ntype="case_escalated",
            title="Case escalated",
            message=msg,
            case_doc_id=snap.id,
            case_data=d,
            evidence=new_evidence,
            admin_uid=admin_uid,
        )

    return get_case_detail(snap.id)


def get_admin_evidence_url(case_id: str, evidence_id: str, disposition: str) -> Optional[Dict[str, Any]]:
    snap = _load_case(case_id)
    if snap is None:
        return None
    for item in _evidence_items(snap.to_dict() or {}):
        if item["id"] == evidence_id:
            return evidence_storage.presign_download(item, disposition)
    raise HTTPException(status_code=404, detail="Evidence file not found on this case.")


def send_admin_message(consumer_key: str, title: str, message: str, case_id: Optional[str], admin_uid: str) -> Dict[str, Any]:
    """Free-form admin notification to one consumer (optionally linked to one of their cases)."""
    title, message = (title or "").strip(), (message or "").strip()
    if not title or not message:
        raise HTTPException(status_code=400, detail="Title and message are required.")
    consumer = _find_consumer_doc(consumer_key)
    if not consumer:
        raise HTTPException(status_code=404, detail="Consumer not found.")
    case_doc_id, case_data = None, None
    if case_id:
        snap = _load_case(case_id)
        if snap is None:
            raise HTTPException(status_code=404, detail="Case not found.")
        case_data = snap.to_dict() or {}
        owner = _consumer_for_case(case_data)
        if not owner or owner["docId"] != consumer["docId"]:
            raise HTTPException(status_code=400, detail="That case does not belong to this consumer.")
        case_doc_id = snap.id
    now = datetime.now(timezone.utc)
    digest = hashlib.sha1((title + "\n" + message).encode()).hexdigest()[:10]
    nid = _notify_consumer(
        consumer,
        event_key=f"msg:{consumer['docId']}:{digest}:{int(now.timestamp())}",
        ntype="admin_message",
        title=title,
        message=message,
        case_doc_id=case_doc_id,
        case_data=case_data,
        admin_uid=admin_uid,
    )
    return {"ok": True, "id": nid}


def _notification_view(snap) -> Dict[str, Any]:
    d = snap.to_dict() or {}
    return {
        "id": snap.id,
        "type": str(d.get("type", "alert")),
        "title": str(d.get("title", "")),
        "message": str(d.get("message", "")),
        "caseId": d.get("caseId"),
        "caseDocId": d.get("caseDocId"),
        "caseTitle": d.get("caseTitle"),
        "caseStatus": d.get("caseStatus"),
        "evidence": [e for e in (d.get("evidence") or []) if isinstance(e, dict)],
        "consumerId": str(d.get("consumerId") or ""),
        "read": bool(d.get("read", False)),
        "readAt": _iso(d.get("readAt")),
        "createdAt": _iso(d.get("createdAt")),
    }


def list_sent_notifications(limit: int, case_id: Optional[str], consumer_id: Optional[str]) -> List[Dict[str, Any]]:
    """Admin history of consumer notifications (newest first)."""
    s = get_settings()
    col = get_db().collection(s.consumer_notifications_collection)
    if case_id:
        snap = _load_case(case_id)
        if snap is None:
            return []
        snaps = list(col.where("caseDocId", "==", snap.id).stream())
    elif consumer_id:
        consumer = _find_consumer_doc(consumer_id)
        if not consumer:
            return []
        snaps = list(col.where("recipientUid", "==", _consumer_uid(consumer)).stream())
    else:
        snaps = list(col.order_by("createdAt", direction=_fb_firestore.Query.DESCENDING).limit(limit).stream())
    out = [_notification_view(sn) for sn in snaps]
    out.sort(key=lambda n: n["createdAt"] or "", reverse=True)
    return out[:limit]


def list_inspectors() -> List[Dict[str, Any]]:
    s = get_settings()
    rows = list(get_db().collection(s.inspectors_collection).stream())
    if rows:
        return [
            {
                "id": snap.id,
                "name": str(first(d, "name", default=snap.id)),
                "area": str(first(d, "area", default="")),
                "available": bool(d.get("available", True)),
            }
            for snap in rows
            for d in [snap.to_dict() or {}]
        ]

    # Fallback: cases mai jo inspector names pehle se use ho rahe hain
    names = sorted({c["assignedInspector"] for c in _cases() if c["assignedInspector"]})
    return [{"id": f"insp:{n}", "name": n, "area": "", "available": True} for n in names]


# ─────────────────────────────────────────────────────────────
# CONSUMER-FACING ("me" endpoints)
# ─────────────────────────────────────────────────────────────
def _me(uid: str, email: str) -> Optional[Dict[str, Any]]:
    """Signed-in consumer: {"docId", "uid", "consumerId", "email"}."""
    s = get_settings()
    col = get_db().collection(s.consumers_collection)
    snap = col.document(uid).get()
    if not snap.exists:
        rows = list(col.where("uid", "==", uid).limit(1).stream())
        snap = rows[0] if rows else None
    if snap is None:
        return None
    d = snap.to_dict() or {}
    return {
        "docId": snap.id,
        "uid": uid,
        "consumerId": str(d.get("consumerId") or "").strip(),
        "email": str(d.get("email") or email or "").strip().lower(),
    }


def _case_belongs_to(d: Dict[str, Any], me: Dict[str, Any]) -> bool:
    if me["uid"] and me["uid"] in (str(d.get("uid") or ""), str(d.get("consumerUid") or "")):
        return True
    if str(d.get("consumerDocId") or "") == me["docId"]:
        return True
    if me["consumerId"] and str(d.get("consumerId") or "").strip().lower() == me["consumerId"].lower():
        return True
    email = str(d.get("consumerEmail") or "").strip().lower()
    return bool(email) and email == me["email"]


def _my_case_snapshot(uid: str, email: str, case_id: str):
    me = _me(uid, email)
    if not me:
        raise HTTPException(status_code=404, detail="Consumer profile not found.")
    snap = _load_case(case_id)
    # Same 404 for "missing" and "not yours" so case ids cannot be probed.
    if snap is None or not _case_belongs_to(snap.to_dict() or {}, me):
        raise HTTPException(status_code=404, detail="Case not found.")
    return snap


def _consumer_case_view(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    evidence = [
        evidence_storage.public_view(item)
        for item in _evidence_items(d)
        if item.get("visibleToConsumer", True)
    ]
    remarks = [
        {"message": str(r.get("message", "")), "at": _iso(r.get("at"))}
        for r in (d.get("remarks") or [])
        if isinstance(r, dict) and r.get("sharedWithConsumer", True)
    ]
    return {
        "id": doc_id,
        "caseNumber": _case_number(d, doc_id),
        "title": _case_title(d),
        "category": str(first(d, "category", "issueType", default="")),
        "description": str(first(d, "description", default="")),
        "status": _normalize_case_status(str(first(d, "currentStatus", "status", default="Open"))),
        "priority": str(first(d, "priority", default="Normal")),
        "area": str(first(d, "area", "location", default="")),
        "inspectorAssigned": bool(str(d.get("assignedInspector") or "").strip()),
        "inspector": str(d.get("assignedInspector") or "").strip() or None,
        "createdAt": _iso(first(d, "createdAt", "created_at")),
        "updatedAt": _iso(first(d, "updatedAt", "updated_at")),
        "timeline": _timeline(d),
        "remarks": remarks,
        "evidence": evidence,
    }


def list_my_cases(uid: str, email: str) -> List[Dict[str, Any]]:
    me = _me(uid, email)
    if not me:
        return []
    s = get_settings()
    col = get_db().collection(s.cases_collection)
    seen: Dict[str, Any] = {}
    queries = [("uid", me["uid"]), ("consumerDocId", me["docId"])]
    if me["consumerId"]:
        queries.append(("consumerId", me["consumerId"]))
    for field, value in queries:
        for snap in col.where(field, "==", value).stream():
            seen.setdefault(snap.id, snap)
    out = [
        _consumer_case_view(snap.id, snap.to_dict() or {})
        for snap in seen.values()
        if _case_belongs_to(snap.to_dict() or {}, me)
    ]
    out.sort(key=lambda c: c["createdAt"] or "", reverse=True)
    return out


def get_my_case(uid: str, email: str, case_id: str) -> Dict[str, Any]:
    snap = _my_case_snapshot(uid, email, case_id)
    return _consumer_case_view(snap.id, snap.to_dict() or {})


def get_my_evidence_url(uid: str, email: str, case_id: str, evidence_id: str, disposition: str) -> Dict[str, Any]:
    snap = _my_case_snapshot(uid, email, case_id)
    for item in _evidence_items(snap.to_dict() or {}):
        if item["id"] == evidence_id and item.get("visibleToConsumer", True):
            log.info("Consumer evidence download: case=%s evidence=%s", snap.id, evidence_id)
            return evidence_storage.presign_download(item, disposition)
    raise HTTPException(status_code=404, detail="Evidence file not found.")


def get_my_notifications(uid: str, email: str, limit: int = 100) -> List[Dict[str, Any]]:
    s = get_settings()
    col = get_db().collection(s.consumer_notifications_collection)
    # Equality filter only (no composite index needed); sorted here.
    snaps = list(col.where("recipientUid", "==", uid).limit(500).stream())
    out = [_notification_view(sn) for sn in snaps]
    out.sort(key=lambda n: n["createdAt"] or "", reverse=True)
    return out[:limit]


def mark_my_notifications_read(uid: str, email: str, ids: List[str], mark_all: bool = False) -> int:
    s = get_settings()
    db = get_db()
    col = db.collection(s.consumer_notifications_collection)
    if mark_all:
        targets = [sn for sn in col.where("recipientUid", "==", uid).stream() if not (sn.to_dict() or {}).get("read")]
    else:
        targets = []
        for nid in dict.fromkeys(str(i) for i in (ids or []) if i):
            if "/" in nid:
                continue
            sn = col.document(nid).get()
            # Only the recipient may change it.
            if sn.exists and (sn.to_dict() or {}).get("recipientUid") == uid:
                targets.append(sn)
    if not targets:
        return 0
    now = datetime.now(timezone.utc)
    batch = db.batch()
    for sn in targets:
        batch.update(sn.reference, {"read": True, "readAt": now})
    batch.commit()
    return len(targets)
