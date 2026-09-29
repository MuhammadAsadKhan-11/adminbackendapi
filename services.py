"""services.py — Firestore se data uthana, normalise karna aur
Dashboard KPIs / chart / risk list / consumer profile banana.

REAL Firestore schema (tumhare console screenshot ke mutabiq):

  consumers     (registered accounts)
      fullName, email, mobileNumber, consumerId, cnicNumber, role, createdAt
      optional: address, area/location/city, meterNumber, status

  consumptions  (HAR CSV UPLOAD ka ek document)
      consumerId ("54321"), consumerName, email,
      totalUnits (77.6), avgUnits (4.1), estimatedBill (1551),
      prediction ("No Theft" / "Theft"), riskScore (1 => 1%),
      dateRange ("05/07/2026 – 06/01/2026"), csvRaw ("05/07/2026,05/08/2026,..."),
      uploadedAt (Timestamp)

  cases         (admin app ke cases — NOTE: imageUrl mai bada base64 hota hai, is liye
                 REST loads mai field projection (select) use hoti hai)
      caseId ("RPT-4011"), consumerId, consumerEmail, consumerName, createdAt,
      currentStatus ("Under Investigation"), description, issueType, issueValue,
      location ("I8"), escalated, resolution, assignedInspector, riskLevel

Ek consumer ke kayi uploads ho sakte hain: LATEST upload uska current risk/prediction
hai, aur csvRaw se daily readings nikal kar chart/history banti hai.
"""
from __future__ import annotations

import logging
import re
import statistics
import threading
import time
import uuid
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from core import get_bucket, get_db, get_settings, local_tz
from firebase_admin import firestore as _fb_firestore

try:
    import requests  # Expo push notifications ke liye
except ImportError:  # requirements.txt mai add hai, lekin fail-safe
    requests = None  # type: ignore

log = logging.getLogger("electraguard.services")

# status mai in mai se koi lafz ho to case "resolved" maana jata hai
RESOLVED_WORDS = ("resolved", "closed", "complete", "done", "dismiss", "reject", "false alarm")
# Cases collection se sirf yeh fields parhte hain (imageUrl base64 skip)
CASE_FIELDS = [
    "caseId", "caseNumber", "caseNo", "case_number",
    "consumerId", "consumerUid", "consumer_id", "uid", "userId", "consumerEmail", "email",
    "description", "title", "issueType", "issueValue", "location",
    "consumerName", "riskLevel", "assignedInspector",
    "currentStatus", "status", "escalated", "resolution",
    "createdAt", "created_at", "resolvedAt", "closedAt", "resolved_at",
    "updatedAt", "updated_at", "lastUpdated", "statusUpdatedAt",
    # Case Management screens (Create/Escalate) ke naye fields:
    "priority", "meterNumber", "evidence", "timeline", "createdBy",
]
BLANK_IDS = {"", "—", "-", "none", "null"}


# ─────────────────────────────────────────────────────────────
# SMALL CACHE  (Firestore reads bachane ke liye; listener change par clear hota hai)
# ─────────────────────────────────────────────────────────────
class TTLCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get_or_load(self, key: str, loader: Callable[[], Any]) -> Any:
        ttl = get_settings().cache_ttl_seconds
        now = time.monotonic()
        with self._lock:
            hit = self._data.get(key)
            if hit is not None and now - hit[0] < ttl:
                return hit[1]
        value = loader()
        with self._lock:
            self._data[key] = (time.monotonic(), value)
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._data.clear()


cache = TTLCache()


# ─────────────────────────────────────────────────────────────
# GENERIC HELPERS
# ─────────────────────────────────────────────────────────────
def first(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """d mai se pehli maujood (None/"" nahi) key ki value."""
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return v
    return default


def num(v: Any, default: float = 0.0) -> float:
    if v is None or isinstance(v, bool):
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def opt_num(v: Any) -> Optional[float]:
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def to_float(tok: str) -> Optional[float]:
    tok = tok.strip().strip('"').strip("'").replace(" ", "")
    if not tok:
        return None
    try:
        return float(tok)
    except ValueError:
        return None


def to_dt(v: Any) -> Optional[datetime]:
    """Firestore Timestamp / datetime / ISO string / epoch => aware datetime (UTC)."""
    if v is None:
        return None
    if isinstance(v, datetime):  # DatetimeWithNanoseconds bhi yahin aata hai
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day, tzinfo=timezone.utc)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        ts = v / 1000.0 if v > 1e11 else float(v)  # ms ya seconds
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(v, str):
        try:
            dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def to_local_day(dt: datetime) -> date:
    return dt.astimezone(local_tz()).date()


def today_local() -> date:
    return datetime.now(local_tz()).date()


def fmt_date(d: Optional[date]) -> str:
    if d is None:
        return "—"
    return f"{d.day:02d} {d.strftime('%b')} {d.year}"


def fmt_label(d: date) -> str:
    return f"{d.strftime('%b')} {d.day:02d}"


def fmt_pkr(v: float) -> str:
    if v >= 1_000_000:
        return f"PKR {v / 1_000_000:.1f}M"
    if v >= 1_000:
        return f"PKR {v / 1_000:.1f}K"
    return f"PKR {v:,.0f}"


def pct_change(new: float, old: float) -> Optional[float]:
    if old <= 0:
        return None
    return round((new - old) / old * 100.0, 1)


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == 1
    return isinstance(v, str) and v.strip().lower() in {"true", "1", "yes"}


def norm_key(v: Any) -> str:
    return str(v).strip().lower() if v is not None else ""


def make_keys(*vals: Any) -> Set[str]:
    return {norm_key(v) for v in vals if norm_key(v) not in BLANK_IDS}


# ─────────────────────────────────────────────────────────────
# RISK / PREDICTION
# ─────────────────────────────────────────────────────────────
def normalize_score(v: Any) -> int:
    """riskScore percent (0-100) maana jata hai (tumhare doc mai riskScore: 1 with 'No Theft').
    Sirf non-integer float 0 < x < 1 (jaise 0.87) ko fraction samajh kar 87 banate hain."""
    n = num(v)
    if isinstance(v, float) and 0 < n < 1:
        n *= 100
    return int(round(max(0.0, min(n, 100.0))))


_NEGATIVE_PREDICTIONS = (
    "no theft", "not theft", "non-theft", "non theft", "no_theft",
    "no anomal", "normal", "safe", "legit", "clean",
)


def is_theft_prediction(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == 1
    if not isinstance(v, str):
        return False
    p = v.strip().lower()
    if not p:
        return False
    if any(w in p for w in _NEGATIVE_PREDICTIONS):
        return False
    return "theft" in p or "fraud" in p or "anomal" in p or p in {"1", "true", "yes"}


def compute_level(score: int, is_theft: bool) -> str:
    s = get_settings()
    if is_theft or score >= s.high_risk_threshold:
        return "High"
    if score >= s.medium_risk_threshold:
        return "Medium"
    return "Low"


def _account_status(d: Dict[str, Any]) -> str:
    raw = first(d, "status", "accountStatus")
    if isinstance(raw, str):
        ok = raw.strip().lower() in {"active", "enabled", "verified", "approved"}
        return "Active" if ok else "Inactive"
    if d.get("isActive") is False or d.get("disabled") is True:
        return "Inactive"
    return "Active"


# ─────────────────────────────────────────────────────────────
# csvRaw / dateRange PARSING
# ─────────────────────────────────────────────────────────────
DATE_FORMATS = (
    "%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%d", "%Y/%m/%d",
    "%m/%d/%y", "%d/%m/%y", "%d-%m-%Y", "%m-%d-%Y",
)


def _parse_dates(tokens: List[str]) -> Optional[List[date]]:
    """Tokens ko dates banata hai. Jo format daily (sab se kam gap) sequence deta hai wahi chunta hai,
    is se 05/07 = May 7 (MM/DD) aur 05/07 = 5 Jul (DD/MM) ka farq khud hal ho jata hai."""
    toks = [t.strip().strip('"').strip("'") for t in tokens]
    if not toks or any(not t for t in toks):
        return None
    best: Optional[List[date]] = None
    best_span = 0
    for fmt in DATE_FORMATS:
        try:
            ds = [datetime.strptime(t, fmt).date() for t in toks]
        except ValueError:
            continue
        if any(b < a for a, b in zip(ds, ds[1:])):
            continue
        span = (ds[-1] - ds[0]).days
        if best is None or span < best_span:
            best, best_span = ds, span
    return best


def parse_csv_series(raw: Any) -> List[Tuple[date, float]]:
    """csvRaw se daily (date, kWh) nikalta hai. Do layouts support hain:
      A) wide : pehli line dates ka header, agli line values
                 05/07/2026,05/08/2026,...
                 4.2,3.9,...            (values se pehle extra columns ho sakte hain)
      B) long : har line "date,value"
    Parse na ho to [] (caller dateRange/totalUnits par fallback karta hai)."""
    if not isinstance(raw, str) or not raw.strip():
        return []
    lines = [ln for ln in re.split(r"[\r\n]+", raw) if ln.strip()]
    rows = [[c.strip().strip('"').strip("'") for c in ln.split(",")] for ln in lines]

    # A) wide
    if len(rows) >= 2:
        for skip in range(0, 4):
            head = rows[0][skip:]
            dates = _parse_dates(head) if len(head) >= 2 else None
            if not dates:
                continue
            n = len(dates)
            for row in rows[1:]:
                if len(row) < n:
                    continue
                vals = [to_float(t) for t in row[-n:]]
                if sum(v is not None for v in vals) >= max(1, n // 2):
                    return [(d, v) for d, v in zip(dates, vals) if v is not None]
            break

    # B) long
    body = rows
    dates = _parse_dates([r[0] for r in body if r])
    if not dates and len(body) > 1:
        body = rows[1:]  # header line hata do
        dates = _parse_dates([r[0] for r in body if r])
    if dates:
        out: List[Tuple[date, float]] = []
        for d, r in zip(dates, [r for r in body if r]):
            v = to_float(r[1]) if len(r) > 1 else None
            if v is not None:
                out.append((d, v))
        return out
    return []


def _range_days(s: Any) -> List[date]:
    """"05/07/2026 – 06/01/2026" => is range ke saare din."""
    if not isinstance(s, str):
        return []
    toks = re.findall(r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4}", s)
    if len(toks) < 2:
        return []
    ds = _parse_dates([t.replace(".", "/") for t in toks[:2]])
    if not ds:
        return []
    span = (ds[1] - ds[0]).days
    if span < 0 or span > 400:
        return []
    return [ds[0] + timedelta(days=i) for i in range(span + 1)]


# ─────────────────────────────────────────────────────────────
# LOADERS  (Firestore => clean dicts)
# ─────────────────────────────────────────────────────────────
def normalize_upload(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    total = num(first(d, "totalUnits", "total_units", "totalKwh"))
    series = parse_csv_series(d.get("csvRaw"))
    source = "csv"
    if not series:
        days = _range_days(d.get("dateRange"))
        if days and total > 0:
            per_day = total / len(days)
            series = [(x, per_day) for x in days]
            source = "dateRange"
    uploaded = to_dt(first(d, "uploadedAt", "createdAt", "timestamp"))
    if not series and uploaded and total > 0:
        series = [(to_local_day(uploaded), total)]
        source = "uploadedAt"

    prediction = str(first(d, "prediction", "result", "label", default="")).strip()
    raw_csv = d.get("csvRaw")
    return {
        "id": doc_id,
        "consumerId": str(first(d, "consumerId", "consumer_id", default="")).strip(),
        "name": str(first(d, "consumerName", "name", "fullName", default="")).strip(),
        "email": str(first(d, "email", default="")).strip(),
        "prediction": prediction,
        "isTheft": is_theft_prediction(first(d, "prediction", "result", "label")),
        "riskScore": normalize_score(d.get("riskScore")),
        "totalUnits": total,
        "avgUnits": num(first(d, "avgUnits", "avg_units")),
        "estimatedBill": num(d.get("estimatedBill")),
        "estimatedLossKwh": opt_num(d.get("estimatedLossKwh")),
        "dateRange": str(first(d, "dateRange", default="")),
        "uploadedAt": uploaded,
        "series": sorted(series, key=lambda x: x[0]),
        "seriesSource": source,
        "csvPreview": raw_csv[:160] if isinstance(raw_csv, str) else "",
    }


def _uploads() -> List[Dict[str, Any]]:
    """Sab consumption uploads, purane se naye (uploadedAt) order mai."""

    def load() -> List[Dict[str, Any]]:
        s = get_settings()
        out = [
            normalize_upload(snap.id, snap.to_dict() or {})
            for snap in get_db().collection(s.consumptions_collection).stream()
        ]
        floor = datetime.min.replace(tzinfo=timezone.utc)
        out.sort(key=lambda u: u["uploadedAt"] or floor)
        return out

    return cache.get_or_load("uploads", load)


def _registered() -> List[Dict[str, Any]]:
    def load() -> List[Dict[str, Any]]:
        s = get_settings()
        out: List[Dict[str, Any]] = []
        for snap in get_db().collection(s.consumers_collection).stream():
            d = snap.to_dict() or {}
            if str(d.get("role", "consumer")).lower() == "admin":
                continue
            address = str(first(d, "address", default=""))
            out.append(
                {
                    "id": snap.id,
                    "consumerId": str(first(d, "consumerId", "consumer_id", default="")).strip(),
                    "name": str(first(d, "fullName", "name", "consumerName", default="Unknown")),
                    "email": str(first(d, "email", default="")).strip(),
                    "phone": str(first(d, "mobileNumber", "phone", "contact", default="")),
                    "cnic": str(first(d, "cnicNumber", "cnic", default="")),
                    "meterNumber": str(first(d, "meterNumber", "meterNo", "meter_number", default="")),
                    "address": address,
                    "location": str(first(d, "area", "location", "city", default="") or address),
                    "status": _account_status(d),
                }
            )
        return out

    return cache.get_or_load("registered", load)


def _cases() -> List[Dict[str, Any]]:
    def load() -> List[Dict[str, Any]]:
        s = get_settings()
        out: List[Dict[str, Any]] = []
        # select(): imageUrl (base64) download nahi hota
        query = get_db().collection(s.cases_collection).select(CASE_FIELDS)
        for snap in query.stream():
            d = snap.to_dict() or {}
            status_raw = str(first(d, "currentStatus", "status", default="Open")).strip() or "Open"
            issue_type = str(first(d, "issueType", default="")).strip()
            issue_value = str(first(d, "issueValue", default="")).strip()
            out.append(
                {
                    "id": snap.id,
                    "keys": make_keys(
                        *[
                            d.get(k)
                            for k in (
                                "consumerId", "consumerUid", "consumer_id", "uid",
                                "userId", "consumerEmail", "email",
                            )
                        ]
                    ),
                    "caseNumber": str(first(d, "caseId", "caseNumber", "caseNo", "case_number", default=snap.id)),
                    # card par chhota title: issueType, warna description
                    "description": issue_type or str(first(d, "description", "title", default="")),
                    "fullDescription": str(first(d, "description", "title", default="")).strip(),
                    "issueType": issue_type,
                    "issueValue": issue_value,
                    "consumerId": str(first(d, "consumerId", "consumer_id", default="")).strip(),
                    "consumerName": str(first(d, "consumerName", default="")).strip(),
                    "text": str(first(d, "description", "title", default="")).strip(),
                    "escalated": _truthy(d.get("escalated")),
                    "riskLevel": str(first(d, "riskLevel", default="")).strip(),
                    "location": str(first(d, "location", default="")).strip(),
                    "status": status_raw.title(),
                    "resolved": any(w in status_raw.lower() for w in RESOLVED_WORDS),
                    "createdAt": to_dt(first(d, "createdAt", "created_at")),
                    "resolvedAt": to_dt(first(d, "resolvedAt", "closedAt", "resolved_at")),
                    "updatedAt": to_dt(first(d, "updatedAt", "updated_at", "lastUpdated", "statusUpdatedAt")),
                    # Case Management (naye fields):
                    "priority": str(first(d, "priority", default="")).strip(),
                    "assignedInspector": str(first(d, "assignedInspector", default="")).strip(),
                    "evidenceCount": len(d.get("evidence") or []),
                }
            )
        return out

    return cache.get_or_load("cases", load)


def _is_theft_case(c: Dict[str, Any]) -> bool:
    """THEFT_CASE_ISSUE_TYPES set ho to sirf unhi issue types ke cases 'theft cases' hain."""
    raw = get_settings().theft_case_issue_types
    wanted = {w.strip().lower() for w in raw.split(",") if w.strip()}
    if not wanted:
        return True
    return c["issueValue"].lower() in wanted or c["issueType"].lower() in wanted


# ─────────────────────────────────────────────────────────────
# MODEL  (registered consumers + uploads => entities)
# ─────────────────────────────────────────────────────────────
def _anomaly(days: Dict[date, Tuple[float, bool]]) -> float:
    """Aakhri 7 din ki average consumption pichle dinon ki average se kitni zyada (%)."""
    vals = [v for _, (v, _t) in sorted(days.items())]
    if len(vals) < 10:
        return 0.0
    recent = sum(vals[-7:]) / 7.0
    rest = vals[:-7]
    base = sum(rest) / len(rest)
    if base <= 0 or recent <= base:
        return 0.0
    return float(round((recent - base) / base * 100.0))


def _per_day(u: Dict[str, Any]) -> float:
    """Upload ki daily average (kWh/din). Alag-alag period wale uploads ko fair compare karne ke liye."""
    if u["avgUnits"] > 0:
        return u["avgUnits"]
    n = max(len(u["series"]), 1)
    return u["totalUnits"] / n


def _model() -> Dict[str, Any]:
    def load() -> Dict[str, Any]:
        entities: List[Dict[str, Any]] = []
        by_key: Dict[str, Dict[str, Any]] = {}

        def register(e: Dict[str, Any]) -> None:
            entities.append(e)
            for k in e["keys"]:
                by_key.setdefault(k, e)

        for r in _registered():
            register(
                {
                    **r,
                    "registered": True,
                    "uploads": [],
                    "keys": make_keys(r["id"], r["consumerId"], r["email"]),
                }
            )

        for u in _uploads():
            e = None
            for cand in (u["consumerId"], u["email"]):
                k = norm_key(cand)
                if k and k not in BLANK_IDS and k in by_key:
                    e = by_key[k]
                    break
            if e is None:
                ident = u["consumerId"] or u["email"] or u["id"]
                register(
                    {
                        "id": f"cid:{ident}",
                        "consumerId": u["consumerId"],
                        "name": u["name"] or "Unknown",
                        "email": u["email"],
                        "phone": "",
                        "cnic": "",
                        "meterNumber": "",
                        "address": "",
                        "location": "",
                        "status": "Active",
                        "registered": False,
                        "uploads": [],
                        "keys": make_keys(f"cid:{ident}", u["consumerId"], u["email"]),
                    }
                )
                e = entities[-1]
            e["uploads"].append(u)
            # is upload ke naye identifiers bhi index kar lo (email/consumerId)
            for k in make_keys(u["consumerId"], u["email"]):
                e["keys"].add(k)
                by_key.setdefault(k, e)

        # consumers doc mai area/address na ho to us consumer ke sab se naye case ki location use karo
        floor = datetime.min.replace(tzinfo=timezone.utc)
        for c in sorted(_cases(), key=lambda x: x["createdAt"] or floor):
            if not c["location"]:
                continue
            for k in c["keys"]:
                target = by_key.get(k)
                if target is not None:
                    target["caseLocation"] = c["location"]
                    break

        daily: Dict[date, Dict[str, float]] = defaultdict(lambda: {"normal": 0.0, "theft": 0.0})
        all_days: List[date] = []

        for e in entities:
            if not e["location"]:
                e["location"] = e.get("caseLocation", "")
            ups = e["uploads"]
            latest = ups[-1] if ups else None
            e["latest"] = latest
            e["hasData"] = latest is not None
            e["riskScore"] = latest["riskScore"] if latest else 0
            e["isTheft"] = bool(latest["isTheft"]) if latest else False
            e["riskLevel"] = compute_level(e["riskScore"], e["isTheft"])
            e["consumption"] = latest["totalUnits"] if latest else 0.0
            e["prevConsumption"] = ups[-2]["totalUnits"] if len(ups) >= 2 else None
            e["perDay"] = _per_day(latest) if latest else 0.0
            e["prevPerDay"] = _per_day(ups[-2]) if len(ups) >= 2 else None

            days: Dict[date, Tuple[float, bool]] = {}
            for u in ups:  # purane pehle => naya upload overlap mai jeet-ta hai
                for d_, v in u["series"]:
                    days[d_] = (v, bool(u["isTheft"]))
            e["days"] = days
            e["anomaly"] = _anomaly(days)

            for d_, (v, th) in days.items():
                daily[d_]["theft" if th else "normal"] += v
                all_days.append(d_)

        return {
            "entities": entities,
            "by_key": by_key,
            "daily": dict(daily),
            "ref_day": max(all_days) if all_days else None,
        }

    return cache.get_or_load("model", load)


def _summary(e: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": e["id"],
        "consumerId": e["consumerId"],
        "name": e["name"],
        "meterNumber": e["meterNumber"],
        "location": e["location"],
        "riskScore": e["riskScore"],
        "riskLevel": e["riskLevel"],
        "consumption": round(e["consumption"], 1),
        "anomaly": e["anomaly"],
        "status": e["status"],
    }


def _estimated_loss_pkr(e: Dict[str, Any]) -> float:
    """Sirf theft-flagged consumers ka estimated loss (PKR)."""
    s = get_settings()
    latest = e["latest"]
    if not latest or not e["isTheft"]:
        return 0.0
    units = latest["totalUnits"]
    if latest["estimatedLossKwh"] is not None:
        loss_kwh = max(latest["estimatedLossKwh"], 0.0)
    else:
        loss_kwh = units * s.theft_loss_fraction
    # asal tariff: is consumer ka estimatedBill / totalUnits, warna default tariff
    bill = latest["estimatedBill"]
    tariff = bill / units if units > 0 and bill > 0 else s.tariff_pkr_per_kwh
    return loss_kwh * tariff


# ─────────────────────────────────────────────────────────────
# PUBLIC BUILDERS
# ─────────────────────────────────────────────────────────────
def build_dashboard() -> Dict[str, Any]:
    s = get_settings()
    m = _model()
    cases = _cases()
    ents: List[Dict[str, Any]] = m["entities"]
    with_data = [e for e in ents if e["hasData"]]

    today = today_local()
    ref_day: date = m["ref_day"] or today

    total = len(ents)
    registered = sum(1 for e in ents if e["registered"])
    active = sum(1 for e in ents if e["registered"] and e["status"] == "Active")
    high = sum(1 for e in with_data if e["riskLevel"] == "High")

    # ── total consumption ──
    if s.total_consumption_mode.strip().lower() == "all":
        total_kwh = sum(u["totalUnits"] for e in ents for u in e["uploads"])
        scope_label = "kWh (all uploads)"
    else:
        total_kwh = sum(e["consumption"] for e in with_data)
        scope_label = "kWh (latest)"
    # % change: daily average (kWh/din) ka comparison, taake alag-alag period wale uploads galat % na dein
    cur = sum(e["perDay"] for e in ents if e["prevPerDay"] is not None)
    prev = sum(e["prevPerDay"] for e in ents if e["prevPerDay"] is not None)
    kwh_change = pct_change(cur, prev)

    # ── loss ──
    loss_pkr = sum(_estimated_loss_pkr(e) for e in with_data)

    # ── cases ──
    active_cases = sum(1 for c in cases if not c["resolved"] and _is_theft_case(c))
    resolved_now = 0
    resolved_prev = 0
    prev_last = today.replace(day=1) - timedelta(days=1)
    for c in cases:
        if not c["resolved"] or not _is_theft_case(c):
            continue
        when = c["resolvedAt"] or c["updatedAt"] or c["createdAt"]
        if when is None:
            continue
        d = to_local_day(when)
        if (d.year, d.month) == (today.year, today.month):
            resolved_now += 1
        elif (d.year, d.month) == (prev_last.year, prev_last.month) and d.day <= today.day:
            resolved_prev += 1

    # ── chart (latest data ke aakhri 7 din) ──
    points: List[Dict[str, Any]] = []
    for i in range(6, -1, -1):
        d = ref_day - timedelta(days=i)
        v = m["daily"].get(d, {"normal": 0.0, "theft": 0.0})
        points.append(
            {
                "date": d.isoformat(),
                "label": fmt_label(d),
                "normal": round(v["normal"], 1),
                "theft": round(v["theft"], 1),
            }
        )
    first_theft = next((p["theft"] for p in points if p["theft"] > 0), None)
    last_theft = points[-1]["theft"]
    spike = round(last_theft / first_theft, 1) if first_theft else None

    return {
        "kpis": {
            "totalConsumers": total,
            "totalConsumptionKwh": round(total_kwh, 1),
            "consumptionScopeLabel": scope_label,
            "consumptionChangePct": kwh_change,
            "activeMembers": active,
            "registeredCount": registered,
            "activePct": round(active / registered * 100.0, 1) if registered else 0.0,
            "highRiskConsumers": high,
            "highRiskPct": round(high / total * 100.0, 1) if total else 0.0,
            "theftCases": active_cases,
            "revenueLoss": round(loss_pkr, 0),
            "revenueLossFormatted": fmt_pkr(loss_pkr),
            "casesResolved": resolved_now,
            "casesResolvedChangePct": pct_change(float(resolved_now), float(resolved_prev)),
            "tariffPkrPerKwh": s.tariff_pkr_per_kwh,
        },
        "chart": {
            "points": points,
            "spikeRatio": spike,
            "windowStart": points[0]["date"],
            "windowEnd": points[-1]["date"],
        },
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }


def build_risk_list(
    level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    ents = [e for e in _model()["entities"] if e["hasData"]]  # jis ki koi upload hai

    counts = {
        "All": len(ents),
        "High": sum(1 for e in ents if e["riskLevel"] == "High"),
        "Medium": sum(1 for e in ents if e["riskLevel"] == "Medium"),
        "Low": sum(1 for e in ents if e["riskLevel"] == "Low"),
    }

    rows = list(ents)
    if level and level.strip().lower() != "all":
        lv = level.strip().lower()
        rows = [e for e in rows if e["riskLevel"].lower() == lv]
    if search and search.strip():
        q = search.strip().lower()
        rows = [
            e
            for e in rows
            if q
            in " ".join(
                [e["name"], e["consumerId"], e["meterNumber"], e["location"], e["address"], e["email"]]
            ).lower()
        ]

    rows.sort(key=lambda e: e["riskScore"], reverse=True)
    return {
        "total": len(rows),
        "counts": counts,
        "items": [_summary(e) for e in rows[: max(1, limit)]],
    }


def _flags_for(e: Dict[str, Any]) -> List[Dict[str, Any]]:
    s = get_settings()
    flags: List[Dict[str, Any]] = []

    # 1) ML prediction jahan "Theft" aaya
    for u in reversed(e["uploads"]):
        if u["isTheft"]:
            flags.append(
                {
                    "type": "ML Theft Detection",
                    "day": to_local_day(u["uploadedAt"]) if u["uploadedAt"] else None,
                    "severity": "High" if u["riskScore"] >= s.high_risk_threshold else "Medium",
                }
            )

    # 2) daily readings mai spikes (median se 2x se zyada)
    days = sorted(e["days"].items())
    if len(days) >= 7:
        med = statistics.median(v for _, (v, _t) in days)
        if med > 0:
            spikes = [(d, v) for d, (v, _t) in reversed(days) if v > 2 * med][:3]
            for d, v in spikes:
                flags.append(
                    {
                        "type": "Consumption Spike",
                        "day": d,
                        "severity": "High" if v > 3 * med else "Medium",
                    }
                )

    flags.sort(key=lambda f: f["day"] or date.min, reverse=True)
    return flags


def build_profile(key: str) -> Optional[Dict[str, Any]]:
    m = _model()
    e = m["by_key"].get(norm_key(key))
    if e is None:
        return None

    days = sorted(e["days"].items())[-7:]
    history = [
        {"date": d.isoformat(), "label": fmt_label(d), "value": round(v, 1)}
        for d, (v, _t) in days
    ]

    case_rows = sorted(
        (c for c in _cases() if c["keys"] & e["keys"]),
        key=lambda c: c["createdAt"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    latest = e["latest"]
    last_day = max(e["days"]) if e["days"] else (
        to_local_day(latest["uploadedAt"]) if latest and latest["uploadedAt"] else None
    )

    profile = _summary(e)
    profile.update(
        {
            "email": e["email"],
            "phone": e["phone"],
            "cnic": e["cnic"],
            "address": e["address"] or e["location"],
            "lastReading": fmt_date(last_day) if last_day else None,
            "prediction": (latest["prediction"] if latest else "") or "—",
            "estimatedBill": latest["estimatedBill"] if latest else 0.0,
            "dateRange": (latest["dateRange"] if latest else "") or "—",
            "consumptionHistory": history,
            "theftFlags": [
                {"type": f["type"], "date": fmt_date(f["day"]), "severity": f["severity"]}
                for f in _flags_for(e)
            ],
            "cases": [
                {
                    "id": c["id"],
                    "caseNumber": c["caseNumber"],
                    "description": c["description"],
                    "status": c["status"],
                    "createdAt": fmt_date(to_local_day(c["createdAt"])) if c["createdAt"] else "—",
                }
                for c in case_rows
            ],
        }
    )
    return profile


def debug_uploads(limit: int = 20) -> List[Dict[str, Any]]:
    """csvRaw parsing check karne ke liye (naye se purane)."""
    out: List[Dict[str, Any]] = []
    for u in reversed(_uploads()[-max(1, limit):]):
        ser = u["series"]
        out.append(
            {
                "id": u["id"],
                "consumerId": u["consumerId"],
                "prediction": u["prediction"],
                "isTheft": u["isTheft"],
                "riskScore": u["riskScore"],
                "totalUnits": u["totalUnits"],
                "dateRange": u["dateRange"],
                "seriesSource": u["seriesSource"],
                "seriesPoints": len(ser),
                "firstDay": ser[0][0].isoformat() if ser else None,
                "lastDay": ser[-1][0].isoformat() if ser else None,
                "sample": [{"date": d.isoformat(), "kwh": v} for d, v in ser[:3]],
                "csvPreview": u["csvPreview"],
            }
        )
    return out


def debug_cases(limit: int = 20) -> List[Dict[str, Any]]:
    """cases ki field-mapping check karne ke liye."""
    floor = datetime.min.replace(tzinfo=timezone.utc)
    rows = sorted(_cases(), key=lambda c: c["createdAt"] or floor, reverse=True)[: max(1, limit)]
    return [
        {
            "id": c["id"],
            "caseNumber": c["caseNumber"],
            "status": c["status"],
            "resolved": c["resolved"],
            "countsAsTheftCase": (not c["resolved"]) and _is_theft_case(c),
            "issueType": c["issueType"],
            "issueValue": c["issueValue"],
            "location": c["location"],
            "matchKeys": sorted(c["keys"]),
            "createdAt": c["createdAt"].isoformat() if c["createdAt"] else None,
        }
        for c in rows
    ]


# ─────────────────────────────────────────────────────────────
# NOTIFICATIONS  (cases + theft-detected uploads + optional extra collections)
# ─────────────────────────────────────────────────────────────
NOTIFICATION_CAP = 200


def _sev(v: Any) -> str:
    p = str(v or "").strip().lower()
    if p.startswith(("high", "crit", "urgent")):
        return "high"
    if p.startswith("med"):
        return "medium"
    if p.startswith("low"):
        return "low"
    return "info"


def _notif(
    nid: str,
    ntype: str,
    title: str,
    message: str,
    severity: str,
    created: Optional[datetime],
    consumer_name: str = "",
    consumer_id: str = "",
    consumer_key: Optional[str] = None,
    case_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "id": nid,
        "type": ntype,
        "title": title,
        "message": message,
        "severity": severity,
        "createdAt": created,
        "consumerName": consumer_name,
        "consumerId": consumer_id,
        "consumerKey": consumer_key,
        "caseId": case_id,
    }


def _entity_for_keys(keys: Set[str]) -> Optional[Dict[str, Any]]:
    by_key = _model()["by_key"]
    for k in sorted(keys):
        e = by_key.get(k)
        if e is not None:
            return e
    return None


def _extra_notifications(name: str) -> List[Dict[str, Any]]:
    """Kisi bhi extra collection ke docs ko generic notification bana deta hai."""

    def load() -> List[Dict[str, Any]]:
        by_key = _model()["by_key"]
        ntype = "alert" if "alert" in name.lower() else "query"
        out: List[Dict[str, Any]] = []
        for snap in get_db().collection(name).limit(200).stream():
            d = snap.to_dict() or {}
            when = to_dt(first(d, "createdAt", "timestamp", "created_at", "time", "date"))
            cid = str(first(d, "consumerId", "consumer_id", default="")).strip()
            email = str(first(d, "consumerEmail", "email", default="")).strip()
            e = by_key.get(norm_key(cid)) or by_key.get(norm_key(email))
            who = str(first(d, "consumerName", "name", "fullName", default="")) or (e["name"] if e else email)
            title = str(first(d, "title", "subject", "issueType", "type", default=name))
            text = str(first(d, "message", "description", "query", "text", "body", default="")).strip()
            out.append(
                _notif(
                    f"{name}:{snap.id}",
                    ntype,
                    title,
                    f"{who}: {text[:140]}" if who and text else (text[:140] or who or title),
                    _sev(first(d, "severity", "priority", "level")),
                    when,
                    consumer_name=who,
                    consumer_id=cid,
                    consumer_key=e["id"] if e else None,
                )
            )
        return out

    return cache.get_or_load(f"extra:{name}", load)


def _all_notifications() -> List[Dict[str, Any]]:
    def load() -> List[Dict[str, Any]]:
        s = get_settings()
        by_key = _model()["by_key"]
        floor = datetime.min.replace(tzinfo=timezone.utc)
        out: List[Dict[str, Any]] = []

        # 1) consumer ke cases / reports / queries
        for c in _cases():
            e = _entity_for_keys(c["keys"])
            name = c["consumerName"] or (e["name"] if e else "") or "Consumer"
            cid = c["consumerId"] or (e["consumerId"] if e else "")
            key = e["id"] if e else None
            who = f"{name} ({cid})" if cid else name
            kind = c["issueType"] or "Consumer report"

            rl = c["riskLevel"].lower()
            sev = "high" if (c["escalated"] or rl.startswith("high")) else ("medium" if rl.startswith("med") else "info")
            out.append(
                _notif(
                    f"case:{c['id']}", "case_filed",
                    f"New case {c['caseNumber']}: {kind}",
                    f"{who}: {c['text'][:140]}" if c["text"] else f"{who} ne naya case file kiya",
                    sev, c["createdAt"], name, cid, key, c["caseNumber"],
                )
            )
            if c["escalated"]:
                out.append(
                    _notif(
                        f"case-esc:{c['id']}", "case_escalated",
                        f"Case {c['caseNumber']} escalated", f"{who} — {kind}",
                        "high", c["updatedAt"] or c["createdAt"], name, cid, key, c["caseNumber"],
                    )
                )
            if c["resolved"]:
                out.append(
                    _notif(
                        f"case-res:{c['id']}", "case_resolved",
                        f"Case {c['caseNumber']} {c['status'].lower()}", f"{who} — {kind}",
                        "low", c["resolvedAt"] or c["updatedAt"] or c["createdAt"], name, cid, key, c["caseNumber"],
                    )
                )

        # 2) ML ne jis CSV upload par theft pakda
        for u in _uploads():
            if not u["isTheft"]:
                continue
            e = by_key.get(norm_key(u["consumerId"])) or by_key.get(norm_key(u["email"]))
            name = u["name"] or (e["name"] if e else "") or "Consumer"
            out.append(
                _notif(
                    f"theft:{u['id']}", "theft_detected", "Theft detected by ML model",
                    f"{name} ({u['consumerId']}) — risk {u['riskScore']}%, {u['totalUnits']:.1f} kWh",
                    "high" if u["riskScore"] >= s.high_risk_threshold else "medium",
                    u["uploadedAt"], name, u["consumerId"], e["id"] if e else None, None,
                )
            )

        # 3) optional extra collections (systemAlerts, support queries ...)
        for name in [x.strip() for x in s.notification_extra_collections.split(",") if x.strip()]:
            try:
                out.extend(_extra_notifications(name))
            except Exception:  # ek collection fail ho to baaki notifications chalti rahen
                continue

        out.sort(key=lambda n: n["createdAt"] or floor, reverse=True)
        return out[:NOTIFICATION_CAP]

    return cache.get_or_load("notifications", load)


def _read_state(uid: str) -> Tuple[Optional[datetime], Set[str]]:
    s = get_settings()
    snap = get_db().collection(s.notification_state_collection).document(uid).get()
    d = (snap.to_dict() or {}) if snap.exists else {}
    return to_dt(d.get("lastReadAll")), set(d.get("readIds") or [])


def get_notifications(uid: str, limit: int = 50, unread_only: bool = False) -> Dict[str, Any]:
    items = _all_notifications()
    last_all, read_ids = _read_state(uid)

    def is_read(n: Dict[str, Any]) -> bool:
        if n["id"] in read_ids:
            return True
        return bool(last_all and n["createdAt"] and n["createdAt"] <= last_all)

    rows = [{**n, "read": is_read(n)} for n in items]
    unread = sum(1 for n in rows if not n["read"])
    if unread_only:
        rows = [n for n in rows if not n["read"]]
    rows = rows[: max(1, limit)]
    return {
        "unreadCount": unread,
        "total": len(items),
        "items": [
            {**n, "createdAt": n["createdAt"].astimezone(timezone.utc).isoformat() if n["createdAt"] else None}
            for n in rows
        ],
    }


def mark_notifications_read(uid: str, ids: List[str], mark_all: bool) -> None:
    s = get_settings()
    ref = get_db().collection(s.notification_state_collection).document(uid)
    if mark_all:
        # lastReadAll + abhi maujood sab ids (clock-skew wali "future" createdAt ke liye bhi safe)
        current = [n["id"] for n in _all_notifications()]
        ref.set({"lastReadAll": datetime.now(timezone.utc), "readIds": current[-500:]}, merge=True)
        return
    if not ids:
        return
    snap = ref.get()
    cur = (snap.to_dict() or {}) if snap.exists else {}
    merged = list(dict.fromkeys(list(cur.get("readIds") or []) + list(ids)))[-500:]
    ref.set({"readIds": merged}, merge=True)


# ═══════════════════════════════════════════════════════════════
# CASE MANAGEMENT  (Cases / Case Profile / Create / Escalate screens)
# Same "cases" collection use hoti hai jo upar dashboard/notifications
# already read karte hain — is liye yahan se banaye cases automatically
# dashboard KPIs, consumer profile "Case History" aur notifications
# mai bhi reflect ho jate hain, koi extra wiring nahi chahiye.
# ═══════════════════════════════════════════════════════════════

CASE_STATUSES = ("Open", "In Progress", "Closed", "Rejected")


def _find_consumer_doc(consumer_id: str) -> Optional[Dict[str, Any]]:
    """consumerId (jaise 'CON001') ya seedha Firestore doc-id se consumer doc dhoondta hai.
    Return: {"docId": ..., "data": {...raw firestore fields...}}"""
    s = get_settings()
    col = get_db().collection(s.consumers_collection)

    rows = list(col.where("consumerId", "==", consumer_id).limit(1).stream())
    if not rows:
        snap = col.document(consumer_id).get()
        rows = [snap] if snap.exists else []

    if not rows:
        return None
    snap = rows[0]
    return {"docId": snap.id, "data": snap.to_dict() or {}}


def _send_expo_push(push_token: str, title: str, body: str, data: Optional[Dict[str, Any]] = None) -> None:
    """Consumer ke Expo push token par notification bhejta hai (best-effort, kabhi raise nahi karta)."""
    if not get_settings().send_push_notifications:
        return
    if not push_token or not str(push_token).startswith("ExponentPushToken"):
        return
    if requests is None:
        log.warning("`requests` package installed nahi hai — push notification skip")
        return
    try:
        requests.post(
            "https://exp.host/--/api/v2/push/send",
            json={
                "to": push_token,
                "title": title,
                "body": body,
                "data": data or {},
                "sound": "default",
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=8,
        )
    except Exception as exc:  # push fail ho to case action fail nahi honi chahiye
        log.warning("Expo push failed: %s", exc)


def _notify_consumer(consumer_doc_id: Optional[str], consumer_data: Dict[str, Any], title: str, body: str, case_id: str, ntype: str) -> None:
    """Consumer ke apne 'notifications/{consumerDocId}' sub-collection mai entry
    banata hai (NotificationsScreen isi se list dikhati hai) + push bhi bhejta hai."""
    if not consumer_doc_id:
        return
    try:
        get_db().collection("notifications").document(consumer_doc_id).collection("items").add(
            {
                "type": ntype,
                "title": title,
                "message": body,
                "caseId": case_id,
                "read": False,
                "createdAt": datetime.now(timezone.utc),
            }
        )
    except Exception as exc:
        log.warning("Consumer notification write failed: %s", exc)

    push_token = str(consumer_data.get("pushToken") or "").strip()
    if push_token:
        _send_expo_push(push_token, title, body, {"caseId": case_id, "type": ntype})


def _evidence_from_upload(case_doc_id: str, filename: str, content: bytes, content_type: str, uploaded_by: str) -> Dict[str, Any]:
    """Ek file Firebase Storage par upload karta hai aur EvidenceItem dict return karta hai."""
    is_image = (content_type or "").startswith("image/")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", filename or "file")
    blob_path = f"case_evidence/{case_doc_id}/{uuid.uuid4().hex[:8]}_{safe_name}"

    bucket = get_bucket()
    blob = bucket.blob(blob_path)
    blob.upload_from_string(content, content_type=content_type or "application/octet-stream")
    blob.make_public()  # simple public URL — bucket ki default privacy rules is se override nahi hoti

    return {
        "name": filename or safe_name,
        "type": "image" if is_image else "document",
        "url": blob.public_url,
        "uploadedBy": uploaded_by or "Admin",
        "date": fmt_date(today_local()),
    }


def _case_doc_to_summary(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    status_raw = str(first(d, "currentStatus", "status", default="Open")).strip().title() or "Open"
    if status_raw not in CASE_STATUSES:
        status_raw = "Open"
    created = to_dt(first(d, "createdAt", "created_at"))
    return {
        "id": doc_id,
        "caseNumber": str(first(d, "caseId", "caseNumber", default=doc_id)),
        "consumerId": str(first(d, "consumerId", default="")).strip(),
        "consumerName": str(first(d, "consumerName", default="")).strip(),
        "area": str(first(d, "location", default="")).strip(),
        "status": status_raw,
        "riskLevel": str(first(d, "riskLevel", default="Low")).strip() or "Low",
        "category": str(first(d, "issueType", default="")).strip(),
        "description": str(first(d, "description", "title", default="")).strip(),
        "inspector": (str(d.get("assignedInspector")).strip() or None) if d.get("assignedInspector") else None,
        "createdAt": fmt_date(to_local_day(created)) if created else "—",
        "evidences": len(d.get("evidence") or []),
    }


def _case_doc_to_detail(doc_id: str, d: Dict[str, Any]) -> Dict[str, Any]:
    summary = _case_doc_to_summary(doc_id, d)
    timeline = [
        {
            "action": str(t.get("action", "")),
            "date": str(t.get("date", "")),
            "time": str(t.get("time", "")),
        }
        for t in (d.get("timeline") or [])
    ]
    evidence = [
        {
            "name": str(ev.get("name", "")),
            "type": str(ev.get("type", "document")),
            "url": str(ev.get("url", "")),
            "uploadedBy": ev.get("uploadedBy"),
            "date": ev.get("date"),
        }
        for ev in (d.get("evidence") or [])
    ]
    summary.update(
        {
            "priority": str(first(d, "priority", default="Normal")).strip() or "Normal",
            "meterNumber": str(first(d, "meterNumber", default="") or summary["consumerId"]) or None,
            "timeline": timeline,
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

    return {
        "total": len(rows),
        "counts": counts,
        "items": [to_summary(c) for c in items],
    }


def get_case_detail(case_id: str) -> Optional[Dict[str, Any]]:
    s = get_settings()
    col = get_db().collection(s.cases_collection)

    snap = col.document(case_id).get()
    if not snap.exists:
        # fallback: caseId field se dhoondo (jaise "CASE000123")
        rows = list(col.where("caseId", "==", case_id).limit(1).stream())
        if not rows:
            return None
        snap = rows[0]

    return _case_doc_to_detail(snap.id, snap.to_dict() or {})


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

    doc_ref = db.collection(settings.cases_collection).document()
    case_number = f"CASE{int(datetime.now(timezone.utc).timestamp() * 1000) % 1000000:06d}"

    evidence = [
        _evidence_from_upload(doc_ref.id, name, content, ctype, "Admin")
        for (name, content, ctype) in files
    ]

    now = datetime.now(timezone.utc)
    now_local = now.astimezone(local_tz())
    status_val = "In Progress" if inspector else "Open"

    data = {
        "caseId": case_number,
        "consumerId": consumer_id,
        "consumerEmail": consumer_email,
        "consumerName": consumer_name,
        "description": description,
        "issueType": category,
        "issueValue": category,
        "location": area,
        "riskLevel": risk_level,
        "priority": priority,
        "assignedInspector": inspector or "",
        "currentStatus": status_val,
        "escalated": False,
        "resolution": "",
        "meterNumber": consumer_id,
        "evidence": evidence,
        "timeline": [
            {
                "action": f"Case created — {category}",
                "date": now_local.date().isoformat(),
                "time": now_local.strftime("%H:%M"),
            }
        ],
        "createdAt": now,
        "updatedAt": now,
        "createdBy": admin_uid,
    }
    doc_ref.set(data)
    cache.invalidate()

    if consumer:
        _notify_consumer(
            consumer["docId"],
            consumer["data"],
            "⚠️ Case Filed Against Your Account",
            f"A new case ({case_number}) has been filed regarding: {category}. Our team will investigate shortly.",
            case_number,
            "case_filed",
        )

    return _case_doc_to_detail(doc_ref.id, data)


def assign_inspector(case_id: str, inspector: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    s = get_settings()
    ref = get_db().collection(s.cases_collection).document(case_id)
    snap = ref.get()
    if not snap.exists:
        return None

    now = datetime.now(timezone.utc)
    now_local = now.astimezone(local_tz())
    d = snap.to_dict() or {}
    current_status = str(first(d, "currentStatus", "status", default="Open")).strip().title()
    new_status = "In Progress" if current_status == "Open" else current_status

    ref.update(
        {
            "assignedInspector": inspector,
            "currentStatus": new_status,
            "updatedAt": now,
            "timeline": (d.get("timeline") or [])
            + [{"action": f"Case assigned to {inspector}", "date": now_local.date().isoformat(), "time": now_local.strftime("%H:%M")}],
        }
    )
    cache.invalidate()
    return get_case_detail(case_id)


def close_case(case_id: str, admin_uid: str) -> Optional[Dict[str, Any]]:
    s = get_settings()
    ref = get_db().collection(s.cases_collection).document(case_id)
    snap = ref.get()
    if not snap.exists:
        return None

    d = snap.to_dict() or {}
    now = datetime.now(timezone.utc)
    now_local = now.astimezone(local_tz())
    ref.update(
        {
            "currentStatus": "Closed",
            "resolvedAt": now,
            "updatedAt": now,
            "timeline": (d.get("timeline") or [])
            + [{"action": "Case closed", "date": now_local.date().isoformat(), "time": now_local.strftime("%H:%M")}],
        }
    )
    cache.invalidate()

    consumer = _find_consumer_doc(str(first(d, "consumerId", default="")))
    if consumer:
        case_number = str(first(d, "caseId", "caseNumber", default=case_id))
        _notify_consumer(
            consumer["docId"],
            consumer["data"],
            "✅ Case Closed",
            f"Your case ({case_number}) has been closed.",
            case_number,
            "case_closed",
        )

    return get_case_detail(case_id)


def escalate_case(
    case_id: str,
    *,
    escalation_level: str,
    reason: str,
    description: str,
    files: List[Tuple[str, bytes, str]],
    admin_uid: str,
) -> Optional[Dict[str, Any]]:
    s = get_settings()
    ref = get_db().collection(s.cases_collection).document(case_id)
    snap = ref.get()
    if not snap.exists:
        return None

    d = snap.to_dict() or {}
    now = datetime.now(timezone.utc)
    now_local = now.astimezone(local_tz())

    new_evidence = [_evidence_from_upload(case_id, name, content, ctype, "Admin") for (name, content, ctype) in files]

    ref.update(
        {
            "escalated": True,
            "riskLevel": "Critical",
            "priority": "Urgent",
            "resolution": f"Escalated to {escalation_level}: {reason} — {description}",
            "evidence": (d.get("evidence") or []) + new_evidence,
            "updatedAt": now,
            "timeline": (d.get("timeline") or [])
            + [
                {
                    "action": f"Case escalated to {escalation_level} — {reason}",
                    "date": now_local.date().isoformat(),
                    "time": now_local.strftime("%H:%M"),
                }
            ],
        }
    )
    cache.invalidate()

    consumer = _find_consumer_doc(str(first(d, "consumerId", default="")))
    if consumer:
        case_number = str(first(d, "caseId", "caseNumber", default=case_id))
        _notify_consumer(
            consumer["docId"],
            consumer["data"],
            "⬆ Case Escalated",
            f"Your case ({case_number}) has been escalated to {escalation_level} for further review.",
            case_number,
            "case_escalated",
        )

    return get_case_detail(case_id)


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
# CONSUMER-FACING NOTIFICATIONS  ("me" endpoints — apna consumer app)
# ─────────────────────────────────────────────────────────────
def _resolve_consumer_doc_id(uid: str, email: str) -> Optional[str]:
    """Firebase Auth uid consumers collection ke doc-id ke barabar hota hai
    (frontend signup isi tarah karta hai) — pehle wahi try karo, warna email se."""
    s = get_settings()
    col = get_db().collection(s.consumers_collection)
    snap = col.document(uid).get()
    if snap.exists:
        return snap.id
    if email:
        rows = list(col.where("email", "==", email).limit(1).stream())
        if rows:
            return rows[0].id
    return None


def get_my_notifications(uid: str, email: str, limit: int = 50) -> List[Dict[str, Any]]:
    doc_id = _resolve_consumer_doc_id(uid, email)
    if not doc_id:
        return []

    items = (
        get_db()
        .collection("notifications")
        .document(doc_id)
        .collection("items")
        .order_by("createdAt", direction=_fb_firestore.Query.DESCENDING)
        .limit(limit)
        .stream()
    )
    out = []
    for snap in items:
        d = snap.to_dict() or {}
        created = to_dt(d.get("createdAt"))
        out.append(
            {
                "id": snap.id,
                "type": str(d.get("type", "alert")),
                "title": str(d.get("title", "")),
                "message": str(d.get("message", "")),
                "caseId": d.get("caseId"),
                "read": bool(d.get("read", False)),
                "createdAt": created.astimezone(timezone.utc).isoformat() if created else None,
            }
        )
    return out


def mark_my_notifications_read(uid: str, email: str, ids: List[str]) -> None:
    doc_id = _resolve_consumer_doc_id(uid, email)
    if not doc_id or not ids:
        return
    col = get_db().collection("notifications").document(doc_id).collection("items")
    for nid in ids:
        try:
            col.document(nid).update({"read": True})
        except Exception:
            continue
