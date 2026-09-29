"""reports_service.py — Reports & Analytics aur System Alerts (Firestore se live).

Endpoints (main.py mai):
    GET /api/reports/summary?period=7d|30d|3m   -> ReportsSummaryResponse
    GET /api/reports/export?period=...          -> CSV file
    GET /api/alerts                             -> AlertsResponse

Data services.py ke pehle se cached loaders se aata hai (_model / _cases / _uploads),
is liye Firestore par extra load nahi padta.

Definitions (zarurat ho to yahin badal sakte ho):
  totalCases       : window mai bane hue (theft) cases
  revenueLoss      : window mai upload hue theft-flagged consumers ka estimated loss (PKR),
                     har consumer ki window ki latest theft upload se
  detectionRate    : AI-flagged (theft / High risk) consumers mai se kitno ka case ban chuka hai (%)
  avgResponseHours : window mai bane resolved cases ka average (resolvedAt - createdAt), ghante
  riskDistribution : window mai upload karne wale consumers ka risk level (latest upload ke hisaab se)
"""
from __future__ import annotations

import csv
import io
import logging
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import services as svc
from core import get_db, get_settings

log = logging.getLogger("electraguard.reports")

PERIODS: Dict[str, Tuple[int, str]] = {
    "7d": (7, "Last 7 days"),
    "30d": (30, "Last 30 days"),
    "3m": (90, "Last 3 months"),
}
MAX_AREAS = 6
MAX_ALERTS = 50
_FLOOR = datetime.min.replace(tzinfo=timezone.utc)


# ─────────────────────────────────────────────────────────────
# SMALL HELPERS
# ─────────────────────────────────────────────────────────────
def _iso(dt: datetime) -> str:
    """UTC ISO-8601 with 'Z' — frontend 'x mins ago' ke liye zaroori."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _chg(new: float, old: float) -> float:
    v = svc.pct_change(new, old)
    return 0.0 if v is None else float(v)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _anchor_day() -> date:
    """Windows kis din par khatam hon: aaj, ya (REPORTS_ANCHOR=latest) sab se naye data ka din."""
    today = svc.today_local()
    if get_settings().reports_anchor.strip().lower() != "latest":
        return today
    days: List[date] = []
    for u in svc._uploads():
        if u["uploadedAt"]:
            days.append(svc.to_local_day(u["uploadedAt"]))
    for c in svc._cases():
        if c["createdAt"]:
            days.append(svc.to_local_day(c["createdAt"]))
    return max(days) if days else today


def _windows(period: str) -> Tuple[date, date, date, date]:
    n, _ = PERIODS[period]
    end = _anchor_day()
    start = end - timedelta(days=n - 1)
    prev_end = start - timedelta(days=1)
    prev_start = prev_end - timedelta(days=n - 1)
    return start, end, prev_start, prev_end


def _in_window(dt: Optional[datetime], start: date, end: date) -> bool:
    return dt is not None and start <= svc.to_local_day(dt) <= end


def _upload_day(u: Dict[str, Any]) -> Optional[date]:
    if u["uploadedAt"]:
        return svc.to_local_day(u["uploadedAt"])
    if u["series"]:
        return u["series"][-1][0]
    return None


def _upload_loss_pkr(u: Dict[str, Any]) -> float:
    """Ek theft-flagged upload ka estimated loss (PKR) — services._estimated_loss_pkr jaisa logic."""
    s = get_settings()
    if not u["isTheft"]:
        return 0.0
    units = u["totalUnits"]
    if u["estimatedLossKwh"] is not None:
        loss_kwh = max(u["estimatedLossKwh"], 0.0)
    else:
        loss_kwh = units * s.theft_loss_fraction
    bill = u["estimatedBill"]
    tariff = bill / units if units > 0 and bill > 0 else s.tariff_pkr_per_kwh
    return loss_kwh * tariff


def _case_area(c: Dict[str, Any], by_key: Dict[str, Dict[str, Any]]) -> str:
    if c["location"]:
        return c["location"]
    for k in c["keys"]:
        e = by_key.get(k)
        if e and e.get("location"):
            return e["location"]
    return "Unknown"


# ─────────────────────────────────────────────────────────────
# ONE WINDOW  => raw numbers
# ─────────────────────────────────────────────────────────────
def _window_numbers(start: date, end: date) -> Dict[str, Any]:
    m = svc._model()
    entities: List[Dict[str, Any]] = m["entities"]
    by_key: Dict[str, Dict[str, Any]] = m["by_key"]
    all_cases = [c for c in svc._cases() if svc._is_theft_case(c)]

    win_cases = [c for c in all_cases if _in_window(c["createdAt"], start, end)]

    area_cases: Dict[str, int] = defaultdict(int)
    for c in win_cases:
        area_cases[_case_area(c, by_key)] += 1

    # response time (resolved cases)
    hours: List[float] = []
    for c in win_cases:
        if not c["resolved"] or c["createdAt"] is None:
            continue
        done = c["resolvedAt"] or c["updatedAt"]
        if done is not None and done >= c["createdAt"]:
            hours.append((done - c["createdAt"]).total_seconds() / 3600.0)
    avg_hours = sum(hours) / len(hours) if hours else 0.0

    # har entity ki window ki latest upload
    risk = {"low": 0, "medium": 0, "high": 0}
    loss_total = 0.0
    loss_by_area: Dict[str, float] = defaultdict(float)
    loss_consumers = 0
    flagged: List[Dict[str, Any]] = []
    for e in entities:
        latest: Optional[Dict[str, Any]] = None
        for u in e["uploads"]:  # purane -> naye
            d = _upload_day(u)
            if d is not None and start <= d <= end:
                latest = u
        if latest is None:
            continue
        level = svc.compute_level(latest["riskScore"], latest["isTheft"])
        risk[level.lower()] += 1
        if latest["isTheft"]:
            loss = _upload_loss_pkr(latest)
            loss_total += loss
            loss_by_area[(e.get("location") or "").strip() or "Unknown"] += loss
            loss_consumers += 1
        if latest["isTheft"] or level == "High":
            flagged.append(e)

    # detection: flagged consumers jinka case (window ke end tak) ban chuka hai
    case_keys = set()
    for c in all_cases:
        if c["createdAt"] is None or svc.to_local_day(c["createdAt"]) <= end:
            case_keys |= c["keys"]
    covered = sum(1 for e in flagged if e["keys"] & case_keys)
    detection = (covered / len(flagged) * 100.0) if flagged else 0.0

    return {
        "cases": len(win_cases),
        "resolved": sum(1 for c in win_cases if c["resolved"]),
        "loss": loss_total,
        "loss_consumers": loss_consumers,
        "detection": detection,
        "flagged": len(flagged),
        "covered": covered,
        "avg_hours": avg_hours,
        "risk": risk,
        "area_cases": dict(area_cases),
        "loss_by_area": dict(loss_by_area),
    }


# ─────────────────────────────────────────────────────────────
# PUBLIC: REPORTS SUMMARY
# ─────────────────────────────────────────────────────────────
def build_reports_summary(period: str) -> Dict[str, Any]:
    n, label = PERIODS[period]
    start, end, p_start, p_end = _windows(period)
    cur = _window_numbers(start, end)
    prev = _window_numbers(p_start, p_end)

    stats = {
        "totalCases": {"value": float(cur["cases"]), "changePct": _chg(cur["cases"], prev["cases"])},
        "revenueLoss": {"value": round(cur["loss"], 0), "changePct": _chg(cur["loss"], prev["loss"])},
        "detectionRate": {
            "value": round(cur["detection"], 1),
            "changePct": _chg(cur["detection"], prev["detection"]),
        },
        "avgResponseHours": {
            "value": round(cur["avg_hours"], 1),
            "changePct": _chg(cur["avg_hours"], prev["avg_hours"]),
        },
    }

    area_theft = [
        {"area": a, "cases": c}
        for a, c in sorted(cur["area_cases"].items(), key=lambda kv: kv[1], reverse=True)[:MAX_AREAS]
    ]
    area_loss = [
        {"area": a, "amount": round(v, 0)}
        for a, v in sorted(cur["loss_by_area"].items(), key=lambda kv: kv[1], reverse=True)[:MAX_AREAS]
        if v > 0
    ]

    # ── insights ─────────────────────────────────────────────
    insights: List[Dict[str, str]] = []
    if cur["area_cases"]:
        area, cnt = max(cur["area_cases"].items(), key=lambda kv: kv[1])
        trend = svc.pct_change(cnt, prev["area_cases"].get(area, 0))
        sub = f"{_plural(cnt, 'case')} reported in {label.lower()}"
        if trend is not None:
            sub += f", {abs(trend):.0f}% {'increase' if trend >= 0 else 'decrease'} from previous period"
        insights.append({"id": "top-area", "type": "alert", "title": f"High theft activity in {area}", "subtitle": sub})

    if cur["flagged"] > 0:
        ch = stats["detectionRate"]["changePct"]
        if ch > 0:
            itype, title = "success", f"Detection rate improved by {ch:.0f}%"
        elif ch < 0:
            itype, title = "alert", f"Detection rate dropped by {abs(ch):.0f}%"
        else:
            itype, title = "info", f"Detection rate steady at {cur['detection']:.0f}%"
        insights.append(
            {
                "id": "detection",
                "type": itype,
                "title": title,
                "subtitle": f"{cur['covered']} of {cur['flagged']} AI-flagged consumers already have a case",
            }
        )

    if cur["loss"] > 0:
        insights.append(
            {
                "id": "savings",
                "type": "savings",
                "title": f"Potential savings of {svc.fmt_pkr(cur['loss'])} identified",
                "subtitle": f"Estimated unbilled electricity across {_plural(cur['loss_consumers'], 'theft-flagged consumer')}",
            }
        )

    if cur["avg_hours"] > 0:
        insights.append(
            {
                "id": "response",
                "type": "info",
                "title": f"Average response time is {cur['avg_hours']:.1f}h",
                "subtitle": f"{cur['resolved']} of {_plural(cur['cases'], 'case')} resolved in {label.lower()}",
            }
        )

    if not insights:
        insights.append(
            {
                "id": "empty",
                "type": "info",
                "title": "No theft activity in this period",
                "subtitle": f"No cases or theft-flagged uploads were found for {label.lower()}.",
            }
        )

    return {
        "period": period,
        "periodLabel": label,
        "windowStart": start.isoformat(),
        "windowEnd": end.isoformat(),
        "stats": stats,
        "riskDistribution": cur["risk"],
        "areaTheft": area_theft,
        "revenueLossByArea": area_loss,
        "insights": insights,
        "generatedAt": _iso(datetime.now(timezone.utc)),
    }


def build_reports_csv(period: str) -> str:
    data = build_reports_summary(period)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ElectraGuard Report", data["periodLabel"], f"{data['windowStart']} to {data['windowEnd']}"])
    w.writerow([])
    w.writerow(["Metric", "Value", "Change vs previous period (%)"])
    st = data["stats"]
    w.writerow(["Total cases", int(st["totalCases"]["value"]), st["totalCases"]["changePct"]])
    w.writerow(["Revenue loss (PKR)", st["revenueLoss"]["value"], st["revenueLoss"]["changePct"]])
    w.writerow(["Detection rate (%)", st["detectionRate"]["value"], st["detectionRate"]["changePct"]])
    w.writerow(["Avg response time (h)", st["avgResponseHours"]["value"], st["avgResponseHours"]["changePct"]])
    w.writerow([])
    w.writerow(["Risk level", "Consumers"])
    for k in ("low", "medium", "high"):
        w.writerow([k.title(), data["riskDistribution"][k]])
    w.writerow([])
    w.writerow(["Area", "Theft cases"])
    for r in data["areaTheft"]:
        w.writerow([r["area"], r["cases"]])
    w.writerow([])
    w.writerow(["Area", "Revenue loss (PKR)"])
    for r in data["revenueLossByArea"]:
        w.writerow([r["area"], r["amount"]])
    w.writerow([])
    w.writerow(["Key insights"])
    for i in data["insights"]:
        w.writerow([i["title"], i["subtitle"]])
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
# SYSTEM ALERTS
# ─────────────────────────────────────────────────────────────
def _norm_severity(v: Any) -> str:
    p = str(v or "").strip().lower()
    if p in {"critical", "high", "error", "danger", "urgent"}:
        return "critical"
    if p in {"warning", "warn", "medium", "moderate"}:
        return "warning"
    return "info"


def _manual_alerts() -> List[Dict[str, Any]]:
    """Admin ke banaye alerts (maintenance notice etc.) — systemAlerts collection se."""

    def load() -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        name = get_settings().alerts_collection
        try:
            for snap in get_db().collection(name).stream():
                d = snap.to_dict() or {}
                if d.get("active") is False or svc._truthy(d.get("resolved")):
                    continue
                out.append(
                    {
                        "id": f"sys:{snap.id}",
                        "severity": _norm_severity(d.get("severity")),
                        "title": str(svc.first(d, "title", "subject", default="System Notice")),
                        "message": str(svc.first(d, "message", "description", default="")),
                        "created": svc.to_dt(svc.first(d, "createdAt", "created_at")),
                    }
                )
        except Exception as exc:  # collection na ho ya permission issue => baaki alerts phir bhi dikhao
            log.warning("systemAlerts read failed: %s", exc)
        return out

    return svc.cache.get_or_load("system_alerts", load)


def build_alerts() -> Dict[str, Any]:
    s = get_settings()
    now = datetime.now(timezone.utc)
    m = svc._model()
    by_key: Dict[str, Dict[str, Any]] = m["by_key"]
    items: List[Tuple[datetime, Dict[str, Any]]] = []

    def add(alert_id: str, severity: str, title: str, message: str, created: Optional[datetime]) -> None:
        created = created or now
        items.append(
            (created, {"id": alert_id, "severity": severity, "title": title, "message": message, "createdAt": _iso(created)})
        )

    # 1) ML-detected theft uploads (recent) => High Anomaly Detected
    since = _anchor_day() - timedelta(days=max(s.alerts_theft_window_days, 1) - 1)
    flagged: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for e in m["entities"]:
        u = e["latest"]
        if not u or not u["isTheft"]:
            continue
        d = _upload_day(u)
        if d is None or d < since:
            continue
        flagged.append((e, u))
    flagged.sort(key=lambda x: (x[1]["riskScore"], x[1]["uploadedAt"] or _FLOOR), reverse=True)
    for e, u in flagged[: max(s.alerts_max_theft_items, 0)]:
        where = f" in {e['location']}" if e.get("location") else ""
        add(
            f"anomaly:{e['id']}",
            "critical",
            "High Anomaly Detected",
            f"Unusual consumption pattern detected for {e['name']}{where} (risk score {u['riskScore']}%)",
            u["uploadedAt"],
        )

    # 2) ek area mai kayi unresolved cases => Multiple Theft Cases
    open_by_area: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in svc._cases():
        if c["resolved"] or not svc._is_theft_case(c):
            continue
        area = _case_area(c, by_key)
        if area != "Unknown":
            open_by_area[area].append(c)
    for area, lst in open_by_area.items():
        if len(lst) >= s.alerts_multi_case_threshold:
            newest = max((c["createdAt"] for c in lst if c["createdAt"]), default=None)
            add(f"cases:{area}", "critical", "Multiple Theft Cases", f"{len(lst)} unresolved theft cases reported in {area}", newest)

    # 3) naya CSV upload nahi aaya => Data Ingestion Delay
    last = max((u["uploadedAt"] for u in svc._uploads() if u["uploadedAt"]), default=None)
    if last is None:
        add("ingestion", "warning", "Data Ingestion Delay", "No consumption data has been uploaded yet.", now)
    else:
        hrs = (now - last).total_seconds() / 3600.0
        if hrs >= s.alerts_ingestion_delay_hours:
            gap = f"{int(hrs)} hours" if hrs < 48 else f"{int(hrs // 24)} days"
            add(
                "ingestion",
                "warning",
                "Data Ingestion Delay",
                f"No new consumption data received for {gap}.",
                last + timedelta(hours=s.alerts_ingestion_delay_hours),
            )

    # 4) admin ke manual alerts
    for a in _manual_alerts():
        add(a["id"], a["severity"], a["title"], a["message"], a["created"])

    items.sort(key=lambda x: x[0], reverse=True)
    alerts = [a for _, a in items[:MAX_ALERTS]]
    return {"activeCount": len(alerts), "alerts": alerts}
