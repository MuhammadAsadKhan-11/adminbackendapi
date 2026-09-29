"""main.py — ElectraGuard Admin API (FastAPI)

Run (local):
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
Docs:
    http://localhost:8000/docs
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from google.api_core.exceptions import GoogleAPICallError

from core import authenticate_token, get_db, get_settings, init_firebase, require_admin, require_consumer
from realtime import live
from schemas import (
    AlertsResponse,
    AssignInspectorRequest,
    CasesListResponse,
    CaseDetail,
    ConsumerProfile,
    DashboardResponse,
    InspectorsResponse,
    MarkMyReadRequest,
    MarkReadRequest,
    MyNotificationsResponse,
    NotificationsResponse,
    OkResponse,
    ReportsSummaryResponse,
    RiskListResponse,
)
from reports_service import PERIODS, build_alerts, build_reports_csv, build_reports_summary
from services import (
    assign_inspector,
    build_dashboard,
    build_profile,
    build_risk_list,
    close_case,
    create_case,
    debug_cases,
    debug_uploads,
    escalate_case,
    get_case_detail,
    get_my_notifications,
    get_notifications,
    list_cases,
    list_inspectors,
    mark_my_notifications_read,
    mark_notifications_read,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("electraguard")

ALLOWED_LEVELS = {"all", "high", "medium", "low"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_firebase()
    await asyncio.to_thread(live.start, asyncio.get_running_loop())
    yield
    live.stop()


app = FastAPI(
    title="ElectraGuard Admin API",
    version="1.0.0",
    description="Dashboard KPIs, theft analytics, risk list and consumer profiles — live from Firestore.",
    lifespan=lifespan,
)

_origins = [o.strip() for o in get_settings().cors_origins.split(",") if o.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,  # Bearer token header use hota hai, cookies nahi
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(GoogleAPICallError)
async def firestore_error_handler(request: Request, exc: GoogleAPICallError):
    log.error("Firestore error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "Database temporarily unavailable"})


# ─────────────────────────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────────────────────────
@app.get("/", tags=["meta"])
def root():
    return {"service": "ElectraGuard Admin API", "docs": "/docs", "health": "/health"}


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.get("/health/db", tags=["meta"])
def health_db():
    """Firestore connection check (deploy ke baad debugging ke liye)."""
    try:
        list(get_db().collection(get_settings().consumers_collection).limit(1).stream())
        return {"status": "ok", "firestore": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Firestore not reachable: {exc}")


# ─────────────────────────────────────────────────────────────
# PROTECTED (admin only)
# ─────────────────────────────────────────────────────────────
@app.get("/api/dashboard", response_model=DashboardResponse, tags=["dashboard"])
def dashboard(_: dict = Depends(require_admin)):
    """6 KPI cards + last-7-days consumption/theft chart."""
    return build_dashboard()


@app.get("/api/risks", response_model=RiskListResponse, tags=["risks"])
def risks(
    level: Optional[str] = Query(None, description="all | high | medium | low"),
    search: Optional[str] = Query(None, description="name, consumer id, meter no ya area"),
    limit: int = Query(200, ge=1, le=1000),
    _: dict = Depends(require_admin),
):
    """Risk list (risk score ke hisaab se descending)."""
    if level is not None and level.strip().lower() not in ALLOWED_LEVELS:
        raise HTTPException(status_code=422, detail="level must be one of: all, high, medium, low")
    return build_risk_list(level=level, search=search, limit=limit)


@app.get("/api/consumers/{consumer_key}", response_model=ConsumerProfile, tags=["consumers"])
def consumer_profile(consumer_key: str, _: dict = Depends(require_admin)):
    """Poori consumer profile. consumer_key = Firestore doc id ya consumerId (CON001)."""
    profile = build_profile(consumer_key)
    if profile is None:
        raise HTTPException(status_code=404, detail="Consumer not found")
    return profile


@app.get("/api/notifications", response_model=NotificationsResponse, tags=["notifications"])
def notifications(
    limit: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    admin: dict = Depends(require_admin),
):
    """Bell icon ki list: consumer cases/queries, theft alerts. read/unread har admin ki apni hoti hai."""
    return get_notifications(admin.get("uid", "dev"), limit, unread_only)


@app.post("/api/notifications/read", response_model=OkResponse, tags=["notifications"])
def notifications_read(body: MarkReadRequest, admin: dict = Depends(require_admin)):
    """ids ko read mark karo, ya markAll=true se sab."""
    mark_notifications_read(admin.get("uid", "dev"), body.ids, body.markAll)
    return {"ok": True}


# ─────────────────────────────────────────────────────────────
# CASE MANAGEMENT  (Cases / Case Profile / Create Case / Escalate screens)
# ─────────────────────────────────────────────────────────────
async def _read_upload_files(files: List[UploadFile]) -> List[tuple]:
    """UploadFile list ko (filename, bytes, content_type) tuples mai badalta hai."""
    out = []
    for f in files or []:
        if not f or not f.filename:
            continue
        content = await f.read()
        out.append((f.filename, content, f.content_type or "application/octet-stream"))
    return out


@app.get("/api/cases", response_model=CasesListResponse, tags=["cases"])
def cases_list(
    status: Optional[str] = Query(None, description="Open | In Progress | Closed | Rejected"),
    search: Optional[str] = Query(None),
    _: dict = Depends(require_admin),
):
    """Case Management screen: status counts + (optionally filtered) list."""
    return list_cases(status=status, search=search)


@app.get("/api/cases/{case_id}", response_model=CaseDetail, tags=["cases"])
def case_detail(case_id: str, _: dict = Depends(require_admin)):
    """Case Profile screen: poori detail — timeline, evidence, inspector."""
    detail = get_case_detail(case_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/cases", response_model=CaseDetail, tags=["cases"])
async def cases_create(
    consumerId: str = Form(...),
    consumerName: str = Form(...),
    area: str = Form(...),
    riskLevel: str = Form(...),
    category: str = Form(...),
    description: str = Form(...),
    inspector: str = Form(""),
    priority: str = Form(...),
    files: List[UploadFile] = File(default=[]),
    admin: dict = Depends(require_admin),
):
    """Create Case screen: naya case banata hai, evidence upload karta hai,
    AUR consumer ko notification + push bhejta hai — sab ek call mein."""
    file_tuples = await _read_upload_files(files)
    return create_case(
        consumer_id=consumerId,
        consumer_name=consumerName,
        area=area,
        risk_level=riskLevel,
        category=category,
        description=description,
        inspector=inspector or None,
        priority=priority,
        files=file_tuples,
        admin_uid=admin.get("uid", "dev"),
    )


@app.post("/api/cases/{case_id}/assign", response_model=CaseDetail, tags=["cases"])
def cases_assign(case_id: str, body: AssignInspectorRequest, admin: dict = Depends(require_admin)):
    """Case Profile screen: inspector assign/change karta hai."""
    detail = assign_inspector(case_id, body.inspector, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/cases/{case_id}/close", response_model=CaseDetail, tags=["cases"])
def cases_close(case_id: str, admin: dict = Depends(require_admin)):
    """Case Profile screen: 'Close Case' button — status Closed + consumer ko notify."""
    detail = close_case(case_id, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/cases/{case_id}/escalate", response_model=CaseDetail, tags=["cases"])
async def cases_escalate(
    case_id: str,
    escalationLevel: str = Form(...),
    reason: str = Form(...),
    description: str = Form(...),
    files: List[UploadFile] = File(default=[]),
    admin: dict = Depends(require_admin),
):
    """Escalate Case screen: 'Confirm Escalation' — riskLevel/priority badhata hai,
    evidence attach karta hai, aur consumer ko notify karta hai."""
    file_tuples = await _read_upload_files(files)
    detail = escalate_case(
        case_id,
        escalation_level=escalationLevel,
        reason=reason,
        description=description,
        files=file_tuples,
        admin_uid=admin.get("uid", "dev"),
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.get("/api/inspectors", response_model=InspectorsResponse, tags=["cases"])
def inspectors_list(_: dict = Depends(require_admin)):
    """Assign Inspector modal ke liye live list."""
    return {"items": list_inspectors()}


# ─────────────────────────────────────────────────────────────
# CONSUMER-FACING  (apna consumer app — "me" endpoints)
# ─────────────────────────────────────────────────────────────
@app.get("/api/consumers/me/notifications", response_model=MyNotificationsResponse, tags=["consumer-self"])
def my_notifications(user: dict = Depends(require_consumer)):
    """Consumer NotificationsScreen: apni khud ki notifications (admin ne case
    create/close/escalate karte waqt bheji hongi)."""
    items = get_my_notifications(user.get("uid", ""), user.get("email", "") or "")
    return {"items": items}


@app.post("/api/consumers/me/notifications/mark-read", response_model=OkResponse, tags=["consumer-self"])
def my_notifications_mark_read(body: MarkMyReadRequest, user: dict = Depends(require_consumer)):
    mark_my_notifications_read(user.get("uid", ""), user.get("email", "") or "", body.ids)
    return {"ok": True}


@app.get("/api/debug/consumptions", tags=["debug"])
def debug_consumptions(limit: int = Query(20, ge=1, le=100), _: dict = Depends(require_admin)):
    """csvRaw parse ho raha hai ya nahi — har upload ke liye parsed days, sample aur csv preview."""
    return debug_uploads(limit)


@app.get("/api/debug/cases", tags=["debug"])
def debug_cases_endpoint(limit: int = Query(20, ge=1, le=100), _: dict = Depends(require_admin)):
    """cases ke fields sahi map ho rahe hain ya nahi (status, caseId, consumer match keys)."""
    return debug_cases(limit)


# ─────────────────────────────────────────────────────────────
# REPORTS & ANALYTICS  +  SYSTEM ALERTS  (Reports / Alerts screens)
# ─────────────────────────────────────────────────────────────
def _check_period(period: str) -> str:
    p = (period or "").strip().lower()
    if p not in PERIODS:
        raise HTTPException(status_code=422, detail="period must be one of: 7d, 30d, 3m")
    return p


@app.get("/api/reports/summary", response_model=ReportsSummaryResponse, tags=["reports"])
def reports_summary(
    period: str = Query("7d", description="7d | 30d | 3m"),
    _: dict = Depends(require_admin),
):
    """Reports & Analytics screen: stat cards, risk distribution, area charts, key insights."""
    return build_reports_summary(_check_period(period))


@app.get("/api/reports/export", tags=["reports"])
def reports_export(
    period: str = Query("7d", description="7d | 30d | 3m"),
    format: str = Query("csv", description="abhi sirf csv"),
    _: dict = Depends(require_admin),
):
    """Export button: report ko CSV ke taur par download/share karne ke liye."""
    if format.strip().lower() != "csv":
        raise HTTPException(status_code=422, detail="Only format=csv is supported")
    p = _check_period(period)
    return Response(
        content=build_reports_csv(p),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="electraguard_report_{p}.csv"'},
    )


@app.get("/api/alerts", response_model=AlertsResponse, tags=["alerts"])
def alerts(_: dict = Depends(require_admin)):
    """System Alerts screen: ML anomalies, multiple-case areas, data-ingestion delay, admin notices."""
    return build_alerts()


# ─────────────────────────────────────────────────────────────
# REALTIME
# ─────────────────────────────────────────────────────────────
@app.websocket("/ws/updates")
async def ws_updates(ws: WebSocket, token: Optional[str] = None):
    """Firestore mai change hote hi {"type": "refresh"} push hota hai.
    App ko sirf apni REST calls dobara chalani hoti hain."""
    if get_settings().require_auth:
        try:
            await asyncio.to_thread(authenticate_token, token or "")
        except HTTPException:
            await ws.close(code=1008)
            return

    await ws.accept()
    await live.connect(ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        live.disconnect(ws)
