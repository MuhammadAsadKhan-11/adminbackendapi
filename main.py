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

import auth_otp
import case_service as cases
import evidence_storage
from core import (
    authenticate_token,
    get_db,
    get_settings,
    init_firebase,
    require_admin,
    require_consumer,
    require_signed_in,
)
from realtime import live
from schemas import (
    AlertsResponse,
    AssignInspectorRequest,
    CaseRemarkRequest,
    CaseStatusRequest,
    CasesListResponse,
    CaseDetail,
    ConsumerProfile,
    DashboardResponse,
    DownloadUrlResponse,
    InspectorsResponse,
    MarkMyReadRequest,
    MarkReadRequest,
    MyCase,
    MyCasesResponse,
    MyNotificationsResponse,
    NotificationsResponse,
    OkResponse,
    OtpRequest,
    OtpRequestResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    ReportsSummaryResponse,
    ResetCodeRequest,
    ResetCodeResponse,
    ResetVerifyRequest,
    ResetVerifyResponse,
    ResolveLoginRequest,
    ResolveLoginResponse,
    RiskListResponse,
    SendNotificationRequest,
    SendNotificationResponse,
    SentNotificationsResponse,
    SessionResponse,
    TwoFactorChangeRequest,
    TwoFactorConfirmRequest,
    TwoFactorConfirmResponse,
    TwoFactorStatus,
)
from reports_service import PERIODS, build_alerts, build_reports_csv, build_reports_summary
from services import (
    build_dashboard,
    build_profile,
    build_risk_list,
    debug_cases,
    debug_uploads,
    get_notifications,
    mark_notifications_read,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("electraguard")

ALLOWED_LEVELS = {"all", "high", "medium", "low"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_firebase()
    if not get_settings().require_auth:
        log.warning("REQUIRE_AUTH=false: API authentication is DISABLED. Use only for local testing.")
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
    expose_headers=["X-Auth-Error", "Retry-After"],  # web build reads these
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
        log.error("Firestore health check failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="Firestore not reachable")


@app.get("/health/config", tags=["meta"])
def health_config():
    """Which integrations are configured (true/false only, never values)."""
    s = get_settings()
    return {
        "s3": {"bucket": evidence_storage.s3_configured(), "region": bool(s.s3_region)},
        "emailjs": auth_otp.emailjs_config_status(),
        "require2fa": s.require_2fa,
        "requireAuth": s.require_auth,
    }


# ─────────────────────────────────────────────────────────────
# AUTH  (email OTP 2FA + password-reset codes)
# ─────────────────────────────────────────────────────────────
@app.post("/api/auth/resolve-login", response_model=ResolveLoginResponse, tags=["auth"])
def auth_resolve_login(body: ResolveLoginRequest, request: Request):
    """Consumer ID -> sign-in email, so the app no longer needs public read access to consumers."""
    auth_otp.rate_limit_ip(request, "resolve", limit=30)
    return {"email": auth_otp.resolve_login_email(body.identifier)}


@app.post("/api/auth/otp/request", response_model=OtpRequestResponse, tags=["auth"])
def auth_otp_request(body: OtpRequest, user: dict = Depends(require_signed_in)):
    """After the password sign-in: emails a 6-digit code (or skips it for a trusted device)."""
    return auth_otp.request_login_otp(user, body.role, body.deviceId, body.resend)


@app.post("/api/auth/otp/verify", response_model=OtpVerifyResponse, tags=["auth"])
def auth_otp_verify(body: OtpVerifyRequest, user: dict = Depends(require_signed_in)):
    return auth_otp.verify_login_otp(user, body.code, body.deviceId)


@app.get("/api/auth/session", response_model=SessionResponse, tags=["auth"])
def auth_session(user: dict = Depends(require_signed_in)):
    """Is the current Firebase sign-in fully verified? (used on app start)."""
    return auth_otp.session_status(user)


@app.post("/api/auth/logout", response_model=OkResponse, tags=["auth"])
def auth_logout(user: dict = Depends(require_signed_in)):
    auth_otp.logout(user)
    return {"ok": True}


@app.get("/api/auth/2fa", response_model=TwoFactorStatus, tags=["auth"])
def auth_2fa_status(user: dict = Depends(require_signed_in)):
    """Profile screen: is two-factor authentication on for this account?"""
    return auth_otp.two_factor_status(user)


@app.post("/api/auth/2fa/request", response_model=OtpRequestResponse, tags=["auth"])
def auth_2fa_request(body: TwoFactorChangeRequest, user: dict = Depends(require_signed_in)):
    """Emails a code to confirm turning 2FA on or off."""
    return auth_otp.request_two_factor_change(user, body.enable, body.resend)


@app.post("/api/auth/2fa/confirm", response_model=TwoFactorConfirmResponse, tags=["auth"])
def auth_2fa_confirm(body: TwoFactorConfirmRequest, user: dict = Depends(require_signed_in)):
    return auth_otp.confirm_two_factor_change(user, body.enable, body.code, body.deviceId)


@app.post("/api/auth/password-reset/request", response_model=ResetCodeResponse, tags=["auth"])
def auth_reset_request(body: ResetCodeRequest, request: Request):
    auth_otp.rate_limit_ip(request, "reset", limit=10)
    return auth_otp.request_reset_code(body.identifier, body.resend)


@app.post("/api/auth/password-reset/verify", response_model=ResetVerifyResponse, tags=["auth"])
def auth_reset_verify(body: ResetVerifyRequest, request: Request):
    auth_otp.rate_limit_ip(request, "reset-verify", limit=20)
    return auth_otp.verify_reset_code(body.identifier, body.code)


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


@app.post("/api/notifications/send", response_model=SendNotificationResponse, tags=["notifications"])
def notifications_send(body: SendNotificationRequest, admin: dict = Depends(require_admin)):
    """Admin -> one consumer (optionally linked to one of that consumer's cases)."""
    return cases.send_admin_message(body.consumerId, body.title, body.message, body.caseId, admin.get("uid", "dev"))


@app.get("/api/notifications/sent", response_model=SentNotificationsResponse, tags=["notifications"])
def notifications_sent(
    limit: int = Query(50, ge=1, le=200),
    caseId: Optional[str] = Query(None),
    consumerId: Optional[str] = Query(None),
    _: dict = Depends(require_admin),
):
    """History of notifications sent to consumers (all, per case, or per consumer)."""
    return {"items": cases.list_sent_notifications(limit, caseId, consumerId)}


@app.post("/api/notifications/read", response_model=OkResponse, tags=["notifications"])
def notifications_read(body: MarkReadRequest, admin: dict = Depends(require_admin)):
    """ids ko read mark karo, ya markAll=true se sab."""
    mark_notifications_read(admin.get("uid", "dev"), body.ids, body.markAll)
    return {"ok": True}


# ─────────────────────────────────────────────────────────────
# CASE MANAGEMENT  (Cases / Case Profile / Create Case / Escalate screens)
# ─────────────────────────────────────────────────────────────
async def _read_upload_files(files: List[UploadFile]) -> List[tuple]:
    """UploadFile list -> (filename, bytes, content_type). Reads at most limit+1 bytes per
    file so oversized uploads are rejected without loading them fully."""
    s = get_settings()
    real = [f for f in (files or []) if f and f.filename]
    if len(real) > s.evidence_max_files:
        raise HTTPException(status_code=400, detail=f"Too many files. Upload at most {s.evidence_max_files} at a time.")
    cap = int(s.evidence_max_file_mb * 1024 * 1024)
    out = []
    for f in real:
        content = await f.read(cap + 1)
        if len(content) > cap:
            raise HTTPException(
                status_code=413,
                detail=f'"{f.filename}" is larger than the {s.evidence_max_file_mb:g} MB limit.',
            )
        out.append((f.filename, content, f.content_type or "application/octet-stream"))
    return out


def _disposition(value: str) -> str:
    v = (value or "attachment").strip().lower()
    if v not in ("attachment", "inline"):
        raise HTTPException(status_code=422, detail="disposition must be attachment or inline")
    return v


@app.get("/api/cases", response_model=CasesListResponse, tags=["cases"])
def cases_list(
    status: Optional[str] = Query(None, description="Open | In Progress | Closed | Rejected"),
    search: Optional[str] = Query(None),
    _: dict = Depends(require_admin),
):
    """Case Management screen: status counts + (optionally filtered) list."""
    return cases.list_cases(status=status, search=search)


@app.get("/api/cases/{case_id}", response_model=CaseDetail, tags=["cases"])
def case_detail(case_id: str, _: dict = Depends(require_admin)):
    """Case Profile screen: poori detail — timeline, evidence, inspector."""
    detail = cases.get_case_detail(case_id)
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
    return cases.create_case(
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
    detail = cases.assign_inspector(case_id, body.inspector, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/cases/{case_id}/close", response_model=CaseDetail, tags=["cases"])
def cases_close(case_id: str, admin: dict = Depends(require_admin)):
    """Case Profile screen: 'Close Case' button — status Closed + consumer ko notify."""
    detail = cases.close_case(case_id, admin.get("uid", "dev"))
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
    detail = cases.escalate_case(
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


@app.post("/api/cases/{case_id}/evidence", response_model=CaseDetail, tags=["cases"])
async def cases_add_evidence(
    case_id: str,
    note: str = Form(""),
    files: List[UploadFile] = File(default=[]),
    admin: dict = Depends(require_admin),
):
    """Upload more evidence/documents to an existing case (S3) and notify the consumer."""
    file_tuples = await _read_upload_files(files)
    detail = cases.add_evidence(case_id, file_tuples, note, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/url", response_model=DownloadUrlResponse, tags=["cases"])
def cases_evidence_url(
    case_id: str,
    evidence_id: str,
    disposition: str = Query("attachment", description="attachment | inline"),
    _: dict = Depends(require_admin),
):
    """Short-lived presigned download URL for one evidence file."""
    res = cases.get_admin_evidence_url(case_id, evidence_id, _disposition(disposition))
    if res is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return res


@app.post("/api/cases/{case_id}/status", response_model=CaseDetail, tags=["cases"])
def cases_status(case_id: str, body: CaseStatusRequest, admin: dict = Depends(require_admin)):
    """Change case status (Open | In Progress | Closed | Rejected). The consumer is notified."""
    detail = cases.update_case_status(case_id, body.status, body.note, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.post("/api/cases/{case_id}/remarks", response_model=CaseDetail, tags=["cases"])
def cases_remark(case_id: str, body: CaseRemarkRequest, admin: dict = Depends(require_admin)):
    """Admin remark / instruction on the case; sent to the consumer when notifyConsumer=true."""
    detail = cases.add_case_remark(case_id, body.message, body.notifyConsumer, admin.get("uid", "dev"))
    if detail is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return detail


@app.get("/api/inspectors", response_model=InspectorsResponse, tags=["cases"])
def inspectors_list(_: dict = Depends(require_admin)):
    """Assign Inspector modal ke liye live list."""
    return {"items": cases.list_inspectors()}


# ─────────────────────────────────────────────────────────────
# CONSUMER-FACING  (apna consumer app — "me" endpoints)
# ─────────────────────────────────────────────────────────────
@app.get("/api/consumers/me/notifications", response_model=MyNotificationsResponse, tags=["consumer-self"])
def my_notifications(
    limit: int = Query(100, ge=1, le=300),
    user: dict = Depends(require_consumer),
):
    """Consumer NotificationsScreen: only this account's notifications."""
    items = cases.get_my_notifications(user.get("uid", ""), user.get("email", "") or "", limit)
    return {"items": items, "unreadCount": sum(1 for n in items if not n["read"])}


@app.post("/api/consumers/me/notifications/mark-read", response_model=OkResponse, tags=["consumer-self"])
def my_notifications_mark_read(body: MarkMyReadRequest, user: dict = Depends(require_consumer)):
    cases.mark_my_notifications_read(user.get("uid", ""), user.get("email", "") or "", body.ids, body.markAll)
    return {"ok": True}


@app.get("/api/consumers/me/cases", response_model=MyCasesResponse, tags=["consumer-self"])
def my_cases(user: dict = Depends(require_consumer)):
    return {"items": cases.list_my_cases(user.get("uid", ""), user.get("email", "") or "")}


@app.get("/api/consumers/me/cases/{case_id}", response_model=MyCase, tags=["consumer-self"])
def my_case(case_id: str, user: dict = Depends(require_consumer)):
    """Case details for a notification: 404 unless the case belongs to this consumer."""
    return cases.get_my_case(user.get("uid", ""), user.get("email", "") or "", case_id)


@app.get(
    "/api/consumers/me/cases/{case_id}/evidence/{evidence_id}/url",
    response_model=DownloadUrlResponse,
    tags=["consumer-self"],
)
def my_case_evidence_url(
    case_id: str,
    evidence_id: str,
    disposition: str = Query("attachment", description="attachment | inline"),
    user: dict = Depends(require_consumer),
):
    """Fresh presigned URL for one of this consumer's evidence files (call again when it expires)."""
    return cases.get_my_evidence_url(
        user.get("uid", ""), user.get("email", "") or "", case_id, evidence_id, _disposition(disposition)
    )


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
