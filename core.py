"""core.py — settings, Firebase initialisation and admin authentication."""
from __future__ import annotations

import json
import logging
import time
from functools import lru_cache
from typing import Optional
from zoneinfo import ZoneInfo

import firebase_admin
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from firebase_admin import auth as fb_auth
from firebase_admin import credentials, firestore
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("electraguard")


# ─────────────────────────────────────────────────────────────
# SETTINGS  (.env file ya environment variables se aati hain)
# ─────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    firebase_credentials_path: Optional[str] = None
    firebase_credentials_json: Optional[str] = None

    require_auth: bool = True
    cors_origins: str = "*"

    app_timezone: str = "Asia/Karachi"
    tariff_pkr_per_kwh: float = 45.0
    theft_loss_fraction: float = 0.25   # theft wale consumer ki consumption ka kitna hissa "unbilled" maana jaye
    high_risk_threshold: float = 80.0
    medium_risk_threshold: float = 50.0
    cache_ttl_seconds: int = 10
    # "latest" => har consumer ki sirf latest upload ki totalUnits ka sum
    # "all"    => sab uploads ki totalUnits ka sum
    total_consumption_mode: str = "latest"
    # comma-separated issueValue/issueType (jaise "meter_tampering,power_theft").
    # Khali => saare unresolved cases "Theft Cases" mai ginay jate hain.
    theft_case_issue_types: str = ""
    # Extra collections jin ke docs bhi notifications mai aayen (comma-separated), jaise
    # "systemAlerts,supportRequests". Generic mapping: title/subject, message/description,
    # consumerName, createdAt. Khali => sirf cases + theft-detected uploads.
    notification_extra_collections: str = ""
    # Har admin ki read/unread state yahan save hoti hai (collection khud ban jati hai)
    notification_state_collection: str = "adminNotificationState"

    consumers_collection: str = "consumers"
    consumptions_collection: str = "consumptions"
    cases_collection: str = "cases"
    theft_flags_collection: str = "theft_flags"
    admins_collection: str = "admins"
    # Inspectors list ke liye — collection khali/na-maujood ho to cases ke
    # assignedInspector se distinct names uthaye jate hain (fallback).
    inspectors_collection: str = "inspectors"

    # ── Reports & System Alerts ──────────────────────────────
    # Admin ke banaye hue system alerts (maintenance notice etc.) is collection se aate hain.
    # Fields: title, message, severity (critical|warning|info), createdAt, optional active/resolved.
    alerts_collection: str = "systemAlerts"
    alerts_theft_window_days: int = 7        # ML-detected theft uploads ko itne din tak alert dikhao
    alerts_max_theft_items: int = 5          # itne se zyada "High Anomaly" alerts nahi
    alerts_multi_case_threshold: int = 3     # ek area mai itne unresolved cases => "Multiple Theft Cases"
    alerts_ingestion_delay_hours: int = 24   # itne ghante naya CSV upload na aaye => "Data Ingestion Delay"
    # Reports ki windows kahan se count hon: "today" ya "latest" (sab se naye upload/case ka din —
    # purane test data ke liye useful).
    reports_anchor: str = "today"

    # Evidence images/PDFs Firebase Storage mai upload hoti hain. Khali chhodein
    # to default bucket (<project-id>.appspot.com) use hoga.
    firebase_storage_bucket: Optional[str] = None
    # Naye case/escalation banate waqt consumer ko Expo push notification
    # (agar unka pushToken Firestore mai maujood hai) bhejna hai ya nahi.
    send_push_notifications: bool = True

    # ── Consumer notifications (one document per event) ──────
    consumer_notifications_collection: str = "consumerNotifications"

    # ── AWS S3 evidence storage ──────────────────────────────
    # Standard AWS variable names. boto3 also falls back to its own credential
    # chain (~/.aws/credentials, IAM role) when the keys are left empty.
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_region: Optional[str] = None
    aws_default_region: Optional[str] = None
    aws_s3_bucket: Optional[str] = None
    aws_s3_prefix: str = "case-evidence"
    # Only for S3-compatible storage or local testing; leave empty for AWS.
    aws_s3_endpoint_url: Optional[str] = None
    evidence_max_file_mb: float = 15.0
    evidence_max_files: int = 10
    presigned_url_ttl_seconds: int = 600

    # ── Email OTP (EmailJS, called from the backend only) ────
    # The private key stays on the server. EXPO_PUBLIC_* names are accepted too
    # so the same values can be copied over unchanged.
    emailjs_service_id: Optional[str] = None
    emailjs_public_key: Optional[str] = None
    emailjs_private_key: Optional[str] = None
    emailjs_consumer_template_id: Optional[str] = None
    emailjs_admin_template_id: Optional[str] = None
    expo_public_emailjs_service_id: Optional[str] = None
    expo_public_emailjs_public_key: Optional[str] = None
    expo_public_emailjs_private_key: Optional[str] = None
    expo_public_emailjs_consumer_template_id: Optional[str] = None
    expo_public_emailjs_admin_template_id: Optional[str] = None

    # true => protected endpoints also require a completed email OTP for the
    # current Firebase sign-in (or a trusted device inside the window below).
    require_2fa: bool = True
    otp_ttl_seconds: int = 600
    otp_max_attempts: int = 5
    otp_resend_cooldown_seconds: int = 60
    otp_max_sends_per_hour: int = 5
    two_fa_trust_days: int = 7
    auth_sessions_collection: str = "authSessions"
    otp_challenges_collection: str = "authOtpChallenges"

    def emailjs(self, name: str) -> str:
        """EmailJS value: EMAILJS_<NAME>, else EXPO_PUBLIC_EMAILJS_<NAME>."""
        return (getattr(self, f"emailjs_{name}") or getattr(self, f"expo_public_emailjs_{name}") or "").strip()

    @property
    def s3_region(self) -> Optional[str]:
        return (self.aws_region or self.aws_default_region or "").strip() or None


@lru_cache
def get_settings() -> Settings:
    return Settings()


def local_tz() -> ZoneInfo:
    return ZoneInfo(get_settings().app_timezone)


# ─────────────────────────────────────────────────────────────
# FIREBASE
# ─────────────────────────────────────────────────────────────
def init_firebase() -> None:
    """Firebase Admin SDK ek hi baar initialise hota hai."""
    try:
        firebase_admin.get_app()
        return
    except ValueError:
        pass

    s = get_settings()
    if s.firebase_credentials_json:
        cred = credentials.Certificate(json.loads(s.firebase_credentials_json))
    elif s.firebase_credentials_path:
        cred = credentials.Certificate(s.firebase_credentials_path)
    else:
        # GOOGLE_APPLICATION_CREDENTIALS env variable par fallback
        cred = credentials.ApplicationDefault()

    firebase_admin.initialize_app(cred, {"storageBucket": s.firebase_storage_bucket} if s.firebase_storage_bucket else None)
    log.info("Firebase Admin SDK initialised")


def get_db():
    init_firebase()
    return firestore.client()


def get_bucket():
    """Evidence images/PDFs ke liye Firebase Storage bucket."""
    init_firebase()
    from firebase_admin import storage as fb_storage

    return fb_storage.bucket()


# ─────────────────────────────────────────────────────────────
# AUTH  (Firebase ID token + admins collection + email OTP)
# ─────────────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)
_ADMIN_TTL = 300  # seconds
_admin_cache: dict[str, float] = {}
_MFA_TTL = 120  # seconds
_mfa_cache: dict[tuple[str, int], float] = {}

TWO_FA_HEADER = {"X-Auth-Error": "2fa_required"}
TOKEN_CLOCK_SKEW_SECONDS = 30


def is_admin(uid: str) -> bool:
    now = time.monotonic()
    ts = _admin_cache.get(uid)
    if ts is not None and now - ts < _ADMIN_TTL:
        return True

    db = get_db()
    col = db.collection(get_settings().admins_collection)

    ok = col.document(uid).get().exists
    if not ok:
        # Tumhare Dashboard mai admins collection "uid" field se dhundi ja rahi thi
        ok = len(list(col.where("uid", "==", uid).limit(1).stream())) > 0

    if ok:
        _admin_cache[uid] = now
    return ok


_is_admin = is_admin  # old name, kept for existing imports


def verify_firebase_token(token: str) -> dict:
    """Verifies a Firebase ID token. 401 on missing/expired/invalid tokens."""
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        # A token is used milliseconds after sign-in; if this server's clock is even
        # 1s behind Google's, verification fails with "Token used too early" (that
        # broke every call right after an admin/consumer login). Allow small skew.
        decoded = fb_auth.verify_id_token(token, clock_skew_seconds=TOKEN_CLOCK_SKEW_SECONDS)
    except Exception as exc:  # expired, invalid, revoked ...
        log.warning("Token verification failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    if not decoded.get("uid"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return decoded


def token_auth_time(decoded: dict) -> int:
    """auth_time = when this Firebase sign-in happened. It stays the same across
    token refreshes and changes on every new password sign-in, so OTP
    verification is tied to one sign-in session."""
    try:
        return int(decoded.get("auth_time") or 0)
    except (TypeError, ValueError):
        return 0


def two_factor_enabled(session: dict, admin: bool) -> bool:
    """Per-account setting chosen in the Profile screen. Until the user changes it,
    consumers start with 2FA OFF and admins with 2FA ON."""
    v = (session or {}).get("twoFactorEnabled")
    return v if isinstance(v, bool) else admin


def is_2fa_verified(uid: str, auth_time: int, admin: bool = False) -> bool:
    key = (uid, auth_time)
    now = time.monotonic()
    ts = _mfa_cache.get(key)
    if ts is not None and now - ts < _MFA_TTL:
        return True
    snap = get_db().collection(get_settings().auth_sessions_collection).document(uid).get()
    d = snap.to_dict() or {}
    verified = {int(x) for x in (d.get("verifiedAuthTimes") or []) if isinstance(x, (int, float))}
    ok = (not two_factor_enabled(d, admin)) or (bool(auth_time) and auth_time in verified)
    if ok:
        _mfa_cache[key] = now
    return ok


def forget_2fa(uid: str, auth_time: Optional[int] = None) -> None:
    for key in list(_mfa_cache):
        if key[0] == uid and (auth_time is None or key[1] == auth_time):
            _mfa_cache.pop(key, None)


def _enforce_2fa(decoded: dict, admin: bool = False) -> None:
    if not get_settings().require_2fa:
        return
    if not is_2fa_verified(decoded["uid"], token_auth_time(decoded), admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification (2FA) is required for this sign-in.",
            headers=TWO_FA_HEADER,
        )


def authenticate_token(token: str) -> dict:
    """Admin token check (used by REST routes and the WebSocket)."""
    decoded = verify_firebase_token(token)
    if not is_admin(decoded["uid"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    _enforce_2fa(decoded, admin=True)
    return decoded


def _dev_identity(creds: Optional[HTTPAuthorizationCredentials], fallback_uid: str) -> dict:
    """REQUIRE_AUTH=false (local testing only): no checks, but if the app sent a
    valid token we still use the real user so per-user data stays correct."""
    if creds is not None:
        try:
            return verify_firebase_token(creds.credentials)
        except HTTPException:
            pass
    return {"uid": fallback_uid}


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """FastAPI dependency — har protected admin route par use hota hai."""
    if not get_settings().require_auth:
        return _dev_identity(creds, "dev")
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    return authenticate_token(creds.credentials)


# ─────────────────────────────────────────────────────────────
# CONSUMER AUTH  (koi bhi logged-in Firebase user — admin hona zaroori nahi)
# ─────────────────────────────────────────────────────────────
def authenticate_any_user(token: str) -> dict:
    """Token + 2FA check, without the admins collection check."""
    decoded = verify_firebase_token(token)
    _enforce_2fa(decoded)
    return decoded


def require_consumer(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """FastAPI dependency — consumer-facing routes (apni notifications, cases, evidence)."""
    if not get_settings().require_auth:
        return _dev_identity(creds, "dev-consumer")
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    return authenticate_any_user(creds.credentials)


def require_signed_in(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Valid Firebase sign-in only (no 2FA yet). Used by the OTP endpoints themselves."""
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    return verify_firebase_token(creds.credentials)
