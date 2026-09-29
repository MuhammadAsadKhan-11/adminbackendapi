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
# AUTH  (Firebase ID token + admins collection)
# ─────────────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)
_ADMIN_TTL = 300  # seconds
_admin_cache: dict[str, float] = {}


def _is_admin(uid: str) -> bool:
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


def authenticate_token(token: str) -> dict:
    """Token verify karo aur check karo ke user admin hai. Fail par HTTPException."""
    try:
        decoded = fb_auth.verify_id_token(token)
    except Exception as exc:  # expired, invalid, revoked ...
        log.warning("Token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    uid = decoded.get("uid")
    if not uid or not _is_admin(uid):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return decoded


def require_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """FastAPI dependency — har protected route par use hota hai."""
    if not get_settings().require_auth:
        return {"uid": "dev"}
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
    """Sirf token verify karta hai — admins collection check nahi karta.
    Consumer app ke apne-notifications jaise endpoints ke liye."""
    try:
        decoded = fb_auth.verify_id_token(token)
    except Exception as exc:
        log.warning("Token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    if not decoded.get("uid"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return decoded


def require_consumer(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """FastAPI dependency — consumer-facing routes (jaise apni notifications) ke liye.
    Sirf yeh check karta hai ke request kisi bhi valid logged-in Firebase user se aa rahi hai."""
    if not get_settings().require_auth:
        return {"uid": "dev-consumer"}
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    return authenticate_any_user(creds.credentials)