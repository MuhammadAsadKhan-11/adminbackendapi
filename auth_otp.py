"""auth_otp.py — email OTP (2FA + password-reset codes) sent through EmailJS.

Why on the server:
  * The OTP is generated with `secrets` and stored only as a salted hash in a
    collection the apps cannot read (see firestore.rules).
  * The EmailJS private key never ships inside the app.
  * Verification ties the code to ONE Firebase sign-in (the token's auth_time),
    so a code cannot be replayed for another session, and is deleted after use.

Collections:
  authOtpChallenges/{purpose}:{uid}   codeHash, salt, expiresAt, attempts, authTime, sendTimes
  authSessions/{uid}                  verifiedAuthTimes[], trustedDevices{hash: expiry}, role
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Optional, Tuple

from fastapi import HTTPException, Request
from firebase_admin import auth as fb_auth
from firebase_admin import firestore as fb_firestore

from core import forget_2fa, get_db, get_settings, is_admin, local_tz, token_auth_time

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

log = logging.getLogger("electraguard.auth")

EMAILJS_SEND_URL = "https://api.emailjs.com/api/v1.0/email/send"
_MAX_REMEMBERED_SIGNINS = 10


# ─────────────────────────────────────────────────────────────
# small helpers
# ─────────────────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_dt(v: Any) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


def mask_email(email: str) -> str:
    name, _, domain = (email or "").partition("@")
    if not domain:
        return "your email"
    shown = name[:2] if len(name) > 2 else name[:1]
    return f"{shown}{'*' * max(2, len(name) - len(shown))}@{domain}"


def _hash_code(code: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{code}".encode()).hexdigest()


def _device_hash(uid: str, device_id: str) -> str:
    return hashlib.sha256(f"{uid}:{device_id}".encode()).hexdigest()[:32]


def _challenges():
    return get_db().collection(get_settings().otp_challenges_collection)


def _sessions():
    return get_db().collection(get_settings().auth_sessions_collection)


# In-memory per-IP limiter for the unauthenticated endpoints.
_ip_hits: Dict[str, Deque[float]] = defaultdict(deque)
_ip_lock = threading.Lock()


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_ip(request: Request, bucket: str, limit: int, window_s: int = 600) -> None:
    key = f"{bucket}:{client_ip(request)}"
    now = time.monotonic()
    with _ip_lock:
        q = _ip_hits[key]
        while q and now - q[0] > window_s:
            q.popleft()
        if len(q) >= limit:
            raise HTTPException(status_code=429, detail="Too many requests. Please wait a few minutes and try again.")
        q.append(now)


# ─────────────────────────────────────────────────────────────
# EmailJS
# ─────────────────────────────────────────────────────────────
def emailjs_config_status() -> Dict[str, bool]:
    s = get_settings()
    return {
        name: bool(s.emailjs(name))
        for name in ("service_id", "public_key", "private_key", "consumer_template_id", "admin_template_id")
    }


def send_otp_email(to_email: str, code: str, *, admin: bool, purpose: str) -> None:
    """Raises HTTPException if the email could not be handed to EmailJS."""
    s = get_settings()
    template = s.emailjs("admin_template_id" if admin else "consumer_template_id")
    service, public, private = s.emailjs("service_id"), s.emailjs("public_key"), s.emailjs("private_key")
    if not (template and service and public):
        log.error("EmailJS is not configured (missing service/public key/template id)")
        raise HTTPException(status_code=503, detail="Email service is not configured on the server.")
    if requests is None:  # pragma: no cover
        raise HTTPException(status_code=503, detail="Email service is unavailable on the server.")

    payload: Dict[str, Any] = {
        "service_id": service,
        "template_id": template,
        "user_id": public,
        "template_params": {
            "to_email": to_email,
            "otp_code": code,
            "expiry_minutes": str(max(1, s.otp_ttl_seconds // 60)),
            "purpose": "Password reset" if purpose == "password_reset" else "Sign-in verification",
            "portal": "Admin" if admin else "Consumer",
            # aliases used by EmailJS's built-in "One-Time Password" template
            "email": to_email,
            "passcode": code,
            "time": (_now() + timedelta(seconds=s.otp_ttl_seconds)).astimezone(local_tz()).strftime("%d %b %Y, %I:%M %p"),
        },
    }
    if private:
        payload["accessToken"] = private

    try:
        res = requests.post(EMAILJS_SEND_URL, json=payload, timeout=15)
    except Exception as exc:
        log.error("EmailJS request failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not send the verification email. Please try again.")
    if res.status_code != 200:
        # EmailJS error bodies are short messages (no secrets); the code is never logged.
        log.error("EmailJS rejected the send: HTTP %s %s", res.status_code, (res.text or "")[:200])
        raise HTTPException(status_code=502, detail="Could not send the verification email. Please try again.")
    log.info("OTP email sent (%s, %s)", purpose, mask_email(to_email))


# ─────────────────────────────────────────────────────────────
# challenge storage
# ─────────────────────────────────────────────────────────────
def _issue_challenge(
    challenge_id: str,
    *,
    uid: str,
    email: str,
    admin: bool,
    purpose: str,
    auth_time: int = 0,
    resend: bool = False,
) -> Dict[str, Any]:
    """Creates/refreshes a challenge and emails the code (cooldown + hourly cap)."""
    s = get_settings()
    ref = _challenges().document(challenge_id)
    snap = ref.get()
    prev = snap.to_dict() or {} if snap.exists else {}
    now = _now()

    last_sent = _as_dt(prev.get("lastSentAt"))
    expires = _as_dt(prev.get("expiresAt"))
    same_session = int(prev.get("authTime") or 0) == int(auth_time or 0)
    since_last = (now - last_sent).total_seconds() if last_sent else None
    active = bool(prev.get("codeHash")) and bool(expires) and expires > now

    # Coming back to the OTP screen: reuse the code already sent.
    if not resend and active and same_session and since_last is not None:
        return {
            "required": True,
            "alreadySent": True,
            "maskedEmail": mask_email(email),
            "expiresIn": int((expires - now).total_seconds()),
            "resendIn": max(0, int(s.otp_resend_cooldown_seconds - since_last)),
        }

    # Cooldown only while a code is still usable; the hourly cap always applies.
    if active and since_last is not None and since_last < s.otp_resend_cooldown_seconds:
        wait = int(s.otp_resend_cooldown_seconds - since_last) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {wait} seconds before requesting another code.",
            headers={"Retry-After": str(wait)},
        )

    recent = [t for t in (_as_dt(x) for x in (prev.get("sendTimes") or [])) if t and now - t < timedelta(hours=1)]
    if len(recent) >= s.otp_max_sends_per_hour:
        raise HTTPException(status_code=429, detail="Too many codes requested. Try again in an hour.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    expires_at = now + timedelta(seconds=s.otp_ttl_seconds)
    ref.set(
        {
            "uid": uid,
            "purpose": purpose,
            "role": "admin" if admin else "consumer",
            "codeHash": _hash_code(code, salt),
            "salt": salt,
            "authTime": int(auth_time or 0),
            "expiresAt": expires_at,
            "attempts": 0,
            "lastSentAt": now,
            "sendTimes": recent + [now],
            "createdAt": now,
        }
    )
    try:
        send_otp_email(email, code, admin=admin, purpose=purpose)
    except HTTPException:
        # No working code may exist if the email never went out.
        _invalidate(ref, "send_failed")
        raise
    return {
        "required": True,
        "alreadySent": False,
        "maskedEmail": mask_email(email),
        "expiresIn": s.otp_ttl_seconds,
        "resendIn": s.otp_resend_cooldown_seconds,
    }


def _invalidate(ref, reason: str) -> None:
    """Kills the current code but keeps the send history (hourly cap survives)."""
    ref.update(
        {
            "codeHash": fb_firestore.DELETE_FIELD,
            "salt": fb_firestore.DELETE_FIELD,
            "invalidatedAt": _now(),
            "invalidReason": reason,
        }
    )


def _check_challenge(challenge_id: str, code: str, *, auth_time: Optional[int] = None) -> Dict[str, Any]:
    """Validates a code. The code is invalidated on success, expiry or lock-out."""
    s = get_settings()
    code = (code or "").strip()
    if not (len(code) == 6 and code.isdigit()):
        raise HTTPException(status_code=400, detail="Enter the 6-digit code.")

    ref = _challenges().document(challenge_id)
    snap = ref.get()
    d = (snap.to_dict() or {}) if snap.exists else {}
    if not d.get("codeHash"):
        raise HTTPException(status_code=400, detail="No active code. Please request a new one.")

    if auth_time is not None and int(d.get("authTime") or 0) != int(auth_time):
        raise HTTPException(status_code=400, detail="This code belongs to an earlier sign-in. Please request a new one.")

    expires = _as_dt(d.get("expiresAt"))
    if not expires or expires <= _now():
        _invalidate(ref, "expired")
        raise HTTPException(status_code=400, detail="This code has expired. Please request a new one.")

    attempts = int(d.get("attempts") or 0)
    if attempts >= s.otp_max_attempts:
        _invalidate(ref, "locked")
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new code.")

    if not hmac.compare_digest(_hash_code(code, str(d.get("salt") or "")), str(d.get("codeHash") or "")):
        attempts += 1
        left = s.otp_max_attempts - attempts
        if left <= 0:
            _invalidate(ref, "locked")
            raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new code.")
        ref.update({"attempts": fb_firestore.Increment(1)})
        raise HTTPException(status_code=400, detail=f"Incorrect code. {left} attempt{'s' if left != 1 else ''} left.")

    _invalidate(ref, "used")  # one-time use
    return d


# ─────────────────────────────────────────────────────────────
# account lookups
# ─────────────────────────────────────────────────────────────
def _consumer_doc_for_uid(uid: str):
    col = get_db().collection(get_settings().consumers_collection)
    snap = col.document(uid).get()
    if snap.exists:
        return snap
    rows = list(col.where("uid", "==", uid).limit(1).stream())
    return rows[0] if rows else None


def _admin_doc_for_uid(uid: str):
    col = get_db().collection(get_settings().admins_collection)
    snap = col.document(uid).get()
    if snap.exists:
        return snap
    rows = list(col.where("uid", "==", uid).limit(1).stream())
    return rows[0] if rows else None


def _role_ok(uid: str, role: str) -> bool:
    if role == "admin":
        return is_admin(uid)
    return _consumer_doc_for_uid(uid) is not None


def _auth_email(decoded: Dict[str, Any]) -> str:
    email = str(decoded.get("email") or "").strip()
    if email:
        return email
    try:
        return str(fb_auth.get_user(decoded["uid"]).email or "").strip()
    except Exception:
        return ""


def resolve_login_email(identifier: str) -> str:
    """Consumer ID -> sign-in email (replaces the app's public Firestore query)."""
    ident = (identifier or "").strip()
    if not ident:
        raise HTTPException(status_code=400, detail="Enter your Consumer ID or email.")
    if "@" in ident:
        return ident
    col = get_db().collection(get_settings().consumers_collection)
    for value in dict.fromkeys([ident, ident.upper(), ident.lower()]):
        rows = list(col.where("consumerId", "==", value).limit(1).stream())
        if rows:
            d = rows[0].to_dict() or {}
            uid = str(d.get("uid") or rows[0].id)
            try:
                email = str(fb_auth.get_user(uid).email or "").strip()
            except Exception:
                email = str(d.get("email") or "").strip()
            if not email:
                raise HTTPException(status_code=404, detail="Consumer email not found. Please contact support.")
            return email
    raise HTTPException(status_code=404, detail="No consumer found with this ID.")


# ─────────────────────────────────────────────────────────────
# LOGIN 2FA
# ─────────────────────────────────────────────────────────────
def _mark_signin_verified(uid: str, auth_time: int, role: str, device_id: str, trust_device: bool) -> None:
    s = get_settings()
    ref = _sessions().document(uid)
    snap = ref.get()
    d = snap.to_dict() or {} if snap.exists else {}
    now = _now()

    times = [int(x) for x in (d.get("verifiedAuthTimes") or []) if isinstance(x, (int, float))]
    if auth_time not in times:
        times.append(auth_time)
    times = times[-_MAX_REMEMBERED_SIGNINS:]

    devices = {k: v for k, v in (d.get("trustedDevices") or {}).items() if (_as_dt(v) or now) > now}
    if trust_device and device_id:
        devices[_device_hash(uid, device_id)] = now + timedelta(days=s.two_fa_trust_days)

    ref.set(
        {
            "uid": uid,
            "role": role,
            "verifiedAuthTimes": times,
            "trustedDevices": devices,
            "lastVerifiedAt": now,
            "updatedAt": now,
        },
        merge=True,
    )


def _sync_user_doc(uid: str, role: str) -> None:
    """Keeps the old isVerified/lastVerifiedAt fields and removes plaintext OTP leftovers."""
    snap = _admin_doc_for_uid(uid) if role == "admin" else _consumer_doc_for_uid(uid)
    if snap is None:
        return
    try:
        snap.reference.update(
            {
                "isVerified": True,
                "lastVerifiedAt": int(time.time() * 1000),
                "loginOtp": fb_firestore.DELETE_FIELD,
                "loginOtpExpiresAt": fb_firestore.DELETE_FIELD,
            }
        )
    except Exception as exc:
        log.warning("User doc sync failed for %s: %s", role, type(exc).__name__)


def request_login_otp(decoded: Dict[str, Any], role: str, device_id: str, resend: bool) -> Dict[str, Any]:
    uid = decoded["uid"]
    role = (role or "").strip().lower()
    if role not in ("admin", "consumer"):
        raise HTTPException(status_code=422, detail="role must be admin or consumer")
    if not _role_ok(uid, role):
        detail = "You are not authorized as an Admin." if role == "admin" else "Consumer record not found for this account."
        raise HTTPException(status_code=403, detail=detail)

    auth_time = token_auth_time(decoded)
    if not auth_time:
        raise HTTPException(status_code=401, detail="Invalid sign-in token.")
    email = _auth_email(decoded)
    if not get_settings().require_2fa:
        # REQUIRE_2FA=false (local testing without EmailJS): password sign-in is enough.
        return {"required": False, "trustedDevice": False, "maskedEmail": mask_email(email)}
    if not email:
        raise HTTPException(status_code=400, detail="This account has no email address for verification.")

    snap = _sessions().document(uid).get()
    d = snap.to_dict() or {} if snap.exists else {}
    if auth_time in {int(x) for x in (d.get("verifiedAuthTimes") or []) if isinstance(x, (int, float))}:
        return {"required": False, "trustedDevice": False, "maskedEmail": mask_email(email)}

    if device_id and not resend:
        expiry = _as_dt((d.get("trustedDevices") or {}).get(_device_hash(uid, device_id)))
        if expiry and expiry > _now():
            _mark_signin_verified(uid, auth_time, role, device_id, trust_device=False)
            return {"required": False, "trustedDevice": True, "maskedEmail": mask_email(email)}

    return _issue_challenge(
        f"login:{uid}",
        uid=uid,
        email=email,
        admin=role == "admin",
        purpose="login",
        auth_time=auth_time,
        resend=resend,
    )


def verify_login_otp(decoded: Dict[str, Any], code: str, device_id: str) -> Dict[str, Any]:
    uid = decoded["uid"]
    auth_time = token_auth_time(decoded)
    challenge = _check_challenge(f"login:{uid}", code, auth_time=auth_time)
    role = str(challenge.get("role") or "consumer")
    if not _role_ok(uid, role):
        raise HTTPException(status_code=403, detail="This account no longer has access to this portal.")
    _mark_signin_verified(uid, auth_time, role, device_id, trust_device=True)
    _sync_user_doc(uid, role)
    log.info("2FA verified for %s sign-in", role)
    return {"verified": True, "role": role}


def session_status(decoded: Dict[str, Any]) -> Dict[str, Any]:
    uid = decoded["uid"]
    auth_time = token_auth_time(decoded)
    snap = _sessions().document(uid).get()
    d = snap.to_dict() or {} if snap.exists else {}
    verified = auth_time in {int(x) for x in (d.get("verifiedAuthTimes") or []) if isinstance(x, (int, float))}
    admin = is_admin(uid)
    role = "admin" if admin else ("consumer" if _consumer_doc_for_uid(uid) is not None else None)
    return {
        "verified": bool(verified) or not get_settings().require_2fa,
        "role": role,
        "twoFactorRequired": get_settings().require_2fa,
    }


def logout(decoded: Dict[str, Any]) -> None:
    """Forgets this sign-in so its tokens stop working on the API."""
    uid = decoded["uid"]
    auth_time = token_auth_time(decoded)
    try:
        _sessions().document(uid).set(
            {"verifiedAuthTimes": fb_firestore.ArrayRemove([auth_time]), "updatedAt": _now()},
            merge=True,
        )
    except Exception as exc:
        log.warning("Logout cleanup failed: %s", type(exc).__name__)
    forget_2fa(uid, auth_time)


# ─────────────────────────────────────────────────────────────
# PASSWORD RESET CODE  (the reset itself is Firebase's own email link)
# ─────────────────────────────────────────────────────────────
def _resolve_account(identifier: str) -> Tuple[str, str, bool]:
    """identifier (email / Consumer ID / Admin ID) -> (uid, auth email, is_admin)."""
    ident = (identifier or "").strip()
    if not ident:
        raise HTTPException(status_code=400, detail="Enter your email or ID.")
    uid = ""
    if "@" in ident:
        for candidate in dict.fromkeys([ident, ident.lower()]):
            try:
                uid = fb_auth.get_user_by_email(candidate).uid
                break
            except Exception:
                continue
    else:
        s = get_settings()
        db = get_db()
        rows = list(db.collection(s.admins_collection).where("adminId", "==", ident).limit(1).stream())
        if not rows:
            col = db.collection(s.consumers_collection)
            for value in dict.fromkeys([ident, ident.upper(), ident.lower()]):
                rows = list(col.where("consumerId", "==", value).limit(1).stream())
                if rows:
                    break
        if rows:
            d = rows[0].to_dict() or {}
            uid = str(d.get("uid") or rows[0].id)
    if not uid:
        raise HTTPException(status_code=404, detail="No account found with this email or ID.")
    try:
        email = str(fb_auth.get_user(uid).email or "").strip()
    except Exception:
        email = ""
    if not email:
        raise HTTPException(status_code=404, detail="No account found with this email or ID.")
    return uid, email, is_admin(uid)


def request_reset_code(identifier: str, resend: bool) -> Dict[str, Any]:
    uid, email, admin = _resolve_account(identifier)
    out = _issue_challenge(f"reset:{uid}", uid=uid, email=email, admin=admin, purpose="password_reset", resend=resend)
    out["portal"] = "admin" if admin else "consumer"
    return out


def verify_reset_code(identifier: str, code: str) -> Dict[str, Any]:
    uid, email, admin = _resolve_account(identifier)
    _check_challenge(f"reset:{uid}", code)
    return {"verified": True, "email": email, "portal": "admin" if admin else "consumer"}
