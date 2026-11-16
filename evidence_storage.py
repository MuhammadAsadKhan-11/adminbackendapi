"""evidence_storage.py — case evidence files in AWS S3.

* Files go to a PRIVATE bucket (no public ACLs). Firestore keeps only metadata.
* Every upload is checked by extension, declared MIME type and file signature.
* Downloads use short-lived presigned GET URLs created after an access check.

Config (environment / .env — never hardcode keys):
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, [AWS_SESSION_TOKEN]
    AWS_REGION (or AWS_DEFAULT_REGION), AWS_S3_BUCKET
    optional: AWS_S3_PREFIX, EVIDENCE_MAX_FILE_MB, EVIDENCE_MAX_FILES, PRESIGNED_URL_TTL_SECONDS
"""
from __future__ import annotations

import logging
import mimetypes
import os
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from core import get_settings

log = logging.getLogger("electraguard.evidence")

# extension -> (category, allowed MIME types)
ALLOWED_TYPES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "jpg": ("image", ("image/jpeg", "image/jpg", "image/pjpeg")),
    "jpeg": ("image", ("image/jpeg", "image/jpg", "image/pjpeg")),
    "png": ("image", ("image/png",)),
    "webp": ("image", ("image/webp",)),
    "heic": ("image", ("image/heic", "image/heif")),
    "pdf": ("document", ("application/pdf",)),
    "doc": ("document", ("application/msword",)),
    "docx": ("document", ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",)),
    "xls": ("spreadsheet", ("application/vnd.ms-excel",)),
    "xlsx": ("spreadsheet", ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",)),
    "csv": ("spreadsheet", ("text/csv", "application/csv", "text/comma-separated-values", "text/plain")),
    "txt": ("document", ("text/plain",)),
}

# Pickers often report these when they do not know the real type; the
# extension + file signature checks still apply.
_GENERIC_MIME = {"", "application/octet-stream", "binary/octet-stream", "application/x-binary"}

CANONICAL_MIME = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
    "heic": "image/heic",
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv",
    "txt": "text/plain",
}

_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # legacy .doc / .xls container
_ZIP = b"PK\x03\x04"  # .docx / .xlsx are zip packages


def _signature_ok(ext: str, head: bytes) -> bool:
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext == "heic":
        return head[4:8] == b"ftyp"
    if ext == "pdf":
        return head.startswith(b"%PDF-")
    if ext in ("doc", "xls"):
        return head.startswith(_OLE)
    if ext in ("docx", "xlsx"):
        return head.startswith(_ZIP)
    if ext in ("csv", "txt"):
        # text: no NUL bytes in the first KB
        return b"\x00" not in head[:1024]
    return False


@dataclass
class ValidatedFile:
    original_name: str
    safe_name: str
    ext: str
    category: str
    content_type: str
    content: bytes

    @property
    def size(self) -> int:
        return len(self.content)


def _safe_name(name: str) -> str:
    base = os.path.basename((name or "").replace("\\", "/")).strip() or "file"
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._") or "file"
    stem = stem[:80]
    return f"{stem}.{ext.lower()}" if ext else stem


def validate_files(files: List[Tuple[str, bytes, str]]) -> List[ValidatedFile]:
    """(filename, bytes, declared content type) -> validated files, or HTTP 400/413."""
    s = get_settings()
    if len(files) > s.evidence_max_files:
        raise HTTPException(status_code=400, detail=f"Too many files. Upload at most {s.evidence_max_files} at a time.")
    max_bytes = int(s.evidence_max_file_mb * 1024 * 1024)

    out: List[ValidatedFile] = []
    for name, content, declared in files:
        original = os.path.basename((name or "").replace("\\", "/")).strip() or "file"
        ext = original.rpartition(".")[2].lower() if "." in original else ""
        if ext not in ALLOWED_TYPES:
            allowed = ", ".join(sorted(ALLOWED_TYPES))
            raise HTTPException(status_code=400, detail=f'"{original}" is not an allowed file type. Allowed: {allowed}.')
        if not content:
            raise HTTPException(status_code=400, detail=f'"{original}" is empty.')
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f'"{original}" is {len(content) / 1048576:.1f} MB. The limit is {s.evidence_max_file_mb:g} MB per file.',
            )
        category, allowed_mimes = ALLOWED_TYPES[ext]
        mime = (declared or "").split(";")[0].strip().lower()
        if mime not in _GENERIC_MIME and mime not in allowed_mimes:
            raise HTTPException(
                status_code=400,
                detail=f'"{original}" was sent as {mime}, which does not match a .{ext} file.',
            )
        if not _signature_ok(ext, content[:2048]):
            raise HTTPException(
                status_code=400,
                detail=f'"{original}" does not look like a real .{ext} file (content check failed).',
            )
        out.append(
            ValidatedFile(
                original_name=original,
                safe_name=_safe_name(original),
                ext=ext,
                category=category,
                content_type=CANONICAL_MIME.get(ext) or mimetypes.guess_type(original)[0] or "application/octet-stream",
                content=content,
            )
        )
    return out


# ─────────────────────────────────────────────────────────────
# S3 client
# ─────────────────────────────────────────────────────────────
_client = None
_client_lock = threading.Lock()


def s3_configured() -> bool:
    return bool((get_settings().aws_s3_bucket or "").strip())


def _bucket() -> str:
    bucket = (get_settings().aws_s3_bucket or "").strip()
    if not bucket:
        raise HTTPException(
            status_code=503,
            detail="Evidence storage is not configured on the server (AWS_S3_BUCKET is missing).",
        )
    return bucket


def get_s3():
    global _client
    with _client_lock:
        if _client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:  # pragma: no cover
                raise HTTPException(status_code=503, detail="boto3 is not installed on the server.") from exc
            s = get_settings()
            kwargs: Dict[str, Any] = {
                "region_name": s.s3_region,
                "config": Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "standard"}),
            }
            if (s.aws_s3_endpoint_url or "").strip():
                kwargs["endpoint_url"] = s.aws_s3_endpoint_url.strip()
            # Explicit keys only when provided; otherwise boto3's normal chain applies.
            if s.aws_access_key_id and s.aws_secret_access_key:
                kwargs["aws_access_key_id"] = s.aws_access_key_id
                kwargs["aws_secret_access_key"] = s.aws_secret_access_key
                if s.aws_session_token:
                    kwargs["aws_session_token"] = s.aws_session_token
            _client = boto3.client("s3", **kwargs)
        return _client


def reset_client() -> None:
    """Tests / config reloads."""
    global _client
    with _client_lock:
        _client = None


def upload_evidence(
    vf: ValidatedFile,
    *,
    case_doc_id: str,
    case_number: str,
    consumer_id: str,
    consumer_uid: str,
    admin_uid: str,
    batch_id: str,
) -> Dict[str, Any]:
    """Uploads one validated file and returns the metadata dict stored in Firestore."""
    s = get_settings()
    bucket = _bucket()
    evidence_id = uuid.uuid4().hex
    prefix = (s.aws_s3_prefix or "case-evidence").strip("/")
    key = f"{prefix}/{case_doc_id}/{evidence_id}/{vf.safe_name}"
    now = datetime.now(timezone.utc)

    try:
        get_s3().put_object(
            Bucket=bucket,
            Key=key,
            Body=vf.content,
            ContentType=vf.content_type,
            ServerSideEncryption="AES256",
            Metadata={
                "case-id": case_doc_id,
                "evidence-id": evidence_id,
                "uploaded-by": admin_uid or "admin",
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        log.error("S3 upload failed for case %s (%s): %s", case_doc_id, vf.safe_name, type(exc).__name__)
        raise HTTPException(status_code=502, detail=f'Could not upload "{vf.original_name}" to evidence storage.') from exc

    log.info("Evidence uploaded: case=%s evidence=%s size=%d", case_doc_id, evidence_id, vf.size)
    return {
        "id": evidence_id,
        "fileName": vf.safe_name,
        "originalFileName": vf.original_name,
        "s3Key": key,
        "s3Bucket": bucket,
        "fileType": vf.content_type,
        "extension": vf.ext,
        "category": vf.category,
        "size": vf.size,
        "uploadedAt": now,
        "caseId": case_doc_id,
        "caseNumber": case_number,
        "consumerId": consumer_id,
        "consumerUid": consumer_uid,
        "adminId": admin_uid,
        "uploadBatchId": batch_id,
        "visibleToConsumer": True,
        "storage": "s3",
        # legacy fields read by the existing admin UI
        "name": vf.original_name,
        "type": "image" if vf.category == "image" else "document",
        "uploadedBy": "Admin",
    }


def delete_objects(keys: List[str]) -> None:
    """Best-effort cleanup when the Firestore write after an upload fails."""
    if not keys or not s3_configured():
        return
    try:
        get_s3().delete_objects(Bucket=_bucket(), Delete={"Objects": [{"Key": k} for k in keys], "Quiet": True})
    except Exception as exc:
        log.warning("S3 cleanup failed: %s", type(exc).__name__)


def presign_download(item: Dict[str, Any], disposition: str = "attachment") -> Dict[str, Any]:
    """Short-lived GET URL for one evidence item (call only after the access check)."""
    s = get_settings()
    ttl = max(60, min(int(s.presigned_url_ttl_seconds), 3600))
    name = str(item.get("originalFileName") or item.get("fileName") or item.get("name") or "evidence")
    ascii_name = re.sub(r'[^A-Za-z0-9_.() -]', "_", name).strip() or "evidence"
    mode = "inline" if disposition == "inline" else "attachment"
    content_type = str(item.get("fileType") or "application/octet-stream")

    if item.get("storage") == "s3" and item.get("s3Key"):
        url = get_s3().generate_presigned_url(
            "get_object",
            Params={
                "Bucket": str(item.get("s3Bucket") or _bucket()),
                "Key": str(item["s3Key"]),
                "ResponseContentDisposition": f'{mode}; filename="{ascii_name}"',
                "ResponseContentType": content_type,
            },
            ExpiresIn=ttl,
        )
        return {
            "url": url,
            "expiresIn": ttl,
            "fileName": name,
            "contentType": content_type,
        }

    # Legacy evidence (uploaded before S3) only has a stored URL.
    legacy = str(item.get("url") or "")
    if legacy:
        return {"url": legacy, "expiresIn": 0, "fileName": name, "contentType": content_type}
    raise HTTPException(status_code=404, detail="This evidence file has no stored object.")


def public_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """Evidence metadata safe to send to the apps (no bucket/key, no URL)."""
    uploaded = item.get("uploadedAt")
    if isinstance(uploaded, datetime):
        uploaded_iso = uploaded.astimezone(timezone.utc).isoformat()
    else:
        uploaded_iso = str(uploaded or item.get("date") or "") or None
    category = str(item.get("category") or ("image" if item.get("type") == "image" else "document"))
    return {
        "id": str(item.get("id") or ""),
        "name": str(item.get("originalFileName") or item.get("name") or item.get("fileName") or "file"),
        "fileName": str(item.get("fileName") or item.get("name") or ""),
        "type": "image" if category == "image" else "document",
        "category": category,
        "fileType": str(item.get("fileType") or ""),
        "extension": str(item.get("extension") or ""),
        "size": int(item.get("size") or 0),
        "uploadedAt": uploaded_iso,
        "uploadedBy": item.get("uploadedBy"),
        "date": item.get("date"),
        "downloadable": bool(item.get("s3Key") or item.get("url")),
    }
