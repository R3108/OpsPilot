"""Password hashing, JWT issuance/verification, API keys, webhook signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings
from app.core.errors import AuthenticationError

TokenType = Literal["access", "refresh"]

BCRYPT_ROUNDS = 12


# --------------------------------------------------------------------------
# passwords
# --------------------------------------------------------------------------
def _prehash(password: str) -> bytes:
    """SHA-256 then base64, so bcrypt sees exactly 44 bytes.

    bcrypt silently truncates its input at 72 bytes and stops at the first NUL.
    Pre-hashing means a long passphrase keeps all of its entropy and no byte of
    the password is silently discarded. base64 (not hex) keeps the digest
    NUL-free and compact.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):  # malformed stored hash must not 500
        return False


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------
def create_token(
    *,
    subject: str,
    tenant_id: str,
    role: str,
    token_type: TokenType = "access",
    extra: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC)
    ttl = (
        timedelta(minutes=settings.access_token_ttl_minutes)
        if token_type == "access"
        else timedelta(days=settings.refresh_token_ttl_days)
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "tid": tenant_id,
        "role": role,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": uuid.uuid4().hex,
        "iss": "opspilot",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str, *, expected_type: TokenType = "access") -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer="opspilot",
        )
    except JWTError as exc:
        raise AuthenticationError("Invalid or expired token") from exc

    if payload.get("type") != expected_type:
        raise AuthenticationError(f"Expected a {expected_type} token")
    for claim in ("sub", "tid", "role"):
        if not payload.get(claim):
            raise AuthenticationError("Malformed token")
    return payload


# --------------------------------------------------------------------------
# API keys (machine-to-machine ingestion)
# --------------------------------------------------------------------------
API_KEY_PREFIX = "opk"


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(full_key, lookup_prefix, stored_hash)``.

    Only the hash is persisted; the full key is shown to the user exactly once.
    """
    raw = secrets.token_urlsafe(32)
    prefix = secrets.token_hex(4)
    full = f"{API_KEY_PREFIX}_{prefix}_{raw}"
    return full, prefix, hash_api_key(full)


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(f"{settings.secret_key}:{full_key}".encode()).hexdigest()


def parse_api_key_prefix(full_key: str) -> str | None:
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX:
        return None
    return parts[1]


# --------------------------------------------------------------------------
# webhook signatures
# --------------------------------------------------------------------------
def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def verify_github_signature(body: bytes, header: str | None, secret: str) -> bool:
    """GitHub sends ``X-Hub-Signature-256: sha256=<hex hmac>``."""
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return constant_time_equals(expected, header)


def verify_slack_signature(
    body: bytes,
    timestamp: str | None,
    signature: str | None,
    secret: str,
    *,
    tolerance_seconds: int | None = None,
) -> bool:
    """Slack v0 signing: ``v0=hmac(secret, "v0:{ts}:{body}")`` with replay window."""
    if not timestamp or not signature:
        return False
    tolerance = tolerance_seconds or settings.webhook_signature_tolerance_seconds
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > tolerance:
        return False
    basestring = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return constant_time_equals(expected, signature)


def verify_hmac_signature(body: bytes, header: str | None, secret: str) -> bool:
    """Generic ``X-OpsPilot-Signature: <hex hmac-sha256>`` used by our own senders."""
    if not header:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return constant_time_equals(expected, header.removeprefix("sha256="))


def sign_payload(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
