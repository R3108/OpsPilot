"""Envelope encryption for tenant integration credentials.

Every secret blob gets its own random 256-bit data key (DEK). The DEK is wrapped
with the deployment key-encryption-key (KEK, ``ENCRYPTION_KEY``) and stored next
to the ciphertext, so rotating the KEK only requires rewrapping small DEKs, and a
leaked DEK exposes exactly one credential.

Wire format (all base64url, joined by ``.``)::

    v1.<wrapped_dek>.<dek_nonce>.<payload_nonce>.<ciphertext>

AAD binds the ciphertext to its tenant + integration so a blob cannot be moved
between rows.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_VERSION = "v1"
_NONCE_BYTES = 12
_KEY_BYTES = 32


class CryptoError(RuntimeError):
    """Raised when a secret cannot be sealed or opened."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_kek() -> str:
    """Generate a fresh base64 KEK suitable for ``ENCRYPTION_KEY``."""
    return base64.urlsafe_b64encode(os.urandom(_KEY_BYTES)).decode("ascii")


def _kek() -> bytes:
    raw = settings.encryption_key
    if not raw:
        if settings.is_production:
            raise CryptoError("ENCRYPTION_KEY is not configured")
        # Deterministic dev key derived from SECRET_KEY so local restarts can
        # still read rows written before the restart.
        import hashlib

        return hashlib.sha256(settings.secret_key.encode()).digest()
    try:
        key = _b64d(raw)
    except Exception as exc:  # noqa: BLE001
        raise CryptoError("ENCRYPTION_KEY is not valid base64") from exc
    if len(key) != _KEY_BYTES:
        raise CryptoError(f"ENCRYPTION_KEY must decode to {_KEY_BYTES} bytes, got {len(key)}")
    return key


def _aad(context: str | None) -> bytes:
    return (context or "opspilot").encode("utf-8")


def seal(plaintext: str, *, context: str | None = None) -> str:
    """Encrypt ``plaintext`` under a fresh DEK wrapped by the KEK."""
    if plaintext is None:
        raise CryptoError("cannot seal None")
    dek = os.urandom(_KEY_BYTES)
    dek_nonce = os.urandom(_NONCE_BYTES)
    payload_nonce = os.urandom(_NONCE_BYTES)
    aad = _aad(context)

    wrapped = AESGCM(_kek()).encrypt(dek_nonce, dek, aad)
    ciphertext = AESGCM(dek).encrypt(payload_nonce, plaintext.encode("utf-8"), aad)

    return ".".join(
        [_VERSION, _b64e(wrapped), _b64e(dek_nonce), _b64e(payload_nonce), _b64e(ciphertext)]
    )


def open_sealed(token: str, *, context: str | None = None) -> str:
    """Decrypt a blob produced by :func:`seal`."""
    try:
        version, wrapped_b64, dek_nonce_b64, payload_nonce_b64, ct_b64 = token.split(".")
    except ValueError as exc:
        raise CryptoError("malformed sealed value") from exc
    if version != _VERSION:
        raise CryptoError(f"unsupported sealed value version {version!r}")

    aad = _aad(context)
    try:
        dek = AESGCM(_kek()).decrypt(_b64d(dek_nonce_b64), _b64d(wrapped_b64), aad)
        plaintext = AESGCM(dek).decrypt(_b64d(payload_nonce_b64), _b64d(ct_b64), aad)
    except InvalidTag as exc:
        raise CryptoError("sealed value failed authentication (wrong key or tampered)") from exc
    return plaintext.decode("utf-8")


def seal_json(data: dict[str, Any], *, context: str | None = None) -> str:
    return seal(json.dumps(data, separators=(",", ":"), sort_keys=True), context=context)


def open_sealed_json(token: str, *, context: str | None = None) -> dict[str, Any]:
    return json.loads(open_sealed(token, context=context))


def fingerprint(value: str) -> str:
    """Short non-reversible identifier so the UI can show *which* secret is set."""
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
