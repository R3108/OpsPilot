"""Credential sealing, password hashing, tokens and webhook signatures."""

from __future__ import annotations

import time

import pytest

from app.core.crypto import (
    CryptoError,
    fingerprint,
    generate_kek,
    open_sealed,
    open_sealed_json,
    seal,
    seal_json,
)
from app.core.errors import AuthenticationError
from app.core.logging import redact
from app.core.security import (
    create_token,
    decode_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    parse_api_key_prefix,
    sign_payload,
    verify_github_signature,
    verify_hmac_signature,
    verify_password,
    verify_slack_signature,
)


# --------------------------------------------------------------------- crypto
def test_seal_round_trip() -> None:
    token = seal("hunter2", context="tenant:1:integration:2")
    assert "hunter2" not in token
    assert open_sealed(token, context="tenant:1:integration:2") == "hunter2"


def test_seal_json_round_trip() -> None:
    payload = {"bot_token": "xoxb-123", "signing_secret": "s3cret"}
    token = seal_json(payload, context="ctx")
    assert "xoxb-123" not in token
    assert open_sealed_json(token, context="ctx") == payload


def test_sealed_value_cannot_be_opened_with_a_different_context() -> None:
    """AAD binding means a blob cannot be moved between tenants or rows."""
    token = seal("secret", context="tenant:A:integration:1")
    with pytest.raises(CryptoError):
        open_sealed(token, context="tenant:B:integration:1")


def test_tampered_ciphertext_is_rejected() -> None:
    token = seal("secret", context="ctx")
    version, wrapped, dek_nonce, payload_nonce, ciphertext = token.split(".")
    flipped = ciphertext[:-4] + ("AAAA" if not ciphertext.endswith("AAAA") else "BBBB")
    with pytest.raises(CryptoError):
        open_sealed(".".join([version, wrapped, dek_nonce, payload_nonce, flipped]), context="ctx")


def test_each_seal_uses_a_fresh_data_key() -> None:
    first = seal("same", context="ctx")
    second = seal("same", context="ctx")
    assert first != second, "identical plaintexts must not produce identical ciphertext"


def test_malformed_sealed_value_raises() -> None:
    with pytest.raises(CryptoError):
        open_sealed("not-a-sealed-value", context="ctx")
    with pytest.raises(CryptoError):
        open_sealed("v9.a.b.c.d", context="ctx")


def test_generated_kek_is_usable() -> None:
    assert len(generate_kek()) >= 40


def test_fingerprint_is_stable_and_not_reversible() -> None:
    assert fingerprint("abc") == fingerprint("abc")
    assert fingerprint("abc") != fingerprint("abd")
    assert "abc" not in fingerprint("abc")


# ------------------------------------------------------------------ passwords
def test_password_round_trip() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong password", hashed)


def test_long_passphrases_keep_their_entropy() -> None:
    """bcrypt truncates at 72 bytes; the pre-hash must prevent that."""
    base = "x" * 100
    assert verify_password(base, hash_password(base))
    assert not verify_password(base + "different-suffix", hash_password(base))


def test_short_password_is_refused() -> None:
    with pytest.raises(ValueError):
        hash_password("short")


def test_malformed_hash_does_not_raise() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


# --------------------------------------------------------------------- tokens
def test_token_round_trip() -> None:
    token = create_token(subject="user-1", tenant_id="tenant-1", role="admin")
    claims = decode_token(token)
    assert claims["sub"] == "user-1"
    assert claims["tid"] == "tenant-1"
    assert claims["role"] == "admin"


def test_access_token_is_not_accepted_as_a_refresh_token() -> None:
    token = create_token(subject="u", tenant_id="t", role="viewer", token_type="access")
    with pytest.raises(AuthenticationError):
        decode_token(token, expected_type="refresh")


def test_tampered_token_is_rejected() -> None:
    token = create_token(subject="u", tenant_id="t", role="viewer")
    with pytest.raises(AuthenticationError):
        decode_token(token[:-3] + "aaa")


def test_expired_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "access_token_ttl_minutes", -1)
    token = create_token(subject="u", tenant_id="t", role="viewer")
    with pytest.raises(AuthenticationError):
        decode_token(token)


# ------------------------------------------------------------------- api keys
def test_api_key_generation_and_verification() -> None:
    full, prefix, stored = generate_api_key()
    assert full.startswith("opk_")
    assert parse_api_key_prefix(full) == prefix
    assert hash_api_key(full) == stored
    assert full not in stored


def test_malformed_api_key_has_no_prefix() -> None:
    assert parse_api_key_prefix("garbage") is None
    assert parse_api_key_prefix("bearer_x_y") is None


# ----------------------------------------------------------------- signatures
def test_github_signature_verification() -> None:
    body = b'{"action":"opened"}'
    secret = "webhook-secret"
    header = "sha256=" + sign_payload(body, secret)
    assert verify_github_signature(body, header, secret)
    assert not verify_github_signature(body, header, "other-secret")
    assert not verify_github_signature(b"tampered", header, secret)
    assert not verify_github_signature(body, None, secret)
    assert not verify_github_signature(body, "md5=abc", secret)


def test_slack_signature_verification() -> None:
    import hashlib
    import hmac

    body = b"token=x&team_id=T1"
    secret = "slack-signing-secret"
    timestamp = str(int(time.time()))
    expected = (
        "v0="
        + hmac.new(
            secret.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    assert verify_slack_signature(body, timestamp, expected, secret)
    assert not verify_slack_signature(body, timestamp, expected, "wrong")


def test_slack_signature_rejects_replays() -> None:
    import hashlib
    import hmac

    body = b"payload"
    secret = "s"
    old = str(int(time.time()) - 3600)
    signature = (
        "v0="
        + hmac.new(secret.encode(), b"v0:" + old.encode() + b":" + body, hashlib.sha256).hexdigest()
    )
    assert not verify_slack_signature(body, old, signature, secret)


def test_generic_hmac_signature() -> None:
    body = b'{"alerts":[]}'
    secret = "shared"
    assert verify_hmac_signature(body, sign_payload(body, secret), secret)
    assert verify_hmac_signature(body, "sha256=" + sign_payload(body, secret), secret)
    assert not verify_hmac_signature(body, "deadbeef", secret)
    assert not verify_hmac_signature(body, None, secret)


# ------------------------------------------------------------------ redaction
def test_secrets_are_redacted_from_log_payloads() -> None:
    scrubbed = redact(
        {
            "password": "hunter2",
            "api_key": "sk-abcdef123456",
            "nested": {"authorization": "Bearer eyJhbGciOi.abc.def"},
            "message": "token is xoxb-1234567890abcdef",
            "safe": "checkout-api",
        }
    )
    assert scrubbed["password"] == "***redacted***"
    assert scrubbed["api_key"] == "***redacted***"
    assert scrubbed["nested"]["authorization"] == "***redacted***"
    assert "xoxb-1234567890abcdef" not in scrubbed["message"]
    assert scrubbed["safe"] == "checkout-api"


def test_redaction_handles_nested_collections() -> None:
    scrubbed = redact({"items": [{"secret": "x"}, {"ok": "y"}]})
    assert scrubbed["items"][0]["secret"] == "***redacted***"
    assert scrubbed["items"][1]["ok"] == "y"
