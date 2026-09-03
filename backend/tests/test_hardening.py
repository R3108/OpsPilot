"""Worker retry policy, auth throttles, and reuse detection.

These pin the production-hardening behaviour: transient infra failures redrive
with backoff, anonymous auth endpoints throttle per IP, and a reused refresh
token burns the whole family.
"""

from __future__ import annotations

import uuid

import pytest
from arq import Retry
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, IntegrationError, IntegrationTimeoutError
from app.core.security import decode_token
from app.models.tenant import RefreshToken, Tenant, User
from app.workers.tasks import _maybe_retry


def test_transient_errors_retry_with_backoff() -> None:
    with pytest.raises(Retry):
        _maybe_retry({"job_try": 1}, IntegrationError("LLM 502"))
    with pytest.raises(Retry):
        _maybe_retry({"job_try": 2}, IntegrationTimeoutError("slow provider"))
    with pytest.raises(Retry):
        _maybe_retry(None, ConnectionError("redis down"))


def test_domain_errors_never_retry() -> None:
    assert _maybe_retry({"job_try": 1}, ConflictError("busy")) is None
    assert _maybe_retry({"job_try": 1}, ValueError("bad params")) is None


def test_retries_stop_after_max_tries() -> None:
    assert _maybe_retry({"job_try": 3}, IntegrationError("still down")) is None
    assert _maybe_retry({"job_try": 99}, TimeoutError()) is None


async def _signup_and_login(client: AsyncClient, slug: str) -> dict[str, str]:
    email = f"user-{uuid.uuid4().hex[:8]}@test.dev"
    signup = await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": slug,
            "email": email,
            "password": "a-good-password-1",
        },
    )
    assert signup.status_code == 201, signup.text
    return signup.json()


async def test_login_is_throttled_per_ip(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    tokens = await _signup_and_login(client, "Throttle Co")
    assert tokens["access_token"]
    # Bypass bcrypt (~4.6s per check locally): throttle counts before auth
    # outcome, so forcing 401s still exercises the 429 path. Stub hash_password
    # too: unknown-email logins hash a timing-equalizer value on every attempt.
    monkeypatch.setattr("app.api.v1.auth.verify_password", lambda *a, **k: False)
    monkeypatch.setattr("app.api.v1.auth.hash_password", lambda *a, **k: "dummy-hash")
    # Freeze the rate-limit window: each attempt costs seconds (bcrypt plus the
    # degraded-Redis connect timeout), so 14 attempts can straddle a 60s window
    # boundary and never reach 10 in one window. Frozen time pins every
    # increment to a single window key — deterministic locally and on CI — and
    # the fixed instant isolates this run from any real window's counters.
    monkeypatch.setattr("app.core.redis_client.time.time", lambda: 1_700_000_000.0)

    statuses = set()
    for _ in range(14):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@test.dev", "password": "wrong-password-1"},
        )
        statuses.add(response.status_code)
    assert 429 in statuses, "expected the anonymous login throttle to engage"


async def test_refresh_reuse_burns_the_whole_family(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    tokens = await _signup_and_login(client, "Reuse Co")
    first = tokens["refresh_token"]

    rotated = await client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert rotated.status_code == 200
    second = rotated.json()["refresh_token"]
    assert second != first

    # Replaying the rotated-out token is theft: the family dies.
    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert replay.status_code == 401

    # Even the token minted from the legitimate rotation is now dead.
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": second})
    assert after.status_code == 401

    rows = list((await session.execute(select(RefreshToken))).scalars().all())
    assert rows, "expected refresh rows to exist"
    assert all(r.revoked_at is not None for r in rows)


async def test_deactivated_user_cannot_refresh(client: AsyncClient, session: AsyncSession) -> None:
    tokens = await _signup_and_login(client, "Deactivate Co")
    refresh_token = tokens["refresh_token"]

    user_id = uuid.UUID(decode_token(refresh_token, expected_type="refresh")["sub"])
    user = await session.get(User, user_id)
    assert user is not None
    user.is_active = False
    await session.commit()

    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 401


async def test_access_token_is_not_a_refresh_token(client: AsyncClient) -> None:
    tokens = await _signup_and_login(client, "Confuse Co")
    response = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["access_token"]}
    )
    assert response.status_code == 401
