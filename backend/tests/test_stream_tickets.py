"""Stream tickets, RLS session helpers, and webhook body validation."""

from __future__ import annotations

import time
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import stream as stream_module
from app.api.v1 import webhooks as webhooks_module
from app.core.db import clear_tenant_setting, set_tenant_setting, tenant_session_scope
from app.core.errors import AuthenticationError, ValidationError
from app.models.tenant import Tenant


class FakeRedis:
    """Minimal getdel/set stand-in for the ticket store."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.store[key] = value
        return True

    async def getdel(self, key: str) -> str | None:
        return self.store.pop(key, None)


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> FakeRedis:
    fake = FakeRedis()
    monkeypatch.setattr(stream_module, "get_redis", lambda: fake)
    return fake


async def test_stream_ticket_mints_and_opens_event_stream(
    auth_client: AsyncClient, session: AsyncSession, fake_redis: FakeRedis
) -> None:
    minted = await auth_client.post("/api/v1/stream/ticket")
    assert minted.status_code == 200, minted.text
    ticket = minted.json()["ticket"]
    assert ticket

    # Single-use: consume the ticket directly instead of holding an SSE
    # response open (an infinite stream can never be asserted with GET).
    user = await stream_module._authenticate(session, ticket)
    assert user is not None
    with pytest.raises(AuthenticationError):
        await stream_module._authenticate(session, ticket)


async def test_stream_rejects_unknown_ticket(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/api/v1/stream/tenant", params={"ticket": "no-such-ticket"})
    assert response.status_code == 401


async def test_stream_rejects_missing_credential(auth_client: AsyncClient) -> None:
    response = await auth_client.get("/api/v1/stream/tenant")
    assert response.status_code == 401


def test_parse_json_body_rejects_malformed() -> None:
    with pytest.raises(ValidationError):
        webhooks_module._parse_json_body(b"{not json")


def test_parse_json_body_rejects_non_object() -> None:
    with pytest.raises(ValidationError):
        webhooks_module._parse_json_body(b"[1, 2, 3]")


def test_parse_json_body_accepts_object() -> None:
    assert webhooks_module._parse_json_body(b'{"a": 1}') == {"a": 1}
    assert webhooks_module._parse_json_body(b"") == {}


async def test_tenant_session_scope_is_noop_on_sqlite(tenant: Tenant) -> None:
    # sqlite has no RLS; the helpers must not fail and must yield a live session.
    async with tenant_session_scope(tenant.id) as session:
        assert session is not None
        await set_tenant_setting(session, tenant.id)
        await clear_tenant_setting(session)


async def test_rate_limit_bucket_counts_up(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.redis_client import rate_limit_ok

    monkeypatch.setattr("app.core.redis_client.time.time", lambda: 1_700_000_000.0)
    bucket = f"test:{uuid.uuid4().hex}:{int(time.time())}"
    ok1, count1 = await rate_limit_ok(bucket, limit=2, window_seconds=60)
    ok2, count2 = await rate_limit_ok(bucket, limit=2, window_seconds=60)
    ok3, _ = await rate_limit_ok(bucket, limit=2, window_seconds=60)
    assert (ok1, count1) == (True, 1)
    assert (ok2, count2) == (True, 2)
    assert ok3 is False
