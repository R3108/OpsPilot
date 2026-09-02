"""Test fixtures.

Tests run against a real (sqlite) database and the real application wiring —
no service is mocked out. The only substitutions are at the true edges: the LLM
(``LLM_PROVIDER=fake``) and the provider transports (simulation mode). Everything
in between — the policy engine, the executor, approvals, audit — is the code that
ships.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import tempfile
import uuid
from collections.abc import AsyncIterator

# Configure the environment before anything imports app.core.config.
#
# A *file*-backed sqlite database, not in-memory: the graph's investigator
# fan-out opens several sessions concurrently, and only a file-backed database
# gives each one its own connection. In-memory sqlite must share a single
# connection, which would serialise those writes and hide exactly the race
# conditions these tests exist to catch.
_TEST_DB = pathlib.Path(tempfile.gettempdir()) / f"opspilot-test-{os.getpid()}.db"
_TEST_DB.unlink(missing_ok=True)

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("LLM_PROVIDER", "fake")
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_TEST_DB.as_posix()}")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-for-jwt-signing")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.core.db import dispose_engine, get_engine, get_sessionmaker  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from app.models.enums import IncidentSeverity, IncidentSource, UserRole  # noqa: E402
from app.models.incident import Incident  # noqa: E402
from app.models.tenant import Tenant, User  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():  # noqa: ANN201
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
async def database() -> AsyncIterator[None]:
    """A fresh schema per test. Cheap on in-memory sqlite, and total isolation."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(autouse=True)
def reset_simulation() -> None:
    from app.integrations.simulation import clear_worlds

    clear_worlds()


@pytest.fixture
async def session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as db:
        yield db
        await db.commit()


@pytest.fixture
async def tenant(session: AsyncSession) -> Tenant:
    row = Tenant(name="Test Org", slug=f"test-{uuid.uuid4().hex[:8]}")
    session.add(row)
    # Committed, not just flushed: API requests run in their own session on their
    # own connection, so uncommitted fixture data would be invisible to them.
    await session.commit()
    return row


@pytest.fixture
async def users(session: AsyncSession, tenant: Tenant) -> dict[str, User]:
    """One user per role, so RBAC can be tested at every boundary."""
    created: dict[str, User] = {}
    for role in (
        UserRole.VIEWER,
        UserRole.RESPONDER,
        UserRole.APPROVER,
        UserRole.ADMIN,
        UserRole.OWNER,
    ):
        user = User(
            tenant_id=tenant.id,
            email=f"{role}@test.dev",
            full_name=f"{role.title()} User",
            password_hash=hash_password("test-password-1"),
            role=role,
        )
        session.add(user)
        created[str(role)] = user
    await session.commit()
    return created


@pytest.fixture
async def incident(session: AsyncSession, tenant: Tenant) -> Incident:
    from datetime import UTC, datetime

    row = Incident(
        tenant_id=tenant.id,
        reference="INC-0001",
        title="checkout-api error rate elevated",
        description="5xx rate at 30%",
        severity=IncidentSeverity.SEV1,
        source=IncidentSource.PROMETHEUS,
        service="checkout-api",
        namespace="payments",
        environment="production",
        labels={"database": "checkout_prod"},
        detected_at=datetime.now(UTC),
        root_cause_confidence=0.85,
    )
    session.add(row)
    await session.commit()
    return row


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
async def auth_client(client: AsyncClient) -> AsyncIterator[AsyncClient]:
    """A signed-up owner with an Authorization header already set."""
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "organization_name": "Fixture Org",
            "email": f"owner-{uuid.uuid4().hex[:8]}@test.dev",
            "password": "test-password-1",
            "full_name": "Fixture Owner",
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["access_token"]
    client.headers["Authorization"] = f"Bearer {token}"
    yield client


@pytest.fixture(scope="session", autouse=True)
async def cleanup() -> AsyncIterator[None]:
    yield
    await dispose_engine()
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(str(_TEST_DB) + suffix).unlink(missing_ok=True)


def auth_headers_for(user: User) -> dict[str, str]:
    from app.core.security import create_token

    token = create_token(subject=str(user.id), tenant_id=str(user.tenant_id), role=str(user.role))
    return {"Authorization": f"Bearer {token}"}
