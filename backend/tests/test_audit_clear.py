"""Clearing the audit log.

The endpoint is destructive and irreversible, so the things worth pinning down
are: who is allowed to call it, that it actually deletes, that it leaves the
``audit.cleared`` marker behind, and that it stops at the tenant boundary.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import AuditAction, UserRole
from app.models.tenant import Tenant, User
from app.services import audit as audit_service
from tests.conftest import auth_headers_for


async def _seed(session: AsyncSession, tenant: Tenant, count: int) -> None:
    for i in range(count):
        await audit_service.record(
            session,
            tenant_id=tenant.id,
            action=AuditAction.INCIDENT_CREATED,
            resource_type="incident",
            resource_id=f"INC-{i:04d}",
            summary=f"seeded entry {i}",
        )
    await session.commit()


async def test_clear_deletes_entries_and_leaves_a_marker(
    client: AsyncClient, session: AsyncSession, tenant: Tenant, users: dict[str, User]
) -> None:
    await _seed(session, tenant, 3)

    response = await client.delete(
        "/api/v1/audit",
        params={"reason": "retention cleanup"},
        headers=auth_headers_for(users[str(UserRole.ADMIN)]),
    )
    assert response.status_code == 200, response.text
    assert response.json()["deleted"] == 3

    rows, total = await audit_service.query(session, tenant_id=tenant.id)
    assert total == 1
    marker = rows[0]
    assert marker.action is AuditAction.AUDIT_CLEARED
    assert marker.actor_label == users[str(UserRole.ADMIN)].full_name
    assert marker.before == {"entry_count": 3}
    assert marker.context["reason"] == "retention cleanup"


async def test_clear_on_an_empty_log_is_not_an_error(
    client: AsyncClient, session: AsyncSession, tenant: Tenant, users: dict[str, User]
) -> None:
    response = await client.delete(
        "/api/v1/audit", headers=auth_headers_for(users[str(UserRole.ADMIN)])
    )
    assert response.status_code == 200
    assert response.json()["deleted"] == 0

    _rows, total = await audit_service.query(session, tenant_id=tenant.id)
    assert total == 1  # the marker itself


async def test_clear_requires_admin(
    client: AsyncClient, session: AsyncSession, tenant: Tenant, users: dict[str, User]
) -> None:
    await _seed(session, tenant, 2)

    for role in (UserRole.VIEWER, UserRole.RESPONDER, UserRole.APPROVER):
        response = await client.delete("/api/v1/audit", headers=auth_headers_for(users[str(role)]))
        assert response.status_code == 403, f"{role} should not be able to clear the log"

    _rows, total = await audit_service.query(session, tenant_id=tenant.id)
    assert total == 2


async def test_clear_is_scoped_to_one_tenant(
    client: AsyncClient,
    session: AsyncSession,
    tenant: Tenant,
    users: dict[str, User],
) -> None:
    """An admin clearing their own log must not touch anybody else's."""
    await _seed(session, tenant, 2)

    other = Tenant(name="Other Org", slug="other-org-clear")
    session.add(other)
    await session.commit()
    await _seed(session, other, 4)

    response = await client.delete(
        "/api/v1/audit", headers=auth_headers_for(users[str(UserRole.ADMIN)])
    )
    assert response.status_code == 200
    assert response.json()["deleted"] == 2

    _rows, other_total = await audit_service.query(session, tenant_id=other.id)
    assert other_total == 4
