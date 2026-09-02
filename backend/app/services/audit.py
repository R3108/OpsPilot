"""The audit trail.

Every write goes through :func:`record`, which redacts before writing. Rows are
immutable once written — there is no update helper, and migration ``0003``
installs a trigger that rejects UPDATE at the database level.

Rows are **not** permanent: :func:`clear` deletes a tenant's entire trail, driven
by the admin-only "Clear audit log" action. That makes the trail a record of
recent activity rather than proof of past activity — an admin can erase the
evidence of their own actions. ``docs/SAFETY.md`` states the consequences.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, redact, request_id_ctx
from app.models.audit import AuditLog
from app.models.enums import AuditAction

log = get_logger(__name__)

# Keys we never persist even in a "before"/"after" diff.
_NEVER_PERSIST = {
    "password",
    "password_hash",
    "credentials",
    "credentials_sealed",
    "webhook_secret",
    "webhook_secret_sealed",
    "token",
    "access_token",
    "refresh_token",
    "key",
    "key_hash",
}


def _scrub(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    cleaned = {k: v for k, v in data.items() if k not in _NEVER_PERSIST}
    return redact(cleaned)  # type: ignore[return-value]


async def record(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: AuditAction,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    actor_type: str = "system",
    actor_id: str | uuid.UUID | None = None,
    actor_label: str = "",
    incident_id: uuid.UUID | None = None,
    summary: str = "",
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog:
    """Write one audit row. Flushed but not committed — the caller owns the txn."""
    entry = AuditLog(
        tenant_id=tenant_id,
        action=action,
        actor_type=actor_type,
        actor_id=str(actor_id) if actor_id else None,
        actor_label=actor_label[:200],
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        incident_id=incident_id,
        summary=summary[:5000],
        before=_scrub(before),
        after=_scrub(after),
        context=_scrub(context),
        request_id=request_id_ctx.get(),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:400] or None,
        occurred_at=datetime.now(UTC),
    )
    session.add(entry)
    await session.flush()
    log.info(
        "audit",
        action=str(action),
        resource=f"{resource_type}:{resource_id}",
        actor=f"{actor_type}:{actor_id}",
        tenant_id=str(tenant_id),
    )
    return entry


async def record_agent(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    action: AuditAction,
    resource_type: str,
    resource_id: str | uuid.UUID | None = None,
    summary: str = "",
    **context: Any,
) -> AuditLog:
    """Convenience wrapper for actions taken by the agent itself."""
    return await record(
        session,
        tenant_id=tenant_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_type="agent",
        actor_id="opspilot-agent",
        actor_label="OpsPilot Agent",
        incident_id=incident_id,
        summary=summary,
        context=context,
    )


async def clear(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_type: str = "system",
    actor_id: str | uuid.UUID | None = None,
    actor_label: str = "",
    reason: str = "",
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[int, AuditLog]:
    """Delete a tenant's audit trail, then record that it happened.

    Destructive and irreversible: export first if the history matters.

    Order is deliberate — the DELETE runs before the marker is written, so the
    marker survives. It is the only row left, and the only evidence that anything
    was here. Flushed but not committed; the caller owns the txn.
    """
    deleted = int(
        (
            await session.execute(delete(AuditLog).where(AuditLog.tenant_id == tenant_id))
        ).rowcount
        or 0
    )

    marker = await record(
        session,
        tenant_id=tenant_id,
        action=AuditAction.AUDIT_CLEARED,
        resource_type="audit_log",
        actor_type=actor_type,
        actor_id=actor_id,
        actor_label=actor_label,
        summary=(
            f"Cleared the audit log: {deleted} "
            f"{'entry' if deleted == 1 else 'entries'} deleted"
            + (f" — {reason}" if reason else "")
        ),
        before={"entry_count": deleted},
        after={"entry_count": 0},
        context={"reason": reason} if reason else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    log.warning(
        "audit.cleared",
        deleted=deleted,
        actor=f"{actor_type}:{actor_id}",
        tenant_id=str(tenant_id),
    )
    return deleted, marker


async def query(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actions: list[AuditAction] | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    incident_id: uuid.UUID | None = None,
    actor_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    stmt = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    count_stmt = select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant_id)

    conditions = []
    if actions:
        conditions.append(AuditLog.action.in_(actions))
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if resource_id:
        conditions.append(AuditLog.resource_id == resource_id)
    if incident_id:
        conditions.append(AuditLog.incident_id == incident_id)
    if actor_id:
        conditions.append(AuditLog.actor_id == actor_id)
    if since:
        conditions.append(AuditLog.occurred_at >= since)
    if until:
        conditions.append(AuditLog.occurred_at <= until)

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    stmt = stmt.order_by(AuditLog.occurred_at.desc()).limit(limit).offset(offset)
    rows = list((await session.execute(stmt)).scalars().all())
    total = int((await session.execute(count_stmt)).scalar_one())
    return rows, total
