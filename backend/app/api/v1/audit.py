"""Audit log access.

Entries are written only as a side effect of the actions they describe — there
is no endpoint that creates one. The one mutating route is ``DELETE``, which
clears the whole trail for the tenant.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.deps import DbSession, RequireAdmin, client_ip
from app.models.enums import AuditAction
from app.schemas.common import ORMModel, Page
from app.services import audit as audit_service

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogOut(ORMModel):
    id: uuid.UUID
    action: AuditAction
    actor_type: str
    actor_id: str | None = None
    actor_label: str
    resource_type: str
    resource_id: str | None = None
    incident_id: uuid.UUID | None = None
    summary: str
    before: dict[str, Any]
    after: dict[str, Any]
    context: dict[str, Any]
    request_id: str | None = None
    ip_address: str | None = None
    occurred_at: datetime


class AuditClearResult(BaseModel):
    deleted: int
    message: str


@router.get("", response_model=Page[AuditLogOut])
async def list_audit_logs(
    principal: RequireAdmin,
    session: DbSession,
    action: Annotated[list[AuditAction] | None, Query()] = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    incident_id: uuid.UUID | None = None,
    actor_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditLogOut]:
    rows, total = await audit_service.query(
        session,
        tenant_id=principal.tenant_id,
        actions=action,
        resource_type=resource_type,
        resource_id=resource_id,
        incident_id=incident_id,
        actor_id=actor_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return Page(
        items=[AuditLogOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/export")
async def export_audit_logs(
    principal: RequireAdmin,
    session: DbSession,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=50_000)] = 10_000,
) -> StreamingResponse:
    """CSV export for compliance review."""
    rows, _total = await audit_service.query(
        session,
        tenant_id=principal.tenant_id,
        since=since,
        until=until,
        limit=limit,
        offset=0,
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "occurred_at",
            "action",
            "actor_type",
            "actor_label",
            "resource_type",
            "resource_id",
            "incident_id",
            "summary",
            "request_id",
            "ip_address",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.occurred_at.isoformat(),
                str(row.action),
                row.actor_type,
                row.actor_label,
                row.resource_type,
                row.resource_id or "",
                str(row.incident_id) if row.incident_id else "",
                row.summary.replace("\n", " ")[:2000],
                row.request_id or "",
                row.ip_address or "",
            ]
        )
    buffer.seek(0)

    filename = f"opspilot-audit-{datetime.now().date().isoformat()}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("", response_model=AuditClearResult)
async def clear_audit_logs(
    request: Request,
    principal: RequireAdmin,
    session: DbSession,
    reason: Annotated[str, Query(max_length=500)] = "",
) -> AuditClearResult:
    """Delete every audit entry for the tenant. Irreversible.

    A single ``audit.cleared`` entry naming the actor is written afterwards and
    is all that remains. Use ``GET /audit/export`` first if the history matters.
    """
    deleted, _marker = await audit_service.clear(
        session,
        tenant_id=principal.tenant_id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        reason=reason.strip(),
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    await session.commit()

    return AuditClearResult(
        deleted=deleted,
        message=f"Deleted {deleted} audit {'entry' if deleted == 1 else 'entries'}.",
    )
