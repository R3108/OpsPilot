"""Approval queue and decisions — the human-in-the-loop surface."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import CurrentPrincipal, DbSession, RequireApprover, rate_limit
from app.core.errors import NotFoundError
from app.models.enums import ApprovalStatus, RemediationStatus
from app.models.incident import Incident
from app.models.remediation import Approval, RemediationAction
from app.schemas.common import Page
from app.schemas.remediation import (
    ApprovalDecision,
    ApprovalOut,
    ApprovalWithAction,
    RemediationActionOut,
)
from app.services import approvals as approval_service

router = APIRouter(prefix="/approvals", tags=["approvals"])


async def _hydrate(session, approval: Approval) -> ApprovalWithAction:  # noqa: ANN001
    action = await session.get(RemediationAction, approval.action_id)
    incident = await session.get(Incident, approval.incident_id)
    payload = ApprovalWithAction.model_validate(
        {
            **ApprovalOut.model_validate(approval).model_dump(),
            "action": RemediationActionOut.model_validate(action).model_dump(),
        }
    )
    if incident is not None:
        payload.incident_reference = incident.reference
        payload.incident_title = incident.title
    return payload


@router.get("", response_model=Page[ApprovalWithAction])
async def list_approvals(
    principal: CurrentPrincipal,
    session: DbSession,
    status_filter: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
    incident_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ApprovalWithAction]:
    from sqlalchemy import func

    base = select(Approval).where(Approval.tenant_id == principal.tenant_id)
    if status_filter is not None:
        base = base.where(Approval.status == status_filter)
    if incident_id is not None:
        base = base.where(Approval.incident_id == incident_id)

    total = int(
        (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    )
    rows = list(
        (
            await session.execute(
                base.order_by(
                    # Pending first, then most recently requested.
                    (Approval.status != ApprovalStatus.PENDING).asc(),
                    Approval.requested_at.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page(
        items=[await _hydrate(session, r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/pending/count")
async def pending_count(principal: CurrentPrincipal, session: DbSession) -> dict[str, int]:
    from sqlalchemy import func

    count = int(
        (
            await session.execute(
                select(func.count(Approval.id)).where(
                    Approval.tenant_id == principal.tenant_id,
                    Approval.status == ApprovalStatus.PENDING,
                )
            )
        ).scalar_one()
    )
    return {"pending": count}


@router.get("/{approval_id}", response_model=ApprovalWithAction)
async def get_approval(
    approval_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> ApprovalWithAction:
    approval = await approval_service.get_approval(
        session, tenant_id=principal.tenant_id, approval_id=approval_id
    )
    return await _hydrate(session, approval)


@router.post(
    "/{approval_id}/decision",
    response_model=ApprovalWithAction,
    dependencies=[rate_limit(limit=60, window_seconds=60, scope="approval_decision")],
)
async def decide(
    approval_id: uuid.UUID,
    payload: ApprovalDecision,
    principal: RequireApprover,
    session: DbSession,
) -> ApprovalWithAction:
    """Approve or reject a pending action.

    On the last outstanding approval for an incident, the paused LangGraph run is
    scheduled to resume. The decision itself is committed first, so a queue
    failure cannot lose it — the worker's reconciler will pick it up.
    """
    approval = await approval_service.get_approval(
        session, tenant_id=principal.tenant_id, approval_id=approval_id
    )
    user = principal.require_user()

    updated = await approval_service.resolve(
        session,
        approval=approval,
        decision=payload.decision,
        user=user,
        note=payload.note,
        modified_params=payload.modified_params,
        surface="web",
    )
    hydrated = await _hydrate(session, updated)

    still_pending = await approval_service.outstanding_for_incident(session, approval.incident_id)
    await session.commit()

    if not still_pending:
        await approval_service.schedule_resume(
            incident_id=approval.incident_id, tenant_id=principal.tenant_id
        )
    return hydrated


@router.post("/{approval_id}/cancel", response_model=ApprovalOut)
async def cancel(
    approval_id: uuid.UUID, principal: RequireApprover, session: DbSession
) -> ApprovalOut:
    """Withdraw a pending request without approving or rejecting it."""
    approval = await approval_service.get_approval(
        session, tenant_id=principal.tenant_id, approval_id=approval_id
    )
    if approval.status is not ApprovalStatus.PENDING:
        raise NotFoundError("Only a pending approval can be cancelled")

    approval.status = ApprovalStatus.CANCELLED
    action = await session.get(RemediationAction, approval.action_id)
    if action is not None:
        action.status = RemediationStatus.SKIPPED
    return ApprovalOut.model_validate(approval)
