"""Approval resolution.

Resolving an approval is the single point where a human's decision enters the
automated pipeline, so it does five things in a strict order: authorise the
approver, re-validate any narrowed parameters, record the decision immutably,
update the action, and only then schedule the graph resume.

If the resume enqueue fails, the decision is still durably recorded — the worker
reconciler will pick the incident up rather than losing the approval.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    ApprovalStatus,
    AuditAction,
    IncidentStatus,
    RemediationStatus,
    UserRole,
)
from app.models.incident import Incident, TimelineEntry
from app.models.remediation import Approval, RemediationAction
from app.models.tenant import User
from app.services import audit, events, notifications
from app.services.actions import get_action
from app.services.policy import check_approver

log = get_logger(__name__)


async def get_approval(
    session: AsyncSession, *, tenant_id: uuid.UUID, approval_id: uuid.UUID
) -> Approval:
    approval = await session.get(Approval, approval_id)
    if approval is None or approval.tenant_id != tenant_id:
        raise NotFoundError("Approval not found")
    return approval


async def list_pending(
    session: AsyncSession, *, tenant_id: uuid.UUID, limit: int = 50, offset: int = 0
) -> tuple[list[Approval], int]:
    from sqlalchemy import func

    base = select(Approval).where(
        Approval.tenant_id == tenant_id, Approval.status == ApprovalStatus.PENDING
    )
    total = int(
        (await session.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    )
    rows = list(
        (await session.execute(base.order_by(Approval.requested_at).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return rows, total


async def expire_stale(session: AsyncSession, *, tenant_id: uuid.UUID | None = None) -> int:
    """Mark timed-out approvals expired. Run by the worker's periodic sweep."""
    stmt = select(Approval).where(
        Approval.status == ApprovalStatus.PENDING,
        Approval.expires_at < datetime.now(UTC),
    )
    if tenant_id is not None:
        stmt = stmt.where(Approval.tenant_id == tenant_id)

    expired = list((await session.execute(stmt)).scalars().all())
    for approval in expired:
        approval.status = ApprovalStatus.EXPIRED
        action = await session.get(RemediationAction, approval.action_id)
        if action is not None and action.status is RemediationStatus.AWAITING_APPROVAL:
            action.status = RemediationStatus.SKIPPED
            action.execution_error = "approval_expired"
        await events.emit(
            type=AgentEventType.APPROVAL_RESOLVED,
            incident_id=approval.incident_id,
            tenant_id=approval.tenant_id,
            phase=AgentPhase.AWAIT_APPROVAL,
            title="Approval expired",
            message="No decision was made before the approval window closed.",
            approval_id=str(approval.id),
            status=str(ApprovalStatus.EXPIRED),
        )
    if expired:
        log.info("approvals.expired", count=len(expired))
    return len(expired)


async def resolve(
    session: AsyncSession,
    *,
    approval: Approval,
    decision: str,
    user: User,
    note: str = "",
    modified_params: dict[str, Any] | None = None,
    surface: str = "web",
) -> Approval:
    """Approve or reject. Returns the updated row; the caller schedules the resume."""
    if approval.status is not ApprovalStatus.PENDING:
        raise ConflictError(
            f"This approval is already {approval.status}",
            details={"status": str(approval.status)},
        )
    if approval.expires_at < datetime.now(UTC):
        approval.status = ApprovalStatus.EXPIRED
        raise ConflictError("This approval has expired and must be re-requested")
    if decision not in ("approve", "reject"):
        raise ValidationError("decision must be 'approve' or 'reject'")

    # 1. authorise -- the approver must clear the tier the policy engine set.
    check_approver(
        approver_role=user.role,
        decision_required_role=UserRole(approval.required_role),
        approver_id=user.id,
    )

    action = await session.get(RemediationAction, approval.action_id)
    if action is None:
        raise NotFoundError("The action this approval refers to no longer exists")

    # 2. re-validate narrowed params -- an approver may tighten, never widen.
    if modified_params is not None:
        spec = get_action(action.action_key)
        spec.parse_params(modified_params)  # raises ValidationError if bad
        _reject_widening(action.params or {}, modified_params, action.action_key)
        approval.modified_params = modified_params

    # 3. record the decision
    approved = decision == "approve"
    metrics.inc("opspilot_approvals_decided_total", labels={"decision": decision})
    approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
    approval.decided_at = datetime.now(UTC)
    approval.decided_by_id = user.id
    approval.decision_note = note[:2000]
    approval.decision_channel = {**(approval.decision_channel or {}), "resolved_via": surface}

    # 4. update the action
    action.status = RemediationStatus.APPROVED if approved else RemediationStatus.REJECTED
    if approved and modified_params is not None:
        action.params = modified_params

    incident = await session.get(Incident, approval.incident_id)
    if incident is not None:
        incident.status = IncidentStatus.REMEDIATING if approved else IncidentStatus.INVESTIGATING

    session.add(
        TimelineEntry(
            tenant_id=approval.tenant_id,
            incident_id=approval.incident_id,
            occurred_at=datetime.now(UTC),
            actor_type="user",
            actor_id=str(user.id),
            actor_label=user.full_name or user.email,
            phase=AgentPhase.AWAIT_APPROVAL,
            title=f"{action.title} {'approved' if approved else 'rejected'}",
            body=note or ("Approved for execution." if approved else "Rejected."),
            metadata_json={
                "approval_id": str(approval.id),
                "action_key": action.action_key,
                "risk_tier": str(approval.risk_tier),
                "surface": surface,
                "modified_params": modified_params,
            },
        )
    )
    await audit.record(
        session,
        tenant_id=approval.tenant_id,
        action=(AuditAction.REMEDIATION_APPROVED if approved else AuditAction.REMEDIATION_REJECTED),
        resource_type="approval",
        resource_id=approval.id,
        actor_type="user",
        actor_id=user.id,
        actor_label=user.full_name or user.email,
        incident_id=approval.incident_id,
        summary=(
            f"{'Approved' if approved else 'Rejected'} {action.action_key} "
            f"({approval.risk_tier} risk) via {surface}"
        ),
        before={"status": str(ApprovalStatus.PENDING)},
        after={"status": str(approval.status), "note": note[:500]},
        context={
            "action_key": action.action_key,
            "params": action.params,
            "modified_params": modified_params,
            "required_role": approval.required_role,
            "approver_role": str(user.role),
        },
    )
    await events.emit(
        type=AgentEventType.APPROVAL_RESOLVED,
        incident_id=approval.incident_id,
        tenant_id=approval.tenant_id,
        phase=AgentPhase.AWAIT_APPROVAL,
        title=f"{action.title} {'approved' if approved else 'rejected'}",
        message=note[:400],
        approval_id=str(approval.id),
        action_id=str(action.id),
        status=str(approval.status),
        decided_by=user.full_name or user.email,
    )
    await notifications.notify_approval_resolved(
        session, approval=approval, decided_by=user.full_name or user.email
    )

    log.info(
        "approval.resolved",
        approval_id=str(approval.id),
        decision=decision,
        action_key=action.action_key,
        user_id=str(user.id),
        surface=surface,
    )
    return approval


def _reject_widening(original: dict[str, Any], modified: dict[str, Any], action_key: str) -> None:
    """Refuse edits that make an approved action *bigger* than what was reviewed.

    An approver reviewed a specific blast radius. Narrowing it (fewer replicas,
    fewer terminations, no drain) is fine; widening it means the thing being
    executed is not the thing that was approved.
    """
    numeric_caps = {
        "replicas": "increase the replica count",
        "max_terminations": "terminate more connections",
        "connection_limit": "raise the connection limit",
    }
    for field, description in numeric_caps.items():
        before, after = original.get(field), modified.get(field)
        if isinstance(before, (int, float)) and isinstance(after, (int, float)) and after > before:
            raise ValidationError(
                f"An approver may not {description} beyond the proposed value "
                f"({before} → {after}). Reject this action and let the agent propose "
                f"a new one instead.",
                details={"action_key": action_key, "field": field},
            )

    if original.get("drain") is False and modified.get("drain") is True:
        raise ValidationError(
            "Enabling drain widens the blast radius of an approved cordon; "
            "reject and re-propose instead.",
            details={"action_key": action_key, "field": "drain"},
        )

    # Retargeting is not narrowing: it is a different action entirely.
    for field in ("namespace", "deployment", "pod_name", "node_name", "database", "pid", "repo"):
        if field in original and field in modified and original[field] != modified[field]:
            raise ValidationError(
                f"An approver may not change '{field}'; that is a different action. "
                f"Reject this one and let the agent propose the right target.",
                details={"action_key": action_key, "field": field},
            )


async def schedule_resume(*, incident_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    """Ask a worker to resume the paused graph, or resume inline if there is none."""
    from app.workers.queue import enqueue_resume

    await enqueue_resume(incident_id=incident_id, tenant_id=tenant_id)


async def outstanding_for_incident(session: AsyncSession, incident_id: uuid.UUID) -> list[Approval]:
    return list(
        (
            await session.execute(
                select(Approval).where(
                    Approval.incident_id == incident_id,
                    Approval.status == ApprovalStatus.PENDING,
                )
            )
        )
        .scalars()
        .all()
    )


def resume_payload(approvals: list[Approval]) -> dict[str, Any]:
    """Build the value handed back to the graph's ``interrupt()``."""
    approved = [a for a in approvals if a.status is ApprovalStatus.APPROVED]
    rejected = [a for a in approvals if a.status is ApprovalStatus.REJECTED]
    expired = [a for a in approvals if a.status is ApprovalStatus.EXPIRED]

    if approved and not rejected:
        status = "approved"
    elif approved and rejected:
        status = "partially_approved"
    elif rejected:
        status = "rejected"
    else:
        status = "expired"

    return {
        "status": status,
        "approved_action_ids": [str(a.action_id) for a in approved],
        "rejected_action_ids": [str(a.action_id) for a in rejected],
        "expired_action_ids": [str(a.action_id) for a in expired],
        "decided_at": datetime.now(UTC).isoformat(),
        "notes": [a.decision_note for a in approvals if a.decision_note],
    }
