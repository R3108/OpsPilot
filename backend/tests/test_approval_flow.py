"""The human-in-the-loop gate: who may approve, what they may change, and what
happens to an action once they decide."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, PermissionDeniedError, ValidationError
from app.models.enums import (
    ApprovalStatus,
    RemediationStatus,
    RiskTier,
)
from app.models.incident import Incident
from app.models.remediation import Approval, RemediationAction
from app.models.tenant import Tenant, User
from app.services import approvals as approval_service


async def make_action_and_approval(
    session: AsyncSession,
    tenant: Tenant,
    incident: Incident,
    *,
    action_key: str = "k8s.scale_deployment",
    params: dict | None = None,
    required_role: str = "approver",
    risk_tier: RiskTier = RiskTier.HIGH,
    expires_in_minutes: int = 60,
) -> tuple[RemediationAction, Approval]:
    action = RemediationAction(
        tenant_id=tenant.id,
        incident_id=incident.id,
        action_key=action_key,
        title="Scale checkout-api",
        params=params or {"namespace": "payments", "deployment": "checkout-api", "replicas": 8},
        rationale="Capacity saturation",
        risk_tier=risk_tier,
        status=RemediationStatus.AWAITING_APPROVAL,
        requires_approval=True,
        evidence_ids=[],
    )
    session.add(action)
    await session.flush()

    approval = Approval(
        tenant_id=tenant.id,
        incident_id=incident.id,
        action_id=action.id,
        status=ApprovalStatus.PENDING,
        risk_tier=risk_tier,
        required_role=required_role,
        request_summary="Scale from 6 to 8 replicas",
        context={},
        requested_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
    )
    session.add(approval)
    await session.flush()
    return action, approval


async def test_approval_marks_action_approved(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    action, approval = await make_action_and_approval(session, tenant, incident)

    await approval_service.resolve(
        session, approval=approval, decision="approve", user=users["approver"], note="looks right"
    )

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by_id == users["approver"].id
    assert approval.decision_note == "looks right"
    assert action.status is RemediationStatus.APPROVED


async def test_rejection_marks_action_rejected(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    action, approval = await make_action_and_approval(session, tenant, incident)

    await approval_service.resolve(
        session, approval=approval, decision="reject", user=users["approver"], note="too risky"
    )

    assert approval.status is ApprovalStatus.REJECTED
    assert action.status is RemediationStatus.REJECTED


async def test_responder_cannot_approve_a_high_risk_action(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(session, tenant, incident)

    with pytest.raises(PermissionDeniedError) as exc:
        await approval_service.resolve(
            session, approval=approval, decision="approve", user=users["responder"]
        )
    assert exc.value.details["required_role"] == "approver"
    assert approval.status is ApprovalStatus.PENDING


async def test_critical_action_needs_an_admin(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(
        session, tenant, incident, required_role="admin", risk_tier=RiskTier.CRITICAL
    )

    with pytest.raises(PermissionDeniedError):
        await approval_service.resolve(
            session, approval=approval, decision="approve", user=users["approver"]
        )

    await approval_service.resolve(
        session, approval=approval, decision="approve", user=users["admin"]
    )
    assert approval.status is ApprovalStatus.APPROVED


async def test_an_approval_can_only_be_decided_once(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(session, tenant, incident)
    await approval_service.resolve(
        session, approval=approval, decision="approve", user=users["approver"]
    )

    with pytest.raises(ConflictError):
        await approval_service.resolve(
            session, approval=approval, decision="reject", user=users["approver"]
        )


async def test_expired_approval_cannot_be_decided(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(
        session, tenant, incident, expires_in_minutes=-1
    )

    with pytest.raises(ConflictError):
        await approval_service.resolve(
            session, approval=approval, decision="approve", user=users["approver"]
        )
    assert approval.status is ApprovalStatus.EXPIRED


# --------------------------------------------------------------------------
# an approver may narrow an action, never widen it
# --------------------------------------------------------------------------
async def test_approver_may_narrow_the_action(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    action, approval = await make_action_and_approval(session, tenant, incident)

    await approval_service.resolve(
        session,
        approval=approval,
        decision="approve",
        user=users["approver"],
        modified_params={"namespace": "payments", "deployment": "checkout-api", "replicas": 7},
    )
    assert action.params["replicas"] == 7


async def test_approver_may_not_widen_the_action(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    """Approving 8 replicas must not become approving 40."""
    _action, approval = await make_action_and_approval(session, tenant, incident)

    with pytest.raises(ValidationError) as exc:
        await approval_service.resolve(
            session,
            approval=approval,
            decision="approve",
            user=users["approver"],
            modified_params={
                "namespace": "payments",
                "deployment": "checkout-api",
                "replicas": 40,
            },
        )
    assert "may not" in exc.value.message
    assert approval.status is ApprovalStatus.PENDING


async def test_approver_may_not_retarget_the_action(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    """Changing the target is a different action, not an amendment."""
    _action, approval = await make_action_and_approval(session, tenant, incident)

    with pytest.raises(ValidationError) as exc:
        await approval_service.resolve(
            session,
            approval=approval,
            decision="approve",
            user=users["approver"],
            modified_params={
                "namespace": "payments",
                "deployment": "a-completely-different-service",
                "replicas": 8,
            },
        )
    assert "different action" in exc.value.message


async def test_approver_may_not_enable_drain(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(
        session,
        tenant,
        incident,
        action_key="k8s.cordon_node",
        params={"node_name": "ip-10-0-6-77", "drain": False},
    )

    with pytest.raises(ValidationError):
        await approval_service.resolve(
            session,
            approval=approval,
            decision="approve",
            user=users["approver"],
            modified_params={"node_name": "ip-10-0-6-77", "drain": True},
        )


async def test_modified_params_must_still_validate(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(session, tenant, incident)

    with pytest.raises(ValidationError):
        await approval_service.resolve(
            session,
            approval=approval,
            decision="approve",
            user=users["approver"],
            modified_params={"namespace": "payments; rm -rf /", "deployment": "x", "replicas": 1},
        )


# --------------------------------------------------------------------------
async def test_stale_approvals_expire(
    session: AsyncSession, tenant: Tenant, incident: Incident
) -> None:
    action, approval = await make_action_and_approval(
        session, tenant, incident, expires_in_minutes=-5
    )

    count = await approval_service.expire_stale(session, tenant_id=tenant.id)
    assert count == 1
    assert approval.status is ApprovalStatus.EXPIRED
    assert action.status is RemediationStatus.SKIPPED


async def test_resume_payload_reflects_the_decisions(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _a1, approval1 = await make_action_and_approval(session, tenant, incident)
    _a2, approval2 = await make_action_and_approval(
        session,
        tenant,
        incident,
        params={"namespace": "search", "deployment": "search-api", "replicas": 4},
    )

    await approval_service.resolve(
        session, approval=approval1, decision="approve", user=users["approver"]
    )
    await approval_service.resolve(
        session, approval=approval2, decision="reject", user=users["approver"]
    )

    payload = approval_service.resume_payload([approval1, approval2])
    assert payload["status"] == "partially_approved"
    assert len(payload["approved_action_ids"]) == 1
    assert len(payload["rejected_action_ids"]) == 1


async def test_outstanding_approvals_are_tracked(
    session: AsyncSession, tenant: Tenant, incident: Incident, users: dict[str, User]
) -> None:
    _action, approval = await make_action_and_approval(session, tenant, incident)
    assert len(await approval_service.outstanding_for_incident(session, incident.id)) == 1

    await approval_service.resolve(
        session, approval=approval, decision="approve", user=users["approver"]
    )
    assert await approval_service.outstanding_for_incident(session, incident.id) == []


async def test_approval_is_scoped_to_its_tenant(
    session: AsyncSession, tenant: Tenant, incident: Incident
) -> None:
    _action, approval = await make_action_and_approval(session, tenant, incident)

    from app.core.errors import NotFoundError

    with pytest.raises(NotFoundError):
        await approval_service.get_approval(
            session, tenant_id=uuid.uuid4(), approval_id=approval.id
        )
