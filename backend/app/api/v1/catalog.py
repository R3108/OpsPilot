"""The action catalog and the policy rules, exposed for the UI and for review.

Publishing the catalog is deliberate: operators should be able to see exactly
what OpsPilot is capable of doing to their infrastructure, with the risk tier and
parameter schema of each action, without reading the source.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status
from sqlalchemy import select

from app.api.deps import CurrentPrincipal, DbSession, RequireAdmin
from app.core.errors import NotFoundError, ValidationError
from app.models.enums import AuditAction, RiskTier
from app.models.remediation import PolicyRule
from app.schemas.common import Acknowledgement
from app.schemas.remediation import (
    ActionSpecOut,
    PolicyRuleCreate,
    PolicyRuleOut,
)
from app.services import audit
from app.services.actions import ACTION_REGISTRY, get_action, list_actions, registry_fingerprint
from app.services.policy import TenantPolicy

router = APIRouter(tags=["catalog"])


@router.get("/actions", response_model=list[ActionSpecOut])
async def get_catalog(
    _principal: CurrentPrincipal,
    max_risk: Annotated[RiskTier | None, Query()] = None,
) -> list[ActionSpecOut]:
    return [
        ActionSpecOut.model_validate(spec.to_public_dict())
        for spec in list_actions(max_risk=max_risk)
    ]


@router.get("/actions/fingerprint")
async def catalog_fingerprint(_principal: CurrentPrincipal) -> dict[str, object]:
    """Identity of the current catalog.

    Recorded on every proposal; execution refuses to run against a different
    fingerprint than the one that was approved.
    """
    return {"fingerprint": registry_fingerprint(), "action_count": len(ACTION_REGISTRY)}


@router.get("/actions/{action_key}", response_model=ActionSpecOut)
async def get_action_spec(action_key: str, _principal: CurrentPrincipal) -> ActionSpecOut:
    return ActionSpecOut.model_validate(get_action(action_key).to_public_dict())


# --------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------
@router.get("/policy/effective")
async def effective_policy(principal: CurrentPrincipal, session: DbSession) -> dict[str, object]:
    """The guardrails as they will actually be applied for this tenant."""
    from app.models.tenant import Tenant

    tenant = await session.get(Tenant, principal.tenant_id)
    policy = TenantPolicy.for_tenant(tenant)
    return {
        "remediation_enabled": policy.remediation_enabled,
        "auto_approve_low_risk": policy.auto_approve_low_risk,
        "always_approve_at_or_above": str(policy.always_approve_at_or_above),
        "protected_namespaces": sorted(policy.protected_namespaces),
        "protected_environments": sorted(policy.protected_environments),
        "max_pods_restart": policy.max_pods_restart,
        "max_replica_delta": policy.max_replica_delta,
        "max_actions_per_incident": policy.max_actions_per_incident,
        "max_actions_per_hour": policy.max_actions_per_hour,
        "min_confidence_high_risk": policy.min_confidence_high_risk,
        "min_confidence_critical_risk": policy.min_confidence_critical_risk,
        "min_evidence_high_risk": policy.min_evidence_high_risk,
        "change_freeze_windows": policy.change_freeze_windows,
        "automation_severities": sorted(policy.automation_severities),
    }


@router.get("/policy/rules", response_model=list[PolicyRuleOut])
async def list_rules(principal: CurrentPrincipal, session: DbSession) -> list[PolicyRuleOut]:
    rows = list(
        (
            await session.execute(
                select(PolicyRule)
                .where(PolicyRule.tenant_id == principal.tenant_id)
                .order_by(PolicyRule.priority)
            )
        )
        .scalars()
        .all()
    )
    return [PolicyRuleOut.model_validate(r) for r in rows]


@router.post("/policy/rules", response_model=PolicyRuleOut, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: PolicyRuleCreate, principal: RequireAdmin, session: DbSession
) -> PolicyRuleOut:
    # Reject rules that reference actions that do not exist — a typo in a deny
    # rule is a silently disabled guardrail.
    for key in payload.match.get("action_keys") or []:
        if "*" not in key and "?" not in key and key not in ACTION_REGISTRY:
            raise ValidationError(
                f"Unknown action key '{key}' in rule matcher",
                details={"available": sorted(ACTION_REGISTRY)},
            )

    rule = PolicyRule(
        tenant_id=principal.tenant_id,
        name=payload.name,
        description=payload.description,
        is_enabled=payload.is_enabled,
        priority=payload.priority,
        match=payload.match,
        effect=payload.effect,
        required_role=str(payload.required_role) if payload.required_role else None,
        reason=payload.reason,
        limits=payload.limits,
        active_window=payload.active_window,
    )
    session.add(rule)
    await session.flush()

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.INTEGRATION_UPDATED,
        resource_type="policy_rule",
        resource_id=rule.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Created policy rule '{rule.name}' with effect {rule.effect}",
        after=payload.model_dump(mode="json"),
    )
    return PolicyRuleOut.model_validate(rule)


@router.patch("/policy/rules/{rule_id}", response_model=PolicyRuleOut)
async def update_rule(
    rule_id: uuid.UUID,
    payload: PolicyRuleCreate,
    principal: RequireAdmin,
    session: DbSession,
) -> PolicyRuleOut:
    rule = await session.get(PolicyRule, rule_id)
    if rule is None or rule.tenant_id != principal.tenant_id:
        raise NotFoundError("Policy rule not found")

    before = {
        "effect": rule.effect,
        "is_enabled": rule.is_enabled,
        "match": rule.match,
        "limits": rule.limits,
    }
    rule.name = payload.name
    rule.description = payload.description
    rule.is_enabled = payload.is_enabled
    rule.priority = payload.priority
    rule.match = payload.match
    rule.effect = payload.effect
    rule.required_role = str(payload.required_role) if payload.required_role else None
    rule.reason = payload.reason
    rule.limits = payload.limits
    rule.active_window = payload.active_window

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.INTEGRATION_UPDATED,
        resource_type="policy_rule",
        resource_id=rule.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Updated policy rule '{rule.name}'",
        before=before,
        after=payload.model_dump(mode="json"),
    )
    return PolicyRuleOut.model_validate(rule)


@router.delete("/policy/rules/{rule_id}", response_model=Acknowledgement)
async def delete_rule(
    rule_id: uuid.UUID, principal: RequireAdmin, session: DbSession
) -> Acknowledgement:
    rule = await session.get(PolicyRule, rule_id)
    if rule is None or rule.tenant_id != principal.tenant_id:
        raise NotFoundError("Policy rule not found")

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.INTEGRATION_DELETED,
        resource_type="policy_rule",
        resource_id=rule.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Deleted policy rule '{rule.name}'",
        before={"name": rule.name, "effect": rule.effect, "match": rule.match},
    )
    await session.delete(rule)
    return Acknowledgement(message="Policy rule deleted")
