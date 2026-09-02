from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

from app.models.enums import (
    ApprovalStatus,
    RemediationStatus,
    RiskTier,
    UserRole,
)
from app.schemas.common import ORMModel


class ActionSpecOut(BaseModel):
    """Public description of a catalog entry, for the UI and for prompt building."""

    key: str
    title: str
    description: str
    provider: str
    risk_tier: RiskTier
    is_reversible: bool
    minimum_role: UserRole
    requires_write_integration: bool
    params_schema: dict[str, Any]
    examples: list[dict[str, Any]] = Field(default_factory=list)


class PolicyViolationOut(BaseModel):
    rule: str
    message: str
    severity: str = "deny"
    context: dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionOut(BaseModel):
    allowed: bool
    requires_approval: bool
    risk_tier: RiskTier
    required_role: UserRole
    violations: list[PolicyViolationOut] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    reason: str = ""
    evaluated_at: datetime


class RemediationActionOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    action_key: str
    title: str
    params: dict[str, Any]
    rationale: str
    expected_effect: str
    evidence_ids: list[Any]
    sequence: int
    risk_tier: RiskTier
    blast_radius: dict[str, Any]
    is_reversible: bool
    status: RemediationStatus
    policy_decision: dict[str, Any]
    policy_violations: list[Any]
    requires_approval: bool
    attempt: int
    executed_at: datetime | None = None
    execution_result: dict[str, Any]
    execution_error: str | None = None
    duration_ms: int | None = None
    created_at: datetime


class ApprovalOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    action_id: uuid.UUID
    status: ApprovalStatus
    risk_tier: RiskTier
    required_role: str
    request_summary: str
    context: dict[str, Any]
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    decided_by_id: uuid.UUID | None = None
    decision_note: str
    modified_params: dict[str, Any] | None = None
    created_at: datetime


class ApprovalWithAction(ApprovalOut):
    action: RemediationActionOut
    incident_reference: str = ""
    incident_title: str = ""


class ApprovalDecision(BaseModel):
    decision: Annotated[str, Field(pattern="^(approve|reject)$")]
    note: Annotated[str, Field(max_length=2000)] = ""
    # An approver may tighten (never widen) the action before it runs; the
    # narrowed params are re-validated against the catalog and re-run through
    # the policy engine before execution.
    modified_params: dict[str, Any] | None = None


class ManualActionRequest(BaseModel):
    """A human proposing an action directly, bypassing the LLM but not the policy engine."""

    action_key: str
    params: dict[str, Any] = Field(default_factory=dict)
    rationale: Annotated[str, Field(min_length=1, max_length=4000)]
    dry_run: bool = False


class PolicyRuleCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: str = ""
    is_enabled: bool = True
    priority: Annotated[int, Field(ge=0, le=10_000)] = 100
    match: dict[str, Any] = Field(default_factory=dict)
    effect: Annotated[str, Field(pattern="^(deny|require_approval|allow|auto_approve)$")] = (
        "require_approval"
    )
    required_role: UserRole | None = None
    reason: str = ""
    limits: dict[str, Any] = Field(default_factory=dict)
    active_window: dict[str, Any] = Field(default_factory=dict)


class PolicyRuleOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str
    is_enabled: bool
    priority: int
    match: dict[str, Any]
    effect: str
    required_role: str | None = None
    reason: str
    limits: dict[str, Any]
    active_window: dict[str, Any]
    hit_count: int
    last_hit_at: datetime | None = None
    created_at: datetime


class ExecutionLogOut(ORMModel):
    id: uuid.UUID
    action_id: uuid.UUID
    attempt: int
    action_key: str
    provider: str
    succeeded: bool
    response: dict[str, Any]
    error: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None
    authorised_by: str
    dry_run: bool
    risk_tier: RiskTier
