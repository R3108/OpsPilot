from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from app.models.base import (
    Base,
    JSONColumn,
    TenantScopedMixin,
    TimestampMixin,
    UTCDateTime,
    UUIDPrimaryKeyMixin,
)
from app.models.enums import ApprovalStatus, RemediationStatus, RiskTier

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.tenant import User


class RemediationAction(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A proposed (and possibly executed) change to production.

    The LLM only ever produces ``action_key`` + ``params``. ``action_key`` must
    resolve in the action catalog (:mod:`app.services.actions`) and ``params``
    must validate against that action's Pydantic schema before this row is even
    written. Nothing here is ever passed to a shell.
    """

    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("ix_remediation_incident_status", "incident_id", "status"),
        Index("ix_remediation_tenant_created", "tenant_id", "created_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL"), nullable=True
    )
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("hypotheses.id", ondelete="SET NULL"), nullable=True
    )

    # -- the proposal -----------------------------------------------------
    action_key: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expected_effect: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Ordered list of ids the model cited to justify this action.
    evidence_ids: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # -- risk assessment (deterministic, computed by the policy engine) ----
    risk_tier: Mapped[RiskTier] = mapped_column(
        Enum(RiskTier, native_enum=False, length=16), default=RiskTier.HIGH, nullable=False
    )
    blast_radius: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    is_reversible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rollback_action_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    rollback_params: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    # -- policy -----------------------------------------------------------
    status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus, native_enum=False, length=32),
        default=RemediationStatus.PROPOSED,
        nullable=False,
        index=True,
    )
    policy_decision: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )
    policy_violations: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # -- execution --------------------------------------------------------
    # Guards against double-execution when a worker retries or a graph resumes.
    idempotency_key: Mapped[str | None] = mapped_column(
        String(120), nullable=True, unique=True, index=True
    )
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)

    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    executed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    execution_result: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )
    execution_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Snapshot taken immediately before mutating, so we can always undo.
    pre_state: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="actions", lazy="noload")
    approval: Mapped[Approval | None] = relationship(
        back_populates="action", uselist=False, cascade="all, delete-orphan", lazy="noload"
    )

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            RemediationStatus.SUCCEEDED,
            RemediationStatus.FAILED,
            RemediationStatus.REJECTED,
            RemediationStatus.BLOCKED_BY_POLICY,
            RemediationStatus.SKIPPED,
            RemediationStatus.ROLLED_BACK,
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RemediationAction {self.action_key} {self.status}>"


class Approval(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A human decision gate. The LangGraph run is interrupted until this resolves.

    Created by the ``policy_check`` node, resolved through the approvals API or a
    Slack interactive message. Resolution enqueues the graph resume.
    """

    __tablename__ = "approvals"
    __table_args__ = (
        Index("ix_approvals_tenant_status", "tenant_id", "status"),
        Index("ix_approvals_incident_status", "incident_id", "status"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    action_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[ApprovalStatus] = mapped_column(
        Enum(ApprovalStatus, native_enum=False, length=24),
        default=ApprovalStatus.PENDING,
        nullable=False,
        index=True,
    )
    risk_tier: Mapped[RiskTier] = mapped_column(
        Enum(RiskTier, native_enum=False, length=16), nullable=False
    )
    required_role: Mapped[str] = mapped_column(String(32), nullable=False, default="approver")

    # Everything the approver needs to decide, frozen at request time.
    request_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    context: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decision_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # e.g. {"surface": "slack", "channel": "C123", "message_ts": "..."}
    decision_channel: Mapped[dict[str, Any]] = mapped_column(
        JSONColumn, default=dict, nullable=False
    )

    # Approver may narrow the action (e.g. fewer replicas) — re-validated on resume.
    modified_params: Mapped[dict[str, Any] | None] = mapped_column(JSONColumn, nullable=True)

    action: Mapped[RemediationAction] = relationship(back_populates="approval", lazy="joined")
    incident: Mapped[Incident] = relationship(back_populates="approvals", lazy="noload")
    decided_by: Mapped[User | None] = relationship(lazy="joined")

    @property
    def is_pending(self) -> bool:
        return self.status is ApprovalStatus.PENDING


class PolicyRule(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Tenant-authored deterministic guardrail evaluated before every action.

    Rules are data, not code: a matcher over (action_key, environment, namespace,
    service, risk_tier) plus an effect. They are evaluated in priority order by
    :mod:`app.services.policy`; the first ``deny`` wins and nothing executes.
    """

    __tablename__ = "policy_rules"
    __table_args__ = (Index("ix_policy_rules_tenant_enabled", "tenant_id", "is_enabled"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # {"action_keys": [...], "environments": [...], "namespaces": [...],
    #  "services": [...], "min_risk_tier": "high"}
    match: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    # "deny" | "require_approval" | "allow" | "auto_approve"
    effect: Mapped[str] = mapped_column(String(32), nullable=False, default="require_approval")
    required_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Optional bounds: {"max_replica_delta": 3, "max_pods": 5}
    limits: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    # Cron-ish window when the rule applies, e.g. business hours freeze.
    active_window: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    hit_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_hit_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class ActionExecutionLog(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Append-only record of every attempt to touch infrastructure.

    Separate from AuditLog because it is the operational forensic trail: one row
    per *attempt*, including failures and retries, with timing and raw provider
    response.
    """

    __tablename__ = "action_execution_logs"
    __table_args__ = (Index("ix_action_exec_action_attempt", "action_id", "attempt"),)

    action_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("remediation_actions.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )

    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    action_key: Mapped[str] = mapped_column(String(120), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    succeeded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Who authorised it — user id, or "policy:auto_approve_low_risk".
    authorised_by: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_tier: Mapped[RiskTier] = mapped_column(
        Enum(RiskTier, native_enum=False, length=16), default=RiskTier.LOW, nullable=False
    )
    confidence_at_execution: Mapped[float | None] = mapped_column(Float, nullable=True)
