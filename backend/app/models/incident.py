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
    UniqueConstraint,
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
from app.models.enums import (
    AgentPhase,
    EvidenceKind,
    EvidenceRelevance,
    IncidentSeverity,
    IncidentSource,
    IncidentStatus,
    InvestigatorKind,
    VerificationOutcome,
)

if TYPE_CHECKING:
    from app.models.remediation import Approval, RemediationAction
    from app.models.tenant import Tenant, User


class Incident(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """The durable spine of the product.

    Every agent run, evidence item, hypothesis, action and approval hangs off an
    incident. The LangGraph thread id is ``incident:{id}`` so a run can always be
    resumed from its checkpoint after a crash or a human approval.
    """

    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "reference", name="uq_incidents_tenant_reference"),
        UniqueConstraint("tenant_id", "dedupe_key", name="uq_incidents_tenant_dedupe_key"),
        Index("ix_incidents_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_incidents_tenant_severity", "tenant_id", "severity"),
        Index("ix_incidents_tenant_service", "tenant_id", "service"),
    )

    # human-facing id, e.g. INC-1042
    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, native_enum=False, length=40),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, native_enum=False, length=16),
        default=IncidentSeverity.SEV3,
        nullable=False,
    )
    severity_rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    source: Mapped[IncidentSource] = mapped_column(
        Enum(IncidentSource, native_enum=False, length=32),
        default=IncidentSource.MANUAL,
        nullable=False,
    )
    # Provider-side identity, used together with dedupe_key to collapse alert storms.
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(255), nullable=True)

    service: Mapped[str | None] = mapped_column(String(200), nullable=True)
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="production")
    cluster: Mapped[str | None] = mapped_column(String(120), nullable=True)
    namespace: Mapped[str | None] = mapped_column(String(120), nullable=True)

    labels: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    mitigated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Denormalised snapshot of the winning hypothesis so incident lists stay cheap.
    root_cause_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    auto_investigate: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    investigation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="incidents", lazy="noload")
    assignee: Mapped[User | None] = relationship(lazy="noload")

    timeline: Mapped[list[TimelineEntry]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="TimelineEntry.occurred_at",
        lazy="noload",
    )
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    hypotheses: Mapped[list[Hypothesis]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="Hypothesis.rank",
        lazy="noload",
    )
    agent_runs: Mapped[list[AgentRun]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    actions: Mapped[list[RemediationAction]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    approvals: Mapped[list[Approval]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    postmortem: Mapped[Postmortem | None] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="noload",
    )

    @property
    def thread_id(self) -> str:
        """LangGraph checkpoint thread id. Stable for the life of the incident."""
        return f"incident:{self.id}"

    @property
    def time_to_detect_seconds(self) -> float | None:
        return (
            None
            if not self.acknowledged_at
            else (self.acknowledged_at - self.detected_at).total_seconds()
        )

    @property
    def time_to_mitigate_seconds(self) -> float | None:
        return (
            None
            if not self.mitigated_at
            else (self.mitigated_at - self.detected_at).total_seconds()
        )

    @property
    def time_to_resolve_seconds(self) -> float | None:
        return (
            None if not self.resolved_at else (self.resolved_at - self.detected_at).total_seconds()
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.reference} {self.severity} {self.status}>"


class TimelineEntry(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Append-only, human-readable incident narrative.

    Written by both agents and humans; it is what the postmortem is built from
    and what the UI renders as the incident timeline.
    """

    __tablename__ = "timeline_entries"
    __table_args__ = (Index("ix_timeline_incident_occurred", "incident_id", "occurred_at"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    # "agent" | "user" | "system" | "integration"
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False, default="system")
    actor_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(200), nullable=False, default="OpsPilot")

    phase: Mapped[AgentPhase | None] = mapped_column(
        Enum(AgentPhase, native_enum=False, length=40), nullable=True
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="timeline", lazy="noload")


class Evidence(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A single fact an investigator retrieved from a real system.

    Evidence is *never* generated by the LLM. It is produced by typed integration
    tools; the model may only cite it by ``id``. That is what makes a postmortem
    verifiable — every claim resolves back to a row here with its raw payload.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_incident_kind", "incident_id", "kind"),
        Index("ix_evidence_incident_relevance", "incident_id", "relevance"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL"), nullable=True
    )

    kind: Mapped[EvidenceKind] = mapped_column(
        Enum(EvidenceKind, native_enum=False, length=40), nullable=False
    )
    investigator: Mapped[InvestigatorKind | None] = mapped_column(
        Enum(InvestigatorKind, native_enum=False, length=32), nullable=True
    )

    # Where it came from, precisely enough to re-fetch it.
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    relevance: Mapped[EvidenceRelevance] = mapped_column(
        Enum(EvidenceRelevance, native_enum=False, length=16),
        default=EvidenceRelevance.MEDIUM,
        nullable=False,
    )
    # 0..1, how strongly this supports *some* hypothesis. Set during correlation.
    weight: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="evidence", lazy="noload")

    @property
    def citation(self) -> str:
        """Short handle the model uses to cite this row, e.g. ``E:3f2a``."""
        return f"E:{str(self.id)[:8]}"


class Hypothesis(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A candidate root cause, ranked, with its supporting/contradicting evidence."""

    __tablename__ = "hypotheses"
    __table_args__ = (Index("ix_hypotheses_incident_rank", "incident_id", "rank"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(400), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(String(80), nullable=True)

    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    rank: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_selected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    supporting_evidence_ids: Mapped[list[Any]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    contradicting_evidence_ids: Mapped[list[Any]] = mapped_column(
        JSONColumn, default=list, nullable=False
    )
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # What would confirm or kill this hypothesis if we looked?
    disconfirming_test: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="hypotheses", lazy="noload")


class AgentRun(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """One execution of the LangGraph investigation for an incident."""

    __tablename__ = "agent_runs"
    __table_args__ = (Index("ix_agent_runs_incident_started", "incident_id", "created_at"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )

    thread_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    phase: Mapped[AgentPhase] = mapped_column(
        Enum(AgentPhase, native_enum=False, length=40),
        default=AgentPhase.TRIAGE,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")

    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # LangSmith run id/url so an operator can jump straight to the trace.
    trace_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    trace_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    # Cost/usage accounting, aggregated across every LLM call in the run.
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    plan: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="agent_runs", lazy="noload")
    steps: Mapped[list[AgentStep]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="AgentStep.sequence",
        lazy="noload",
    )

    @property
    def duration_seconds(self) -> float | None:
        return (
            None if not self.finished_at else (self.finished_at - self.started_at).total_seconds()
        )


class AgentStep(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """One node/tool execution inside a run. Powers the live agent console."""

    __tablename__ = "agent_steps"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_agent_steps_run_sequence"),
        Index("ix_agent_steps_run_sequence", "run_id", "sequence"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )

    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[AgentPhase] = mapped_column(
        Enum(AgentPhase, native_enum=False, length=40), nullable=False
    )
    investigator: Mapped[InvestigatorKind | None] = mapped_column(
        Enum(InvestigatorKind, native_enum=False, length=32), nullable=True
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # "node" | "tool" | "llm"
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="node")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")

    input_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    output_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    run: Mapped[AgentRun] = relationship(back_populates="steps", lazy="noload")


class Verification(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """Post-remediation health check. Deterministic: metric thresholds, not vibes."""

    __tablename__ = "verifications"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    action_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("remediation_actions.id", ondelete="SET NULL"), nullable=True
    )

    attempt: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    outcome: Mapped[VerificationOutcome] = mapped_column(
        Enum(VerificationOutcome, native_enum=False, length=32), nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # [{check, expected, observed, passed}]
    checks: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class Postmortem(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    __tablename__ = "postmortems"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detection: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolution: Mapped[str] = mapped_column(Text, nullable=False, default="")
    lessons_learned: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # [{when, what, source}] rendered from TimelineEntry
    timeline_markdown: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # [{title, owner, priority, rationale}]
    action_items: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)
    # Evidence ids cited anywhere in the document; every claim must resolve here.
    evidence_ids: Mapped[list[Any]] = mapped_column(JSONColumn, default=list, nullable=False)

    metrics: Mapped[dict[str, Any]] = mapped_column(JSONColumn, default=dict, nullable=False)

    markdown: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_published: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    generated_by_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped[Incident] = relationship(back_populates="postmortem", lazy="noload")
