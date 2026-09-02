from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

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
from app.schemas.common import ORMModel


# ---------------------------------------------------------------- ingestion
class IncidentCreate(BaseModel):
    title: Annotated[str, Field(min_length=3, max_length=500)]
    description: str = ""
    severity: IncidentSeverity | None = None
    source: IncidentSource = IncidentSource.MANUAL
    source_event_id: str | None = None
    dedupe_key: str | None = None
    service: str | None = None
    environment: str = "production"
    cluster: str | None = None
    namespace: str | None = None
    labels: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime | None = None
    auto_investigate: bool = True


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    service: str | None = None
    assignee_id: uuid.UUID | None = None
    labels: dict[str, Any] | None = None


class IncidentComment(BaseModel):
    body: Annotated[str, Field(min_length=1, max_length=10_000)]


# ---------------------------------------------------------------- evidence
class EvidenceOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    kind: EvidenceKind
    investigator: InvestigatorKind | None = None
    source: str
    source_ref: str | None = None
    source_url: str | None = None
    summary: str
    detail: str
    raw: dict[str, Any]
    relevance: EvidenceRelevance
    weight: float
    observed_at: datetime | None = None
    collected_at: datetime
    citation: str = ""


class HypothesisOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    statement: str
    category: str | None = None
    confidence: float
    rank: int
    is_selected: bool
    supporting_evidence_ids: list[Any]
    contradicting_evidence_ids: list[Any]
    reasoning: str
    disconfirming_test: str | None = None
    created_at: datetime


# ---------------------------------------------------------------- timeline
class TimelineEntryOut(ORMModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_type: str
    actor_label: str
    phase: AgentPhase | None = None
    title: str
    body: str
    metadata_json: dict[str, Any] = Field(default_factory=dict, alias="metadata_json")


# ---------------------------------------------------------------- agent runs
class AgentStepOut(ORMModel):
    id: uuid.UUID
    sequence: int
    phase: AgentPhase
    investigator: InvestigatorKind | None = None
    name: str
    kind: str
    status: str
    input_summary: str
    output_summary: str
    payload: dict[str, Any]
    error: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int | None = None


class AgentRunOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    thread_id: str
    attempt: int
    phase: AgentPhase
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    error: str | None = None
    trace_url: str | None = None
    prompt_tokens: int
    completion_tokens: int
    tool_call_count: int
    cost_usd: float
    plan: dict[str, Any]
    duration_seconds: float | None = None


class AgentRunDetail(AgentRunOut):
    steps: list[AgentStepOut] = Field(default_factory=list)


class VerificationOut(ORMModel):
    id: uuid.UUID
    attempt: int
    outcome: VerificationOutcome
    summary: str
    checks: list[Any]
    observed_at: datetime


# ---------------------------------------------------------------- incident
class IncidentSummary(ORMModel):
    id: uuid.UUID
    reference: str
    title: str
    status: IncidentStatus
    severity: IncidentSeverity
    source: IncidentSource
    service: str | None = None
    environment: str
    detected_at: datetime
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    root_cause_summary: str | None = None
    root_cause_confidence: float | None = None
    assignee_id: uuid.UUID | None = None
    open_approval_count: int = 0


class IncidentDetail(IncidentSummary):
    description: str
    severity_rationale: str
    severity_confidence: float
    cluster: str | None = None
    namespace: str | None = None
    labels: dict[str, Any]
    acknowledged_at: datetime | None = None
    mitigated_at: datetime | None = None
    closed_at: datetime | None = None
    auto_investigate: bool
    investigation_count: int
    time_to_detect_seconds: float | None = None
    time_to_mitigate_seconds: float | None = None
    time_to_resolve_seconds: float | None = None

    timeline: list[TimelineEntryOut] = Field(default_factory=list)
    evidence: list[EvidenceOut] = Field(default_factory=list)
    hypotheses: list[HypothesisOut] = Field(default_factory=list)
    runs: list[AgentRunOut] = Field(default_factory=list)
    verifications: list[VerificationOut] = Field(default_factory=list)


class IncidentFilters(BaseModel):
    status: list[IncidentStatus] | None = None
    severity: list[IncidentSeverity] | None = None
    source: list[IncidentSource] | None = None
    service: str | None = None
    environment: str | None = None
    assignee_id: uuid.UUID | None = None
    query: str | None = None
    since: datetime | None = None
    until: datetime | None = None


# ---------------------------------------------------------------- postmortem
class ActionItem(BaseModel):
    title: str
    owner: str | None = None
    priority: str = "medium"
    rationale: str = ""


class PostmortemOut(ORMModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    summary: str
    impact: str
    root_cause: str
    detection: str
    resolution: str
    lessons_learned: str
    timeline_markdown: str
    action_items: list[Any]
    evidence_ids: list[Any]
    metrics: dict[str, Any]
    markdown: str
    is_published: bool
    published_at: datetime | None = None
    created_at: datetime


class PostmortemUpdate(BaseModel):
    title: str | None = None
    summary: str | None = None
    impact: str | None = None
    root_cause: str | None = None
    detection: str | None = None
    resolution: str | None = None
    lessons_learned: str | None = None
    action_items: list[ActionItem] | None = None
    is_published: bool | None = None
