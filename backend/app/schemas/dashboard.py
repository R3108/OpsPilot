from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import IncidentSeverity, IncidentStatus


class CountByKey(BaseModel):
    key: str
    label: str
    count: int


class TimeBucket(BaseModel):
    bucket: datetime
    count: int
    sev1: int = 0
    sev2: int = 0


class MttrStats(BaseModel):
    """All values in seconds; ``None`` when there is not enough data yet."""

    mean_time_to_acknowledge: float | None = None
    mean_time_to_mitigate: float | None = None
    mean_time_to_resolve: float | None = None
    p50_time_to_resolve: float | None = None
    p90_time_to_resolve: float | None = None
    sample_size: int = 0


class AgentStats(BaseModel):
    runs_total: int = 0
    runs_succeeded: int = 0
    runs_failed: int = 0
    mean_run_seconds: float | None = None
    total_cost_usd: float = 0.0
    total_tool_calls: int = 0
    # How often the top-ranked hypothesis was the one a human ultimately kept.
    hypothesis_precision: float | None = None


class RemediationStats(BaseModel):
    proposed: int = 0
    auto_approved: int = 0
    approved: int = 0
    rejected: int = 0
    blocked_by_policy: int = 0
    executed: int = 0
    succeeded: int = 0
    failed: int = 0
    mean_approval_latency_seconds: float | None = None
    recovery_rate: float | None = None


class DashboardOverview(BaseModel):
    window_days: int
    generated_at: datetime

    open_incidents: int
    active_investigations: int
    pending_approvals: int
    incidents_in_window: int

    by_status: list[CountByKey] = Field(default_factory=list)
    by_severity: list[CountByKey] = Field(default_factory=list)
    by_source: list[CountByKey] = Field(default_factory=list)
    by_service: list[CountByKey] = Field(default_factory=list)
    volume: list[TimeBucket] = Field(default_factory=list)

    mttr: MttrStats = Field(default_factory=MttrStats)
    agents: AgentStats = Field(default_factory=AgentStats)
    remediation: RemediationStats = Field(default_factory=RemediationStats)


class IncidentTrendPoint(BaseModel):
    date: datetime
    opened: int
    resolved: int
    auto_remediated: int


class ServiceHealthRow(BaseModel):
    service: str
    incidents: int
    sev1: int
    sev2: int
    open_now: int
    mean_time_to_resolve: float | None = None
    last_incident_at: datetime | None = None
    top_status: IncidentStatus | None = None
    top_severity: IncidentSeverity | None = None
