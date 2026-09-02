"""Domain enums shared by the ORM, the API schemas and the agent graph."""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    """RBAC roles, ordered from least to most privileged."""

    VIEWER = "viewer"
    RESPONDER = "responder"
    APPROVER = "approver"
    ADMIN = "admin"
    OWNER = "owner"


ROLE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 0,
    UserRole.RESPONDER: 10,
    UserRole.APPROVER: 20,
    UserRole.ADMIN: 30,
    UserRole.OWNER: 40,
}


def role_satisfies(actual: UserRole | str, required: UserRole | str) -> bool:
    """True when ``actual`` is at least as privileged as ``required``."""
    return ROLE_RANK[UserRole(actual)] >= ROLE_RANK[UserRole(required)]


class TenantPlan(StrEnum):
    FREE = "free"
    TEAM = "team"
    ENTERPRISE = "enterprise"


class IncidentSeverity(StrEnum):
    SEV1 = "sev1"  # full outage / data loss risk
    SEV2 = "sev2"  # major degradation, customer visible
    SEV3 = "sev3"  # partial degradation, limited blast radius
    SEV4 = "sev4"  # minor / internal only
    SEV5 = "sev5"  # informational

    @property
    def rank(self) -> int:
        return {"sev1": 5, "sev2": 4, "sev3": 3, "sev4": 2, "sev5": 1}[self.value]

    @property
    def is_major(self) -> bool:
        return self in (IncidentSeverity.SEV1, IncidentSeverity.SEV2)


class IncidentStatus(StrEnum):
    OPEN = "open"  # ingested, not yet triaged
    TRIAGED = "triaged"  # severity + service assigned
    INVESTIGATING = "investigating"  # agents fanned out
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    CLOSED = "closed"  # postmortem published
    FAILED = "failed"  # graph gave up; needs a human

    @property
    def is_terminal(self) -> bool:
        return self in (IncidentStatus.CLOSED, IncidentStatus.FAILED)

    @property
    def is_active(self) -> bool:
        return not self.is_terminal and self is not IncidentStatus.RESOLVED


class IncidentSource(StrEnum):
    SLACK = "slack"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    CLOUDWATCH = "cloudwatch"
    MANUAL = "manual"
    API = "api"
    SYNTHETIC = "synthetic"  # eval / replay


class AgentPhase(StrEnum):
    """Nodes of the LangGraph investigation graph, in canonical order."""

    INGESTED = "ingested"
    TRIAGE = "triage"
    PLAN = "plan"
    INVESTIGATE = "investigate"
    CORRELATE = "correlate"
    HYPOTHESIZE = "hypothesize"
    PROPOSE_REMEDIATION = "propose_remediation"
    POLICY_CHECK = "policy_check"
    AWAIT_APPROVAL = "await_approval"
    EXECUTE = "execute"
    VERIFY = "verify"
    POSTMORTEM = "postmortem"
    DONE = "done"
    FAILED = "failed"


class InvestigatorKind(StrEnum):
    """The specialised parallel investigators."""

    LOGS = "logs"
    METRICS = "metrics"
    DATABASE = "database"
    DEPLOYMENTS = "deployments"
    HISTORY = "history"


class EvidenceKind(StrEnum):
    LOG_PATTERN = "log_pattern"
    METRIC_SERIES = "metric_series"
    DB_HEALTH = "db_health"
    DEPLOYMENT = "deployment"
    COMMIT = "commit"
    K8S_EVENT = "k8s_event"
    ALERT = "alert"
    HISTORICAL_INCIDENT = "historical_incident"
    TRACE = "trace"
    NOTE = "note"


class EvidenceRelevance(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOISE = "noise"


class RiskTier(StrEnum):
    """How much damage an action can do if it is wrong."""

    LOW = "low"  # read-only / trivially reversible (e.g. clear a cache key)
    MEDIUM = "medium"  # restart a single pod, bump a feature flag
    HIGH = "high"  # rollback a deploy, scale a service, failover a replica
    CRITICAL = "critical"  # anything touching data or a protected namespace

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @property
    def minimum_role(self) -> UserRole:
        return {
            RiskTier.LOW: UserRole.RESPONDER,
            RiskTier.MEDIUM: UserRole.APPROVER,
            RiskTier.HIGH: UserRole.APPROVER,
            RiskTier.CRITICAL: UserRole.ADMIN,
        }[self]


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class RemediationStatus(StrEnum):
    PROPOSED = "proposed"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


class VerificationOutcome(StrEnum):
    RECOVERED = "recovered"
    PARTIAL = "partial"
    NOT_RECOVERED = "not_recovered"
    INCONCLUSIVE = "inconclusive"


class IntegrationProvider(StrEnum):
    SLACK = "slack"
    GITHUB = "github"
    KUBERNETES = "kubernetes"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    CLOUDWATCH = "cloudwatch"
    POSTGRES = "postgres"


class IntegrationStatus(StrEnum):
    PENDING = "pending"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"


class AuditAction(StrEnum):
    # auth
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_CREATED = "user.created"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_DISABLED = "user.disabled"
    # incidents
    INCIDENT_CREATED = "incident.created"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"
    INCIDENT_SEVERITY_CHANGED = "incident.severity_changed"
    INCIDENT_ASSIGNED = "incident.assigned"
    INCIDENT_COMMENTED = "incident.commented"
    # agents
    AGENT_RUN_STARTED = "agent.run_started"
    AGENT_RUN_COMPLETED = "agent.run_completed"
    AGENT_RUN_FAILED = "agent.run_failed"
    AGENT_TOOL_CALLED = "agent.tool_called"
    # remediation
    REMEDIATION_PROPOSED = "remediation.proposed"
    REMEDIATION_POLICY_BLOCKED = "remediation.policy_blocked"
    REMEDIATION_APPROVED = "remediation.approved"
    REMEDIATION_REJECTED = "remediation.rejected"
    REMEDIATION_EXECUTED = "remediation.executed"
    REMEDIATION_FAILED = "remediation.failed"
    # integrations
    INTEGRATION_CREATED = "integration.created"
    INTEGRATION_UPDATED = "integration.updated"
    INTEGRATION_DELETED = "integration.deleted"
    INTEGRATION_CREDENTIAL_ROTATED = "integration.credential_rotated"
    # postmortem
    POSTMORTEM_GENERATED = "postmortem.generated"
    POSTMORTEM_PUBLISHED = "postmortem.published"
    # audit
    AUDIT_CLEARED = "audit.cleared"


class AgentEventType(StrEnum):
    """Streamed to the UI over SSE."""

    PHASE_STARTED = "phase.started"
    PHASE_COMPLETED = "phase.completed"
    PHASE_FAILED = "phase.failed"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    EVIDENCE_ADDED = "evidence.added"
    HYPOTHESIS_ADDED = "hypothesis.added"
    ACTION_PROPOSED = "action.proposed"
    POLICY_DECISION = "policy.decision"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"
    EXECUTION_RESULT = "execution.result"
    VERIFICATION_RESULT = "verification.result"
    INCIDENT_UPDATED = "incident.updated"
    POSTMORTEM_READY = "postmortem.ready"
    THINKING = "thinking"
    HEARTBEAT = "heartbeat"
