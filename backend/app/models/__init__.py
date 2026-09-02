"""SQLAlchemy models.

Importing this package registers every table on ``Base.metadata``, which is what
Alembic autogenerate and the test fixtures rely on.
"""

from app.models.audit import AuditLog
from app.models.base import Base
from app.models.incident import (
    AgentRun,
    AgentStep,
    Evidence,
    Hypothesis,
    Incident,
    Postmortem,
    TimelineEntry,
    Verification,
)
from app.models.integration import Integration
from app.models.knowledge import IncidentEmbedding, Runbook
from app.models.remediation import (
    ActionExecutionLog,
    Approval,
    PolicyRule,
    RemediationAction,
)
from app.models.tenant import ApiKey, Tenant, User

__all__ = [
    "ActionExecutionLog",
    "AgentRun",
    "AgentStep",
    "ApiKey",
    "Approval",
    "AuditLog",
    "Base",
    "Evidence",
    "Hypothesis",
    "Incident",
    "IncidentEmbedding",
    "Integration",
    "PolicyRule",
    "Postmortem",
    "RemediationAction",
    "Runbook",
    "Tenant",
    "TimelineEntry",
    "User",
    "Verification",
]
