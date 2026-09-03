"""Triage node: classify severity and frame the incident."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.agents import prompts
from app.agents.collectors import recent_incidents_for_service
from app.agents.contracts import TriageResult
from app.agents.llm import get_llm
from app.agents.runtime import (
    add_timeline,
    agent_step,
    incident_snapshot,
    load_incident,
    record_usage,
    set_phase,
)
from app.agents.state import InvestigationState
from app.core.db import tenant_session_scope
from app.core.logging import get_logger
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    AuditAction,
    IncidentSeverity,
    IncidentStatus,
)
from app.services import audit, events

log = get_logger(__name__)


async def triage_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])

    async with agent_step(
        state,
        name="Triage",
        phase=AgentPhase.TRIAGE,
        input_summary=f"Classifying {state['incident'].get('reference', '')}",
    ) as step:
        await set_phase(state, AgentPhase.TRIAGE)

        async with tenant_session_scope(tenant_id) as session:
            incident = await load_incident(session, incident_id)
            snapshot = incident_snapshot(incident)
            similar = await recent_incidents_for_service(
                session, tenant_id=tenant_id, service=incident.service
            )
            previous_severity = incident.severity

        result, usage = await get_llm().structured(
            schema=TriageResult,
            system=prompts.TRIAGE_SYSTEM,
            user=prompts.triage_user(snapshot, similar),
            purpose="triage",
            fast=True,
            context={"incident": snapshot, "recent_similar": similar},
            metadata={"incident_id": str(incident_id), "tenant_id": str(tenant_id)},
        )
        await record_usage(uuid.UUID(state["run_id"]), usage)

        severity = IncidentSeverity(result.severity)

        async with tenant_session_scope(tenant_id) as session:
            incident = await load_incident(session, incident_id)
            incident.severity = severity
            incident.severity_rationale = result.rationale
            incident.severity_confidence = result.confidence
            if result.likely_service and not incident.service:
                incident.service = result.likely_service[:200]
            if incident.status is IncidentStatus.OPEN:
                incident.status = IncidentStatus.TRIAGED
            if incident.acknowledged_at is None:
                incident.acknowledged_at = datetime.now(UTC)

            if previous_severity != severity:
                await audit.record_agent(
                    session,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    action=AuditAction.INCIDENT_SEVERITY_CHANGED,
                    resource_type="incident",
                    resource_id=incident_id,
                    summary=(
                        f"Severity {previous_severity} -> {severity} "
                        f"(confidence {result.confidence:.0%})"
                    ),
                    rationale=result.rationale,
                )
            snapshot = incident_snapshot(incident)

        step.set_output(
            f"{severity} at {result.confidence:.0%} confidence — {result.rationale[:200]}",
            severity=str(severity),
            confidence=result.confidence,
            symptoms=result.symptoms,
        )

        await add_timeline(
            state,
            title=f"Triaged as {str(severity).upper()}",
            body=result.rationale,
            phase=AgentPhase.TRIAGE,
            confidence=result.confidence,
            customer_impact=result.customer_impact,
        )
        await events.emit(
            type=AgentEventType.INCIDENT_UPDATED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.TRIAGE,
            title=f"Severity set to {str(severity).upper()}",
            message=result.rationale[:400],
            severity=str(severity),
            status=str(IncidentStatus.TRIAGED),
        )

    return {
        "incident": snapshot,
        "severity": str(severity),
        "severity_confidence": result.confidence,
        "severity_rationale": result.rationale,
        "symptoms": list(result.symptoms),
        "customer_impact": result.customer_impact,
        "phase": str(AgentPhase.TRIAGE),
    }
