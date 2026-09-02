"""Planning node: decide which investigators to fan out to, and what they seek."""

from __future__ import annotations

import uuid
from typing import Any

from app.agents import prompts
from app.agents.collectors import available_investigators
from app.agents.contracts import InvestigationPlan
from app.agents.llm import get_llm
from app.agents.runtime import (
    add_timeline,
    agent_step,
    record_usage,
    set_phase,
)
from app.agents.state import InvestigationState
from app.core.db import session_scope
from app.core.logging import get_logger
from app.integrations.base import ClientRegistry
from app.models.enums import AgentPhase, IncidentStatus, InvestigatorKind
from app.models.incident import AgentRun, Incident

log = get_logger(__name__)


async def plan_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    iteration = int(state.get("iteration", 0)) + 1

    async with agent_step(
        state,
        name=f"Plan investigation (pass {iteration})",
        phase=AgentPhase.PLAN,
        input_summary=f"Selecting investigators for {state['incident'].get('reference', '')}",
    ) as step:
        await set_phase(state, AgentPhase.PLAN)

        async with session_scope() as session:
            registry = await ClientRegistry(tenant_id).load(session)
            available = available_investigators(registry)
            await registry.aclose()

            # Only statuses that mean "not being worked yet" or "done". The
            # in-flight ones (awaiting_approval, remediating, verifying) are
            # deliberately absent: a later planning pass must not drag an incident
            # backwards out of them. A re-investigation of a resolved, closed or
            # failed incident does belong here — otherwise it runs while the UI
            # still shows the old terminal badge and never counts the attempt.
            incident = await session.get(Incident, incident_id)
            if incident is not None and incident.status in (
                IncidentStatus.OPEN,
                IncidentStatus.TRIAGED,
                IncidentStatus.RESOLVED,
                IncidentStatus.CLOSED,
                IncidentStatus.FAILED,
            ):
                incident.status = IncidentStatus.INVESTIGATING
                incident.investigation_count = (incident.investigation_count or 0) + 1

        triage = {
            "severity": state.get("severity"),
            "confidence": state.get("severity_confidence"),
            "rationale": state.get("severity_rationale"),
            "symptoms": state.get("symptoms") or [],
            "customer_impact": state.get("customer_impact"),
        }

        plan, usage = await get_llm().structured(
            schema=InvestigationPlan,
            system=prompts.PLAN_SYSTEM,
            user=prompts.plan_user(state["incident"], triage, [str(a) for a in available]),
            purpose="plan",
            fast=True,
            context={
                "incident": state["incident"],
                "triage": triage,
                "available_investigators": [str(a) for a in available],
                "previous_questions": state.get("additional_questions") or [],
            },
            metadata={"incident_id": str(incident_id), "iteration": iteration},
        )
        await record_usage(uuid.UUID(state["run_id"]), usage)

        # A plan may only dispatch investigators the tenant can actually run.
        # The prompt says so; this enforces it.
        available_set = set(available)
        tasks = [
            {
                "investigator": str(task.investigator),
                "objective": task.objective,
                "questions": list(task.questions),
                "priority": task.priority,
            }
            for task in plan.tasks
            if InvestigatorKind(task.investigator) in available_set
        ]
        dropped = [
            str(t.investigator)
            for t in plan.tasks
            if str(t.investigator) not in {t2["investigator"] for t2 in tasks}
        ]

        if not tasks:
            # Degenerate but survivable: run whatever is available so the run
            # produces evidence rather than failing outright.
            tasks = [
                {
                    "investigator": str(kind),
                    "objective": "Collect any available evidence",
                    "questions": [],
                    "priority": 3,
                }
                for kind in available
            ]

        plan_payload = {
            "summary": plan.summary,
            "tasks": tasks,
            "time_window_minutes": plan.time_window_minutes,
            "target_service": plan.target_service or state.get("target_service"),
            "target_namespace": plan.target_namespace or state.get("target_namespace"),
            "initial_suspicions": list(plan.initial_suspicions),
            "dropped_investigators": dropped,
            "iteration": iteration,
        }

        step.set_output(
            f"{len(tasks)} investigator(s): "
            + ", ".join(t["investigator"] for t in tasks)
            + (f" (dropped {', '.join(dropped)}: no integration)" if dropped else ""),
            tasks=tasks,
            suspicions=plan_payload["initial_suspicions"],
        )

        await add_timeline(
            state,
            title=f"Investigation plan ready ({len(tasks)} parallel tracks)",
            body=plan.summary
            + (
                "\n\nInitial suspicions: " + "; ".join(plan.initial_suspicions)
                if plan.initial_suspicions
                else ""
            ),
            phase=AgentPhase.PLAN,
            tasks=[t["investigator"] for t in tasks],
        )

    async with session_scope() as session:
        run = await session.get(AgentRun, uuid.UUID(state["run_id"]))
        if run is not None:
            run.plan = plan_payload

    return {
        "plan": plan_payload,
        "time_window_minutes": plan.time_window_minutes,
        "target_service": plan_payload["target_service"] or "",
        "target_namespace": plan_payload["target_namespace"] or "",
        "iteration": iteration,
        "phase": str(AgentPhase.PLAN),
    }
