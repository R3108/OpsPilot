"""The parallel investigator nodes.

Each investigator is the same three-step shape:

1. run its **typed collector** against real systems (read-only),
2. persist what came back as ``Evidence`` rows,
3. ask the model to *interpret* that evidence — and nothing else.

The five run concurrently as separate graph nodes, so a slow provider delays one
track rather than the whole investigation, and each writes into a distinct state
key so LangGraph can merge them without a race.
"""

from __future__ import annotations

import asyncio
import uuid
from functools import partial
from typing import Any

from app.agents import prompts
from app.agents.collectors import COLLECTORS, CollectContext
from app.agents.contracts import InvestigatorFinding
from app.agents.llm import get_llm
from app.agents.runtime import (
    agent_step,
    bump_tool_calls,
    error_entry,
    load_incident,
    persist_evidence,
    record_usage,
    set_phase,
    valid_citations,
)
from app.agents.state import InvestigationState
from app.core.config import settings
from app.core.db import tenant_session_scope
from app.core.logging import get_logger
from app.integrations.base import ClientRegistry
from app.models.enums import AgentPhase, IntegrationProvider, InvestigatorKind

log = get_logger(__name__)

# Which providers each investigator opens clients for. Loading only what is
# needed keeps credential decryption to a minimum.
_PROVIDERS: dict[InvestigatorKind, set[IntegrationProvider]] = {
    InvestigatorKind.LOGS: {IntegrationProvider.KUBERNETES, IntegrationProvider.CLOUDWATCH},
    InvestigatorKind.METRICS: {IntegrationProvider.PROMETHEUS, IntegrationProvider.CLOUDWATCH},
    InvestigatorKind.DATABASE: {IntegrationProvider.POSTGRES},
    InvestigatorKind.DEPLOYMENTS: {
        IntegrationProvider.GITHUB,
        IntegrationProvider.KUBERNETES,
        IntegrationProvider.GRAFANA,
    },
    InvestigatorKind.HISTORY: set(),
}


def _task_for(state: InvestigationState, kind: InvestigatorKind) -> dict[str, Any] | None:
    for task in (state.get("plan") or {}).get("tasks") or []:
        if task.get("investigator") == str(kind):
            return task
    return None


async def run_investigator(state: InvestigationState, kind: InvestigatorKind) -> dict[str, Any]:
    """Body shared by all five investigator nodes."""
    task = _task_for(state, kind)
    if task is None:
        # Not in this iteration's plan: contribute nothing, cleanly.
        return {}

    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])

    try:
        async with agent_step(
            state,
            name=f"{str(kind).title()} investigator",
            phase=AgentPhase.INVESTIGATE,
            investigator=kind,
            input_summary=task.get("objective", ""),
        ) as step:
            await set_phase(state, AgentPhase.INVESTIGATE)

            # ---- 1. collect (typed, read-only) --------------------------
            drafts = []
            collect_error: str | None = None
            async with tenant_session_scope(tenant_id) as session:
                incident = await load_incident(session, incident_id)
                registry = await ClientRegistry(
                    tenant_id, scenario=(incident.labels or {}).get("scenario")
                ).load(session, providers=_PROVIDERS[kind] or None)
                ctx = CollectContext(
                    incident=incident,
                    registry=registry,
                    session=session,
                    window_minutes=int(state.get("time_window_minutes") or 120),
                    objective=task.get("objective", ""),
                    questions=list(task.get("questions") or []),
                )
                try:
                    drafts = await asyncio.wait_for(
                        COLLECTORS[kind](ctx),
                        timeout=settings.tool_timeout_seconds * 3,
                    )
                except TimeoutError:
                    collect_error = "collection timed out"
                    log.warning("investigator.timeout", investigator=str(kind))
                except Exception as exc:  # noqa: BLE001 - one provider must not kill the run
                    collect_error = str(exc)[:500]
                    log.warning(
                        "investigator.collect_failed", investigator=str(kind), error=collect_error
                    )
                finally:
                    await registry.aclose()

            await bump_tool_calls(run_id, max(1, len(drafts)))
            digests = await persist_evidence(state, drafts)

            # ---- 2. interpret (LLM reads evidence; produces no facts) ----
            finding, usage = await get_llm().structured(
                schema=InvestigatorFinding,
                system=prompts.INVESTIGATE_SYSTEM.format(
                    investigator=str(kind),
                    objective=task.get("objective", ""),
                    questions="; ".join(task.get("questions") or []) or "(none specified)",
                ),
                user=prompts.investigate_user(state["incident"], digests, task),
                purpose=f"investigate.{kind}",
                fast=True,
                context={
                    "incident": state["incident"],
                    "evidence": digests,
                    "investigator": str(kind),
                    "objective": task.get("objective", ""),
                },
                metadata={"incident_id": str(incident_id), "investigator": str(kind)},
            )
            await record_usage(run_id, usage)

            citations = valid_citations(finding.cited_evidence_ids, digests)
            payload = {
                "summary": finding.summary,
                "key_observations": list(finding.key_observations),
                "cited_evidence_ids": citations,
                "anomaly_detected": finding.anomaly_detected,
                "anomaly_description": finding.anomaly_description,
                "confidence": finding.confidence,
                "suggests_root_cause": finding.suggests_root_cause,
                "dead_end": finding.dead_end,
                "evidence_count": len(digests),
                "collect_error": collect_error,
            }

            step.set_output(
                f"{len(digests)} evidence item(s); "
                + (
                    f"anomaly: {finding.anomaly_description[:150]}"
                    if finding.anomaly_detected
                    else "no anomaly detected"
                ),
                evidence_count=len(digests),
                confidence=finding.confidence,
                anomaly=finding.anomaly_detected,
            )

        return {
            "findings": {str(kind): payload},
            "evidence_ids": [d["id"] for d in digests],
            "evidence_digest": digests,
        }

    except Exception as exc:  # noqa: BLE001 - recorded, never fatal
        log.warning("investigator.failed", investigator=str(kind), error=str(exc)[:300])
        return {
            "investigator_errors": {str(kind): str(exc)[:500]},
            "errors": [error_entry(f"investigate.{kind}", exc)],
            "findings": {
                str(kind): {
                    "summary": f"The {kind} investigator failed: {exc}",
                    "confidence": 0.0,
                    "dead_end": True,
                    "cited_evidence_ids": [],
                    "key_observations": [],
                    "anomaly_detected": False,
                }
            },
        }


# Concrete node callables, one per investigator, so the graph can fan out.
logs_node = partial(run_investigator, kind=InvestigatorKind.LOGS)
metrics_node = partial(run_investigator, kind=InvestigatorKind.METRICS)
database_node = partial(run_investigator, kind=InvestigatorKind.DATABASE)
deployments_node = partial(run_investigator, kind=InvestigatorKind.DEPLOYMENTS)
history_node = partial(run_investigator, kind=InvestigatorKind.HISTORY)

INVESTIGATOR_NODES: dict[InvestigatorKind, Any] = {
    InvestigatorKind.LOGS: logs_node,
    InvestigatorKind.METRICS: metrics_node,
    InvestigatorKind.DATABASE: database_node,
    InvestigatorKind.DEPLOYMENTS: deployments_node,
    InvestigatorKind.HISTORY: history_node,
}
