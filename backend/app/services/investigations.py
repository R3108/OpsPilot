"""Starting, resuming and cancelling investigations.

The graph is always driven from here so that run bookkeeping — the ``AgentRun``
row, LangSmith trace linkage, error capture, terminal status — happens in exactly
one place, whether the trigger was an incoming alert, a human clicking
"investigate", an approval decision, or a worker retry.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.agents.graph import get_compiled_graph, thread_config
from app.agents.runtime import incident_snapshot
from app.agents.state import initial_state
from app.core.config import settings
from app.core.db import session_scope
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.core.redis_client import advisory_lock
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    AuditAction,
    IncidentStatus,
)
from app.models.incident import AgentRun, Incident
from app.services import audit, events

log = get_logger(__name__)


class InvestigationBusy(ConflictError):
    """Another worker already holds this incident's graph thread."""


async def start_investigation(
    *,
    incident_id: uuid.UUID,
    tenant_id: uuid.UUID,
    triggered_by: str = "system",
    force: bool = False,
) -> dict[str, Any]:
    """Run the graph from the top for an incident."""
    async with advisory_lock(f"investigation:{incident_id}", ttl_seconds=1800) as acquired:
        if not acquired:
            raise InvestigationBusy(
                "An investigation is already running for this incident",
                details={"incident_id": str(incident_id)},
            )

        async with session_scope() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None or incident.tenant_id != tenant_id:
                raise NotFoundError("Incident not found")

            if incident.status.is_terminal and not force:
                raise ConflictError(
                    f"Incident is {incident.status}; pass force=true to re-investigate",
                    details={"status": str(incident.status)},
                )

            attempt = (
                int(
                    (
                        await session.execute(
                            select(AgentRun.attempt)
                            .where(AgentRun.incident_id == incident_id)
                            .order_by(AgentRun.attempt.desc())
                            .limit(1)
                        )
                    ).scalar()
                    or 0
                )
                + 1
            )

            run = AgentRun(
                tenant_id=tenant_id,
                incident_id=incident_id,
                thread_id=incident.thread_id,
                attempt=attempt,
                phase=AgentPhase.TRIAGE,
                status="running",
                started_at=datetime.now(UTC),
            )
            session.add(run)
            await session.flush()
            run_id = run.id
            snapshot = incident_snapshot(incident)

            await audit.record(
                session,
                tenant_id=tenant_id,
                action=AuditAction.AGENT_RUN_STARTED,
                resource_type="agent_run",
                resource_id=run_id,
                actor_type="system",
                actor_id=triggered_by,
                actor_label=triggered_by,
                incident_id=incident_id,
                summary=f"Investigation attempt {attempt} started",
            )

        started_at = datetime.now(UTC)
        state = initial_state(
            incident_id=str(incident_id),
            tenant_id=str(tenant_id),
            run_id=str(run_id),
            thread_id=snapshot["id"],
            incident=snapshot,
            attempt=attempt,
            max_iterations=settings.max_agent_iterations,
            started_at=started_at.isoformat(),
            deadline_at=(
                started_at + timedelta(seconds=settings.investigation_timeout_seconds)
            ).isoformat(),
        )

        await events.emit(
            type=AgentEventType.PHASE_STARTED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.TRIAGE,
            title="Investigation started",
            message=f"Attempt {attempt}",
            run_id=run_id,
        )

        return await _drive(
            incident_id=incident_id,
            tenant_id=tenant_id,
            run_id=run_id,
            payload=state,
        )


async def resume_investigation(
    *,
    incident_id: uuid.UUID,
    tenant_id: uuid.UUID,
    resume_value: dict[str, Any],
) -> dict[str, Any]:
    """Resume a graph parked at an ``interrupt`` (i.e. awaiting approval)."""
    from langgraph.types import Command

    async with advisory_lock(f"investigation:{incident_id}", ttl_seconds=1800) as acquired:
        if not acquired:
            raise InvestigationBusy(
                "This incident's investigation is already being resumed",
                details={"incident_id": str(incident_id)},
            )

        async with session_scope() as session:
            run = (
                await session.execute(
                    select(AgentRun)
                    .where(AgentRun.incident_id == incident_id)
                    .order_by(AgentRun.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if run is None:
                raise NotFoundError("No investigation to resume for this incident")
            run_id = run.id
            run.status = "running"

        # A resume needs somewhere to resume from. A run that died before its
        # first checkpoint has no thread state, and `Command(resume=...)` against
        # an empty thread does not fail — the graph starts from the top with no
        # state at all, which surfaces as `KeyError: 'incident_id'` inside the
        # triage node. Say what actually happened instead.
        graph = await get_compiled_graph()
        config = thread_config(incident_id, tenant_id=tenant_id, run_id=run_id)
        snapshot = await _read_state(graph, config)
        if snapshot is not None and not snapshot.values:
            log.warning(
                "investigation.nothing_to_resume",
                incident_id=str(incident_id),
                run_id=str(run_id),
            )
            await _finish_run(
                run_id,
                status="failed",
                phase=AgentPhase.FAILED,
                error=(
                    "No checkpoint to resume from: this run stopped before the graph "
                    "saved any state. Start a new investigation."
                ),
            )
            return {"status": "unresumable", "run_id": str(run_id)}

        if snapshot is not None:
            await _credit_stranded_time(graph, config, snapshot, incident_id=incident_id)

        log.info(
            "investigation.resuming",
            incident_id=str(incident_id),
            resume=resume_value.get("status"),
        )
        return await _drive(
            incident_id=incident_id,
            tenant_id=tenant_id,
            run_id=run_id,
            payload=Command(resume=resume_value),
        )


async def _drive(
    *,
    incident_id: uuid.UUID,
    tenant_id: uuid.UUID,
    run_id: uuid.UUID,
    payload: Any,
) -> dict[str, Any]:
    """Invoke the compiled graph and reconcile the run row with the result."""
    graph = await get_compiled_graph()
    config = thread_config(incident_id, tenant_id=tenant_id, run_id=run_id)

    try:
        final_state = await graph.ainvoke(payload, config=config)
    except Exception as exc:  # noqa: BLE001 - a crashed graph must still be recorded
        log.exception("investigation.failed", incident_id=str(incident_id))
        await _finish_run(
            run_id,
            status="failed",
            phase=AgentPhase.FAILED,
            error=f"{type(exc).__name__}: {exc}"[:4000],
        )
        async with session_scope() as session:
            incident = await session.get(Incident, incident_id)
            if incident is not None and incident.status.is_active:
                incident.status = IncidentStatus.FAILED
            await audit.record(
                session,
                tenant_id=tenant_id,
                action=AuditAction.AGENT_RUN_FAILED,
                resource_type="agent_run",
                resource_id=run_id,
                actor_type="agent",
                actor_id="opspilot-agent",
                incident_id=incident_id,
                summary=f"Investigation failed: {exc}"[:2000],
            )
        await events.emit(
            type=AgentEventType.PHASE_FAILED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.FAILED,
            title="Investigation failed",
            message=str(exc)[:400],
            run_id=run_id,
        )
        raise

    # A graph parked on an interrupt returns without reaching END.
    interrupts = await _pending_interrupts(graph, config)
    if interrupts:
        await _finish_run(run_id, status="awaiting_approval", phase=AgentPhase.AWAIT_APPROVAL)
        log.info("investigation.paused", incident_id=str(incident_id), reason="approval")
        return {
            "status": "awaiting_approval",
            "run_id": str(run_id),
            "interrupts": interrupts,
            "state": _public_state(final_state),
        }

    await _finish_run(
        run_id,
        status="completed",
        phase=AgentPhase.DONE,
        result=_public_state(final_state),
    )
    async with session_scope() as session:
        await audit.record(
            session,
            tenant_id=tenant_id,
            action=AuditAction.AGENT_RUN_COMPLETED,
            resource_type="agent_run",
            resource_id=run_id,
            actor_type="agent",
            actor_id="opspilot-agent",
            incident_id=incident_id,
            summary=(f"Investigation completed; recovered={bool(final_state.get('recovered'))}"),
        )
    log.info(
        "investigation.completed",
        incident_id=str(incident_id),
        recovered=bool(final_state.get("recovered")),
        iterations=final_state.get("iteration"),
    )
    return {
        "status": "completed",
        "run_id": str(run_id),
        "state": _public_state(final_state),
    }


async def _read_state(graph: Any, config: dict[str, Any]) -> Any | None:
    """This thread's checkpoint, or None if it could not be read at all.

    None means "unknown", not "empty" — an unreadable thread is treated as
    resumable rather than declared dead.
    """
    try:
        return await graph.aget_state(config)
    except Exception as exc:  # noqa: BLE001
        log.warning("investigation.state_read_failed", error=str(exc)[:300])
        return None


async def _credit_stranded_time(
    graph: Any, config: dict[str, Any], snapshot: Any, *, incident_id: uuid.UUID
) -> None:
    """Push the deadline out by the time this run spent with nothing driving it.

    ``deadline_at`` bounds how long the agent may work, but it is wall-clock, so a
    run whose worker died burns its entire budget sitting still. The reconciler
    only picks up runs older than twice the timeout — meaning without this credit
    *every* rescued run resumes already past its deadline, and both
    ``after_hypothesize`` and ``after_verify`` divert it straight to postmortem.
    The safety net would rescue a run only to make it give up.

    Crediting the idle time keeps the budget measuring agent work rather than
    elapsed time; a genuinely runaway investigation is still bounded, because time
    spent actually running is never refunded.
    """
    deadline = (snapshot.values or {}).get("deadline_at")
    checkpointed_at = getattr(snapshot, "created_at", None)
    if not deadline or not checkpointed_at:
        return

    try:
        stranded = datetime.now(UTC) - datetime.fromisoformat(str(checkpointed_at))
        if stranded <= timedelta(0):
            return
        extended = datetime.fromisoformat(str(deadline)) + stranded
    except (TypeError, ValueError):  # pragma: no cover - defensive against odd clocks
        return

    try:
        await graph.aupdate_state(config, {"deadline_at": extended.isoformat()})
    except Exception as exc:  # noqa: BLE001 - a missed credit must not block the resume
        log.warning("investigation.deadline_credit_failed", error=str(exc)[:300])
        return

    log.info(
        "investigation.deadline_credited",
        incident_id=str(incident_id),
        stranded_seconds=int(stranded.total_seconds()),
        deadline_at=extended.isoformat(),
    )


async def _pending_interrupts(graph: Any, config: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        snapshot = await graph.aget_state(config)
    except Exception as exc:  # noqa: BLE001
        log.warning("investigation.state_read_failed", error=str(exc)[:300])
        return []
    raw = getattr(snapshot, "interrupts", None) or ()
    return [
        {"value": getattr(item, "value", item), "id": getattr(item, "id", None)} for item in raw
    ]


async def _finish_run(
    run_id: uuid.UUID,
    *,
    status: str,
    phase: AgentPhase,
    error: str | None = None,
    result: dict[str, Any] | None = None,
) -> None:
    async with session_scope() as session:
        run = await session.get(AgentRun, run_id)
        if run is None:  # pragma: no cover
            return
        run.status = status
        run.phase = phase
        run.error = error
        if result is not None:
            run.result = result
        if status in ("completed", "failed"):
            run.finished_at = datetime.now(UTC)


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    """Trim the graph state down to what is worth persisting on the run row."""
    return {
        "phase": state.get("phase"),
        "iteration": state.get("iteration"),
        "severity": state.get("severity"),
        "recovered": bool(state.get("recovered")),
        "selected_hypothesis": (state.get("selected_hypothesis") or {}).get("title"),
        "hypothesis_confidence": (state.get("selected_hypothesis") or {}).get("confidence"),
        "evidence_count": len(state.get("evidence_ids") or []),
        "actions_proposed": len(state.get("proposed_action_ids") or []),
        "actions_executed": len(
            [r for r in (state.get("execution_results") or []) if r.get("succeeded")]
        ),
        "verification": state.get("verification") or {},
        "postmortem_id": state.get("postmortem_id"),
        "errors": state.get("errors") or [],
        "terminal_reason": state.get("terminal_reason"),
    }


async def get_graph_state(incident_id: uuid.UUID, tenant_id: uuid.UUID) -> dict[str, Any]:
    """Inspect the live checkpoint — used by the API for resumability diagnostics."""
    graph = await get_compiled_graph()
    config = thread_config(incident_id, tenant_id=tenant_id, run_id="inspect")
    snapshot = await graph.aget_state(config)
    return {
        "next": list(getattr(snapshot, "next", ()) or ()),
        "interrupts": await _pending_interrupts(graph, config),
        "created_at": getattr(snapshot, "created_at", None),
        "state": _public_state(dict(getattr(snapshot, "values", {}) or {})),
    }
