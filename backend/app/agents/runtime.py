"""Shared plumbing for graph nodes: step recording, evidence persistence, events.

Every node runs inside :func:`agent_step`, which gives four things for free:
a durable ``AgentStep`` row, a pair of SSE events, timing, and uniform error
capture. A node that raises still leaves a complete, queryable trace of what it
was doing when it failed.
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.collectors import EvidenceDraft
from app.agents.state import InvestigationState
from app.core.db import session_scope, set_tenant_setting, tenant_session_scope
from app.core.logging import get_logger, incident_id_ctx
from app.models.enums import AgentEventType, AgentPhase, InvestigatorKind
from app.models.incident import AgentRun, AgentStep, Evidence, Incident
from app.services import events

log = get_logger(__name__)


@dataclass(slots=True)
class StepRecorder:
    """Handle a node uses to describe what it did."""

    step_id: uuid.UUID
    sequence: int
    output_summary: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "succeeded"

    def set_output(self, summary: str, **payload: Any) -> None:
        self.output_summary = summary[:5000]
        self.payload.update(payload)


async def _insert_step(
    *,
    tenant_id: uuid.UUID,
    run_id: uuid.UUID,
    incident_id: uuid.UUID,
    phase: AgentPhase,
    investigator: InvestigatorKind | None,
    name: str,
    kind: str,
    input_summary: str,
    started: datetime,
) -> tuple[uuid.UUID, int]:
    """Insert a step, allocating the next sequence number.

    The five investigators run concurrently in their own sessions, so two of
    them can read the same ``max(sequence)`` and collide on the
    ``(run_id, sequence)`` unique constraint. Rather than serialise every step
    behind a lock, we let the constraint arbitrate and retry with a freshly read
    maximum — contention is bounded by the fan-out width, so this converges in a
    couple of attempts at most.
    """
    from sqlalchemy.exc import IntegrityError

    attempts = 12
    for attempt in range(attempts):
        try:
            async with tenant_session_scope(tenant_id) as session:
                current = (
                    await session.execute(
                        select(func.max(AgentStep.sequence)).where(AgentStep.run_id == run_id)
                    )
                ).scalar()
                sequence = int(current or 0) + 1
                step = AgentStep(
                    tenant_id=tenant_id,
                    run_id=run_id,
                    incident_id=incident_id,
                    sequence=sequence,
                    phase=phase,
                    investigator=investigator,
                    name=name,
                    kind=kind,
                    status="running",
                    input_summary=input_summary[:5000],
                    started_at=started,
                )
                session.add(step)
                await session.flush()
                return step.id, sequence
        except IntegrityError:
            if attempt == attempts - 1:
                raise
            # Stagger the retries so concurrent writers do not resynchronise.
            # Jitter only — nothing here is a security decision.
            await asyncio.sleep(0.01 * (attempt + 1) + random.random() * 0.01)  # noqa: S311
    raise AssertionError("unreachable")  # pragma: no cover


@asynccontextmanager
async def agent_step(
    state: InvestigationState,
    *,
    name: str,
    phase: AgentPhase,
    kind: str = "node",
    investigator: InvestigatorKind | None = None,
    input_summary: str = "",
) -> AsyncIterator[StepRecorder]:
    tenant_id = uuid.UUID(state["tenant_id"])
    incident_id = uuid.UUID(state["incident_id"])
    run_id = uuid.UUID(state["run_id"])
    incident_id_ctx.set(str(incident_id))

    started = datetime.now(UTC)
    clock = time.perf_counter()

    step_id, sequence = await _insert_step(
        tenant_id=tenant_id,
        run_id=run_id,
        incident_id=incident_id,
        phase=phase,
        investigator=investigator,
        name=name,
        kind=kind,
        input_summary=input_summary,
        started=started,
    )

    await events.emit(
        type=AgentEventType.PHASE_STARTED if kind == "node" else AgentEventType.TOOL_STARTED,
        incident_id=incident_id,
        tenant_id=tenant_id,
        phase=phase,
        title=name,
        message=input_summary[:500],
        investigator=str(investigator) if investigator else None,
        run_id=run_id,
        step_id=step_id,
        sequence=sequence,
    )

    recorder = StepRecorder(step_id=step_id, sequence=sequence)
    try:
        yield recorder
    except Exception as exc:
        recorder.status = "failed"
        duration_ms = int((time.perf_counter() - clock) * 1000)
        await _finalise_step(step_id, recorder, duration_ms, error=str(exc)[:4000])
        await events.emit(
            type=AgentEventType.PHASE_FAILED if kind == "node" else AgentEventType.TOOL_FAILED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=phase,
            title=name,
            message=str(exc)[:500],
            investigator=str(investigator) if investigator else None,
            run_id=run_id,
            step_id=step_id,
            sequence=sequence,
            error_type=type(exc).__name__,
        )
        log.warning("agent.step_failed", step=name, phase=str(phase), error=str(exc)[:300])
        raise
    else:
        duration_ms = int((time.perf_counter() - clock) * 1000)
        await _finalise_step(step_id, recorder, duration_ms)
        await events.emit(
            type=AgentEventType.PHASE_COMPLETED
            if kind == "node"
            else AgentEventType.TOOL_COMPLETED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=phase,
            title=name,
            message=recorder.output_summary[:500],
            investigator=str(investigator) if investigator else None,
            run_id=run_id,
            step_id=step_id,
            sequence=sequence,
            duration_ms=duration_ms,
            **{k: v for k, v in recorder.payload.items() if k not in ("raw",)},
        )


async def _finalise_step(
    step_id: uuid.UUID, recorder: StepRecorder, duration_ms: int, error: str | None = None
) -> None:
    async with session_scope() as session:
        step = await session.get(AgentStep, step_id)
        if step is None:  # pragma: no cover
            return
        await set_tenant_setting(session, step.tenant_id)
        step.status = recorder.status
        step.output_summary = recorder.output_summary
        step.payload = recorder.payload
        step.error = error
        step.finished_at = datetime.now(UTC)
        step.duration_ms = duration_ms


# --------------------------------------------------------------------------
# persistence helpers
# --------------------------------------------------------------------------
async def load_incident(session: AsyncSession, incident_id: uuid.UUID) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise LookupError(f"incident {incident_id} no longer exists")
    return incident


def incident_snapshot(incident: Incident) -> dict[str, Any]:
    return {
        "id": str(incident.id),
        "reference": incident.reference,
        "title": incident.title,
        "description": incident.description,
        "status": str(incident.status),
        "severity": str(incident.severity),
        "source": str(incident.source),
        "service": incident.service,
        "environment": incident.environment,
        "cluster": incident.cluster,
        "namespace": incident.namespace,
        "labels": incident.labels or {},
        "raw_payload": incident.raw_payload or {},
        "detected_at": incident.detected_at.isoformat(),
        "root_cause_summary": incident.root_cause_summary,
    }


async def persist_evidence(
    state: InvestigationState,
    drafts: Sequence[EvidenceDraft],
) -> list[dict[str, Any]]:
    """Write evidence rows and return their digests for the graph state."""
    if not drafts:
        return []

    tenant_id = uuid.UUID(state["tenant_id"])
    incident_id = uuid.UUID(state["incident_id"])
    run_id = uuid.UUID(state["run_id"])
    now = datetime.now(UTC)

    digests: list[dict[str, Any]] = []
    async with tenant_session_scope(tenant_id) as session:
        for draft in drafts:
            row = Evidence(
                tenant_id=tenant_id,
                incident_id=incident_id,
                agent_run_id=run_id,
                kind=draft.kind,
                investigator=draft.investigator,
                source=draft.source,
                source_ref=draft.source_ref,
                source_url=draft.source_url,
                summary=draft.summary[:8000],
                detail=draft.detail[:20000],
                raw=_truncate_raw(draft.raw),
                relevance=draft.relevance,
                observed_at=draft.observed_at,
                collected_at=now,
            )
            session.add(row)
            await session.flush()
            digests.append(evidence_digest(row))

    await events.emit(
        type=AgentEventType.EVIDENCE_ADDED,
        incident_id=incident_id,
        tenant_id=tenant_id,
        phase=AgentPhase.INVESTIGATE,
        title=f"{len(digests)} evidence item(s) collected",
        run_id=run_id,
        count=len(digests),
        items=[
            {"id": d["id"], "summary": d["summary"], "relevance": d["relevance"]}
            for d in digests[:10]
        ],
    )
    return digests


def evidence_digest(row: Evidence) -> dict[str, Any]:
    """Compact form of an Evidence row for prompts and graph state."""
    return {
        "id": str(row.id),
        "citation": row.citation,
        "kind": str(row.kind),
        "investigator": str(row.investigator) if row.investigator else None,
        "source": row.source,
        "source_ref": row.source_ref,
        "summary": row.summary,
        "detail": row.detail[:2000],
        "raw": row.raw,
        "relevance": str(row.relevance),
        "observed_at": row.observed_at.isoformat() if row.observed_at else None,
    }


def _truncate_raw(raw: dict[str, Any], *, limit: int = 60_000) -> dict[str, Any]:
    """Keep raw payloads bounded so one chatty provider cannot bloat the table."""
    import json

    try:
        encoded = json.dumps(raw, default=str)
    except (TypeError, ValueError):
        return {"unserialisable": str(raw)[:2000]}
    if len(encoded) <= limit:
        return raw
    return {"truncated": True, "preview": encoded[:limit], "original_size": len(encoded)}


async def load_evidence_digests(
    incident_id: uuid.UUID, run_id: uuid.UUID | None = None
) -> list[dict[str, Any]]:
    async with session_scope() as session:
        first = (
            await session.execute(
                select(Evidence.tenant_id).where(Evidence.incident_id == incident_id).limit(1)
            )
        ).scalar_one_or_none()
        if first is not None:
            await set_tenant_setting(session, first)
        stmt = select(Evidence).where(Evidence.incident_id == incident_id)
        if run_id is not None:
            stmt = stmt.where(Evidence.agent_run_id == run_id)
        rows = list((await session.execute(stmt.order_by(Evidence.collected_at))).scalars().all())
    return [evidence_digest(r) for r in rows]


def valid_citations(cited: list[str], known: list[dict[str, Any]]) -> list[str]:
    """Drop any evidence id the model invented.

    A hallucinated citation is the one failure mode that would silently poison a
    postmortem, so it is filtered at every boundary rather than trusted.
    """
    known_ids = {d["id"] for d in known}
    # Accept both raw ids and the short ``E:xxxxxxxx`` citation form.
    by_prefix = {d["id"][:8]: d["id"] for d in known}
    resolved: list[str] = []
    for raw in cited:
        value = str(raw).strip()
        if value in known_ids:
            resolved.append(value)
            continue
        short = value.removeprefix("E:")[:8]
        if short in by_prefix:
            resolved.append(by_prefix[short])
    return list(dict.fromkeys(resolved))


async def record_usage(run_id: uuid.UUID, usage: Any) -> None:
    async with session_scope() as session:
        run = await session.get(AgentRun, run_id)
        if run is None:  # pragma: no cover
            return
        await set_tenant_setting(session, run.tenant_id)
        run.prompt_tokens += usage.prompt_tokens
        run.completion_tokens += usage.completion_tokens
        run.cost_usd = round(run.cost_usd + usage.cost_usd, 6)
        run.last_heartbeat_at = datetime.now(UTC)


async def bump_tool_calls(run_id: uuid.UUID, count: int = 1) -> None:
    async with session_scope() as session:
        run = await session.get(AgentRun, run_id)
        if run is not None:
            await set_tenant_setting(session, run.tenant_id)
            run.tool_call_count += count
            run.last_heartbeat_at = datetime.now(UTC)


async def set_phase(state: InvestigationState, phase: AgentPhase) -> None:
    async with session_scope() as session:
        run = await session.get(AgentRun, uuid.UUID(state["run_id"]))
        if run is not None:
            await set_tenant_setting(session, run.tenant_id)
            run.phase = phase
            run.last_heartbeat_at = datetime.now(UTC)


async def add_timeline(
    state: InvestigationState,
    *,
    title: str,
    body: str = "",
    phase: AgentPhase | None = None,
    actor_type: str = "agent",
    actor_label: str = "OpsPilot Agent",
    **metadata: Any,
) -> None:
    from app.models.incident import TimelineEntry

    async with tenant_session_scope(uuid.UUID(state["tenant_id"])) as session:
        session.add(
            TimelineEntry(
                tenant_id=uuid.UUID(state["tenant_id"]),
                incident_id=uuid.UUID(state["incident_id"]),
                occurred_at=datetime.now(UTC),
                actor_type=actor_type,
                actor_id=state.get("run_id"),
                actor_label=actor_label,
                phase=phase,
                title=title[:300],
                body=body[:20000],
                metadata_json=metadata,
            )
        )


def deadline_exceeded(state: InvestigationState) -> bool:
    deadline = state.get("deadline_at")
    if not deadline:
        return False
    try:
        return datetime.now(UTC) >= datetime.fromisoformat(deadline)
    except ValueError:  # pragma: no cover
        return False


def error_entry(node: str, exc: BaseException) -> dict[str, Any]:
    return {
        "node": node,
        "type": type(exc).__name__,
        "message": str(exc)[:1000],
        "at": datetime.now(UTC).isoformat(),
    }
