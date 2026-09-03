"""Correlation and hypothesis nodes.

Correlation merges the independent investigator reports into one timeline;
hypothesis generation turns that into ranked, falsifiable causal claims with
calibrated confidence. Both persist their output so the UI and the postmortem
read from the database, not from graph state.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select

from app.agents import prompts
from app.agents.contracts import Correlation, HypothesisSet
from app.agents.llm import get_llm
from app.agents.runtime import (
    add_timeline,
    agent_step,
    load_evidence_digests,
    record_usage,
    set_phase,
    valid_citations,
)
from app.agents.state import InvestigationState
from app.core.db import tenant_session_scope
from app.core.logging import get_logger
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    EvidenceRelevance,
)
from app.models.incident import Evidence, Hypothesis, Incident
from app.services import events

log = get_logger(__name__)

# Evidence cited as supporting the winning hypothesis is worth more than
# evidence nobody referenced. These weights feed the postmortem's ordering.
_RELEVANCE_WEIGHT = {
    EvidenceRelevance.CRITICAL: 1.0,
    EvidenceRelevance.HIGH: 0.8,
    EvidenceRelevance.MEDIUM: 0.5,
    EvidenceRelevance.LOW: 0.25,
    EvidenceRelevance.NOISE: 0.05,
}


async def correlate_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])

    digests = await load_evidence_digests(incident_id)
    findings = state.get("findings") or {}

    async with agent_step(
        state,
        name="Correlate evidence",
        phase=AgentPhase.CORRELATE,
        input_summary=(f"{len(digests)} evidence item(s) from {len(findings)} investigator(s)"),
    ) as step:
        await set_phase(state, AgentPhase.CORRELATE)

        correlation, usage = await get_llm().structured(
            schema=Correlation,
            system=prompts.CORRELATE_SYSTEM,
            user=prompts.correlate_user(state["incident"], findings, digests),
            purpose="correlate",
            context={
                "incident": state["incident"],
                "evidence": digests,
                "findings": findings,
            },
            metadata={"incident_id": str(incident_id)},
        )
        await record_usage(run_id, usage)

        signals = [
            {
                "description": signal.description,
                "evidence_ids": valid_citations(signal.evidence_ids, digests),
                "signal_type": signal.signal_type,
                "strength": signal.strength,
            }
            for signal in correlation.signals
        ]
        payload = {
            "timeline_summary": correlation.timeline_summary,
            "change_point": correlation.change_point,
            "signals": signals,
            "contradictions": list(correlation.contradictions),
            "gaps": list(correlation.gaps),
        }

        await _reweight_evidence(incident_id, signals, tenant_id=tenant_id)

        step.set_output(
            f"{len(signals)} correlated signal(s)"
            + (f"; change point {correlation.change_point}" if correlation.change_point else ""),
            signals=len(signals),
            contradictions=len(correlation.contradictions),
            gaps=len(correlation.gaps),
        )

        await add_timeline(
            state,
            title="Evidence correlated",
            body=correlation.timeline_summary
            + (f"\n\nChange point: {correlation.change_point}" if correlation.change_point else "")
            + (
                "\n\nContradictions: " + "; ".join(correlation.contradictions)
                if correlation.contradictions
                else ""
            ),
            phase=AgentPhase.CORRELATE,
            signal_count=len(signals),
        )

    return {
        "correlation": payload,
        "evidence_digest": [],  # already merged; avoid duplicating on the reducer
        "phase": str(AgentPhase.CORRELATE),
    }


async def _reweight_evidence(
    incident_id: uuid.UUID, signals: list[dict[str, Any]], *, tenant_id: uuid.UUID
) -> None:
    """Raise the weight of evidence that participates in a strong signal."""
    contributions: dict[str, float] = {}
    for signal in signals:
        for evidence_id in signal["evidence_ids"]:
            contributions[evidence_id] = max(
                contributions.get(evidence_id, 0.0), float(signal["strength"])
            )
    if not contributions:
        return

    async with tenant_session_scope(tenant_id) as session:
        rows = list(
            (await session.execute(select(Evidence).where(Evidence.incident_id == incident_id)))
            .scalars()
            .all()
        )
        for row in rows:
            base = _RELEVANCE_WEIGHT.get(row.relevance, 0.5)
            signal_strength = contributions.get(str(row.id), 0.0)
            row.weight = round(min(1.0, 0.5 * base + 0.5 * signal_strength), 4)


async def hypothesize_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])

    digests = await load_evidence_digests(incident_id)
    previous_attempt = _previous_attempt(state)

    async with agent_step(
        state,
        name="Generate and rank hypotheses",
        phase=AgentPhase.HYPOTHESIZE,
        input_summary=f"Reasoning over {len(digests)} evidence item(s)",
    ) as step:
        await set_phase(state, AgentPhase.HYPOTHESIZE)

        result, usage = await get_llm().structured(
            schema=HypothesisSet,
            system=prompts.HYPOTHESIZE_SYSTEM,
            user=prompts.hypothesize_user(
                state["incident"],
                state.get("correlation") or {},
                digests,
                state.get("findings") or {},
                previous_attempt,
            ),
            purpose="hypothesize",
            context={
                "incident": state["incident"],
                "evidence": digests,
                "correlation": state.get("correlation") or {},
                "findings": state.get("findings") or {},
                "previous_attempt": previous_attempt,
            },
            metadata={"incident_id": str(incident_id), "iteration": state.get("iteration")},
        )
        await record_usage(run_id, usage)

        # The model gives an index; clamp it rather than trusting it blindly.
        selected_index = min(max(result.selected_index, 0), len(result.hypotheses) - 1)

        stored: list[dict[str, Any]] = []
        async with tenant_session_scope(tenant_id) as session:
            # Re-ranking replaces this run's hypotheses rather than appending, so
            # the UI never shows two competing rankings for one incident.
            await session.execute(
                delete(Hypothesis).where(
                    Hypothesis.incident_id == incident_id,
                    Hypothesis.agent_run_id == run_id,
                )
            )
            for rank, item in enumerate(result.hypotheses):
                supporting = valid_citations(item.supporting_evidence_ids, digests)
                contradicting = valid_citations(item.contradicting_evidence_ids, digests)
                row = Hypothesis(
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    agent_run_id=run_id,
                    title=item.title[:400],
                    statement=item.statement,
                    category=item.category,
                    confidence=item.confidence,
                    rank=rank,
                    is_selected=(rank == selected_index),
                    supporting_evidence_ids=supporting,
                    contradicting_evidence_ids=contradicting,
                    reasoning=item.reasoning,
                    disconfirming_test=item.disconfirming_test or None,
                )
                session.add(row)
                await session.flush()
                stored.append(
                    {
                        "id": str(row.id),
                        "title": row.title,
                        "statement": row.statement,
                        "category": row.category,
                        "confidence": row.confidence,
                        "rank": rank,
                        "is_selected": row.is_selected,
                        "supporting_evidence_ids": supporting,
                        "contradicting_evidence_ids": contradicting,
                        "reasoning": row.reasoning,
                        "disconfirming_test": row.disconfirming_test,
                    }
                )

        selected = stored[selected_index]

        async with tenant_session_scope(tenant_id) as session:
            incident = await session.get(Incident, incident_id)
            if incident is not None:
                incident.root_cause_summary = selected["title"]
                incident.root_cause_confidence = selected["confidence"]

        step.set_output(
            f"{len(stored)} hypothesis(es); leading: {selected['title']} "
            f"at {selected['confidence']:.0%}",
            hypotheses=[{"title": h["title"], "confidence": h["confidence"]} for h in stored],
            selected=selected["title"],
        )

        for item in stored:
            await events.emit(
                type=AgentEventType.HYPOTHESIS_ADDED,
                incident_id=incident_id,
                tenant_id=tenant_id,
                phase=AgentPhase.HYPOTHESIZE,
                title=item["title"],
                message=item["statement"][:400],
                run_id=run_id,
                confidence=item["confidence"],
                rank=item["rank"],
                is_selected=item["is_selected"],
                hypothesis_id=item["id"],
            )

        await add_timeline(
            state,
            title=f"Leading hypothesis: {selected['title']}",
            body=(
                f"{selected['statement']}\n\n"
                f"Confidence: {selected['confidence']:.0%}\n"
                f"Selection: {result.selection_reasoning}"
                + (
                    f"\n\nDisconfirming test: {selected['disconfirming_test']}"
                    if selected.get("disconfirming_test")
                    else ""
                )
            ),
            phase=AgentPhase.HYPOTHESIZE,
            confidence=selected["confidence"],
            alternatives=[h["title"] for h in stored if not h["is_selected"]],
        )

    return {
        "hypotheses": stored,
        "selected_hypothesis": selected,
        "needs_more_investigation": result.needs_more_investigation,
        "additional_questions": list(result.additional_questions),
        "phase": str(AgentPhase.HYPOTHESIZE),
    }


def _previous_attempt(state: InvestigationState) -> dict[str, Any] | None:
    """Context for a re-investigation after a failed remediation."""
    if int(state.get("iteration") or 0) <= 1:
        return None
    verification = state.get("verification") or {}
    if not verification or verification.get("outcome") == "recovered":
        return None
    executed = state.get("execution_results") or []
    return {
        "title": (state.get("selected_hypothesis") or {}).get("title"),
        "action": ", ".join(str(r.get("action_key")) for r in executed) or "(none executed)",
        "verification_summary": verification.get("summary", ""),
    }
