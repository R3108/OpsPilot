"""Postmortem node.

The document is assembled from database rows — timeline, evidence, actions,
verification — and every claim the model makes is checked against the evidence
set it was shown. Citations that do not resolve are dropped and the document is
marked as having unverified claims rather than silently publishing them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.agents import prompts
from app.agents.contracts import PostmortemDraft
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
from app.core.db import session_scope
from app.core.logging import get_logger
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    AuditAction,
    IncidentStatus,
)
from app.models.incident import Incident, Postmortem, TimelineEntry
from app.models.remediation import RemediationAction
from app.services import audit, events
from app.services.similarity import store_incident_embedding

log = get_logger(__name__)


async def postmortem_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])

    async with agent_step(
        state,
        name="Generate postmortem",
        phase=AgentPhase.POSTMORTEM,
        input_summary="Assembling an evidence-backed postmortem",
    ) as step:
        await set_phase(state, AgentPhase.POSTMORTEM)

        digests = await load_evidence_digests(incident_id)

        async with session_scope() as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                raise LookupError("incident disappeared before postmortem")

            timeline_rows = list(
                (
                    await session.execute(
                        select(TimelineEntry)
                        .where(TimelineEntry.incident_id == incident_id)
                        .order_by(TimelineEntry.occurred_at)
                    )
                )
                .scalars()
                .all()
            )
            action_rows = list(
                (
                    await session.execute(
                        select(RemediationAction)
                        .where(RemediationAction.incident_id == incident_id)
                        .order_by(RemediationAction.created_at)
                    )
                )
                .scalars()
                .all()
            )
            snapshot = {
                "id": str(incident.id),
                "reference": incident.reference,
                "title": incident.title,
                "description": incident.description,
                "severity": str(incident.severity),
                "status": str(incident.status),
                "source": str(incident.source),
                "service": incident.service,
                "environment": incident.environment,
                "namespace": incident.namespace,
                "detected_at": incident.detected_at.isoformat(),
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "labels": incident.labels,
            }
            metrics = {
                "time_to_detect_seconds": incident.time_to_detect_seconds,
                "time_to_mitigate_seconds": incident.time_to_mitigate_seconds,
                "time_to_resolve_seconds": incident.time_to_resolve_seconds,
                "evidence_count": len(digests),
                "hypothesis_count": len(state.get("hypotheses") or []),
                "actions_executed": sum(1 for a in action_rows if str(a.status) == "succeeded"),
                "investigation_passes": int(state.get("iteration") or 1),
            }

        timeline = [
            {
                "occurred_at": t.occurred_at.isoformat(),
                "actor_label": t.actor_label,
                "title": t.title,
                "body": t.body,
                "phase": str(t.phase) if t.phase else None,
            }
            for t in timeline_rows
        ]
        actions = [
            {
                "action_key": a.action_key,
                "title": a.title,
                "status": str(a.status),
                "rationale": a.rationale,
                "params": a.params,
                "execution_result": a.execution_result,
                "risk_tier": str(a.risk_tier),
            }
            for a in action_rows
        ]
        hypothesis = state.get("selected_hypothesis") or {}
        verification = state.get("verification") or {}

        draft, usage = await get_llm().structured(
            schema=PostmortemDraft,
            system=prompts.POSTMORTEM_SYSTEM,
            user=prompts.postmortem_user(
                snapshot, hypothesis, digests, timeline, actions, verification
            ),
            purpose="postmortem",
            context={
                "incident": snapshot,
                "selected_hypothesis": hypothesis,
                "evidence": digests,
                "actions": actions,
                "verification": verification,
                "gaps": (state.get("correlation") or {}).get("gaps") or [],
                "customer_impact": state.get("customer_impact"),
            },
            metadata={"incident_id": str(incident_id)},
        )
        await record_usage(run_id, usage)

        cited = valid_citations(draft.cited_evidence_ids, digests)
        dropped = len(draft.cited_evidence_ids) - len(cited)
        if dropped:
            log.warning("postmortem.dropped_citations", count=dropped, incident_id=str(incident_id))

        markdown = _render_markdown(
            draft, snapshot, timeline, actions, digests, cited, verification, metrics
        )

        async with session_scope() as session:
            existing = (
                await session.execute(
                    select(Postmortem).where(Postmortem.incident_id == incident_id)
                )
            ).scalar_one_or_none()

            postmortem = existing or Postmortem(tenant_id=tenant_id, incident_id=incident_id)
            postmortem.title = draft.title[:500]
            postmortem.summary = draft.summary
            postmortem.impact = draft.impact
            postmortem.root_cause = draft.root_cause
            postmortem.detection = draft.detection
            postmortem.resolution = draft.resolution
            postmortem.lessons_learned = draft.lessons_learned
            postmortem.timeline_markdown = _timeline_markdown(timeline)
            postmortem.action_items = [
                {
                    "title": item.title,
                    "owner": item.owner_hint,
                    "priority": item.priority,
                    "rationale": item.rationale,
                }
                for item in draft.action_items
            ]
            postmortem.evidence_ids = cited
            postmortem.metrics = {
                **metrics,
                "dropped_citations": dropped,
                "contributing_factors": list(draft.contributing_factors),
                "what_went_well": list(draft.what_went_well),
                "what_went_poorly": list(draft.what_went_poorly),
            }
            postmortem.markdown = markdown
            postmortem.generated_by_run_id = run_id
            if existing is None:
                session.add(postmortem)
            await session.flush()
            postmortem_id = str(postmortem.id)

            incident = await session.get(Incident, incident_id)
            if incident is not None:
                if incident.status is IncidentStatus.RESOLVED:
                    incident.status = IncidentStatus.CLOSED
                    incident.closed_at = datetime.now(UTC)
                elif incident.status.is_active:
                    # We reached the write-up without ever verifying a recovery:
                    # the graph ran out of time, or had nothing confident enough
                    # to propose. Either way it has given up, so park the
                    # incident for a human. Leaving it in a live status would
                    # make the console report an investigation that is no longer
                    # running, with nothing left to move it along.
                    incident.status = IncidentStatus.FAILED
                incident.root_cause_summary = hypothesis.get("title") or incident.root_cause_summary
                # Index the resolved incident so future investigations can find it.
                await store_incident_embedding(session, incident, root_cause=draft.root_cause)

            await audit.record_agent(
                session,
                tenant_id=tenant_id,
                incident_id=incident_id,
                action=AuditAction.POSTMORTEM_GENERATED,
                resource_type="postmortem",
                resource_id=postmortem_id,
                summary=f"Postmortem generated citing {len(cited)} evidence item(s)",
                dropped_citations=dropped,
            )

        step.set_output(
            f"Postmortem generated with {len(cited)} cited evidence item(s) and "
            f"{len(draft.action_items)} action item(s)",
            postmortem_id=postmortem_id,
            cited=len(cited),
            action_items=len(draft.action_items),
        )

        await events.emit(
            type=AgentEventType.POSTMORTEM_READY,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.POSTMORTEM,
            title=draft.title[:200],
            message=draft.summary[:400],
            postmortem_id=postmortem_id,
        )
        await add_timeline(
            state,
            title="Postmortem generated",
            body=draft.summary,
            phase=AgentPhase.POSTMORTEM,
            postmortem_id=postmortem_id,
        )

    return {
        "postmortem_id": postmortem_id,
        "phase": str(AgentPhase.DONE),
        "done": True,
    }


# --------------------------------------------------------------------------
def _timeline_markdown(timeline: list[dict[str, Any]]) -> str:
    return "\n".join(
        f"- **{t['occurred_at']}** — _{t['actor_label']}_ — {t['title']}"
        + (f"\n  > {t['body'][:400]}" if t.get("body") else "")
        for t in timeline
    )


def _render_markdown(
    draft: PostmortemDraft,
    incident: dict[str, Any],
    timeline: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    cited: list[str],
    verification: dict[str, Any],
    metrics: dict[str, Any],
) -> str:
    by_id = {e["id"]: e for e in evidence}

    def _duration(seconds: float | None) -> str:
        if seconds is None:
            return "—"
        minutes, secs = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m" if hours else f"{minutes}m {secs}s"

    evidence_section = (
        "\n".join(
            f"- `{by_id[e_id]['citation']}` **{by_id[e_id]['kind']}** from "
            f"{by_id[e_id]['source']} — {by_id[e_id]['summary']}"
            for e_id in cited
            if e_id in by_id
        )
        or "_No evidence was cited._"
    )

    actions_section = (
        "\n".join(
            f"- **{a['action_key']}** ({a['status']}, {a['risk_tier']} risk) — {a['title']}\n"
            f"  - Rationale: {a['rationale']}\n"
            f"  - Parameters: `{a['params']}`\n"
            f"  - Result: {(a.get('execution_result') or {}).get('summary', '—')}"
            for a in actions
        )
        or "_No remediation actions were executed._"
    )

    checks_section = (
        "\n".join(
            f"- {'✅' if c.get('passed') else '❌'} **{c.get('name')}** — observed "
            f"`{c.get('observed')}`, required `{c.get('comparator')} {c.get('threshold')}`"
            for c in verification.get("checks") or []
        )
        or "_No automated verification checks were evaluated._"
    )

    action_items = (
        "\n".join(
            f"- [ ] **[{item.priority.upper()}]** {item.title}"
            + (f" _(suggested owner: {item.owner_hint})_" if item.owner_hint else "")
            + (f"\n  - Why: {item.rationale}" if item.rationale else "")
            for item in draft.action_items
        )
        or "_No action items identified._"
    )

    return f"""# {draft.title}

| | |
|---|---|
| **Incident** | {incident["reference"]} |
| **Severity** | {str(incident["severity"]).upper()} |
| **Service** | {incident.get("service") or "—"} |
| **Environment** | {incident.get("environment")} |
| **Detected** | {incident.get("detected_at")} |
| **Resolved** | {incident.get("resolved_at") or "—"} |
| **Time to mitigate** | {_duration(metrics.get("time_to_mitigate_seconds"))} |
| **Time to resolve** | {_duration(metrics.get("time_to_resolve_seconds"))} |
| **Investigation passes** | {metrics.get("investigation_passes")} |

## Summary

{draft.summary}

## Impact

{draft.impact}

## Root cause

{draft.root_cause}

{_contributing(draft)}

## Detection

{draft.detection}

## Resolution

{draft.resolution}

### Remediation actions

{actions_section}

### Recovery verification

{checks_section}

_Outcome: **{verification.get("outcome", "not verified")}** — {verification.get("summary", "")}_

## Timeline

{_timeline_markdown(timeline)}

## Lessons learned

{draft.lessons_learned}

{_bullets("What went well", draft.what_went_well)}

{_bullets("What went poorly", draft.what_went_poorly)}

## Action items

{action_items}

## Evidence

Every claim above is traceable to one of the following, collected by OpsPilot's
read-only investigation tools during the incident:

{evidence_section}

---
_Generated by OpsPilot AI. {metrics.get("evidence_count", 0)} evidence items collected,
{metrics.get("hypothesis_count", 0)} hypotheses considered,
{metrics.get("actions_executed", 0)} remediation action(s) executed._
"""


def _contributing(draft: PostmortemDraft) -> str:
    if not draft.contributing_factors:
        return ""
    body = "\n".join(f"- {factor}" for factor in draft.contributing_factors)
    return f"### Contributing factors\n\n{body}\n"


def _bullets(heading: str, items: list[str]) -> str:
    if not items:
        return ""
    body = "\n".join(f"- {item}" for item in items)
    return f"### {heading}\n\n{body}\n"
