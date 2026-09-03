"""Remediation nodes: propose → policy check → (human) → execute.

The boundary between reasoning and action lives here. ``propose_node`` is the
last node where model output matters; from ``policy_check_node`` onward every
decision is deterministic Python or a human being.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.agents import prompts
from app.agents.contracts import RemediationProposal, VerificationCheck
from app.agents.llm import get_llm
from app.agents.runtime import (
    add_timeline,
    agent_step,
    error_entry,
    load_evidence_digests,
    record_usage,
    set_phase,
    valid_citations,
)
from app.agents.state import InvestigationState
from app.core.config import settings
from app.core.db import tenant_session_scope
from app.core.errors import OpsPilotError
from app.core.logging import get_logger
from app.integrations.prometheus import STANDARD_QUERIES
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    ApprovalStatus,
    AuditAction,
    IncidentStatus,
    RemediationStatus,
)
from app.models.incident import Incident
from app.models.remediation import Approval, RemediationAction
from app.models.tenant import Tenant
from app.services import audit, events
from app.services.actions import catalog_for_prompt, get_action, list_actions, registry_fingerprint
from app.services.executor import evaluate_action, execute_action
from app.services.notifications import notify_approval_requested
from app.services.policy import TenantPolicy

log = get_logger(__name__)


def measurable_checks(
    checks: Iterable[VerificationCheck],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Split proposed recovery checks into the queryable ones and the invented ones.

    ``standard_query`` accepts a fixed vocabulary. A check naming anything else —
    however plausible a Prometheus series it looks — returns no data at all, and a
    check that cannot be measured cannot confirm recovery, so the postmortem node
    parks the incident as ``failed`` however well the remediation worked. Drop them
    here, the same way an invented action key is dropped against the catalog.
    """
    kept: list[dict[str, Any]] = []
    unmeasurable: list[str] = []
    for check in checks:
        if check.metric not in STANDARD_QUERIES:
            unmeasurable.append(check.metric)
            continue
        kept.append(
            {
                "name": check.name,
                "metric": check.metric,
                "comparator": check.comparator,
                "threshold": check.threshold,
                "description": check.description,
            }
        )
    return kept, unmeasurable


# ==========================================================================
# propose
# ==========================================================================
async def propose_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])

    hypothesis = state.get("selected_hypothesis") or {}
    digests = await load_evidence_digests(incident_id)

    async with agent_step(
        state,
        name="Propose remediation",
        phase=AgentPhase.PROPOSE_REMEDIATION,
        input_summary=f"For hypothesis: {hypothesis.get('title', '(none)')}",
    ) as step:
        await set_phase(state, AgentPhase.PROPOSE_REMEDIATION)

        # The model is shown only actions this tenant could actually run.
        async with tenant_session_scope(tenant_id) as session:
            from app.integrations.base import ClientRegistry

            registry = await ClientRegistry(tenant_id).load(session)
            providers = set(registry.as_dict())
            await registry.aclose()

            # The same policy the proposal will be judged against, so the prompt
            # can state the tenant's real evidence bar rather than a default.
            tenant_policy = TenantPolicy.for_tenant(await session.get(Tenant, tenant_id))

        specs = list_actions(providers=providers or None)
        catalog_keys = [s.key for s in specs]

        blocked_previously = [
            {"action_key": d.get("action_key"), "reason": d.get("reason")}
            for d in (state.get("policy_decisions") or [])
            if not d.get("allowed")
        ]

        proposal, usage = await get_llm().structured(
            schema=RemediationProposal,
            system=prompts.REMEDIATION_SYSTEM.format(
                catalog=catalog_for_prompt(specs),
                metrics=", ".join(sorted(STANDARD_QUERIES)),
                min_evidence=tenant_policy.min_evidence_high_risk,
            ),
            user=prompts.remediation_user(
                state["incident"], hypothesis, digests, blocked_previously
            ),
            purpose="propose_remediation",
            context={
                "incident": state["incident"],
                "selected_hypothesis": hypothesis,
                "evidence": digests,
                "available_action_keys": catalog_keys,
            },
            metadata={"incident_id": str(incident_id)},
        )
        await record_usage(run_id, usage)

        verification_checks, unmeasurable = measurable_checks(proposal.verification_checks)
        if unmeasurable:
            log.warning(
                "remediation.unmeasurable_checks_dropped",
                incident_id=str(incident_id),
                metrics=unmeasurable,
                available=sorted(STANDARD_QUERIES),
            )

        if proposal.no_action_recommended or not proposal.actions:
            step.set_output(
                f"No action recommended: {proposal.no_action_reason[:200]}",
                no_action=True,
            )
            await add_timeline(
                state,
                title="No automated remediation recommended",
                body=proposal.no_action_reason
                or "The agent did not identify a safe automated remediation.",
                phase=AgentPhase.PROPOSE_REMEDIATION,
            )
            return {
                "proposal": {
                    "no_action_recommended": True,
                    "no_action_reason": proposal.no_action_reason,
                    "verification_plan": proposal.verification_plan,
                },
                "proposed_action_ids": [],
                "verification_checks": verification_checks,
                "phase": str(AgentPhase.PROPOSE_REMEDIATION),
            }

        # ---- validate every proposal against the catalog -----------------
        created: list[str] = []
        rejected: list[dict[str, Any]] = []

        async with tenant_session_scope(tenant_id) as session:
            incident = await session.get(Incident, incident_id)
            for item in sorted(proposal.actions, key=lambda a: a.sequence):
                try:
                    spec = get_action(item.action_key)
                    params = spec.parse_params(item.params)
                except OpsPilotError as exc:
                    # This is the design working: an unusable proposal is dropped
                    # here, loudly, and never becomes a database row.
                    rejected.append({"action_key": item.action_key, "reason": exc.message})
                    log.warning(
                        "propose.rejected",
                        action_key=item.action_key,
                        reason=exc.message,
                        incident_id=str(incident_id),
                    )
                    continue

                idempotency_key = f"{incident_id}:{spec.key}:{state.get('iteration', 1)}"

                # This node raises the approval interrupt, and LangGraph
                # re-executes an interrupted node from the top when the graph
                # resumes — so the insert has to be replay-safe. Without this,
                # every resume after a human approval dies on the
                # idempotency-key constraint and the action never runs.
                existing = (
                    await session.execute(
                        select(RemediationAction).where(
                            RemediationAction.tenant_id == tenant_id,
                            RemediationAction.idempotency_key == idempotency_key,
                        )
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    log.info(
                        "propose.replayed",
                        action_key=spec.key,
                        action_id=str(existing.id),
                        incident_id=str(incident_id),
                    )
                    created.append(str(existing.id))
                    continue

                radius = spec.blast_radius(params)
                action = RemediationAction(
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    agent_run_id=run_id,
                    hypothesis_id=(uuid.UUID(hypothesis["id"]) if hypothesis.get("id") else None),
                    action_key=spec.key,
                    title=spec.title,
                    params=params.model_dump(mode="json"),
                    rationale=item.rationale,
                    expected_effect=item.expected_effect,
                    evidence_ids=valid_citations(item.evidence_ids, digests),
                    sequence=item.sequence,
                    risk_tier=spec.risk_tier,
                    blast_radius=radius.to_dict(),
                    is_reversible=spec.is_reversible,
                    status=RemediationStatus.PROPOSED,
                    max_attempts=spec.max_attempts,
                    idempotency_key=idempotency_key,
                )
                session.add(action)
                await session.flush()
                created.append(str(action.id))

                await audit.record_agent(
                    session,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    action=AuditAction.REMEDIATION_PROPOSED,
                    resource_type="remediation_action",
                    resource_id=action.id,
                    summary=f"Proposed {spec.key}: {item.rationale[:300]}",
                    risk_tier=str(spec.risk_tier),
                    blast_radius=radius.to_dict(),
                )
                await events.emit(
                    type=AgentEventType.ACTION_PROPOSED,
                    incident_id=incident_id,
                    tenant_id=tenant_id,
                    phase=AgentPhase.PROPOSE_REMEDIATION,
                    title=spec.title,
                    message=item.rationale[:400],
                    run_id=run_id,
                    action_id=str(action.id),
                    action_key=spec.key,
                    risk_tier=str(spec.risk_tier),
                    params=action.params,
                    blast_radius=radius.to_dict(),
                )

            if incident is not None and created:
                incident.status = IncidentStatus.AWAITING_APPROVAL

        step.set_output(
            f"{len(created)} action(s) proposed"
            + (f", {len(rejected)} rejected by the catalog" if rejected else ""),
            proposed=len(created),
            rejected=rejected,
        )

        if created:
            await add_timeline(
                state,
                title=f"{len(created)} remediation action(s) proposed",
                body="\n".join(
                    f"- {a.action_key}: {a.rationale[:200]}"
                    for a in await _load_actions(created, tenant_id=tenant_id)
                ),
                phase=AgentPhase.PROPOSE_REMEDIATION,
            )

    return {
        "proposal": {
            "no_action_recommended": False,
            "verification_plan": proposal.verification_plan,
            "rollback_plan": proposal.rollback_plan,
            "rejected": rejected,
        },
        "proposed_action_ids": created,
        "verification_checks": verification_checks,
        "phase": str(AgentPhase.PROPOSE_REMEDIATION),
    }


async def _load_actions(action_ids: list[str], *, tenant_id: uuid.UUID) -> list[RemediationAction]:
    async with tenant_session_scope(tenant_id) as session:
        return list(
            (
                await session.execute(
                    select(RemediationAction)
                    .where(RemediationAction.id.in_([uuid.UUID(a) for a in action_ids]))
                    .order_by(RemediationAction.sequence)
                )
            )
            .scalars()
            .all()
        )


# ==========================================================================
# policy check
# ==========================================================================
async def policy_check_node(state: InvestigationState) -> dict[str, Any]:
    """Deterministic gate. Creates Approval rows for anything needing a human."""
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    run_id = uuid.UUID(state["run_id"])
    action_ids = state.get("proposed_action_ids") or []

    if not action_ids:
        return {
            "policy_decisions": [],
            "pending_approval_ids": [],
            "phase": str(AgentPhase.POLICY_CHECK),
        }

    decisions: list[dict[str, Any]] = []
    pending: list[str] = []
    auto_ok: list[str] = []

    async with agent_step(
        state,
        name="Policy and risk check",
        phase=AgentPhase.POLICY_CHECK,
        input_summary=f"Evaluating {len(action_ids)} proposed action(s)",
    ) as step:
        await set_phase(state, AgentPhase.POLICY_CHECK)
        hypothesis = state.get("selected_hypothesis") or {}

        async with tenant_session_scope(tenant_id) as session:
            incident = await session.get(Incident, incident_id)
            if incident is None:
                raise LookupError("incident disappeared during policy check")

            for action_id in action_ids:
                action = await session.get(RemediationAction, uuid.UUID(action_id))
                if action is None:
                    continue

                spec = get_action(action.action_key)
                params = spec.parse_params(action.params)
                decision = await evaluate_action(
                    session,
                    incident=incident,
                    action=action,
                    spec=spec,
                    params=params,
                    hypothesis_confidence=hypothesis.get("confidence"),
                    supporting_evidence_count=len(action.evidence_ids or []),
                )

                decision_dict = {
                    **decision.to_dict(),
                    "action_id": action_id,
                    "action_key": action.action_key,
                    "catalog_fingerprint": registry_fingerprint(),
                }
                decisions.append(
                    {**decision_dict, "reason": decision.reason or decision.deny_summary()}
                )

                action.policy_decision = decision_dict
                action.policy_violations = [v.to_dict() for v in decision.violations]
                action.risk_tier = decision.risk_tier
                action.requires_approval = decision.requires_approval
                action.blast_radius = decision.effective_blast_radius

                await events.emit(
                    type=AgentEventType.POLICY_DECISION,
                    incident_id=incident_id,
                    tenant_id=tenant_id,
                    phase=AgentPhase.POLICY_CHECK,
                    title=(
                        f"{action.action_key}: " + ("allowed" if decision.allowed else "blocked")
                    ),
                    message=decision.reason or decision.deny_summary(),
                    action_id=action_id,
                    allowed=decision.allowed,
                    requires_approval=decision.requires_approval,
                    risk_tier=str(decision.risk_tier),
                    violations=[v.rule for v in decision.violations],
                )

                if not decision.allowed:
                    action.status = RemediationStatus.BLOCKED_BY_POLICY
                    await audit.record_agent(
                        session,
                        tenant_id=tenant_id,
                        incident_id=incident_id,
                        action=AuditAction.REMEDIATION_POLICY_BLOCKED,
                        resource_type="remediation_action",
                        resource_id=action.id,
                        summary=decision.deny_summary(),
                        violations=[v.rule for v in decision.violations],
                    )
                    continue

                if decision.requires_approval:
                    # Replay-safe for the same reason as the proposal insert:
                    # this node is re-executed when the graph resumes after the
                    # approval interrupt, and an action has at most one
                    # approval. Reuse the decided row rather than re-requesting
                    # a decision the human has already made.
                    prior = (
                        await session.execute(
                            select(Approval).where(Approval.action_id == action.id)
                        )
                    ).scalar_one_or_none()
                    if prior is not None:
                        if prior.status == ApprovalStatus.PENDING:
                            pending.append(str(prior.id))
                        log.info(
                            "policy_check.approval_replayed",
                            approval_id=str(prior.id),
                            status=str(prior.status),
                            incident_id=str(incident_id),
                        )
                        continue

                    approval = Approval(
                        tenant_id=tenant_id,
                        incident_id=incident_id,
                        action_id=action.id,
                        agent_run_id=run_id,
                        status=ApprovalStatus.PENDING,
                        risk_tier=decision.risk_tier,
                        required_role=str(decision.required_role),
                        request_summary=_approval_summary(action, decision, hypothesis),
                        context={
                            "action_key": action.action_key,
                            "params": action.params,
                            "rationale": action.rationale,
                            "expected_effect": action.expected_effect,
                            "blast_radius": decision.effective_blast_radius,
                            "risk_tier": str(decision.risk_tier),
                            "policy_reason": decision.reason,
                            "warnings": [w.to_dict() for w in decision.warnings],
                            "checklist": spec.approval_checklist,
                            "hypothesis": {
                                "title": hypothesis.get("title"),
                                "confidence": hypothesis.get("confidence"),
                            },
                            "evidence_ids": action.evidence_ids,
                            "is_reversible": spec.is_reversible,
                        },
                        requested_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC)
                        + timedelta(minutes=settings.approval_ttl_minutes),
                    )
                    session.add(approval)
                    await session.flush()
                    action.status = RemediationStatus.AWAITING_APPROVAL
                    pending.append(str(approval.id))
                else:
                    action.status = RemediationStatus.APPROVED
                    auto_ok.append(action_id)

            if incident is not None:
                incident.status = (
                    IncidentStatus.AWAITING_APPROVAL if pending else IncidentStatus.REMEDIATING
                )

        step.set_output(
            f"{len(auto_ok)} auto-approved, {len(pending)} awaiting human approval, "
            f"{len([d for d in decisions if not d['allowed']])} blocked",
            auto_approved=len(auto_ok),
            pending=len(pending),
            blocked=len([d for d in decisions if not d["allowed"]]),
        )

    for approval_id in pending:
        await _announce_approval(tenant_id, incident_id, uuid.UUID(approval_id))

    if pending:
        await add_timeline(
            state,
            title=f"Waiting for human approval ({len(pending)} action(s))",
            body="Execution is paused until an approver decides.",
            phase=AgentPhase.AWAIT_APPROVAL,
        )

    return {
        "policy_decisions": decisions,
        "pending_approval_ids": pending,
        "phase": str(AgentPhase.POLICY_CHECK),
    }


def _approval_summary(action: RemediationAction, decision: Any, hypothesis: dict[str, Any]) -> str:
    radius = decision.effective_blast_radius
    lines = [
        action.rationale,
        "",
        f"Action: {action.action_key} with {action.params}",
        f"Expected effect: {action.expected_effect}",
        f"Risk: {decision.risk_tier} — {decision.reason}",
        (
            f"Blast radius: {radius.get('scope')} affecting "
            f"~{radius.get('estimated_affected_units')} unit(s)"
        ),
        f"Reversible: {'yes' if action.is_reversible else 'no'}",
    ]
    if radius.get("causes_downtime"):
        lines.append("WARNING: this action causes downtime.")
    if radius.get("touches_data"):
        lines.append("WARNING: this action touches data and cannot be undone.")
    if radius.get("notes"):
        lines.append(f"Note: {radius['notes']}")
    if hypothesis:
        lines.append(
            f"Derived from hypothesis '{hypothesis.get('title')}' at "
            f"{float(hypothesis.get('confidence') or 0):.0%} confidence."
        )
    return "\n".join(lines)


async def _announce_approval(
    tenant_id: uuid.UUID, incident_id: uuid.UUID, approval_id: uuid.UUID
) -> None:
    async with tenant_session_scope(tenant_id) as session:
        approval = await session.get(Approval, approval_id)
        incident = await session.get(Incident, incident_id)
        if approval is None or incident is None:
            return
        action = await session.get(RemediationAction, approval.action_id)
        await events.emit(
            type=AgentEventType.APPROVAL_REQUESTED,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.AWAIT_APPROVAL,
            title=f"Approval required: {action.title if action else ''}",
            message=approval.request_summary[:600],
            approval_id=str(approval_id),
            action_id=str(approval.action_id),
            risk_tier=str(approval.risk_tier),
            required_role=approval.required_role,
            expires_at=approval.expires_at.isoformat(),
        )
        try:
            await notify_approval_requested(session, approval=approval, incident=incident)
        except Exception as exc:  # noqa: BLE001 - notification is best effort
            log.warning("approval.notify_failed", error=str(exc)[:300])


# ==========================================================================
# await approval  (LangGraph interrupt)
# ==========================================================================
async def await_approval_node(state: InvestigationState) -> dict[str, Any]:
    """Suspend the graph until a human decides.

    ``interrupt()`` persists the checkpoint and stops the run. The API resolves
    the approval and enqueues a resume with ``Command(resume=...)``; execution
    picks up exactly here, in a fresh process if need be.
    """
    from langgraph.types import interrupt

    pending = state.get("pending_approval_ids") or []
    if not pending:
        return {"approval_outcome": {"status": "not_required"}}

    await set_phase(state, AgentPhase.AWAIT_APPROVAL)

    async with tenant_session_scope(uuid.UUID(state["tenant_id"])) as session:
        approvals = list(
            (
                await session.execute(
                    select(Approval).where(Approval.id.in_([uuid.UUID(a) for a in pending]))
                )
            )
            .scalars()
            .all()
        )
        request = {
            "type": "approval_required",
            "incident_id": state["incident_id"],
            "approvals": [
                {
                    "approval_id": str(a.id),
                    "action_id": str(a.action_id),
                    "risk_tier": str(a.risk_tier),
                    "required_role": a.required_role,
                    "summary": a.request_summary,
                    "expires_at": a.expires_at.isoformat(),
                }
                for a in approvals
            ],
        }

    # Blocks here. The value supplied on resume is returned.
    decision: Any = interrupt(request)

    outcome = decision if isinstance(decision, dict) else {"status": str(decision)}
    log.info(
        "approval.resumed",
        incident_id=state["incident_id"],
        outcome=outcome.get("status"),
    )
    return {
        "approval_outcome": outcome,
        "phase": str(AgentPhase.AWAIT_APPROVAL),
    }


# ==========================================================================
# execute
# ==========================================================================
async def execute_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])

    async with agent_step(
        state,
        name="Execute approved remediation",
        phase=AgentPhase.EXECUTE,
        input_summary="Running approved actions in sequence",
    ) as step:
        await set_phase(state, AgentPhase.EXECUTE)

        results: list[dict[str, Any]] = []
        async with tenant_session_scope(tenant_id) as session:
            actions = list(
                (
                    await session.execute(
                        select(RemediationAction)
                        .where(
                            RemediationAction.incident_id == incident_id,
                            RemediationAction.status == RemediationStatus.APPROVED,
                        )
                        .order_by(RemediationAction.sequence, RemediationAction.created_at)
                    )
                )
                .scalars()
                .all()
            )

            for action in actions:
                try:
                    outcome = await execute_action(
                        session,
                        action,
                        actor="opspilot-agent",
                        actor_type="agent",
                    )
                    results.append({**outcome.to_dict(), "action_key": action.action_key})
                except OpsPilotError as exc:
                    results.append(
                        {
                            "action_id": str(action.id),
                            "action_key": action.action_key,
                            "succeeded": False,
                            "error": exc.message,
                            "status": str(action.status),
                        }
                    )
                    log.warning(
                        "execute.action_error", action_key=action.action_key, error=exc.message
                    )
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        {
                            "action_id": str(action.id),
                            "action_key": action.action_key,
                            "succeeded": False,
                            "error": str(exc)[:500],
                        }
                    )
                    log.exception("execute.unexpected", action_id=str(action.id))

                # Stop the chain on the first failure: later actions were planned
                # assuming the earlier one worked.
                if results and not results[-1]["succeeded"]:
                    break

        succeeded = [r for r in results if r.get("succeeded")]
        step.set_output(
            f"{len(succeeded)}/{len(results)} action(s) succeeded",
            results=[
                {"action_key": r.get("action_key"), "succeeded": r.get("succeeded")}
                for r in results
            ],
        )

        if results:
            await add_timeline(
                state,
                title=f"Remediation executed: {len(succeeded)}/{len(results)} succeeded",
                body="\n".join(
                    f"- {r.get('action_key')}: {r.get('summary') or r.get('error')}"
                    for r in results
                ),
                phase=AgentPhase.EXECUTE,
            )

    return {
        "execution_results": results,
        "phase": str(AgentPhase.EXECUTE),
        "errors": [
            error_entry("execute", RuntimeError(r.get("error", "unknown")))
            for r in results
            if not r.get("succeeded")
        ],
    }
