"""End-to-end: the whole graph, against the simulated world.

These are the tests that would catch a regression anywhere in the pipeline —
triage, planning, the parallel fan-out, correlation, hypothesis ranking, the
catalog boundary, the policy engine, the approval interrupt, resumption,
execution, verification and the postmortem.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.db import session_scope
from app.evals.dataset import (
    create_scenario_incident,
    ensure_eval_tenant,
    load_scenario,
    provision_scenario,
)
from app.models.enums import (
    AgentPhase,
    IncidentStatus,
    RemediationStatus,
)
from app.models.incident import (
    AgentRun,
    AgentStep,
    Evidence,
    Hypothesis,
    Incident,
    Postmortem,
)
from app.models.remediation import ActionExecutionLog, Approval, RemediationAction
from app.services import approvals as approval_service
from app.services import investigations


async def run_to_approval(scenario_name: str):  # noqa: ANN201
    """Start an investigation and stop where it pauses for a human."""
    scenario = load_scenario(scenario_name)
    async with session_scope() as session:
        tenant, approver = await ensure_eval_tenant(
            session, slug=f"t-{scenario_name.replace('_', '-')}"
        )
        await provision_scenario(session, tenant=tenant, scenario=scenario)
        incident = await create_scenario_incident(session, tenant=tenant, scenario=scenario)
        ids = (tenant.id, incident.id, approver.id)

    outcome = await investigations.start_investigation(
        incident_id=ids[1], tenant_id=ids[0], triggered_by="test"
    )
    return scenario, ids, outcome


async def test_investigation_pauses_for_approval_before_touching_production() -> None:
    """The single most important behaviour in the product."""
    _scenario, (tenant_id, incident_id, _approver_id), outcome = await run_to_approval(
        "failed_deployment"
    )

    assert outcome["status"] == "awaiting_approval"
    assert outcome["interrupts"], "the graph must be parked on an interrupt"

    async with session_scope() as session:
        actions = list(
            (
                await session.execute(
                    select(RemediationAction).where(RemediationAction.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert actions, "a remediation should have been proposed"
        assert all(a.status is RemediationStatus.AWAITING_APPROVAL for a in actions)

        # Nothing was executed.
        executions = list(
            (
                await session.execute(
                    select(ActionExecutionLog).where(ActionExecutionLog.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert executions == [], "no action may execute before approval"

        incident = await session.get(Incident, incident_id)
        assert incident.status is IncidentStatus.AWAITING_APPROVAL


async def test_full_lifecycle_from_alert_to_postmortem() -> None:
    scenario, (tenant_id, incident_id, approver_id), outcome = await run_to_approval("memory_leak")
    assert outcome["status"] == "awaiting_approval"

    # -- a human approves --------------------------------------------------
    from app.models.tenant import User

    async with session_scope() as session:
        approver = await session.get(User, approver_id)
        pending = await approval_service.outstanding_for_incident(session, incident_id)
        assert len(pending) == 1
        approval = pending[0]
        assert approval.risk_tier.rank >= 2
        assert "restart" in approval.request_summary.lower()
        await approval_service.resolve(
            session, approval=approval, decision="approve", user=approver, note="ok"
        )
        decided = [approval]

    resumed = await investigations.resume_investigation(
        incident_id=incident_id,
        tenant_id=tenant_id,
        resume_value=approval_service.resume_payload(decided),
    )
    assert resumed["status"] == "completed"

    # -- everything landed in the database ---------------------------------
    async with session_scope() as session:
        incident = await session.get(Incident, incident_id)
        assert incident.status is IncidentStatus.CLOSED
        assert incident.resolved_at is not None
        assert incident.mitigated_at is not None
        assert "memory leak" in (incident.root_cause_summary or "").lower()

        evidence = list(
            (await session.execute(select(Evidence).where(Evidence.incident_id == incident_id)))
            .scalars()
            .all()
        )
        assert len(evidence) >= 5
        assert {str(e.investigator) for e in evidence if e.investigator} >= {"logs", "metrics"}

        hypotheses = list(
            (await session.execute(select(Hypothesis).where(Hypothesis.incident_id == incident_id)))
            .scalars()
            .all()
        )
        assert len(hypotheses) >= 2, "the agent should consider alternatives"
        selected = [h for h in hypotheses if h.is_selected]
        assert len(selected) == 1
        assert 0.0 < selected[0].confidence <= 1.0

        actions = list(
            (
                await session.execute(
                    select(RemediationAction).where(RemediationAction.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert [a.action_key for a in actions] == ["k8s.rollout_restart"]
        assert actions[0].status is RemediationStatus.SUCCEEDED

        executions = list(
            (
                await session.execute(
                    select(ActionExecutionLog).where(ActionExecutionLog.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(executions) == 1
        assert executions[0].succeeded is True
        assert executions[0].dry_run is False

        postmortem = (
            await session.execute(select(Postmortem).where(Postmortem.incident_id == incident_id))
        ).scalar_one()
        assert postmortem.markdown
        assert postmortem.evidence_ids
        assert postmortem.action_items

        # Every citation resolves to a real evidence row.
        known = {str(e.id) for e in evidence}
        assert set(map(str, postmortem.evidence_ids)) <= known


async def test_every_phase_is_recorded_as_a_step() -> None:
    _scenario, (tenant_id, incident_id, _approver), _outcome = await run_to_approval(
        "latency_spike"
    )

    async with session_scope() as session:
        run = (
            await session.execute(select(AgentRun).where(AgentRun.incident_id == incident_id))
        ).scalar_one()
        steps = list(
            (
                await session.execute(
                    select(AgentStep).where(AgentStep.run_id == run.id).order_by(AgentStep.sequence)
                )
            )
            .scalars()
            .all()
        )

    phases = {str(s.phase) for s in steps}
    assert {
        str(AgentPhase.TRIAGE),
        str(AgentPhase.PLAN),
        str(AgentPhase.INVESTIGATE),
        str(AgentPhase.CORRELATE),
        str(AgentPhase.HYPOTHESIZE),
        str(AgentPhase.PROPOSE_REMEDIATION),
        str(AgentPhase.POLICY_CHECK),
    } <= phases

    # Sequence numbers are unique and contiguous despite the parallel fan-out.
    sequences = [s.sequence for s in steps]
    assert sequences == sorted(sequences)
    assert len(set(sequences)) == len(sequences)

    # Every step finished cleanly and recorded a duration.
    assert all(s.status == "succeeded" for s in steps), [
        (s.name, s.status, s.error) for s in steps if s.status != "succeeded"
    ]
    assert all(s.duration_ms is not None for s in steps)


async def test_investigators_run_in_parallel_and_all_contribute() -> None:
    _scenario, (_tenant_id, incident_id, _approver), _outcome = await run_to_approval(
        "db_connection_exhaustion"
    )

    async with session_scope() as session:
        steps = list(
            (
                await session.execute(
                    select(AgentStep).where(
                        AgentStep.incident_id == incident_id,
                        AgentStep.phase == AgentPhase.INVESTIGATE,
                    )
                )
            )
            .scalars()
            .all()
        )

    investigators = {str(s.investigator) for s in steps}
    assert {"logs", "metrics", "database", "deployments"} <= investigators

    # Parallelism: the investigator steps overlap in wall-clock time.
    starts = [s.started_at for s in steps]
    ends = [s.finished_at for s in steps if s.finished_at]
    assert max(starts) < max(ends), "investigator steps should overlap, not serialise"


async def test_rejected_approval_does_not_execute() -> None:
    from app.models.tenant import User

    _scenario, (tenant_id, incident_id, approver_id), outcome = await run_to_approval(
        "kubernetes_node_failure"
    )
    assert outcome["status"] == "awaiting_approval"

    async with session_scope() as session:
        approver = await session.get(User, approver_id)
        pending = await approval_service.outstanding_for_incident(session, incident_id)
        approval = pending[0]
        await approval_service.resolve(
            session,
            approval=approval,
            decision="reject",
            user=approver,
            note="we will handle the node manually",
        )
        decided = [approval]

    resumed = await investigations.resume_investigation(
        incident_id=incident_id,
        tenant_id=tenant_id,
        resume_value=approval_service.resume_payload(decided),
    )
    assert resumed["status"] == "completed"

    async with session_scope() as session:
        actions = list(
            (
                await session.execute(
                    select(RemediationAction).where(RemediationAction.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert all(a.status is RemediationStatus.REJECTED for a in actions)

        executions = list(
            (
                await session.execute(
                    select(ActionExecutionLog).where(ActionExecutionLog.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert executions == [], "a rejected action must never execute"

        # A postmortem is still written: a rejected remediation is a finding.
        postmortem = (
            await session.execute(select(Postmortem).where(Postmortem.incident_id == incident_id))
        ).scalar_one_or_none()
        assert postmortem is not None


async def test_global_kill_switch_prevents_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "remediation_disabled", True)

    _scenario, (_tenant_id, incident_id, _approver), outcome = await run_to_approval(
        "failed_deployment"
    )

    # With remediation disabled the policy engine denies everything, so the run
    # completes without ever pausing for approval.
    assert outcome["status"] == "completed"

    async with session_scope() as session:
        actions = list(
            (
                await session.execute(
                    select(RemediationAction).where(RemediationAction.incident_id == incident_id)
                )
            )
            .scalars()
            .all()
        )
        assert actions
        assert all(a.status is RemediationStatus.BLOCKED_BY_POLICY for a in actions)
        assert all(
            any("kill_switch" in v.get("rule", "") for v in a.policy_violations) for a in actions
        )

        approvals = list(
            (await session.execute(select(Approval).where(Approval.incident_id == incident_id)))
            .scalars()
            .all()
        )
        assert approvals == [], "a denied action must not create an approval request"


async def test_agent_run_records_usage_and_trace_metadata() -> None:
    _scenario, (_tenant_id, incident_id, _approver), _outcome = await run_to_approval(
        "latency_spike"
    )

    async with session_scope() as session:
        run = (
            await session.execute(select(AgentRun).where(AgentRun.incident_id == incident_id))
        ).scalar_one()

    assert run.thread_id.startswith("incident:")
    assert run.attempt == 1
    assert run.tool_call_count > 0
    assert run.prompt_tokens > 0
    assert run.plan.get("tasks")
