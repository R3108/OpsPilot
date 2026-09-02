"""Resuming a run whose worker died.

``reconcile_stuck_investigations`` is the only thing that rescues an investigation
after its driver disappears, so its two edge cases — a thread with no checkpoint,
and a thread whose wall-clock budget expired while nothing was running — decide
whether the safety net actually saves the run or just marks it dead.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select
from test_investigation_e2e import run_to_approval

from app.agents.graph import get_compiled_graph, thread_config
from app.agents.runtime import deadline_exceeded
from app.core.db import session_scope
from app.evals.dataset import (
    create_scenario_incident,
    ensure_eval_tenant,
    load_scenario,
    provision_scenario,
)
from app.models.enums import AgentPhase
from app.models.incident import AgentRun
from app.services import investigations


async def test_a_rescued_run_is_credited_the_time_it_spent_stranded() -> None:
    """The deadline bounds agent *work*, not the hours a dead worker sat there.

    Without the credit every rescued run resumes past its deadline — the
    reconciler only looks at runs older than twice the timeout — and both
    `after_hypothesize` and `after_verify` divert it straight to postmortem.
    """
    _scenario, (tenant_id, incident_id, _approver_id), _outcome = await run_to_approval(
        "failed_deployment"
    )

    async with session_scope() as session:
        run_id = (
            await session.execute(select(AgentRun.id).where(AgentRun.incident_id == incident_id))
        ).scalar_one()

    graph = await get_compiled_graph()
    config = thread_config(incident_id, tenant_id=tenant_id, run_id=run_id)
    live = await graph.aget_state(config)
    before = datetime.fromisoformat(live.values["deadline_at"])

    # The real checkpoint, backdated: this run last made progress an hour ago.
    stranded_for = timedelta(hours=1)
    stale = SimpleNamespace(
        values=live.values,
        created_at=(datetime.now(UTC) - stranded_for).isoformat(),
    )
    await investigations._credit_stranded_time(
        graph, config, stale, incident_id=incident_id
    )

    resumed = await graph.aget_state(config)
    after = datetime.fromisoformat(resumed.values["deadline_at"])

    assert after - before >= stranded_for - timedelta(seconds=30)
    assert not deadline_exceeded(resumed.values), "a rescued run must still have budget to work"


async def test_resuming_a_run_that_never_checkpointed_is_reported_not_crashed() -> None:
    """Regression: this surfaced as `KeyError: 'incident_id'` inside the triage node.

    `Command(resume=...)` against an empty thread does not fail — the graph starts
    from the top with no state at all.
    """
    scenario = load_scenario("failed_deployment")
    async with session_scope() as session:
        tenant, _approver = await ensure_eval_tenant(session, slug="t-no-checkpoint")
        await provision_scenario(session, tenant=tenant, scenario=scenario)
        incident = await create_scenario_incident(session, tenant=tenant, scenario=scenario)
        run = AgentRun(
            tenant_id=tenant.id,
            incident_id=incident.id,
            thread_id=incident.thread_id,
            attempt=1,
            phase=AgentPhase.TRIAGE,
            status="running",
            started_at=datetime.now(UTC),
        )
        session.add(run)
        await session.flush()
        tenant_id, incident_id, run_id = tenant.id, incident.id, run.id

    outcome = await investigations.resume_investigation(
        incident_id=incident_id,
        tenant_id=tenant_id,
        resume_value={"status": "expired"},
    )

    assert outcome["status"] == "unresumable"
    async with session_scope() as session:
        run = await session.get(AgentRun, run_id)
        assert run is not None
        assert run.status == "failed"
        assert "No checkpoint" in (run.error or "")
