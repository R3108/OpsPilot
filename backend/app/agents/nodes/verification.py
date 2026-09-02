"""Verification node: did the service actually recover?

Deliberately **not** an LLM judgement. The model proposed thresholds during
remediation; this node fetches the metrics itself and evaluates them in Python.
A model is never allowed to declare its own fix successful.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from app.agents.runtime import add_timeline, agent_step, set_phase
from app.agents.state import InvestigationState
from app.core.db import session_scope
from app.core.logging import get_logger
from app.integrations.base import ClientRegistry
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    IncidentStatus,
    IntegrationProvider,
    VerificationOutcome,
)
from app.models.incident import Incident, Verification
from app.services import events

log = get_logger(__name__)

# Give the system a moment to settle before measuring; a pod that restarted one
# second ago has not had time to prove anything.
SETTLE_SECONDS = 20

# Applied when the proposal supplied no checks of its own.
DEFAULT_CHECKS: list[dict[str, Any]] = [
    {
        "name": "error rate below 2%",
        "metric": "error_rate",
        "comparator": "lt",
        "threshold": 0.02,
        "description": "Fallback check: service is not returning widespread errors",
    },
]

COMPARATORS = {
    "lt": lambda v, t: v < t,
    "lte": lambda v, t: v <= t,
    "gt": lambda v, t: v > t,
    "gte": lambda v, t: v >= t,
}
COMPARATOR_TEXT = {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}


async def verify_node(state: InvestigationState) -> dict[str, Any]:
    incident_id = uuid.UUID(state["incident_id"])
    tenant_id = uuid.UUID(state["tenant_id"])
    attempt = int(state.get("iteration") or 1)

    executed = [r for r in (state.get("execution_results") or []) if r.get("succeeded")]
    checks = state.get("verification_checks") or DEFAULT_CHECKS

    async with agent_step(
        state,
        name="Verify recovery",
        phase=AgentPhase.VERIFY,
        input_summary=f"Evaluating {len(checks)} recovery check(s)",
    ) as step:
        await set_phase(state, AgentPhase.VERIFY)

        if not executed:
            outcome = VerificationOutcome.INCONCLUSIVE
            summary = "No remediation executed, so there is nothing to verify."
            evaluated: list[dict[str, Any]] = []
        else:
            await asyncio.sleep(SETTLE_SECONDS if not _in_test_mode() else 0)
            evaluated = await _evaluate_checks(state, checks)
            outcome, summary = _judge(evaluated)

        async with session_scope() as session:
            session.add(
                Verification(
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    action_id=(
                        uuid.UUID(executed[0]["action_id"])
                        if executed and executed[0].get("action_id")
                        else None
                    ),
                    attempt=attempt,
                    outcome=outcome,
                    summary=summary,
                    checks=evaluated,
                    observed_at=datetime.now(UTC),
                )
            )

            incident = await session.get(Incident, incident_id)
            if incident is not None:
                if outcome is VerificationOutcome.RECOVERED:
                    incident.status = IncidentStatus.RESOLVED
                    incident.resolved_at = datetime.now(UTC)
                    if incident.mitigated_at is None:
                        incident.mitigated_at = incident.resolved_at
                elif outcome is VerificationOutcome.NOT_RECOVERED:
                    incident.status = IncidentStatus.INVESTIGATING
                else:
                    incident.status = IncidentStatus.VERIFYING

        recovered = outcome is VerificationOutcome.RECOVERED
        step.set_output(
            f"{outcome}: {summary[:200]}",
            outcome=str(outcome),
            passed=sum(1 for c in evaluated if c.get("passed")),
            total=len(evaluated),
        )

        await events.emit(
            type=AgentEventType.VERIFICATION_RESULT,
            incident_id=incident_id,
            tenant_id=tenant_id,
            phase=AgentPhase.VERIFY,
            title=f"Verification: {outcome}",
            message=summary[:400],
            outcome=str(outcome),
            checks=evaluated,
            recovered=recovered,
        )
        await add_timeline(
            state,
            title=("Service recovered" if recovered else f"Recovery not confirmed ({outcome})"),
            body=summary
            + "\n\n"
            + "\n".join(
                f"{'PASS' if c['passed'] else 'FAIL'} {c['name']}: observed "
                f"{c['observed']} {COMPARATOR_TEXT.get(c['comparator'], c['comparator'])} "
                f"{c['threshold']}"
                for c in evaluated
            ),
            phase=AgentPhase.VERIFY,
            outcome=str(outcome),
        )

    return {
        "verification": {
            "outcome": str(outcome),
            "summary": summary,
            "checks": evaluated,
            "attempt": attempt,
        },
        "recovered": outcome is VerificationOutcome.RECOVERED,
        "phase": str(AgentPhase.VERIFY),
    }


async def _evaluate_checks(
    state: InvestigationState, checks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    tenant_id = uuid.UUID(state["tenant_id"])
    incident_id = uuid.UUID(state["incident_id"])

    evaluated: list[dict[str, Any]] = []
    async with session_scope() as session:
        incident = await session.get(Incident, incident_id)

    registry = ClientRegistry(
        tenant_id, scenario=(incident.labels or {}).get("scenario") if incident else None
    )
    try:
        async with session_scope() as session:
            await registry.load(
                session,
                providers={IntegrationProvider.PROMETHEUS, IntegrationProvider.CLOUDWATCH},
            )
        prom = registry.get(IntegrationProvider.PROMETHEUS)

        for check in checks:
            observed: float | None = None
            error: str | None = None
            if prom is None:
                error = "no metrics integration configured"
            else:
                try:
                    result = await prom.standard_query(
                        check["metric"],
                        service=(incident.service if incident else "") or "",
                        namespace=(incident.namespace if incident else "") or "",
                        database=(incident.labels or {}).get("database", "") if incident else "",
                        # A short window: we want the state *now*, not the average
                        # across the outage.
                        minutes=10,
                    )
                    series = result.get("series") or []
                    if series:
                        observed = series[0].get("last")
                except Exception as exc:  # noqa: BLE001
                    error = str(exc)[:300]

            comparator = check.get("comparator", "lt")
            threshold = float(check.get("threshold", 0))
            passed = (
                COMPARATORS.get(comparator, COMPARATORS["lt"])(observed, threshold)
                if observed is not None
                else False
            )
            evaluated.append(
                {
                    "name": check.get("name", check.get("metric", "check")),
                    "metric": check.get("metric"),
                    "comparator": comparator,
                    "threshold": threshold,
                    "observed": observed,
                    "passed": bool(passed),
                    "error": error,
                    "description": check.get("description", ""),
                }
            )
    finally:
        await registry.aclose()
    return evaluated


def _judge(checks: list[dict[str, Any]]) -> tuple[VerificationOutcome, str]:
    if not checks:
        return (
            VerificationOutcome.INCONCLUSIVE,
            "No recovery checks could be evaluated.",
        )

    measurable = [c for c in checks if c["observed"] is not None]
    if not measurable:
        reasons = {c.get("error") for c in checks if c.get("error")}
        return (
            VerificationOutcome.INCONCLUSIVE,
            "None of the recovery checks could be measured"
            + (f" ({'; '.join(str(r) for r in reasons if r)})" if reasons else "")
            + ". A human should confirm the service state.",
        )

    passed = [c for c in measurable if c["passed"]]
    if len(passed) == len(measurable):
        return (
            VerificationOutcome.RECOVERED,
            f"All {len(passed)} measurable recovery check(s) passed: "
            + "; ".join(f"{c['name']} observed {c['observed']:.4g}" for c in passed),
        )
    if passed:
        failing = [c for c in measurable if not c["passed"]]
        return (
            VerificationOutcome.PARTIAL,
            f"{len(passed)}/{len(measurable)} checks passed. Still failing: "
            + "; ".join(
                f"{c['name']} observed {c['observed']:.4g}, needs "
                f"{COMPARATOR_TEXT.get(c['comparator'], '')} {c['threshold']:.4g}"
                for c in failing
            ),
        )
    return (
        VerificationOutcome.NOT_RECOVERED,
        "No recovery check passed: "
        + "; ".join(
            f"{c['name']} observed {c['observed']:.4g}, needs "
            f"{COMPARATOR_TEXT.get(c['comparator'], '')} {c['threshold']:.4g}"
            for c in measurable
        ),
    )


def _in_test_mode() -> bool:
    from app.core.config import settings

    return settings.testing or settings.llm_provider == "fake"
