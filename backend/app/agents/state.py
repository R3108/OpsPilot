"""LangGraph state.

Everything here must be JSON-serialisable: it is what gets written to the
Postgres checkpointer after every node, and what a resumed run is rebuilt from
after an approval, a crash or a worker restart.

The state is deliberately a *summary*, not a cache. Evidence, hypotheses and
actions all live in Postgres as first-class rows; the state carries their ids and
just enough denormalised text for the next node's prompt.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Reducer for parallel investigator writes into one map."""
    return {**left, **right}


def keep_last(_left: Any, right: Any) -> Any:
    return right


class InvestigationState(TypedDict, total=False):
    # -- identity ---------------------------------------------------------
    incident_id: str
    tenant_id: str
    run_id: str
    thread_id: str
    attempt: int

    # -- incident snapshot (refreshed at the top of each iteration) --------
    incident: dict[str, Any]

    # -- triage ------------------------------------------------------------
    severity: str
    severity_confidence: float
    severity_rationale: str
    symptoms: list[str]
    customer_impact: str

    # -- plan --------------------------------------------------------------
    plan: dict[str, Any]
    time_window_minutes: int
    target_service: str
    target_namespace: str

    # -- investigation (parallel fan-out) ----------------------------------
    # Each investigator writes one key; the reducer merges without clobbering.
    findings: Annotated[dict[str, Any], merge_dicts]
    evidence_ids: Annotated[list[str], operator.add]
    evidence_digest: Annotated[list[dict[str, Any]], operator.add]
    investigator_errors: Annotated[dict[str, Any], merge_dicts]

    # -- synthesis ---------------------------------------------------------
    correlation: dict[str, Any]
    hypotheses: list[dict[str, Any]]
    selected_hypothesis: dict[str, Any]
    needs_more_investigation: bool
    additional_questions: list[str]

    # -- remediation -------------------------------------------------------
    proposal: dict[str, Any]
    proposed_action_ids: list[str]
    policy_decisions: list[dict[str, Any]]
    # Set when the graph is interrupted waiting for a human.
    pending_approval_ids: list[str]
    approval_outcome: dict[str, Any]
    execution_results: list[dict[str, Any]]

    # -- verification ------------------------------------------------------
    verification: dict[str, Any]
    recovered: bool
    verification_checks: list[dict[str, Any]]

    # -- postmortem --------------------------------------------------------
    postmortem_id: str

    # -- control -----------------------------------------------------------
    phase: str
    iteration: int
    max_iterations: int
    errors: Annotated[list[dict[str, Any]], operator.add]
    started_at: str
    deadline_at: str
    # Set when the run ends for a reason other than success.
    terminal_reason: str
    done: bool


def initial_state(
    *,
    incident_id: str,
    tenant_id: str,
    run_id: str,
    thread_id: str,
    incident: dict[str, Any],
    attempt: int = 1,
    max_iterations: int = 3,
    started_at: str,
    deadline_at: str,
) -> InvestigationState:
    return InvestigationState(
        incident_id=incident_id,
        tenant_id=tenant_id,
        run_id=run_id,
        thread_id=thread_id,
        attempt=attempt,
        incident=incident,
        severity=incident.get("severity", "sev3"),
        severity_confidence=0.0,
        severity_rationale="",
        symptoms=[],
        customer_impact="",
        plan={},
        time_window_minutes=120,
        target_service=incident.get("service") or "",
        target_namespace=incident.get("namespace") or "",
        findings={},
        evidence_ids=[],
        evidence_digest=[],
        investigator_errors={},
        correlation={},
        hypotheses=[],
        selected_hypothesis={},
        needs_more_investigation=False,
        additional_questions=[],
        proposal={},
        proposed_action_ids=[],
        policy_decisions=[],
        pending_approval_ids=[],
        approval_outcome={},
        execution_results=[],
        verification={},
        recovered=False,
        verification_checks=[],
        postmortem_id="",
        phase="triage",
        iteration=0,
        max_iterations=max_iterations,
        errors=[],
        started_at=started_at,
        deadline_at=deadline_at,
        terminal_reason="",
        done=False,
    )
