"""The investigation graph.

```
              ┌──────────────────────────────────────────────┐
              ▼                                              │
START ─▶ triage ─▶ plan ─┬─▶ logs ────────┐                  │ (re-investigate)
                         ├─▶ metrics      │                  │
                         ├─▶ database     ├─▶ correlate       │
                         ├─▶ deployments  │      │            │
                         └─▶ history ─────┘      ▼            │
                                            hypothesize ──────┤ needs more evidence
                                                 │            │
                                                 ▼            │
                                             propose          │
                                                 │            │
                                                 ▼            │
                                           policy_check       │
                                          ┌──────┴──────┐     │
                                    all blocked    needs approval
                                          │              │    │
                                          │       await_approval ⏸
                                          │              │    │
                                          │           approved│
                                          │              ▼    │
                                          │           execute │
                                          │              │    │
                                          │              ▼    │
                                          │           verify ─┘ not recovered
                                          │              │
                                          └──────────────┴─▶ postmortem ─▶ END
```

Two properties this shape buys:

* **Resumability.** Every edge crosses a checkpoint. The graph can be killed at
  any point — including while parked in ``await_approval`` for an hour — and
  resumed in a different process from the Postgres checkpointer.
* **A bounded retry loop.** ``verify`` feeds back into ``plan``, not into
  ``execute``, so a failed remediation forces a fresh investigation with the
  failure as evidence rather than retrying the same action. ``max_iterations``
  caps it.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from app.agents.nodes import (
    await_approval_node,
    correlate_node,
    database_node,
    deployments_node,
    execute_node,
    history_node,
    hypothesize_node,
    logs_node,
    metrics_node,
    plan_node,
    policy_check_node,
    postmortem_node,
    propose_node,
    triage_node,
    verify_node,
)
from app.agents.runtime import deadline_exceeded
from app.agents.state import InvestigationState
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import InvestigatorKind

log = get_logger(__name__)

INVESTIGATOR_NODE_NAMES: dict[InvestigatorKind, str] = {
    InvestigatorKind.LOGS: "investigate_logs",
    InvestigatorKind.METRICS: "investigate_metrics",
    InvestigatorKind.DATABASE: "investigate_database",
    InvestigatorKind.DEPLOYMENTS: "investigate_deployments",
    InvestigatorKind.HISTORY: "investigate_history",
}


# --------------------------------------------------------------------------
# routers
# --------------------------------------------------------------------------
def fan_out_investigators(state: InvestigationState) -> list[Send]:
    """Dispatch only the investigators this iteration's plan selected."""
    tasks = (state.get("plan") or {}).get("tasks") or []
    sends: list[Send] = []
    for task in tasks:
        try:
            kind = InvestigatorKind(task["investigator"])
        except ValueError:  # pragma: no cover - plan node already filters
            continue
        sends.append(Send(INVESTIGATOR_NODE_NAMES[kind], state))
    if not sends:
        # Nothing to investigate (no integrations at all): go straight to
        # synthesis so the incident still gets a documented conclusion.
        sends.append(Send("correlate", state))
    return sends


def after_hypothesize(
    state: InvestigationState,
) -> Literal["plan", "propose", "postmortem"]:
    if deadline_exceeded(state):
        log.warning("graph.deadline_exceeded", incident_id=state.get("incident_id"))
        return "postmortem"

    iteration = int(state.get("iteration") or 1)
    max_iterations = int(state.get("max_iterations") or settings.max_agent_iterations)

    if state.get("needs_more_investigation") and iteration < max_iterations:
        return "plan"

    selected = state.get("selected_hypothesis") or {}
    # Below this, there is nothing worth proposing an action from; write up what
    # we found and hand it to a human rather than guessing at production.
    if float(selected.get("confidence") or 0) < 0.25:
        return "postmortem"
    return "propose"


def after_propose(state: InvestigationState) -> Literal["policy_check", "postmortem"]:
    return "policy_check" if state.get("proposed_action_ids") else "postmortem"


def after_policy_check(
    state: InvestigationState,
) -> Literal["await_approval", "execute", "postmortem"]:
    if state.get("pending_approval_ids"):
        return "await_approval"
    decisions = state.get("policy_decisions") or []
    if any(d.get("allowed") for d in decisions):
        return "execute"
    return "postmortem"


def after_approval(state: InvestigationState) -> Literal["execute", "postmortem"]:
    outcome = state.get("approval_outcome") or {}
    # "partially_approved" still executes: the rejected actions were already
    # marked REJECTED, and `execute` only picks up APPROVED ones.
    if outcome.get("status") in ("approved", "partially_approved"):
        return "execute"
    log.info(
        "graph.approval_not_granted",
        incident_id=state.get("incident_id"),
        status=outcome.get("status"),
    )
    return "postmortem"


def after_verify(state: InvestigationState) -> Literal["plan", "postmortem"]:
    if state.get("recovered"):
        return "postmortem"
    if deadline_exceeded(state):
        return "postmortem"

    iteration = int(state.get("iteration") or 1)
    max_iterations = int(state.get("max_iterations") or settings.max_agent_iterations)
    if iteration >= max_iterations:
        log.info("graph.iterations_exhausted", incident_id=state.get("incident_id"))
        return "postmortem"

    # Recovery failed and we have budget: investigate again, now knowing the
    # first hypothesis was wrong.
    return "plan"


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------
def build_graph() -> StateGraph:
    graph = StateGraph(InvestigationState)

    graph.add_node("triage", triage_node)
    graph.add_node("plan", plan_node)
    graph.add_node("investigate_logs", logs_node)
    graph.add_node("investigate_metrics", metrics_node)
    graph.add_node("investigate_database", database_node)
    graph.add_node("investigate_deployments", deployments_node)
    graph.add_node("investigate_history", history_node)
    graph.add_node("correlate", correlate_node)
    graph.add_node("hypothesize", hypothesize_node)
    graph.add_node("propose", propose_node)
    graph.add_node("policy_check", policy_check_node)
    graph.add_node("await_approval", await_approval_node)
    graph.add_node("execute", execute_node)
    graph.add_node("verify", verify_node)
    graph.add_node("postmortem", postmortem_node)

    graph.add_edge(START, "triage")
    graph.add_edge("triage", "plan")

    graph.add_conditional_edges(
        "plan",
        fan_out_investigators,
        [*INVESTIGATOR_NODE_NAMES.values(), "correlate"],
    )
    for node_name in INVESTIGATOR_NODE_NAMES.values():
        graph.add_edge(node_name, "correlate")

    graph.add_edge("correlate", "hypothesize")

    graph.add_conditional_edges("hypothesize", after_hypothesize, ["plan", "propose", "postmortem"])
    graph.add_conditional_edges("propose", after_propose, ["policy_check", "postmortem"])
    graph.add_conditional_edges(
        "policy_check", after_policy_check, ["await_approval", "execute", "postmortem"]
    )
    graph.add_conditional_edges("await_approval", after_approval, ["execute", "postmortem"])
    graph.add_edge("execute", "verify")
    graph.add_conditional_edges("verify", after_verify, ["plan", "postmortem"])
    graph.add_edge("postmortem", END)

    return graph


# --------------------------------------------------------------------------
# checkpointer
# --------------------------------------------------------------------------
_compiled: Any = None
_checkpointer: Any = None


def _wants_memory_checkpointer() -> bool:
    """True when there is no Postgres to checkpoint into.

    Keyed on the *application* database as well as the checkpoint URL: the
    checkpoint URL has a Postgres default, so a developer pointing
    ``DATABASE_URL`` at sqlite would otherwise get a confusing connection error
    from a component they never configured.
    """
    return (
        settings.testing
        or settings.checkpoint_database_url.startswith("sqlite")
        or settings.database_url.startswith("sqlite")
    )


async def get_checkpointer() -> Any:
    """Postgres-backed checkpointer, or in-memory when there is no Postgres.

    The Postgres saver is what makes an approval pause survive a deploy: the
    thread's state lives in the database, not in the worker's memory. The
    in-memory saver keeps the graph runnable for tests, evals and a sqlite demo,
    at the cost of losing parked runs on restart — which is why it refuses to be
    used in production.
    """
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    if _wants_memory_checkpointer():
        if settings.is_production:
            raise RuntimeError(
                "Refusing to use the in-memory LangGraph checkpointer in "
                f"{settings.environment}: an approval pause would not survive a "
                "restart. Configure CHECKPOINT_DATABASE_URL to point at Postgres."
            )
        from langgraph.checkpoint.memory import MemorySaver

        _checkpointer = MemorySaver()
        log.info(
            "graph.checkpointer_ready",
            backend="memory",
            detail="runs parked on an approval will not survive a restart",
        )
        return _checkpointer

    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from psycopg_pool import AsyncConnectionPool
    except ImportError as exc:  # pragma: no cover - a packaging problem, not a runtime one
        raise RuntimeError(
            "langgraph-checkpoint-postgres is required for durable checkpoints. "
            "Install it, or point CHECKPOINT_DATABASE_URL at sqlite for local work."
        ) from exc

    pool = AsyncConnectionPool(
        conninfo=settings.checkpoint_database_url,
        max_size=10,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0},
    )
    await pool.open()
    saver = AsyncPostgresSaver(pool)
    await saver.setup()  # idempotent; creates the checkpoint tables
    _checkpointer = saver
    log.info("graph.checkpointer_ready", backend="postgres")
    return _checkpointer


async def get_compiled_graph() -> Any:
    global _compiled
    if _compiled is None:
        _compiled = build_graph().compile(checkpointer=await get_checkpointer())
        log.info("graph.compiled", nodes=len(_compiled.nodes))
    return _compiled


async def reset_graph() -> None:
    """Test hook: drop the cached compilation and checkpointer."""
    global _compiled, _checkpointer
    _compiled = None
    _checkpointer = None


def thread_config(
    incident_id: uuid.UUID | str, *, tenant_id: uuid.UUID | str, run_id: uuid.UUID | str
) -> dict[str, Any]:
    """LangGraph config, including LangSmith metadata for the run."""
    return {
        "configurable": {"thread_id": f"incident:{incident_id}"},
        "recursion_limit": 60,
        "run_name": f"opspilot.investigation.{incident_id}",
        "tags": ["opspilot", "investigation", f"tenant:{tenant_id}"],
        "metadata": {
            "incident_id": str(incident_id),
            "tenant_id": str(tenant_id),
            "run_id": str(run_id),
            "environment": settings.environment,
        },
    }
