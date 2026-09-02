"""Database remediation actions.

These are the sharpest tools in the box, so the parameter surface is the
narrowest. Note what is *absent*: there is no "run this SQL" action. Every
statement below is a fixed, parameterised query defined in
:mod:`app.integrations.postgres`; the model can only choose *which* of them runs
and against which pid/application name, never the SQL itself.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IntegrationProvider, RiskTier
from app.services.actions.registry import (
    ActionSpec,
    BlastRadius,
    ExecutionContext,
    ExecutionResult,
    register_action,
)

# Postgres identifiers we accept as filters. No quotes, no semicolons, no spaces.
IDENT = r"^[A-Za-z0-9_.\-]{1,63}$"


class TerminateIdleConnectionsParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    database: Annotated[str, Field(pattern=IDENT)]
    # Only connections idle-in-transaction longer than this are eligible.
    idle_seconds: Annotated[int, Field(ge=30, le=86_400)] = 300
    application_name: Annotated[str, Field(pattern=IDENT)] | None = None
    max_terminations: Annotated[int, Field(ge=1, le=200)] = 25


async def _terminate_idle(
    params: TerminateIdleConnectionsParams, ctx: ExecutionContext
) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.POSTGRES)

    candidates = await client.list_idle_in_transaction(
        database=params.database,
        idle_seconds=params.idle_seconds,
        application_name=params.application_name,
        limit=params.max_terminations,
    )
    pre = {"candidate_count": len(candidates), "candidates": candidates[:50]}

    if not candidates:
        return ExecutionResult(
            succeeded=True,
            summary="No idle-in-transaction connections matched; nothing to terminate",
            pre_state=pre,
            provider="postgres",
        )
    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would terminate {len(candidates)} idle connections",
            detail=pre,
            pre_state=pre,
            provider="postgres",
        )

    terminated = await client.terminate_backends([c["pid"] for c in candidates])
    return ExecutionResult(
        succeeded=True,
        summary=(
            f"Terminated {len(terminated)} idle-in-transaction connections on {params.database}"
        ),
        detail={"terminated_pids": terminated, "candidates": candidates[:50]},
        pre_state=pre,
        provider="postgres",
    )


register_action(
    ActionSpec(
        key="db.terminate_idle_connections",
        title="Terminate idle-in-transaction connections",
        description=(
            "Kill backends stuck in 'idle in transaction' for longer than a threshold. "
            "The standard fix for connection-pool exhaustion caused by a leaked "
            "transaction. Does not touch active queries."
        ),
        provider=IntegrationProvider.POSTGRES,
        params_model=TerminateIdleConnectionsParams,
        executor=_terminate_idle,
        risk_tier=RiskTier.HIGH,
        is_reversible=False,
        blast_radius_fn=lambda p: BlastRadius(
            scope="database",
            targets=[p.database],
            estimated_affected_units=p.max_terminations,
            causes_downtime=False,
            touches_data=True,
            notes=(
                "Terminated transactions roll back. Clients see a connection error and "
                "must retry; uncommitted work in those transactions is lost."
            ),
        ),
        approval_checklist=[
            "Are any of these connections a long-running migration or backfill?",
            "Do the affected clients retry safely on a dropped connection?",
        ],
        timeout_seconds=60,
    )
)


class TerminateLongQueryParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    database: Annotated[str, Field(pattern=IDENT)]
    # Explicit pid: the model must have seen it in evidence first.
    pid: Annotated[int, Field(ge=1)]
    # Safety interlock: we re-check the backend still matches before killing it.
    expected_duration_seconds_min: Annotated[int, Field(ge=10, le=86_400)] = 60


async def _terminate_long_query(
    params: TerminateLongQueryParams, ctx: ExecutionContext
) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.POSTGRES)

    backend = await client.get_backend(params.database, params.pid)
    if backend is None:
        return ExecutionResult(
            succeeded=True,
            summary=f"Backend pid {params.pid} is already gone",
            provider="postgres",
        )

    # Re-verify at execution time: between proposal and approval the pid may have
    # been recycled onto a completely different (possibly critical) query.
    duration = float(backend.get("duration_seconds") or 0)
    if duration < params.expected_duration_seconds_min:
        return ExecutionResult.failure(
            f"Refusing to terminate pid {params.pid}: it has only been running "
            f"{duration:.0f}s, below the {params.expected_duration_seconds_min}s interlock",
            error="interlock_duration_mismatch",
            backend=backend,
        )

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would terminate pid {params.pid}",
            pre_state=backend,
            provider="postgres",
        )

    await client.terminate_backends([params.pid])
    return ExecutionResult(
        succeeded=True,
        summary=f"Terminated long-running query pid {params.pid} ({duration:.0f}s)",
        detail={"backend": backend},
        pre_state=backend,
        provider="postgres",
    )


register_action(
    ActionSpec(
        key="db.terminate_long_query",
        title="Terminate a specific long-running query",
        description=(
            "Cancel one runaway backend by pid. Use when a single query is holding "
            "locks or pinning CPU. The pid must come from collected evidence."
        ),
        provider=IntegrationProvider.POSTGRES,
        params_model=TerminateLongQueryParams,
        executor=_terminate_long_query,
        risk_tier=RiskTier.CRITICAL,
        is_reversible=False,
        blast_radius_fn=lambda p: BlastRadius(
            scope="database",
            targets=[f"{p.database}#{p.pid}"],
            estimated_affected_units=1,
            touches_data=True,
            notes="The query's transaction rolls back. Irreversible.",
        ),
        approval_checklist=[
            "Confirm the pid from the evidence, not from memory — pids are recycled.",
            "Is this a user-facing query or a background job that can be re-run?",
        ],
        timeout_seconds=60,
    )
)


class SetConnectionLimitParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    database: Annotated[str, Field(pattern=IDENT)]
    role: Annotated[str, Field(pattern=IDENT)]
    connection_limit: Annotated[int, Field(ge=-1, le=10_000)]


async def _set_connection_limit(
    params: SetConnectionLimitParams, ctx: ExecutionContext
) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.POSTGRES)
    pre = await client.get_role_connection_limit(params.database, params.role)

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=(
                f"[dry-run] would set {params.role} connection limit "
                f"{pre.get('connection_limit')} -> {params.connection_limit}"
            ),
            pre_state=pre,
            provider="postgres",
        )

    await client.set_role_connection_limit(params.database, params.role, params.connection_limit)
    return ExecutionResult(
        succeeded=True,
        summary=(f"Set connection limit for role {params.role} to {params.connection_limit}"),
        detail={"previous": pre.get("connection_limit")},
        pre_state=pre,
        provider="postgres",
    )


def _connection_limit_rollback(
    params: SetConnectionLimitParams, result: ExecutionResult
) -> tuple[str, dict[str, Any]] | None:
    previous = result.pre_state.get("connection_limit")
    if previous is None:
        return None
    return (
        "db.set_connection_limit",
        {
            "database": params.database,
            "role": params.role,
            "connection_limit": int(previous),
        },
    )


register_action(
    ActionSpec(
        key="db.set_connection_limit",
        title="Change a role's connection limit",
        description=(
            "Raise or lower the per-role connection cap. Use to stop a runaway client "
            "from starving the rest of the fleet, or to give headroom during recovery."
        ),
        provider=IntegrationProvider.POSTGRES,
        params_model=SetConnectionLimitParams,
        executor=_set_connection_limit,
        risk_tier=RiskTier.HIGH,
        is_reversible=True,
        rollback_fn=_connection_limit_rollback,
        blast_radius_fn=lambda p: BlastRadius(
            scope="database",
            targets=[f"{p.database}:{p.role}"],
            estimated_affected_units=1,
            causes_downtime=p.connection_limit == 0,
            notes=(
                "A limit of 0 blocks all new connections for this role."
                if p.connection_limit == 0
                else "Existing connections are unaffected; only new ones are gated."
            ),
        ),
        approval_checklist=[
            "Will raising the limit push the server past max_connections?",
            "Is this role shared by services other than the one in the incident?",
        ],
    )
)
