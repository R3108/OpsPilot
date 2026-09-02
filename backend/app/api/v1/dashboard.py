"""Dashboard aggregates.

All computed in SQL over the tenant's own rows. Percentiles are calculated in
Python from the resolved-duration column rather than with a dialect-specific
``percentile_cont`` so the same code runs on Postgres and on the sqlite used by
the tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Query
from sqlalchemy import Float, cast, func, select

from app.api.deps import CurrentPrincipal, DbSession
from app.models.enums import (
    ApprovalStatus,
    IncidentSeverity,
    IncidentStatus,
    RemediationStatus,
    VerificationOutcome,
)
from app.models.incident import AgentRun, Incident, Verification
from app.models.remediation import Approval, RemediationAction
from app.schemas.dashboard import (
    AgentStats,
    CountByKey,
    DashboardOverview,
    MttrStats,
    RemediationStats,
    ServiceHealthRow,
    TimeBucket,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview", response_model=DashboardOverview)
async def overview(
    principal: CurrentPrincipal,
    session: DbSession,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> DashboardOverview:
    tenant_id = principal.tenant_id
    since = datetime.now(UTC) - timedelta(days=days)
    scope = (Incident.tenant_id == tenant_id, Incident.created_at >= since)

    open_incidents = await _scalar(
        session,
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tenant_id,
            Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]),
        ),
    )
    active_investigations = await _scalar(
        session,
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tenant_id,
            Incident.status.in_(
                [
                    IncidentStatus.INVESTIGATING,
                    IncidentStatus.REMEDIATING,
                    IncidentStatus.VERIFYING,
                ]
            ),
        ),
    )
    pending_approvals = await _scalar(
        session,
        select(func.count(Approval.id)).where(
            Approval.tenant_id == tenant_id, Approval.status == ApprovalStatus.PENDING
        ),
    )
    incidents_in_window = await _scalar(session, select(func.count(Incident.id)).where(*scope))

    return DashboardOverview(
        window_days=days,
        generated_at=datetime.now(UTC),
        open_incidents=open_incidents,
        active_investigations=active_investigations,
        pending_approvals=pending_approvals,
        incidents_in_window=incidents_in_window,
        by_status=await _group(session, Incident.status, scope),
        by_severity=await _group(session, Incident.severity, scope),
        by_source=await _group(session, Incident.source, scope),
        by_service=await _group(session, Incident.service, scope, limit=10),
        volume=await _volume(session, tenant_id, since),
        mttr=await _mttr(session, tenant_id, since),
        agents=await _agent_stats(session, tenant_id, since),
        remediation=await _remediation_stats(session, tenant_id, since),
    )


@router.get("/services", response_model=list[ServiceHealthRow])
async def service_health(
    principal: CurrentPrincipal,
    session: DbSession,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ServiceHealthRow]:
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        await session.execute(
            select(
                Incident.service,
                func.count(Incident.id).label("incidents"),
                func.sum(cast(Incident.severity == IncidentSeverity.SEV1, Float)).label("sev1"),
                func.sum(cast(Incident.severity == IncidentSeverity.SEV2, Float)).label("sev2"),
                func.sum(
                    cast(
                        Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]),
                        Float,
                    )
                ).label("open_now"),
                func.max(Incident.created_at).label("last_incident_at"),
            )
            .where(
                Incident.tenant_id == principal.tenant_id,
                Incident.created_at >= since,
                Incident.service.isnot(None),
            )
            .group_by(Incident.service)
            .order_by(func.count(Incident.id).desc())
            .limit(limit)
        )
    ).all()

    # Resolve durations separately so the aggregate above stays dialect-neutral.
    durations = await _resolved_durations_by_service(session, principal.tenant_id, since)

    return [
        ServiceHealthRow(
            service=row.service,
            incidents=int(row.incidents),
            sev1=int(row.sev1 or 0),
            sev2=int(row.sev2 or 0),
            open_now=int(row.open_now or 0),
            mean_time_to_resolve=(
                sum(durations[row.service]) / len(durations[row.service])
                if durations.get(row.service)
                else None
            ),
            last_incident_at=row.last_incident_at,
        )
        for row in rows
    ]


# --------------------------------------------------------------------------
async def _scalar(session, stmt) -> int:  # noqa: ANN001
    return int((await session.execute(stmt)).scalar_one() or 0)


async def _group(
    session,  # noqa: ANN001
    column: Any,
    scope: tuple[Any, ...],
    *,
    limit: int | None = None,
) -> list[CountByKey]:
    stmt = (
        select(column, func.count(Incident.id))
        .where(*scope)
        .group_by(column)
        .order_by(func.count(Incident.id).desc())
    )
    if limit:
        stmt = stmt.limit(limit)
    rows = (await session.execute(stmt)).all()
    return [
        CountByKey(
            key=str(key) if key is not None else "unassigned",
            label=str(key).replace("_", " ").title() if key is not None else "Unassigned",
            count=int(count),
        )
        for key, count in rows
    ]


async def _volume(session, tenant_id, since) -> list[TimeBucket]:  # noqa: ANN001
    """Daily incident counts. Bucketed in Python to stay dialect-neutral."""
    rows = (
        await session.execute(
            select(Incident.created_at, Incident.severity).where(
                Incident.tenant_id == tenant_id, Incident.created_at >= since
            )
        )
    ).all()

    buckets: dict[datetime, dict[str, int]] = {}
    for created_at, severity in rows:
        day = created_at.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        entry = buckets.setdefault(day, {"count": 0, "sev1": 0, "sev2": 0})
        entry["count"] += 1
        if severity is IncidentSeverity.SEV1:
            entry["sev1"] += 1
        elif severity is IncidentSeverity.SEV2:
            entry["sev2"] += 1

    return [
        TimeBucket(bucket=day, count=v["count"], sev1=v["sev1"], sev2=v["sev2"])
        for day, v in sorted(buckets.items())
    ]


async def _mttr(session, tenant_id, since) -> MttrStats:  # noqa: ANN001
    rows = (
        await session.execute(
            select(
                Incident.detected_at,
                Incident.acknowledged_at,
                Incident.mitigated_at,
                Incident.resolved_at,
            ).where(
                Incident.tenant_id == tenant_id,
                Incident.created_at >= since,
                Incident.resolved_at.isnot(None),
            )
        )
    ).all()
    if not rows:
        return MttrStats()

    acknowledge, mitigate, resolve = [], [], []
    for detected_at, acknowledged_at, mitigated_at, resolved_at in rows:
        if acknowledged_at:
            acknowledge.append((acknowledged_at - detected_at).total_seconds())
        if mitigated_at:
            mitigate.append((mitigated_at - detected_at).total_seconds())
        resolve.append((resolved_at - detected_at).total_seconds())

    resolve.sort()
    return MttrStats(
        mean_time_to_acknowledge=_mean(acknowledge),
        mean_time_to_mitigate=_mean(mitigate),
        mean_time_to_resolve=_mean(resolve),
        p50_time_to_resolve=_percentile(resolve, 0.50),
        p90_time_to_resolve=_percentile(resolve, 0.90),
        sample_size=len(resolve),
    )


async def _agent_stats(session, tenant_id, since) -> AgentStats:  # noqa: ANN001
    rows = (
        await session.execute(
            select(
                AgentRun.status,
                AgentRun.started_at,
                AgentRun.finished_at,
                AgentRun.cost_usd,
                AgentRun.tool_call_count,
            ).where(AgentRun.tenant_id == tenant_id, AgentRun.created_at >= since)
        )
    ).all()
    if not rows:
        return AgentStats()

    durations = [
        (finished - started).total_seconds()
        for _status, started, finished, _cost, _tools in rows
        if finished is not None
    ]
    return AgentStats(
        runs_total=len(rows),
        runs_succeeded=sum(1 for r in rows if r[0] == "completed"),
        runs_failed=sum(1 for r in rows if r[0] == "failed"),
        mean_run_seconds=_mean(durations),
        total_cost_usd=round(sum(float(r[3] or 0) for r in rows), 4),
        total_tool_calls=sum(int(r[4] or 0) for r in rows),
    )


async def _remediation_stats(session, tenant_id, since) -> RemediationStats:  # noqa: ANN001
    status_rows = (
        await session.execute(
            select(RemediationAction.status, func.count(RemediationAction.id))
            .where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.created_at >= since,
            )
            .group_by(RemediationAction.status)
        )
    ).all()
    counts = {str(status): int(count) for status, count in status_rows}

    approvals = (
        await session.execute(
            select(Approval.requested_at, Approval.decided_at, Approval.status).where(
                Approval.tenant_id == tenant_id, Approval.requested_at >= since
            )
        )
    ).all()
    latencies = [
        (decided - requested).total_seconds()
        for requested, decided, _status in approvals
        if decided is not None
    ]

    verifications = (
        await session.execute(
            select(Verification.outcome, func.count(Verification.id))
            .where(Verification.tenant_id == tenant_id, Verification.created_at >= since)
            .group_by(Verification.outcome)
        )
    ).all()
    verification_counts = {str(outcome): int(count) for outcome, count in verifications}
    verified_total = sum(verification_counts.values())

    executed = counts.get(str(RemediationStatus.SUCCEEDED), 0) + counts.get(
        str(RemediationStatus.FAILED), 0
    )
    return RemediationStats(
        proposed=sum(counts.values()),
        approved=sum(1 for _r, decided, s in approvals if decided and s is ApprovalStatus.APPROVED),
        rejected=sum(1 for _r, decided, s in approvals if decided and s is ApprovalStatus.REJECTED),
        auto_approved=max(
            0,
            counts.get(str(RemediationStatus.SUCCEEDED), 0)
            + counts.get(str(RemediationStatus.APPROVED), 0)
            - len([a for a in approvals if a[2] is ApprovalStatus.APPROVED]),
        ),
        blocked_by_policy=counts.get(str(RemediationStatus.BLOCKED_BY_POLICY), 0),
        executed=executed,
        succeeded=counts.get(str(RemediationStatus.SUCCEEDED), 0),
        failed=counts.get(str(RemediationStatus.FAILED), 0),
        mean_approval_latency_seconds=_mean(latencies),
        recovery_rate=(
            verification_counts.get(str(VerificationOutcome.RECOVERED), 0) / verified_total
            if verified_total
            else None
        ),
    )


async def _resolved_durations_by_service(
    session,
    tenant_id,
    since,  # noqa: ANN001
) -> dict[str, list[float]]:
    rows = (
        await session.execute(
            select(Incident.service, Incident.detected_at, Incident.resolved_at).where(
                Incident.tenant_id == tenant_id,
                Incident.created_at >= since,
                Incident.resolved_at.isnot(None),
                Incident.service.isnot(None),
            )
        )
    ).all()
    durations: dict[str, list[float]] = {}
    for service, detected_at, resolved_at in rows:
        durations.setdefault(service, []).append((resolved_at - detected_at).total_seconds())
    return durations


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def _percentile(sorted_values: list[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    index = min(int(round(fraction * (len(sorted_values) - 1))), len(sorted_values) - 1)
    return round(sorted_values[index], 2)
