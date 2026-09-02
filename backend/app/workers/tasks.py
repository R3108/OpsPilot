"""Worker jobs.

Every job takes the arq context as its first argument (``None`` when a job is
run inline as a fallback), is idempotent, and never raises past the worker: a
failed job records its failure on the domain object so an operator can see it in
the UI rather than only in a log.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.db import session_scope
from app.core.logging import get_logger, request_id_ctx, tenant_id_ctx
from app.models.enums import AgentPhase, ApprovalStatus, IntegrationStatus
from app.models.integration import Integration
from app.models.remediation import Approval
from app.services import approvals as approval_service
from app.services import investigations

log = get_logger(__name__)


async def run_investigation(
    ctx: Any,
    incident_id: str,
    tenant_id: str,
    triggered_by: str = "system",
    force: bool = False,
) -> dict[str, Any]:
    request_id_ctx.set(f"job:investigate:{incident_id[:8]}")
    tenant_id_ctx.set(tenant_id)
    try:
        return await investigations.start_investigation(
            incident_id=uuid.UUID(incident_id),
            tenant_id=uuid.UUID(tenant_id),
            triggered_by=triggered_by,
            # Re-investigating a closed or failed incident is a deliberate human
            # act; without carrying the flag this far the graph refuses it and the
            # job dies in the log, having already told the caller "queued".
            force=force,
        )
    except investigations.InvestigationBusy:
        log.info("job.investigation_already_running", incident_id=incident_id)
        return {"status": "already_running"}
    except Exception as exc:  # noqa: BLE001 - already recorded on the run row
        log.error("job.investigation_failed", incident_id=incident_id, error=str(exc)[:500])
        return {"status": "failed", "error": str(exc)[:500]}


async def resume_investigation(ctx: Any, incident_id: str, tenant_id: str) -> dict[str, Any]:
    """Resume a graph parked on an approval interrupt."""
    request_id_ctx.set(f"job:resume:{incident_id[:8]}")
    tenant_id_ctx.set(tenant_id)

    incident_uuid = uuid.UUID(incident_id)
    async with session_scope() as session:
        pending = await approval_service.outstanding_for_incident(session, incident_uuid)
        if pending:
            log.info(
                "job.resume_deferred",
                incident_id=incident_id,
                pending=len(pending),
                detail="approvals still outstanding",
            )
            return {"status": "still_waiting", "pending": len(pending)}

        decided = list(
            (
                await session.execute(
                    select(Approval).where(
                        Approval.incident_id == incident_uuid,
                        Approval.status.in_(
                            [
                                ApprovalStatus.APPROVED,
                                ApprovalStatus.REJECTED,
                                ApprovalStatus.EXPIRED,
                            ]
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        payload = approval_service.resume_payload(decided)

    try:
        return await investigations.resume_investigation(
            incident_id=incident_uuid,
            tenant_id=uuid.UUID(tenant_id),
            resume_value=payload,
        )
    except investigations.InvestigationBusy:
        return {"status": "already_running"}
    except Exception as exc:  # noqa: BLE001
        log.error("job.resume_failed", incident_id=incident_id, error=str(exc)[:500])
        return {"status": "failed", "error": str(exc)[:500]}


async def check_integration_health(ctx: Any, integration_id: str) -> dict[str, Any]:
    from app.integrations.base import build_client

    async with session_scope() as session:
        integration = await session.get(Integration, uuid.UUID(integration_id))
        if integration is None:
            return {"status": "not_found"}

        client = None
        try:
            client = build_client(integration)
            if client is None:
                integration.status = IntegrationStatus.ERROR
                integration.last_error = "no client implementation for this provider"
                return {"status": "unsupported"}

            report = await client.health_check()
            integration.status = report.status
            integration.last_health_check_at = datetime.now(UTC)
            integration.last_error = None if report.healthy else report.detail[:2000]
            integration.consecutive_failures = (
                0 if report.healthy else integration.consecutive_failures + 1
            )
            # Repeated failures take the integration out of rotation so the agents
            # stop planning around a provider that is not answering.
            if integration.consecutive_failures >= 5:
                integration.status = IntegrationStatus.DEGRADED
            return {
                "status": str(integration.status),
                "healthy": report.healthy,
                "latency_ms": report.latency_ms,
            }
        except Exception as exc:  # noqa: BLE001
            integration.status = IntegrationStatus.ERROR
            integration.last_error = str(exc)[:2000]
            integration.consecutive_failures += 1
            integration.last_health_check_at = datetime.now(UTC)
            log.warning(
                "job.health_check_failed",
                integration_id=integration_id,
                error=str(exc)[:300],
            )
            return {"status": "error", "error": str(exc)[:300]}
        finally:
            if client is not None:
                await client.aclose()


# --------------------------------------------------------------------------
# periodic
# --------------------------------------------------------------------------
async def expire_approvals(ctx: Any) -> dict[str, Any]:
    """Sweep timed-out approvals and unpark the graphs waiting on them."""
    async with session_scope() as session:
        count = await approval_service.expire_stale(session)
        if not count:
            return {"expired": 0}

        stale = list(
            (
                await session.execute(
                    select(Approval.incident_id, Approval.tenant_id)
                    .where(Approval.status == ApprovalStatus.EXPIRED)
                    .distinct()
                )
            ).all()
        )

    for incident_id, tenant_id in stale:
        async with session_scope() as session:
            if await approval_service.outstanding_for_incident(session, incident_id):
                continue
        await resume_investigation(ctx, str(incident_id), str(tenant_id))

    return {"expired": count}


async def health_check_all_integrations(ctx: Any) -> dict[str, Any]:
    async with session_scope() as session:
        ids = list(
            (await session.execute(select(Integration.id).where(Integration.is_enabled.is_(True))))
            .scalars()
            .all()
        )
    for integration_id in ids:
        await check_integration_health(ctx, str(integration_id))
    return {"checked": len(ids)}


async def reconcile_stuck_investigations(ctx: Any) -> dict[str, Any]:
    """Safety net for runs whose worker died mid-flight.

    A run that has been ``running`` for longer than the investigation timeout,
    with no pending approvals, is resumed; the checkpointer means it picks up
    where it stopped rather than starting over.
    """
    from datetime import timedelta

    from app.core.config import settings
    from app.models.incident import AgentRun

    cutoff = datetime.now(UTC) - timedelta(seconds=settings.investigation_timeout_seconds * 2)
    async with session_scope() as session:
        stuck = list(
            (
                await session.execute(
                    select(AgentRun).where(
                        AgentRun.status == "running",
                        AgentRun.started_at < cutoff,
                        AgentRun.finished_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

    resumed = 0
    superseded = 0
    for run in stuck:
        async with session_scope() as session:
            # The graph thread is keyed by incident, not by run, so a "running"
            # row from an attempt that a later one replaced has nothing of its own
            # left to resume. Resuming would pick up the newest run instead and
            # leave this row running — putting it back in this query every pass,
            # forever. Close it out as the stale bookkeeping it is.
            newer = (
                await session.execute(
                    select(AgentRun.id)
                    .where(
                        AgentRun.incident_id == run.incident_id,
                        AgentRun.created_at > run.created_at,
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if newer is not None:
                stale = await session.get(AgentRun, run.id)
                if stale is not None:
                    stale.status = "failed"
                    stale.phase = AgentPhase.FAILED
                    stale.error = "Superseded by a later investigation attempt"
                    stale.finished_at = datetime.now(UTC)
                log.info(
                    "job.superseded_stuck_run",
                    run_id=str(run.id),
                    incident_id=str(run.incident_id),
                )
                superseded += 1
                continue

            if await approval_service.outstanding_for_incident(session, run.incident_id):
                continue

        log.warning(
            "job.reconciling_stuck_run",
            run_id=str(run.id),
            incident_id=str(run.incident_id),
            started_at=run.started_at.isoformat(),
        )
        await resume_investigation(ctx, str(run.incident_id), str(run.tenant_id))
        resumed += 1

    return {"stuck": len(stuck), "resumed": resumed, "superseded": superseded}
