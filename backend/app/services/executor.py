"""Executes an approved remediation action.

This is the narrowest point in the whole system, and the checks below run in this
order every single time — including on a graph resume, a worker retry and a
manual API-triggered execution:

1. the action key still resolves in the catalog;
2. the stored params still validate against that action's schema;
3. the catalog fingerprint has not changed since approval (an action key must
   not silently come to mean something else);
4. the policy engine re-evaluates *now*, not at proposal time;
5. approval, if required, exists, is APPROVED, and has not expired;
6. the idempotency key has not already been consumed;
7. the write-capable integration still exists and is still write-enabled.

Only then does the typed executor run, under a timeout, with the attempt logged
before and after.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import (
    ApprovalRequiredError,
    ConflictError,
    OpsPilotError,
    ValidationError,
)
from app.core.logging import get_logger
from app.core.redis_client import advisory_lock
from app.integrations.base import ClientRegistry
from app.models.enums import (
    AgentEventType,
    AgentPhase,
    ApprovalStatus,
    AuditAction,
    IncidentStatus,
    RemediationStatus,
)
from app.models.incident import Incident
from app.models.remediation import (
    ActionExecutionLog,
    Approval,
    PolicyRule,
    RemediationAction,
)
from app.models.tenant import Tenant
from app.services import audit, events
from app.services.actions import (
    ExecutionContext,
    ExecutionResult,
    get_action,
    registry_fingerprint,
)
from app.services.policy import PolicyInput, evaluate

log = get_logger(__name__)


@dataclass(slots=True)
class ExecutionOutcome:
    action_id: uuid.UUID
    succeeded: bool
    status: RemediationStatus
    summary: str
    detail: dict[str, Any]
    error: str | None = None
    duration_ms: int = 0
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "succeeded": self.succeeded,
            "status": str(self.status),
            "summary": self.summary,
            "detail": self.detail,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "skipped": self.skipped,
        }


async def execute_action(
    session: AsyncSession,
    action: RemediationAction,
    *,
    actor: str,
    actor_type: str = "agent",
    dry_run: bool = False,
) -> ExecutionOutcome:
    """Run one action through every gate. Never raises for a policy refusal."""
    incident = await session.get(Incident, action.incident_id)
    if incident is None:
        raise ValidationError("incident no longer exists")

    # -- 0. terminal / duplicate ------------------------------------------
    if action.status is RemediationStatus.SUCCEEDED:
        return ExecutionOutcome(
            action.id,
            True,
            action.status,
            "Action already executed successfully",
            action.execution_result or {},
            skipped=True,
        )
    if action.is_terminal:
        return ExecutionOutcome(
            action.id,
            False,
            action.status,
            f"Action is already in terminal state {action.status}",
            {},
            skipped=True,
        )

    # -- 1/2. catalog + schema --------------------------------------------
    try:
        spec = get_action(action.action_key)
        params = spec.parse_params(action.params or {})
    except OpsPilotError as exc:
        return await _fail(
            session,
            action,
            incident,
            status=RemediationStatus.BLOCKED_BY_POLICY,
            summary="Action failed catalog validation",
            error=exc.message,
            actor=actor,
        )

    # -- 3. catalog fingerprint --------------------------------------------
    approved_fingerprint = (action.policy_decision or {}).get("catalog_fingerprint")
    if approved_fingerprint and approved_fingerprint != registry_fingerprint():
        return await _fail(
            session,
            action,
            incident,
            status=RemediationStatus.BLOCKED_BY_POLICY,
            summary="Action catalog changed after approval",
            error=(
                "The action catalog was modified between approval and execution; "
                "re-approval is required."
            ),
            actor=actor,
        )

    # -- 4. policy re-evaluation -------------------------------------------
    decision = await evaluate_action(
        session, incident=incident, action=action, spec=spec, params=params
    )
    if not decision.allowed:
        return await _fail(
            session,
            action,
            incident,
            status=RemediationStatus.BLOCKED_BY_POLICY,
            summary="Blocked by policy at execution time",
            error=decision.deny_summary(),
            actor=actor,
            policy_decision=decision.to_dict(),
        )

    # -- 5. approval --------------------------------------------------------
    if decision.requires_approval:
        approval = (
            await session.execute(select(Approval).where(Approval.action_id == action.id))
        ).scalar_one_or_none()
        if approval is None or approval.status is not ApprovalStatus.APPROVED:
            raise ApprovalRequiredError(
                "This action requires an approval that has not been granted",
                details={
                    "action_id": str(action.id),
                    "approval_status": str(approval.status) if approval else "missing",
                },
            )
        if approval.expires_at < datetime.now(UTC):
            approval.status = ApprovalStatus.EXPIRED
            return await _fail(
                session,
                action,
                incident,
                status=RemediationStatus.BLOCKED_BY_POLICY,
                summary="Approval expired before execution",
                error="approval_expired",
                actor=actor,
            )
        # An approver may narrow the action; re-validate the narrowed params.
        if approval.modified_params:
            try:
                params = spec.parse_params(approval.modified_params)
                action.params = approval.modified_params
            except OpsPilotError as exc:
                return await _fail(
                    session,
                    action,
                    incident,
                    status=RemediationStatus.BLOCKED_BY_POLICY,
                    summary="Approver-modified parameters are invalid",
                    error=exc.message,
                    actor=actor,
                )

    # -- 6. idempotency -----------------------------------------------------
    lock_name = f"action:{action.id}"
    async with advisory_lock(lock_name, ttl_seconds=spec.timeout_seconds + 60) as acquired:
        if not acquired:
            raise ConflictError(
                "This action is already being executed by another worker",
                details={"action_id": str(action.id)},
            )
        return await _run(
            session,
            action=action,
            incident=incident,
            spec=spec,
            params=params,
            decision_dict=decision.to_dict(),
            actor=actor,
            actor_type=actor_type,
            dry_run=dry_run or settings.remediation_disabled,
        )


async def _run(
    session: AsyncSession,
    *,
    action: RemediationAction,
    incident: Incident,
    spec: Any,
    params: Any,
    decision_dict: dict[str, Any],
    actor: str,
    actor_type: str,
    dry_run: bool,
) -> ExecutionOutcome:
    attempt = action.attempt + 1
    started_at = datetime.now(UTC)
    clock = time.perf_counter()

    action.attempt = attempt
    action.status = RemediationStatus.EXECUTING
    await session.flush()

    log_row = ActionExecutionLog(
        tenant_id=action.tenant_id,
        action_id=action.id,
        incident_id=action.incident_id,
        attempt=attempt,
        action_key=action.action_key,
        params=action.params,
        provider=str(spec.provider),
        started_at=started_at,
        authorised_by=actor,
        dry_run=dry_run,
        risk_tier=action.risk_tier,
        confidence_at_execution=incident.root_cause_confidence,
    )
    session.add(log_row)
    await session.flush()

    await events.emit(
        type=AgentEventType.EXECUTION_RESULT,
        incident_id=action.incident_id,
        tenant_id=action.tenant_id,
        phase=AgentPhase.EXECUTE,
        title=f"Executing {action.action_key}",
        message=action.title,
        action_id=str(action.id),
        state="started",
        dry_run=dry_run,
    )

    # -- 7. write integration ------------------------------------------------
    registry = ClientRegistry(action.tenant_id, scenario=(incident.labels or {}).get("scenario"))
    await registry.load(
        session, providers={spec.provider}, require_write=spec.requires_write_integration
    )
    integration = registry.integration(spec.provider)
    if spec.requires_write_integration and (integration is None or not integration.allow_write):
        await registry.aclose()
        return await _fail(
            session,
            action,
            incident,
            status=RemediationStatus.FAILED,
            summary=f"No write-enabled {spec.provider} integration is available",
            error="missing_write_integration",
            actor=actor,
        )

    ctx = ExecutionContext(
        tenant_id=action.tenant_id,
        incident_id=action.incident_id,
        action_id=action.id,
        actor=actor,
        dry_run=dry_run,
        clients=registry.as_dict(),
        scope=registry.scope_for(spec.provider),
        idempotency_key=action.idempotency_key,
        timeout_seconds=spec.timeout_seconds,
    )

    result: ExecutionResult
    try:
        import asyncio

        result = await asyncio.wait_for(
            spec.executor(params, ctx), timeout=spec.timeout_seconds + 15
        )
    except TimeoutError:
        result = ExecutionResult.failure(
            f"{action.action_key} timed out after {spec.timeout_seconds}s",
            error="execution_timeout",
        )
    except PermissionError as exc:  # scope fences raise this
        result = ExecutionResult.failure(str(exc), error="scope_violation")
    except Exception as exc:  # noqa: BLE001 - provider failures are data, not crashes
        log.exception("executor.failed", action_key=action.action_key, action_id=str(action.id))
        result = ExecutionResult.failure(
            f"{action.action_key} failed: {exc}", error=type(exc).__name__
        )
    finally:
        await registry.aclose()

    duration_ms = int((time.perf_counter() - clock) * 1000)

    log_row.succeeded = result.succeeded
    log_row.response = result.detail
    log_row.error = result.error
    log_row.finished_at = datetime.now(UTC)
    log_row.duration_ms = duration_ms

    action.execution_result = {
        "summary": result.summary,
        "detail": result.detail,
        "provider": result.provider or str(spec.provider),
        "dry_run": dry_run,
    }
    action.execution_error = result.error
    action.executed_at = datetime.now(UTC)
    action.duration_ms = duration_ms
    action.pre_state = result.pre_state or action.pre_state
    action.policy_decision = {**(action.policy_decision or {}), "at_execution": decision_dict}

    if result.succeeded:
        action.status = RemediationStatus.SUCCEEDED
        # Record how to undo this, so a failed verification has a way back.
        rollback = spec.build_rollback(params, result)
        if rollback is not None:
            action.rollback_action_key, action.rollback_params = rollback
    else:
        retriable = action.attempt < action.max_attempts and result.error not in (
            "scope_violation",
            "workflow_not_allowlisted",
            "interlock_duration_mismatch",
        )
        action.status = RemediationStatus.APPROVED if retriable else RemediationStatus.FAILED

    if incident.status is not IncidentStatus.REMEDIATING:
        incident.status = IncidentStatus.REMEDIATING
    if result.succeeded and incident.mitigated_at is None:
        incident.mitigated_at = datetime.now(UTC)

    await audit.record(
        session,
        tenant_id=action.tenant_id,
        action=(
            AuditAction.REMEDIATION_EXECUTED if result.succeeded else AuditAction.REMEDIATION_FAILED
        ),
        resource_type="remediation_action",
        resource_id=action.id,
        actor_type=actor_type,
        actor_id=actor,
        actor_label=actor,
        incident_id=action.incident_id,
        summary=result.summary[:5000],
        after={
            "status": str(action.status),
            "action_key": action.action_key,
            "attempt": attempt,
            "dry_run": dry_run,
        },
        context={"risk_tier": str(action.risk_tier), "duration_ms": duration_ms},
    )

    await _timeline(
        session,
        action=action,
        title=(
            f"{'[dry-run] ' if dry_run else ''}"
            f"{'Executed' if result.succeeded else 'Execution failed'}: {action.title}"
        ),
        body=result.summary + (f"\n\nError: {result.error}" if result.error else ""),
        actor_label=actor,
        actor_type=actor_type,
    )

    await events.emit(
        type=AgentEventType.EXECUTION_RESULT,
        incident_id=action.incident_id,
        tenant_id=action.tenant_id,
        phase=AgentPhase.EXECUTE,
        title=result.summary[:200],
        message=result.error or "",
        action_id=str(action.id),
        state="succeeded" if result.succeeded else "failed",
        duration_ms=duration_ms,
        dry_run=dry_run,
    )

    log.info(
        "action.executed",
        action_key=action.action_key,
        action_id=str(action.id),
        succeeded=result.succeeded,
        dry_run=dry_run,
        attempt=attempt,
        ms=duration_ms,
    )

    return ExecutionOutcome(
        action_id=action.id,
        succeeded=result.succeeded,
        status=action.status,
        summary=result.summary,
        detail=result.detail,
        error=result.error,
        duration_ms=duration_ms,
    )


async def evaluate_action(
    session: AsyncSession,
    *,
    incident: Incident,
    action: RemediationAction,
    spec: Any,
    params: Any,
    hypothesis_confidence: float | None = None,
    supporting_evidence_count: int | None = None,
) -> Any:
    """Assemble the policy inputs and evaluate. Used at proposal and at execution."""
    tenant = await session.get(Tenant, incident.tenant_id)
    rules = list(
        (
            await session.execute(
                select(PolicyRule).where(
                    PolicyRule.tenant_id == incident.tenant_id,
                    PolicyRule.is_enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )

    actions_this_incident = int(
        (
            await session.execute(
                select(func.count(RemediationAction.id)).where(
                    RemediationAction.incident_id == incident.id,
                    RemediationAction.status.in_(
                        [
                            RemediationStatus.SUCCEEDED,
                            RemediationStatus.EXECUTING,
                            RemediationStatus.APPROVED,
                        ]
                    ),
                    RemediationAction.id != action.id,
                )
            )
        ).scalar_one()
    )
    hour_ago = datetime.now(UTC).timestamp() - 3600
    actions_this_hour = int(
        (
            await session.execute(
                select(func.count(ActionExecutionLog.id)).where(
                    ActionExecutionLog.tenant_id == incident.tenant_id,
                    ActionExecutionLog.started_at >= datetime.fromtimestamp(hour_ago, tz=UTC),
                )
            )
        ).scalar_one()
    )

    live_facts = await _live_facts(session, incident=incident, spec=spec, params=params)

    registry = ClientRegistry(incident.tenant_id)
    await registry.load(session, providers={spec.provider})
    integration = registry.integration(spec.provider)
    await registry.aclose()

    return evaluate(
        PolicyInput(
            spec=spec,
            params=params,
            blast_radius=spec.blast_radius(params),
            incident=incident,
            tenant=tenant,
            rules=rules,
            integration=integration,
            hypothesis_confidence=(
                hypothesis_confidence
                if hypothesis_confidence is not None
                else incident.root_cause_confidence
            ),
            supporting_evidence_count=(
                supporting_evidence_count
                if supporting_evidence_count is not None
                else len(action.evidence_ids or [])
            ),
            actions_this_incident=actions_this_incident,
            actions_this_hour=actions_this_hour,
            live_facts=live_facts,
        )
    )


async def _live_facts(
    session: AsyncSession, *, incident: Incident, spec: Any, params: Any
) -> dict[str, Any]:
    """Fetch the few live numbers the policy engine needs to size blast radius.

    Read-only and best-effort: if the cluster is unreachable we fall back to the
    static estimate, which is more conservative, not less.
    """
    from app.models.enums import IntegrationProvider

    namespace = getattr(params, "namespace", None)
    deployment = getattr(params, "deployment", None)
    if spec.provider is not IntegrationProvider.KUBERNETES or not (namespace and deployment):
        return {}

    registry = ClientRegistry(incident.tenant_id, scenario=(incident.labels or {}).get("scenario"))
    try:
        await registry.load(session, providers={IntegrationProvider.KUBERNETES})
        client = registry.get(IntegrationProvider.KUBERNETES)
        if client is None:
            return {}
        info = await client.get_deployment(namespace, deployment)
        if info.get("error"):
            return {}
        return {
            "current_replicas": info.get("replicas"),
            "ready_replicas": info.get("ready_replicas"),
            "revision": info.get("revision"),
        }
    except Exception as exc:  # noqa: BLE001
        log.debug("executor.live_facts_failed", error=str(exc)[:200])
        return {}
    finally:
        await registry.aclose()


async def _fail(
    session: AsyncSession,
    action: RemediationAction,
    incident: Incident,
    *,
    status: RemediationStatus,
    summary: str,
    error: str,
    actor: str,
    policy_decision: dict[str, Any] | None = None,
) -> ExecutionOutcome:
    action.status = status
    action.execution_error = error
    if policy_decision is not None:
        action.policy_decision = policy_decision
        action.policy_violations = policy_decision.get("violations", [])

    await audit.record(
        session,
        tenant_id=action.tenant_id,
        action=(
            AuditAction.REMEDIATION_POLICY_BLOCKED
            if status is RemediationStatus.BLOCKED_BY_POLICY
            else AuditAction.REMEDIATION_FAILED
        ),
        resource_type="remediation_action",
        resource_id=action.id,
        actor_type="system",
        actor_id=actor,
        incident_id=action.incident_id,
        summary=f"{summary}: {error}",
        after={"status": str(status), "action_key": action.action_key},
    )
    await _timeline(
        session,
        action=action,
        title=summary,
        body=error,
        actor_label="OpsPilot policy engine",
        actor_type="system",
    )
    await events.emit(
        type=AgentEventType.POLICY_DECISION,
        incident_id=action.incident_id,
        tenant_id=action.tenant_id,
        phase=AgentPhase.POLICY_CHECK,
        title=summary,
        message=error,
        action_id=str(action.id),
        allowed=False,
    )
    log.warning(
        "action.blocked", action_key=action.action_key, action_id=str(action.id), reason=error
    )
    return ExecutionOutcome(
        action_id=action.id,
        succeeded=False,
        status=status,
        summary=summary,
        detail={},
        error=error,
    )


async def _timeline(
    session: AsyncSession,
    *,
    action: RemediationAction,
    title: str,
    body: str,
    actor_label: str,
    actor_type: str,
) -> None:
    from app.models.incident import TimelineEntry

    session.add(
        TimelineEntry(
            tenant_id=action.tenant_id,
            incident_id=action.incident_id,
            occurred_at=datetime.now(UTC),
            actor_type=actor_type,
            actor_id=str(action.id),
            actor_label=actor_label[:200],
            phase=AgentPhase.EXECUTE,
            title=title[:300],
            body=body[:20000],
            metadata_json={
                "action_key": action.action_key,
                "action_id": str(action.id),
                "risk_tier": str(action.risk_tier),
            },
        )
    )
