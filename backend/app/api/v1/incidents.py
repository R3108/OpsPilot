"""Incident CRUD, investigation control, evidence, actions and postmortems."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import select

from app.api.deps import (
    CurrentPrincipal,
    DbSession,
    RequireResponder,
    rate_limit,
)
from app.core.config import settings
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.models.enums import (
    ApprovalStatus,
    AuditAction,
    IncidentSeverity,
    IncidentSource,
    IncidentStatus,
    RemediationStatus,
)
from app.models.incident import AgentRun, AgentStep, Postmortem
from app.models.remediation import ActionExecutionLog, Approval, RemediationAction
from app.schemas.common import Acknowledgement, Page
from app.schemas.incident import (
    AgentRunDetail,
    AgentRunOut,
    AgentStepOut,
    EvidenceOut,
    HypothesisOut,
    IncidentComment,
    IncidentCreate,
    IncidentDetail,
    IncidentFilters,
    IncidentSummary,
    IncidentUpdate,
    PostmortemOut,
    PostmortemUpdate,
    TimelineEntryOut,
    VerificationOut,
)
from app.schemas.remediation import (
    ExecutionLogOut,
    ManualActionRequest,
    RemediationActionOut,
)
from app.services import audit
from app.services import incidents as incident_service
from app.services.actions import get_action
from app.services.executor import evaluate_action, execute_action
from app.services.investigations import get_graph_state
from app.workers.queue import enqueue_investigation

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _summary(incident, open_approvals: int = 0) -> IncidentSummary:  # noqa: ANN001
    data = IncidentSummary.model_validate(incident)
    data.open_approval_count = open_approvals
    return data


@router.get("", response_model=Page[IncidentSummary])
async def list_incidents(
    principal: CurrentPrincipal,
    session: DbSession,
    status_filter: Annotated[list[IncidentStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[IncidentSeverity] | None, Query()] = None,
    source: Annotated[list[IncidentSource] | None, Query()] = None,
    service: str | None = None,
    environment: str | None = None,
    assignee_id: uuid.UUID | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[IncidentSummary]:
    filters = IncidentFilters(
        status=status_filter,
        severity=severity,
        source=source,
        service=service,
        environment=environment,
        assignee_id=assignee_id,
        query=q,
        since=since,
        until=until,
    )
    rows, total, approvals = await incident_service.list_incidents(
        session, tenant_id=principal.tenant_id, filters=filters, limit=limit, offset=offset
    )
    return Page(
        items=[_summary(r, approvals.get(r.id, 0)) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "",
    response_model=IncidentSummary,
    status_code=status.HTTP_201_CREATED,
    dependencies=[rate_limit(limit=120, window_seconds=60, scope="incident_create")],
)
async def create_incident(
    payload: IncidentCreate,
    principal: RequireResponder,
    session: DbSession,
    response: Response,
) -> IncidentSummary:
    incident, deduplicated = await incident_service.create_incident(
        session,
        tenant_id=principal.tenant_id,
        payload=payload,
        actor_type=principal.audit_actor_type,
        actor_id=str(principal.id),
        actor_label=principal.label,
    )
    if deduplicated:
        response.status_code = status.HTTP_200_OK
    elif payload.auto_investigate:
        await session.commit()  # the worker must be able to see the row
        await enqueue_investigation(
            incident_id=incident.id,
            tenant_id=principal.tenant_id,
            triggered_by=principal.label,
        )
    return _summary(incident)


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> IncidentDetail:
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    detail = await incident_service.load_detail(session, incident=incident)

    payload = IncidentDetail.model_validate(incident)
    payload.open_approval_count = detail["open_approval_count"]
    payload.timeline = [TimelineEntryOut.model_validate(t) for t in detail["timeline"]]
    payload.evidence = [
        EvidenceOut.model_validate(e).model_copy(update={"citation": e.citation})
        for e in detail["evidence"]
    ]
    payload.hypotheses = [HypothesisOut.model_validate(h) for h in detail["hypotheses"]]
    payload.runs = [AgentRunOut.model_validate(r) for r in detail["runs"]]
    payload.verifications = [VerificationOut.model_validate(v) for v in detail["verifications"]]
    return payload


@router.patch("/{incident_id}", response_model=IncidentSummary)
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    principal: RequireResponder,
    session: DbSession,
) -> IncidentSummary:
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    user = principal.require_user()
    updated = await incident_service.update_incident(
        session,
        incident=incident,
        payload=payload,
        actor_id=user.id,
        actor_label=principal.label,
    )
    return _summary(updated)


@router.post("/{incident_id}/comments", response_model=TimelineEntryOut)
async def add_comment(
    incident_id: uuid.UUID,
    payload: IncidentComment,
    principal: RequireResponder,
    session: DbSession,
) -> TimelineEntryOut:
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    user = principal.require_user()
    entry = await incident_service.add_comment(
        session,
        incident=incident,
        body=payload.body,
        actor_id=user.id,
        actor_label=principal.label,
    )
    return TimelineEntryOut.model_validate(entry)


# --------------------------------------------------------------------------
# investigation control
# --------------------------------------------------------------------------
@router.post(
    "/{incident_id}/investigate",
    response_model=Acknowledgement,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[rate_limit(limit=30, window_seconds=300, scope="investigate")],
)
async def start_investigation(
    incident_id: uuid.UUID,
    principal: RequireResponder,
    session: DbSession,
    force: bool = False,
) -> Acknowledgement:
    """Queue an investigation. Returns immediately; watch /stream for progress."""
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    if incident.status.is_terminal and not force:
        raise ConflictError(f"Incident is {incident.status}; pass force=true to investigate again")
    await session.commit()

    job_id = await enqueue_investigation(
        incident_id=incident_id,
        tenant_id=principal.tenant_id,
        triggered_by=principal.label,
        force=force,
    )
    return Acknowledgement(
        message=f"Investigation queued for {incident.reference}"
        + (f" (job {job_id})" if job_id else "")
    )


@router.get("/{incident_id}/runs", response_model=list[AgentRunOut])
async def list_runs(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> list[AgentRunOut]:
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    rows = list(
        (
            await session.execute(
                select(AgentRun)
                .where(AgentRun.incident_id == incident_id)
                .order_by(AgentRun.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [AgentRunOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/runs/{run_id}", response_model=AgentRunDetail)
async def get_run(
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
) -> AgentRunDetail:
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    run = await session.get(AgentRun, run_id)
    if run is None or run.incident_id != incident_id:
        raise NotFoundError("Agent run not found")

    steps = list(
        (
            await session.execute(
                select(AgentStep).where(AgentStep.run_id == run_id).order_by(AgentStep.sequence)
            )
        )
        .scalars()
        .all()
    )
    detail = AgentRunDetail.model_validate(run)
    detail.steps = [AgentStepOut.model_validate(s) for s in steps]
    return detail


@router.get("/{incident_id}/graph-state")
async def graph_state(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> dict:
    """Live LangGraph checkpoint for this incident — what it will run next."""
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    return await get_graph_state(incident_id, principal.tenant_id)


# --------------------------------------------------------------------------
# evidence / actions / postmortem
# --------------------------------------------------------------------------
@router.get("/{incident_id}/evidence", response_model=list[EvidenceOut])
async def list_evidence(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> list[EvidenceOut]:
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    detail = await incident_service.load_detail(session, incident=incident)
    return [
        EvidenceOut.model_validate(e).model_copy(update={"citation": e.citation})
        for e in detail["evidence"]
    ]


@router.get("/{incident_id}/actions", response_model=list[RemediationActionOut])
async def list_actions(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> list[RemediationActionOut]:
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    rows = list(
        (
            await session.execute(
                select(RemediationAction)
                .where(RemediationAction.incident_id == incident_id)
                .order_by(RemediationAction.sequence, RemediationAction.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [RemediationActionOut.model_validate(r) for r in rows]


@router.post(
    "/{incident_id}/actions",
    response_model=RemediationActionOut,
    status_code=status.HTTP_201_CREATED,
)
async def propose_manual_action(
    incident_id: uuid.UUID,
    payload: ManualActionRequest,
    principal: RequireResponder,
    session: DbSession,
) -> RemediationActionOut:
    """A human proposing an action.

    This bypasses the LLM but **not** the catalog, the schema, the policy engine
    or the approval requirement — a responder gets the same guardrails the agent
    does.
    """
    incident = await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    spec = get_action(payload.action_key)
    params = spec.parse_params(payload.params)
    radius = spec.blast_radius(params)

    action = RemediationAction(
        tenant_id=principal.tenant_id,
        incident_id=incident_id,
        action_key=spec.key,
        title=spec.title,
        params=params.model_dump(mode="json"),
        rationale=payload.rationale,
        expected_effect="(proposed manually)",
        risk_tier=spec.risk_tier,
        blast_radius=radius.to_dict(),
        is_reversible=spec.is_reversible,
        status=RemediationStatus.PROPOSED,
        max_attempts=spec.max_attempts,
        idempotency_key=f"manual:{incident_id}:{uuid.uuid4().hex[:12]}",
    )
    session.add(action)
    await session.flush()

    decision = await evaluate_action(
        session, incident=incident, action=action, spec=spec, params=params
    )
    action.policy_decision = decision.to_dict()
    action.policy_violations = [v.to_dict() for v in decision.violations]
    action.risk_tier = decision.risk_tier
    action.requires_approval = decision.requires_approval
    action.blast_radius = decision.effective_blast_radius
    action.status = (
        RemediationStatus.BLOCKED_BY_POLICY
        if not decision.allowed
        else RemediationStatus.AWAITING_APPROVAL
        if decision.requires_approval
        else RemediationStatus.APPROVED
    )

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.REMEDIATION_PROPOSED,
        resource_type="remediation_action",
        resource_id=action.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        incident_id=incident_id,
        summary=f"Manually proposed {spec.key}",
        after={"status": str(action.status), "risk_tier": str(action.risk_tier)},
    )

    if decision.requires_approval:
        from app.agents.nodes.remediation import _approval_summary

        session.add(
            Approval(
                tenant_id=principal.tenant_id,
                incident_id=incident_id,
                action_id=action.id,
                status=ApprovalStatus.PENDING,
                risk_tier=decision.risk_tier,
                required_role=str(decision.required_role),
                request_summary=_approval_summary(action, decision, {}),
                context={
                    "action_key": action.action_key,
                    "params": action.params,
                    "rationale": action.rationale,
                    "blast_radius": decision.effective_blast_radius,
                    "checklist": spec.approval_checklist,
                    "proposed_by": principal.label,
                },
                requested_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(minutes=settings.approval_ttl_minutes),
            )
        )

    return RemediationActionOut.model_validate(action)


@router.post("/{incident_id}/actions/{action_id}/execute", response_model=RemediationActionOut)
async def execute_approved_action(
    incident_id: uuid.UUID,
    action_id: uuid.UUID,
    principal: RequireResponder,
    session: DbSession,
    dry_run: bool = False,
) -> RemediationActionOut:
    """Execute an already-approved action out of band.

    Useful when the graph has finished but an operator wants to run the last
    approved step. Every gate in :mod:`app.services.executor` still applies.
    """
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    action = await session.get(RemediationAction, action_id)
    if action is None or action.incident_id != incident_id:
        raise NotFoundError("Action not found")
    if action.status not in (RemediationStatus.APPROVED, RemediationStatus.PROPOSED):
        raise ValidationError(
            f"Action is {action.status}; only approved actions can be executed",
        )

    await execute_action(
        session,
        action,
        actor=principal.label,
        actor_type=principal.audit_actor_type,
        dry_run=dry_run,
    )
    return RemediationActionOut.model_validate(action)


@router.get("/{incident_id}/actions/{action_id}/logs", response_model=list[ExecutionLogOut])
async def action_logs(
    incident_id: uuid.UUID,
    action_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: DbSession,
) -> list[ExecutionLogOut]:
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    rows = list(
        (
            await session.execute(
                select(ActionExecutionLog)
                .where(ActionExecutionLog.action_id == action_id)
                .order_by(ActionExecutionLog.attempt)
            )
        )
        .scalars()
        .all()
    )
    return [ExecutionLogOut.model_validate(r) for r in rows]


@router.get("/{incident_id}/postmortem", response_model=PostmortemOut)
async def get_postmortem(
    incident_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> PostmortemOut:
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    postmortem = (
        await session.execute(select(Postmortem).where(Postmortem.incident_id == incident_id))
    ).scalar_one_or_none()
    if postmortem is None:
        raise NotFoundError("No postmortem has been generated for this incident yet")
    return PostmortemOut.model_validate(postmortem)


@router.patch("/{incident_id}/postmortem", response_model=PostmortemOut)
async def update_postmortem(
    incident_id: uuid.UUID,
    payload: PostmortemUpdate,
    principal: RequireResponder,
    session: DbSession,
) -> PostmortemOut:
    """Humans own the final document; the agent only ever writes the draft."""
    await incident_service.get_incident(
        session, tenant_id=principal.tenant_id, incident_id=incident_id
    )
    postmortem = (
        await session.execute(select(Postmortem).where(Postmortem.incident_id == incident_id))
    ).scalar_one_or_none()
    if postmortem is None:
        raise NotFoundError("No postmortem to update")

    for field in (
        "title",
        "summary",
        "impact",
        "root_cause",
        "detection",
        "resolution",
        "lessons_learned",
    ):
        value = getattr(payload, field)
        if value is not None:
            setattr(postmortem, field, value)
    if payload.action_items is not None:
        postmortem.action_items = [item.model_dump() for item in payload.action_items]
    if payload.is_published is not None and payload.is_published != postmortem.is_published:
        postmortem.is_published = payload.is_published
        postmortem.published_at = datetime.now(UTC) if payload.is_published else None
        await audit.record(
            session,
            tenant_id=principal.tenant_id,
            action=AuditAction.POSTMORTEM_PUBLISHED,
            resource_type="postmortem",
            resource_id=postmortem.id,
            actor_type=principal.audit_actor_type,
            actor_id=principal.id,
            actor_label=principal.label,
            incident_id=incident_id,
            summary=f"Postmortem {'published' if payload.is_published else 'unpublished'}",
        )
    return PostmortemOut.model_validate(postmortem)
