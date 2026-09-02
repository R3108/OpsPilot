"""Incident lifecycle: creation, deduplication, querying, status transitions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.models.enums import (
    AgentEventType,
    ApprovalStatus,
    AuditAction,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.incident import (
    AgentRun,
    Evidence,
    Hypothesis,
    Incident,
    TimelineEntry,
    Verification,
)
from app.models.remediation import Approval
from app.schemas.incident import IncidentCreate, IncidentFilters, IncidentUpdate
from app.services import audit, events

log = get_logger(__name__)

# Status transitions a human is allowed to make directly. The agent moves
# through the rest as it works.
ALLOWED_MANUAL_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.TRIAGED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.TRIAGED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.FAILED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.AWAITING_APPROVAL: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.REMEDIATING: {
        IncidentStatus.VERIFYING,
        IncidentStatus.RESOLVED,
        IncidentStatus.FAILED,
    },
    IncidentStatus.VERIFYING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FAILED,
    },
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.FAILED: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: {IncidentStatus.INVESTIGATING},
}


async def next_reference(session: AsyncSession, tenant_id: uuid.UUID) -> str:
    """Allocate the next ``INC-n`` for a tenant.

    Derived from the current maximum rather than a sequence so that references
    stay per-tenant and gap-free-ish; the unique constraint on
    ``(tenant_id, reference)`` is what actually guarantees correctness under
    concurrency, and :func:`create_incident` retries on conflict.
    """
    latest = (
        (
            await session.execute(
                select(Incident.reference)
                .where(Incident.tenant_id == tenant_id)
                .order_by(Incident.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )

    highest = 0
    for reference in latest:
        try:
            highest = max(highest, int(str(reference).split("-")[-1]))
        except (ValueError, IndexError):
            continue
    return f"INC-{highest + 1:04d}"


def build_dedupe_key(payload: IncidentCreate) -> str:
    """Collapse an alert storm into one incident.

    Keyed on the stable identity of the *condition*, not the notification: the
    provider's own fingerprint when it gives us one, otherwise
    source+service+environment+title.
    """
    if payload.dedupe_key:
        return payload.dedupe_key[:255]
    labels = payload.labels or {}
    for candidate in ("fingerprint", "alertname", "groupKey", "alarmName"):
        if labels.get(candidate):
            return f"{payload.source}:{payload.service or '-'}:{labels[candidate]}"[:255]
    return (
        f"{payload.source}:{payload.service or '-'}:{payload.environment}:"
        f"{payload.title.strip().lower()[:120]}"
    )[:255]


async def find_duplicate(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    dedupe_key: str,
    window_minutes: int = 60,
) -> Incident | None:
    """An *active* incident with the same key inside the window is the same incident."""
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    return (
        await session.execute(
            select(Incident)
            .where(
                Incident.tenant_id == tenant_id,
                Incident.dedupe_key == dedupe_key,
                Incident.created_at >= cutoff,
                Incident.status.notin_([IncidentStatus.CLOSED, IncidentStatus.FAILED]),
            )
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def create_incident(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    payload: IncidentCreate,
    actor_type: str = "system",
    actor_id: str | None = None,
    actor_label: str = "OpsPilot",
    deduplicate: bool = True,
) -> tuple[Incident, bool]:
    """Create an incident, or attach to the existing one it duplicates.

    Returns ``(incident, was_deduplicated)``.
    """
    dedupe_key = build_dedupe_key(payload)

    if deduplicate:
        existing = await find_duplicate(session, tenant_id=tenant_id, dedupe_key=dedupe_key)
        if existing is not None:
            session.add(
                TimelineEntry(
                    tenant_id=tenant_id,
                    incident_id=existing.id,
                    occurred_at=datetime.now(UTC),
                    actor_type=actor_type,
                    actor_id=actor_id,
                    actor_label=actor_label,
                    title="Duplicate alert received",
                    body=payload.title,
                    metadata_json={
                        "source": str(payload.source),
                        "source_event_id": payload.source_event_id,
                        "dedupe_key": dedupe_key,
                    },
                )
            )
            # A repeat alert is itself a signal that the condition persists.
            existing.raw_payload = {
                **(existing.raw_payload or {}),
                "duplicate_count": int((existing.raw_payload or {}).get("duplicate_count", 1)) + 1,
                "last_duplicate_at": datetime.now(UTC).isoformat(),
            }
            log.info(
                "incident.deduplicated",
                incident_id=str(existing.id),
                reference=existing.reference,
                dedupe_key=dedupe_key,
            )
            return existing, True

    detected_at = payload.detected_at or datetime.now(UTC)
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=UTC)

    # Retry on the unique-reference race rather than serialising every insert.
    last_error: Exception | None = None
    for _ in range(5):
        reference = await next_reference(session, tenant_id)
        incident = Incident(
            tenant_id=tenant_id,
            reference=reference,
            title=payload.title.strip()[:500],
            description=payload.description or "",
            status=IncidentStatus.OPEN,
            severity=payload.severity or IncidentSeverity.SEV3,
            source=payload.source,
            source_event_id=payload.source_event_id,
            dedupe_key=dedupe_key,
            service=payload.service,
            environment=payload.environment,
            cluster=payload.cluster,
            namespace=payload.namespace,
            labels=payload.labels or {},
            raw_payload=payload.raw_payload or {},
            detected_at=detected_at,
            auto_investigate=payload.auto_investigate,
        )
        session.add(incident)
        try:
            await session.flush()
            break
        except IntegrityError as exc:
            await session.rollback()
            last_error = exc
            continue
    else:  # pragma: no cover - five collisions in a row is pathological
        raise ValidationError(f"Could not allocate an incident reference: {last_error}")

    session.add(
        TimelineEntry(
            tenant_id=tenant_id,
            incident_id=incident.id,
            occurred_at=detected_at,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_label=actor_label,
            title=f"Incident created from {payload.source}",
            body=payload.description or payload.title,
            metadata_json={
                "source": str(payload.source),
                "source_event_id": payload.source_event_id,
                "labels": payload.labels or {},
            },
        )
    )
    await audit.record(
        session,
        tenant_id=tenant_id,
        action=AuditAction.INCIDENT_CREATED,
        resource_type="incident",
        resource_id=incident.id,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_label=actor_label,
        incident_id=incident.id,
        summary=f"{incident.reference}: {incident.title}",
        after={
            "severity": str(incident.severity),
            "source": str(incident.source),
            "service": incident.service,
        },
    )
    await events.emit(
        type=AgentEventType.INCIDENT_UPDATED,
        incident_id=incident.id,
        tenant_id=tenant_id,
        title=f"{incident.reference} created",
        message=incident.title,
        severity=str(incident.severity),
        status=str(incident.status),
    )
    log.info(
        "incident.created",
        incident_id=str(incident.id),
        reference=incident.reference,
        source=str(incident.source),
        service=incident.service,
    )
    return incident, False


async def get_incident(
    session: AsyncSession, *, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> Incident:
    incident = await session.get(Incident, incident_id)
    if incident is None or incident.tenant_id != tenant_id:
        raise NotFoundError("Incident not found")
    return incident


async def get_by_reference(
    session: AsyncSession, *, tenant_id: uuid.UUID, reference: str
) -> Incident:
    incident = (
        await session.execute(
            select(Incident).where(Incident.tenant_id == tenant_id, Incident.reference == reference)
        )
    ).scalar_one_or_none()
    if incident is None:
        raise NotFoundError(f"Incident {reference} not found")
    return incident


def apply_filters(stmt: Select[Any], filters: IncidentFilters) -> Select[Any]:
    if filters.status:
        stmt = stmt.where(Incident.status.in_(filters.status))
    if filters.severity:
        stmt = stmt.where(Incident.severity.in_(filters.severity))
    if filters.source:
        stmt = stmt.where(Incident.source.in_(filters.source))
    if filters.service:
        stmt = stmt.where(Incident.service == filters.service)
    if filters.environment:
        stmt = stmt.where(Incident.environment == filters.environment)
    if filters.assignee_id:
        stmt = stmt.where(Incident.assignee_id == filters.assignee_id)
    if filters.since:
        stmt = stmt.where(Incident.created_at >= filters.since)
    if filters.until:
        stmt = stmt.where(Incident.created_at <= filters.until)
    if filters.query:
        needle = f"%{filters.query.strip()}%"
        stmt = stmt.where(
            or_(
                Incident.title.ilike(needle),
                Incident.description.ilike(needle),
                Incident.reference.ilike(needle),
                Incident.service.ilike(needle),
                Incident.root_cause_summary.ilike(needle),
            )
        )
    return stmt


async def list_incidents(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    filters: IncidentFilters,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Incident], int, dict[uuid.UUID, int]]:
    base = select(Incident).where(Incident.tenant_id == tenant_id)
    base = apply_filters(base, filters)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = int((await session.execute(count_stmt)).scalar_one())

    rows = list(
        (
            await session.execute(
                base.order_by(
                    Incident.status.in_([IncidentStatus.CLOSED, IncidentStatus.RESOLVED]).asc(),
                    Incident.created_at.desc(),
                )
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )

    # Pending-approval counts for the list badges, in one query.
    approval_counts: dict[uuid.UUID, int] = {}
    if rows:
        counts = await session.execute(
            select(Approval.incident_id, func.count(Approval.id))
            .where(
                Approval.incident_id.in_([r.id for r in rows]),
                Approval.status == ApprovalStatus.PENDING,
            )
            .group_by(Approval.incident_id)
        )
        approval_counts = {row[0]: int(row[1]) for row in counts}

    return rows, total, approval_counts


async def update_incident(
    session: AsyncSession,
    *,
    incident: Incident,
    payload: IncidentUpdate,
    actor_id: uuid.UUID,
    actor_label: str,
) -> Incident:
    before = {
        "status": str(incident.status),
        "severity": str(incident.severity),
        "assignee_id": str(incident.assignee_id) if incident.assignee_id else None,
    }

    if payload.status is not None and payload.status is not incident.status:
        allowed = ALLOWED_MANUAL_TRANSITIONS.get(incident.status, set())
        if payload.status not in allowed:
            raise ValidationError(
                f"Cannot move an incident from {incident.status} to {payload.status}",
                details={"allowed": sorted(str(s) for s in allowed)},
            )
        incident.status = payload.status
        now = datetime.now(UTC)
        if payload.status is IncidentStatus.RESOLVED and incident.resolved_at is None:
            incident.resolved_at = now
        if payload.status is IncidentStatus.CLOSED and incident.closed_at is None:
            incident.closed_at = now

    if payload.title is not None:
        incident.title = payload.title.strip()[:500]
    if payload.description is not None:
        incident.description = payload.description
    if payload.severity is not None:
        incident.severity = payload.severity
    if payload.service is not None:
        incident.service = payload.service
    if payload.labels is not None:
        incident.labels = payload.labels
    if payload.assignee_id is not None:
        incident.assignee_id = payload.assignee_id

    after = {
        "status": str(incident.status),
        "severity": str(incident.severity),
        "assignee_id": str(incident.assignee_id) if incident.assignee_id else None,
    }
    changed = {k for k in before if before[k] != after[k]}

    if changed:
        session.add(
            TimelineEntry(
                tenant_id=incident.tenant_id,
                incident_id=incident.id,
                occurred_at=datetime.now(UTC),
                actor_type="user",
                actor_id=str(actor_id),
                actor_label=actor_label,
                title="Incident updated by " + actor_label,
                body="; ".join(f"{k}: {before[k]} → {after[k]}" for k in sorted(changed)),
                metadata_json={"changed": sorted(changed)},
            )
        )
        await audit.record(
            session,
            tenant_id=incident.tenant_id,
            action=AuditAction.INCIDENT_STATUS_CHANGED,
            resource_type="incident",
            resource_id=incident.id,
            actor_type="user",
            actor_id=actor_id,
            actor_label=actor_label,
            incident_id=incident.id,
            summary="; ".join(f"{k}: {before[k]} → {after[k]}" for k in sorted(changed)),
            before=before,
            after=after,
        )
        await events.emit(
            type=AgentEventType.INCIDENT_UPDATED,
            incident_id=incident.id,
            tenant_id=incident.tenant_id,
            title="Incident updated",
            message="; ".join(sorted(changed)),
            **after,
        )
    return incident


async def add_comment(
    session: AsyncSession,
    *,
    incident: Incident,
    body: str,
    actor_id: uuid.UUID,
    actor_label: str,
) -> TimelineEntry:
    entry = TimelineEntry(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        occurred_at=datetime.now(UTC),
        actor_type="user",
        actor_id=str(actor_id),
        actor_label=actor_label,
        title="Comment",
        body=body,
        metadata_json={"kind": "comment"},
    )
    session.add(entry)
    await audit.record(
        session,
        tenant_id=incident.tenant_id,
        action=AuditAction.INCIDENT_COMMENTED,
        resource_type="incident",
        resource_id=incident.id,
        actor_type="user",
        actor_id=actor_id,
        actor_label=actor_label,
        incident_id=incident.id,
        summary=body[:500],
    )
    await events.emit(
        type=AgentEventType.INCIDENT_UPDATED,
        incident_id=incident.id,
        tenant_id=incident.tenant_id,
        title=f"Comment from {actor_label}",
        message=body[:400],
    )
    return entry


async def load_detail(session: AsyncSession, *, incident: Incident) -> dict[str, Any]:
    """Everything the incident detail page needs, in one place."""
    timeline = list(
        (
            await session.execute(
                select(TimelineEntry)
                .where(TimelineEntry.incident_id == incident.id)
                .order_by(TimelineEntry.occurred_at)
            )
        )
        .scalars()
        .all()
    )
    evidence = list(
        (
            await session.execute(
                select(Evidence)
                .where(Evidence.incident_id == incident.id)
                .order_by(Evidence.weight.desc(), Evidence.collected_at)
            )
        )
        .scalars()
        .all()
    )
    hypotheses = list(
        (
            await session.execute(
                select(Hypothesis)
                .where(Hypothesis.incident_id == incident.id)
                .order_by(Hypothesis.rank)
            )
        )
        .scalars()
        .all()
    )
    runs = list(
        (
            await session.execute(
                select(AgentRun)
                .where(AgentRun.incident_id == incident.id)
                .order_by(AgentRun.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    verifications = list(
        (
            await session.execute(
                select(Verification)
                .where(Verification.incident_id == incident.id)
                .order_by(Verification.observed_at)
            )
        )
        .scalars()
        .all()
    )
    pending_approvals = int(
        (
            await session.execute(
                select(func.count(Approval.id)).where(
                    Approval.incident_id == incident.id,
                    Approval.status == ApprovalStatus.PENDING,
                )
            )
        ).scalar_one()
    )
    return {
        "timeline": timeline,
        "evidence": evidence,
        "hypotheses": hypotheses,
        "runs": runs,
        "verifications": verifications,
        "open_approval_count": pending_approvals,
    }
