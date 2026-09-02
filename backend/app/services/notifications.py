"""Outbound notifications.

Best-effort by design: a Slack outage must never block an investigation or,
worse, an approval. Every function here swallows provider errors after logging
them — the durable record is always the database, and the web UI is always a
complete approval surface on its own.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.integrations.base import ClientRegistry
from app.models.enums import IntegrationProvider
from app.models.incident import Incident
from app.models.remediation import Approval, RemediationAction
from app.services.actions import get_action

log = get_logger(__name__)


def _web_url(path: str) -> str:
    base = (settings.cors_origin_list or ["http://localhost:3000"])[0].rstrip("/")
    return f"{base}{path}"


async def notify_approval_requested(
    session: AsyncSession, *, approval: Approval, incident: Incident
) -> None:
    """Post an interactive approval card to Slack, if Slack is configured."""
    registry = ClientRegistry(incident.tenant_id)
    try:
        await registry.load(session, providers={IntegrationProvider.SLACK})
        client = registry.get(IntegrationProvider.SLACK)
        if client is None:
            return

        integration = registry.integration(IntegrationProvider.SLACK)
        channel = incident.labels.get("slack_channel") or (
            integration.config.get("default_channel") if integration else None
        )
        if not channel:
            log.debug("notify.no_slack_channel", incident_id=str(incident.id))
            return

        action = await session.get(RemediationAction, approval.action_id)
        checklist: list[str] = []
        if action is not None:
            try:
                checklist = get_action(action.action_key).approval_checklist
            except Exception:  # noqa: BLE001 - catalog drift must not block the page
                checklist = []

        result = await client.request_approval(
            channel=channel,
            approval_id=str(approval.id),
            incident_reference=incident.reference,
            incident_title=incident.title,
            action_title=action.title if action else approval.request_summary[:120],
            risk_tier=approval.risk_tier,
            summary=approval.request_summary,
            blast_radius=(approval.context or {}).get("blast_radius", {}),
            checklist=checklist,
            approve_url=_web_url(f"/incidents/{incident.id}?approval={approval.id}"),
        )
        approval.decision_channel = {"surface": "slack", **result}
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.approval_failed", error=str(exc)[:300], approval_id=str(approval.id))
    finally:
        await registry.aclose()


async def notify_approval_resolved(
    session: AsyncSession, *, approval: Approval, decided_by: str
) -> None:
    channel_info = approval.decision_channel or {}
    if channel_info.get("surface") != "slack":
        return

    registry = ClientRegistry(approval.tenant_id)
    try:
        await registry.load(session, providers={IntegrationProvider.SLACK})
        client = registry.get(IntegrationProvider.SLACK)
        if client is None:
            return
        action = await session.get(RemediationAction, approval.action_id)
        await client.resolve_approval_message(
            channel=channel_info.get("channel", ""),
            ts=channel_info.get("ts", ""),
            decision=str(approval.status),
            decided_by=decided_by,
            action_title=action.title if action else "remediation action",
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.resolve_failed", error=str(exc)[:300])
    finally:
        await registry.aclose()


async def notify_incident_update(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident: Incident,
    headline: str,
    body: str = "",
    status: str = "investigating",
) -> dict[str, Any] | None:
    registry = ClientRegistry(tenant_id)
    try:
        await registry.load(session, providers={IntegrationProvider.SLACK})
        client = registry.get(IntegrationProvider.SLACK)
        if client is None:
            return None
        integration = registry.integration(IntegrationProvider.SLACK)
        channel = incident.labels.get("slack_channel") or (
            integration.config.get("default_channel") if integration else None
        )
        if not channel:
            return None
        return await client.post_incident_update(
            channel=channel,
            headline=headline,
            body=body,
            status=status,
            incident_id=str(incident.id),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.update_failed", error=str(exc)[:300])
        return None
    finally:
        await registry.aclose()


async def annotate_grafana(
    session: AsyncSession, *, tenant_id: uuid.UUID, incident: Incident, text: str
) -> None:
    """Mark the incident on the dashboards so the graphs carry their own context."""
    registry = ClientRegistry(tenant_id)
    try:
        await registry.load(session, providers={IntegrationProvider.GRAFANA}, require_write=True)
        client = registry.get(IntegrationProvider.GRAFANA)
        if client is None:
            return
        await client.create_annotation(
            text=f"{incident.reference}: {text}",
            tags=["incident", str(incident.severity), incident.service or "unknown"],
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("notify.annotation_failed", error=str(exc)[:200])
    finally:
        await registry.aclose()
