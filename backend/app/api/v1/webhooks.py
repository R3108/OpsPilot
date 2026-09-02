"""Alert ingestion.

Every endpoint here is unauthenticated in the normal sense — the caller is a
third-party system — so each one:

* addresses a specific integration by id, and verifies an HMAC signature against
  that integration's own sealed webhook secret;
* de-duplicates on a delivery id so provider retries do not create duplicate
  incidents;
* normalises a provider-specific payload into an ``IncidentCreate`` and hands it
  to the same service the UI uses.

A request that fails signature verification is rejected before its body is
parsed into anything meaningful.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, Request, Response, status
from sqlalchemy import select

from app.core.crypto import CryptoError, open_sealed
from app.core.db import session_scope
from app.core.errors import AuthenticationError, NotFoundError
from app.core.logging import get_logger, tenant_id_ctx
from app.core.redis_client import claim_once, rate_limit_ok
from app.core.security import (
    verify_github_signature,
    verify_hmac_signature,
    verify_slack_signature,
)
from app.models.enums import IncidentSeverity, IncidentSource, IntegrationProvider
from app.models.integration import Integration
from app.schemas.incident import IncidentCreate
from app.schemas.integration import WebhookIngestResult
from app.services import incidents as incident_service
from app.workers.queue import enqueue_investigation

log = get_logger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Alertmanager/Grafana severity labels -> our scale.
SEVERITY_MAP = {
    "critical": IncidentSeverity.SEV1,
    "page": IncidentSeverity.SEV1,
    "error": IncidentSeverity.SEV2,
    "high": IncidentSeverity.SEV2,
    "warning": IncidentSeverity.SEV3,
    "medium": IncidentSeverity.SEV3,
    "info": IncidentSeverity.SEV4,
    "low": IncidentSeverity.SEV4,
    "none": IncidentSeverity.SEV5,
}


async def _load_integration(session, integration_id: uuid.UUID, provider: IntegrationProvider):  # noqa: ANN001, ANN202
    integration = await session.get(Integration, integration_id)
    if integration is None or integration.provider is not provider:
        raise NotFoundError("Unknown webhook endpoint")
    if not integration.is_enabled:
        raise NotFoundError("This integration is disabled")
    tenant_id_ctx.set(str(integration.tenant_id))
    return integration


def _webhook_secret(integration: Integration) -> str:
    if not integration.webhook_secret_sealed:
        raise AuthenticationError(
            "This integration has no webhook secret configured; set one before sending alerts to it"
        )
    try:
        return open_sealed(integration.webhook_secret_sealed, context=integration.crypto_context)
    except CryptoError as exc:  # pragma: no cover
        raise AuthenticationError("Webhook secret could not be read") from exc


async def _throttle(integration: Integration) -> None:
    ok, count = await rate_limit_ok(f"webhook:{integration.id}", limit=600, window_seconds=60)
    if not ok:
        log.warning("webhook.rate_limited", integration_id=str(integration.id), count=count)
        raise AuthenticationError("Webhook rate limit exceeded for this integration")


async def _ingest(
    session,  # noqa: ANN001
    *,
    integration: Integration,
    payload: IncidentCreate,
    delivery_id: str | None,
) -> WebhookIngestResult:
    if delivery_id:
        key = f"webhook:{integration.id}:{delivery_id}"
        if not await claim_once(key, ttl_seconds=86_400):
            log.info("webhook.duplicate_delivery", integration_id=str(integration.id))
            return WebhookIngestResult(
                accepted=True, deduplicated=True, reason="duplicate delivery"
            )

    incident, deduplicated = await incident_service.create_incident(
        session,
        tenant_id=integration.tenant_id,
        payload=payload,
        actor_type="integration",
        actor_id=str(integration.id),
        actor_label=f"{integration.provider}:{integration.name}",
    )
    await session.commit()

    if not deduplicated and payload.auto_investigate:
        await enqueue_investigation(
            incident_id=incident.id,
            tenant_id=integration.tenant_id,
            triggered_by=f"webhook:{integration.provider}",
        )

    return WebhookIngestResult(
        accepted=True,
        incident_id=incident.id,
        incident_reference=incident.reference,
        deduplicated=deduplicated,
        reason="attached to existing incident" if deduplicated else "incident created",
    )


# ==========================================================================
# Prometheus Alertmanager
# ==========================================================================
@router.post("/alertmanager/{integration_id}", response_model=WebhookIngestResult)
async def alertmanager_webhook(
    integration_id: uuid.UUID,
    request: Request,
    x_opspilot_signature: str | None = Header(default=None, alias="X-OpsPilot-Signature"),
) -> WebhookIngestResult:
    """Alertmanager has no native signing, so we require our own HMAC header."""
    body = await request.body()
    async with session_scope() as session:
        integration = await _load_integration(
            session, integration_id, IntegrationProvider.PROMETHEUS
        )
        await _throttle(integration)
        if not verify_hmac_signature(body, x_opspilot_signature, _webhook_secret(integration)):
            log.warning("webhook.bad_signature", provider="alertmanager")
            raise AuthenticationError("Invalid webhook signature")

        data = json.loads(body or b"{}")
        firing = [a for a in data.get("alerts", []) if a.get("status") == "firing"]
        if not firing:
            return WebhookIngestResult(accepted=True, reason="no firing alerts in this delivery")

        primary = firing[0]
        labels = {**data.get("commonLabels", {}), **primary.get("labels", {})}
        annotations = {**data.get("commonAnnotations", {}), **primary.get("annotations", {})}

        payload = IncidentCreate(
            title=(annotations.get("summary") or labels.get("alertname") or "Prometheus alert")[
                :500
            ],
            description=annotations.get("description", ""),
            severity=SEVERITY_MAP.get(str(labels.get("severity", "")).lower()),
            source=IncidentSource.PROMETHEUS,
            source_event_id=data.get("groupKey"),
            dedupe_key=(
                f"prometheus:{labels.get('alertname')}:{labels.get('service') or labels.get('job')}"
            ),
            service=labels.get("service") or labels.get("job"),
            environment=labels.get("environment", "production"),
            cluster=labels.get("cluster"),
            namespace=labels.get("namespace"),
            labels={**labels, "alert_count": len(firing)},
            raw_payload=data,
            detected_at=_parse_time(primary.get("startsAt")),
        )
        return await _ingest(
            session, integration=integration, payload=payload, delivery_id=data.get("groupKey")
        )


# ==========================================================================
# Grafana
# ==========================================================================
@router.post("/grafana/{integration_id}", response_model=WebhookIngestResult)
async def grafana_webhook(
    integration_id: uuid.UUID,
    request: Request,
    x_opspilot_signature: str | None = Header(default=None, alias="X-OpsPilot-Signature"),
) -> WebhookIngestResult:
    body = await request.body()
    async with session_scope() as session:
        integration = await _load_integration(session, integration_id, IntegrationProvider.GRAFANA)
        await _throttle(integration)
        if not verify_hmac_signature(body, x_opspilot_signature, _webhook_secret(integration)):
            raise AuthenticationError("Invalid webhook signature")

        data = json.loads(body or b"{}")
        alerts = data.get("alerts") or []
        firing = [a for a in alerts if a.get("status") == "firing"] or alerts
        if not firing:
            return WebhookIngestResult(accepted=True, reason="no alerts in delivery")

        primary = firing[0]
        labels = primary.get("labels", {})
        annotations = primary.get("annotations", {})

        payload = IncidentCreate(
            title=(data.get("title") or labels.get("alertname") or "Grafana alert")[:500],
            description=annotations.get("description") or data.get("message", ""),
            severity=SEVERITY_MAP.get(str(labels.get("severity", "")).lower()),
            source=IncidentSource.GRAFANA,
            source_event_id=primary.get("fingerprint"),
            dedupe_key=f"grafana:{labels.get('alertname')}:{labels.get('service', '')}",
            service=labels.get("service"),
            environment=labels.get("environment", "production"),
            namespace=labels.get("namespace"),
            labels={**labels, "dashboard_url": primary.get("dashboardURL")},
            raw_payload=data,
            detected_at=_parse_time(primary.get("startsAt")),
        )
        return await _ingest(
            session,
            integration=integration,
            payload=payload,
            delivery_id=primary.get("fingerprint"),
        )


# ==========================================================================
# CloudWatch (SNS)
# ==========================================================================
@router.post("/cloudwatch/{integration_id}", response_model=WebhookIngestResult)
async def cloudwatch_webhook(
    integration_id: uuid.UUID,
    request: Request,
    response: Response,
    x_opspilot_signature: str | None = Header(default=None, alias="X-OpsPilot-Signature"),
) -> WebhookIngestResult:
    body = await request.body()
    async with session_scope() as session:
        integration = await _load_integration(
            session, integration_id, IntegrationProvider.CLOUDWATCH
        )
        await _throttle(integration)
        if not verify_hmac_signature(body, x_opspilot_signature, _webhook_secret(integration)):
            raise AuthenticationError("Invalid webhook signature")

        envelope = json.loads(body or b"{}")
        if envelope.get("Type") == "SubscriptionConfirmation":
            # Confirming is a deliberate manual step; surface the URL instead of
            # auto-confirming a subscription we did not ask for.
            response.status_code = status.HTTP_202_ACCEPTED
            log.info(
                "webhook.sns_subscription_pending",
                integration_id=str(integration.id),
                subscribe_url=envelope.get("SubscribeURL"),
            )
            return WebhookIngestResult(
                accepted=True,
                reason="SNS subscription confirmation received; confirm it manually",
            )

        try:
            alarm = json.loads(envelope.get("Message") or "{}")
        except json.JSONDecodeError:
            alarm = {"AlarmName": envelope.get("Subject", "CloudWatch alarm")}

        if alarm.get("NewStateValue") not in (None, "ALARM"):
            return WebhookIngestResult(
                accepted=True, reason=f"ignoring state {alarm.get('NewStateValue')}"
            )

        trigger = alarm.get("Trigger", {})
        dimensions = {d.get("name"): d.get("value") for d in trigger.get("Dimensions", []) if d}
        payload = IncidentCreate(
            title=(alarm.get("AlarmName") or "CloudWatch alarm")[:500],
            description=alarm.get("NewStateReason") or alarm.get("AlarmDescription", ""),
            severity=IncidentSeverity.SEV2,
            source=IncidentSource.CLOUDWATCH,
            source_event_id=envelope.get("MessageId"),
            dedupe_key=f"cloudwatch:{alarm.get('AlarmName')}",
            service=dimensions.get("ServiceName") or dimensions.get("FunctionName"),
            environment=dimensions.get("Environment", "production"),
            labels={
                "metric": trigger.get("MetricName"),
                "namespace": trigger.get("Namespace"),
                "region": alarm.get("Region"),
                **dimensions,
            },
            raw_payload=alarm,
            detected_at=_parse_time(alarm.get("StateChangeTime")),
        )
        return await _ingest(
            session,
            integration=integration,
            payload=payload,
            delivery_id=envelope.get("MessageId"),
        )


# ==========================================================================
# GitHub
# ==========================================================================
@router.post("/github/{integration_id}", response_model=WebhookIngestResult)
async def github_webhook(
    integration_id: uuid.UUID,
    request: Request,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
) -> WebhookIngestResult:
    """Failed deployments and failed workflow runs become incidents.

    Other events are acknowledged and ignored — GitHub sends a lot of traffic and
    only a narrow slice of it indicates a production problem.
    """
    body = await request.body()
    async with session_scope() as session:
        integration = await _load_integration(session, integration_id, IntegrationProvider.GITHUB)
        await _throttle(integration)
        if not verify_github_signature(body, x_hub_signature_256, _webhook_secret(integration)):
            log.warning("webhook.bad_signature", provider="github")
            raise AuthenticationError("Invalid webhook signature")

        data = json.loads(body or b"{}")
        repo = (data.get("repository") or {}).get("full_name", "unknown")

        if x_github_event == "deployment_status":
            state = (data.get("deployment_status") or {}).get("state")
            if state not in ("failure", "error"):
                return WebhookIngestResult(accepted=True, reason=f"deployment {state}")
            deployment = data.get("deployment") or {}
            payload = IncidentCreate(
                title=f"Deployment failed: {repo} → {deployment.get('environment')}",
                description=(data.get("deployment_status") or {}).get("description", ""),
                severity=IncidentSeverity.SEV2,
                source=IncidentSource.GITHUB,
                source_event_id=x_github_delivery,
                dedupe_key=f"github:deployment_failure:{repo}:{deployment.get('environment')}",
                service=deployment.get("environment"),
                environment=deployment.get("environment", "production"),
                labels={
                    "repo": repo,
                    "sha": deployment.get("sha"),
                    "ref": deployment.get("ref"),
                    "event": "deployment_status",
                },
                raw_payload=data,
            )
        elif x_github_event == "workflow_run":
            run = data.get("workflow_run") or {}
            if run.get("conclusion") != "failure" or data.get("action") != "completed":
                return WebhookIngestResult(
                    accepted=True, reason=f"workflow {run.get('conclusion')}"
                )
            # Only deploy-ish workflows are incident-worthy; a failing lint job is not.
            name = str(run.get("name", "")).lower()
            if not any(word in name for word in ("deploy", "release", "publish", "prod")):
                return WebhookIngestResult(
                    accepted=True, reason="non-deployment workflow failure ignored"
                )
            payload = IncidentCreate(
                title=f"Deployment workflow failed: {run.get('name')} on {repo}",
                description=f"Workflow run {run.get('id')} concluded with failure.",
                severity=IncidentSeverity.SEV3,
                source=IncidentSource.GITHUB,
                source_event_id=x_github_delivery,
                dedupe_key=f"github:workflow_failure:{repo}:{run.get('name')}",
                labels={
                    "repo": repo,
                    "workflow": run.get("name"),
                    "head_sha": run.get("head_sha"),
                    "url": run.get("html_url"),
                    "event": "workflow_run",
                },
                raw_payload=data,
            )
        else:
            return WebhookIngestResult(
                accepted=True, reason=f"event '{x_github_event}' is not ingested"
            )

        return await _ingest(
            session, integration=integration, payload=payload, delivery_id=x_github_delivery
        )


# ==========================================================================
# Slack
# ==========================================================================
@router.post("/slack/{integration_id}")
async def slack_webhook(
    integration_id: uuid.UUID,
    request: Request,
    x_slack_signature: str | None = Header(default=None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str | None = Header(default=None, alias="X-Slack-Request-Timestamp"),
) -> Any:
    """Slack events, slash commands and interactive approval buttons."""
    body = await request.body()
    async with session_scope() as session:
        integration = await _load_integration(session, integration_id, IntegrationProvider.SLACK)
        await _throttle(integration)

        secret = _webhook_secret(integration)
        if not verify_slack_signature(body, x_slack_request_timestamp, x_slack_signature, secret):
            log.warning("webhook.bad_signature", provider="slack")
            raise AuthenticationError("Invalid Slack signature")

        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs

            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            if "payload" in form:
                return await _slack_interaction(session, integration, json.loads(form["payload"]))
            return await _slack_command(session, integration, form)

        data = json.loads(body or b"{}")
        if data.get("type") == "url_verification":
            return {"challenge": data.get("challenge")}
        return {"ok": True}


async def _slack_interaction(
    session,
    integration: Integration,
    payload: dict[str, Any],  # noqa: ANN001
) -> dict[str, Any]:
    """Handle an Approve/Reject button click.

    The button carries only an approval id. Authorisation happens here against
    the OpsPilot user mapped to the clicking Slack account — a click from someone
    without the required role is refused exactly as an API call would be.
    """
    from app.core.errors import OpsPilotError
    from app.models.tenant import User
    from app.services import approvals as approval_service

    actions = payload.get("actions") or []
    if not actions:
        return {"text": "No action in payload."}

    value = str(actions[0].get("value", ""))
    decision, _, approval_id = value.partition(":")
    if decision not in ("approve", "reject") or not approval_id:
        return {"text": "Unrecognised action."}

    slack_user_id = (payload.get("user") or {}).get("id", "")
    user = (
        await session.execute(
            select(User).where(
                User.tenant_id == integration.tenant_id,
                User.is_active.is_(True),
                User.external_ids["slack"].as_string() == slack_user_id,
            )
        )
    ).scalar_one_or_none()

    if user is None:
        log.warning(
            "slack.unmapped_user",
            slack_user_id=slack_user_id,
            tenant_id=str(integration.tenant_id),
        )
        return {
            "response_type": "ephemeral",
            "text": (
                "Your Slack account is not linked to an OpsPilot user, so this "
                "approval cannot be attributed. Ask an admin to link it, or decide "
                "in the OpsPilot web app."
            ),
        }

    try:
        approval = await approval_service.get_approval(
            session, tenant_id=integration.tenant_id, approval_id=uuid.UUID(approval_id)
        )
        await approval_service.resolve(
            session,
            approval=approval,
            decision=decision,
            user=user,
            note=f"Decided in Slack by {slack_user_id}",
            surface="slack",
        )
        still_pending = await approval_service.outstanding_for_incident(
            session, approval.incident_id
        )
        await session.commit()

        if not still_pending:
            await approval_service.schedule_resume(
                incident_id=approval.incident_id, tenant_id=integration.tenant_id
            )
        return {
            "response_type": "in_channel",
            "text": f"{'Approved' if decision == 'approve' else 'Rejected'} by <@{slack_user_id}>.",
        }
    except OpsPilotError as exc:
        return {"response_type": "ephemeral", "text": exc.message}


async def _slack_command(
    session,
    integration: Integration,
    form: dict[str, str],  # noqa: ANN001
) -> dict[str, Any]:
    """``/opspilot declare <title>`` opens an incident from a channel."""
    text = (form.get("text") or "").strip()
    if not text.startswith("declare"):
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/opspilot declare <what is broken>`",
        }

    title = text.removeprefix("declare").strip() or "Incident declared from Slack"
    payload = IncidentCreate(
        title=title[:500],
        description=f"Declared by <@{form.get('user_id')}> in <#{form.get('channel_id')}>",
        source=IncidentSource.SLACK,
        source_event_id=form.get("trigger_id"),
        labels={
            "slack_channel": form.get("channel_id", ""),
            "slack_user": form.get("user_id", ""),
        },
        raw_payload=dict(form),
    )
    result = await _ingest(
        session, integration=integration, payload=payload, delivery_id=form.get("trigger_id")
    )
    return {
        "response_type": "in_channel",
        "text": (
            f"Incident *{result.incident_reference}* created. OpsPilot is investigating."
            if result.incident_reference
            else "Incident received."
        ),
    }


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _delivery_fingerprint(body: bytes) -> str:
    """Fallback delivery id for providers that do not send one."""
    return hashlib.sha256(body).hexdigest()[:32]
