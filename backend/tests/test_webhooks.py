"""Alert ingestion: signature verification, normalisation and de-duplication."""

from __future__ import annotations

import json
import time
import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import seal
from app.core.security import sign_payload
from app.models.enums import IncidentSeverity, IncidentSource, IntegrationProvider
from app.models.integration import Integration
from app.models.tenant import Tenant

SECRET = "webhook-signing-secret"


async def make_integration(
    session: AsyncSession, tenant: Tenant, provider: IntegrationProvider
) -> Integration:
    integration = Integration(
        tenant_id=tenant.id,
        provider=provider,
        name="test",
        config={"repos": ["acme/api"]},
        is_enabled=True,
    )
    session.add(integration)
    await session.flush()
    integration.webhook_secret_sealed = seal(SECRET, context=integration.crypto_context)
    await session.commit()
    return integration


ALERTMANAGER_PAYLOAD = {
    "groupKey": '{}:{alertname="HighErrorRate"}',
    "status": "firing",
    "commonLabels": {"severity": "critical", "environment": "production"},
    "commonAnnotations": {},
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "HighErrorRate",
                "service": "checkout-api",
                "namespace": "payments",
                "severity": "critical",
            },
            "annotations": {
                "summary": "checkout-api error rate above 5%",
                "description": "Error rate has been above 5% for 10 minutes",
            },
            "startsAt": "2026-08-30T14:02:00Z",
        }
    ],
}


async def test_alertmanager_webhook_creates_an_incident(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    body = json.dumps(ALERTMANAGER_PAYLOAD).encode()

    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-OpsPilot-Signature": sign_payload(body, SECRET),
        },
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["accepted"] is True
    assert result["incident_reference"]

    from sqlalchemy import select

    from app.models.incident import Incident

    incident = (
        await session.execute(select(Incident).where(Incident.tenant_id == tenant.id))
    ).scalar_one()
    assert incident.title == "checkout-api error rate above 5%"
    assert incident.severity is IncidentSeverity.SEV1
    assert incident.source is IncidentSource.PROMETHEUS
    assert incident.service == "checkout-api"
    assert incident.namespace == "payments"


async def test_malformed_json_is_rejected_with_400_not_500(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    body = b"{not valid json"

    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-OpsPilot-Signature": sign_payload(body, SECRET),
        },
    )
    assert response.status_code == 422, response.text


async def test_bad_signature_is_rejected(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    body = json.dumps(ALERTMANAGER_PAYLOAD).encode()

    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=body,
        headers={"X-OpsPilot-Signature": sign_payload(body, "the-wrong-secret")},
    )
    assert response.status_code == 401


async def test_tampered_body_is_rejected(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
    signature = sign_payload(body, SECRET)

    tampered = json.dumps({**ALERTMANAGER_PAYLOAD, "injected": True}).encode()
    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=tampered,
        headers={"X-OpsPilot-Signature": signature},
    )
    assert response.status_code == 401


async def test_missing_signature_is_rejected(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=json.dumps(ALERTMANAGER_PAYLOAD).encode(),
    )
    assert response.status_code == 401


async def test_unknown_integration_is_not_found(client: AsyncClient) -> None:
    body = b"{}"
    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{uuid.uuid4()}",
        content=body,
        headers={"X-OpsPilot-Signature": sign_payload(body, SECRET)},
    )
    assert response.status_code == 404


async def test_resolved_alerts_do_not_create_incidents(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    payload = {
        **ALERTMANAGER_PAYLOAD,
        "alerts": [{**ALERTMANAGER_PAYLOAD["alerts"][0], "status": "resolved"}],
    }
    body = json.dumps(payload).encode()

    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=body,
        headers={"X-OpsPilot-Signature": sign_payload(body, SECRET)},
    )
    assert response.status_code == 200
    assert response.json()["incident_id"] is None


async def test_repeat_delivery_is_deduplicated(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    """Providers retry. One condition must remain one incident."""
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)

    async def deliver(group_key: str) -> dict:
        payload = {**ALERTMANAGER_PAYLOAD, "groupKey": group_key}
        body = json.dumps(payload).encode()
        response = await client.post(
            f"/api/v1/webhooks/alertmanager/{integration.id}",
            content=body,
            headers={"X-OpsPilot-Signature": sign_payload(body, SECRET)},
        )
        return response.json()

    first = await deliver("group-a")
    # Same delivery id -> idempotency short-circuit.
    repeat = await deliver("group-a")
    assert repeat["deduplicated"] is True

    # Different delivery id, same underlying alert -> attaches to the incident.
    related = await deliver("group-b")
    assert related["deduplicated"] is True
    assert related["incident_reference"] == first["incident_reference"]

    from sqlalchemy import func, select

    from app.models.incident import Incident

    count = (
        await session.execute(
            select(func.count(Incident.id)).where(Incident.tenant_id == tenant.id)
        )
    ).scalar_one()
    assert count == 1


async def test_github_deployment_failure_creates_an_incident(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.GITHUB)
    payload = {
        "repository": {"full_name": "acme/api"},
        "deployment": {"environment": "production", "sha": "abc123", "ref": "main"},
        "deployment_status": {"state": "failure", "description": "health check failed"},
    }
    body = json.dumps(payload).encode()

    response = await client.post(
        f"/api/v1/webhooks/github/{integration.id}",
        content=body,
        headers={
            "X-Hub-Signature-256": "sha256=" + sign_payload(body, SECRET),
            "X-GitHub-Event": "deployment_status",
            "X-GitHub-Delivery": uuid.uuid4().hex,
        },
    )
    assert response.status_code == 200
    assert response.json()["incident_reference"]


async def test_github_noise_events_are_ignored(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.GITHUB)
    body = json.dumps({"repository": {"full_name": "acme/api"}}).encode()

    response = await client.post(
        f"/api/v1/webhooks/github/{integration.id}",
        content=body,
        headers={
            "X-Hub-Signature-256": "sha256=" + sign_payload(body, SECRET),
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": uuid.uuid4().hex,
        },
    )
    assert response.status_code == 200
    assert response.json()["incident_id"] is None
    assert "not ingested" in response.json()["reason"]


async def test_non_deploy_workflow_failures_are_ignored(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.GITHUB)
    payload = {
        "action": "completed",
        "repository": {"full_name": "acme/api"},
        "workflow_run": {"name": "lint", "conclusion": "failure", "id": 1},
    }
    body = json.dumps(payload).encode()

    response = await client.post(
        f"/api/v1/webhooks/github/{integration.id}",
        content=body,
        headers={
            "X-Hub-Signature-256": "sha256=" + sign_payload(body, SECRET),
            "X-GitHub-Event": "workflow_run",
            "X-GitHub-Delivery": uuid.uuid4().hex,
        },
    )
    assert response.status_code == 200
    assert response.json()["incident_id"] is None


async def test_slack_url_verification_handshake(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.SLACK)
    body = json.dumps({"type": "url_verification", "challenge": "abc123"}).encode()
    timestamp = str(int(time.time()))

    import hashlib
    import hmac

    signature = (
        "v0="
        + hmac.new(
            SECRET.encode(), b"v0:" + timestamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()
    )
    response = await client.post(
        f"/api/v1/webhooks/slack/{integration.id}",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Slack-Signature": signature,
            "X-Slack-Request-Timestamp": timestamp,
        },
    )
    assert response.status_code == 200
    assert response.json()["challenge"] == "abc123"


async def test_disabled_integration_stops_accepting_alerts(
    client: AsyncClient, session: AsyncSession, tenant: Tenant
) -> None:
    integration = await make_integration(session, tenant, IntegrationProvider.PROMETHEUS)
    integration.is_enabled = False
    await session.commit()

    body = json.dumps(ALERTMANAGER_PAYLOAD).encode()
    response = await client.post(
        f"/api/v1/webhooks/alertmanager/{integration.id}",
        content=body,
        headers={"X-OpsPilot-Signature": sign_payload(body, SECRET)},
    )
    assert response.status_code == 404
