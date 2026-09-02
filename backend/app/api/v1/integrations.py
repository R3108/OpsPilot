"""Integration management.

Credentials go in and never come out: the API accepts them, seals them with
envelope encryption, and thereafter returns only fingerprints so the UI can show
*which* secrets are configured without ever displaying one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, status
from sqlalchemy import select

from app.api.deps import CurrentPrincipal, DbSession, RequireAdmin
from app.core.crypto import fingerprint, open_sealed_json, seal, seal_json
from app.core.errors import ConflictError, NotFoundError
from app.core.logging import get_logger
from app.models.enums import AuditAction, IntegrationProvider, IntegrationStatus
from app.models.integration import Integration
from app.schemas.common import Acknowledgement
from app.schemas.integration import (
    IntegrationCreate,
    IntegrationHealth,
    IntegrationOut,
    IntegrationUpdate,
)
from app.services import audit
from app.workers.queue import enqueue_integration_health_check

log = get_logger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


def _to_out(integration: Integration) -> IntegrationOut:
    payload = IntegrationOut.model_validate(integration)
    payload.has_webhook_secret = bool(integration.webhook_secret_sealed)
    return payload


@router.get("", response_model=list[IntegrationOut])
async def list_integrations(
    principal: CurrentPrincipal, session: DbSession
) -> list[IntegrationOut]:
    rows = list(
        (
            await session.execute(
                select(Integration)
                .where(Integration.tenant_id == principal.tenant_id)
                .order_by(Integration.provider, Integration.name)
            )
        )
        .scalars()
        .all()
    )
    return [_to_out(r) for r in rows]


@router.post("", response_model=IntegrationOut, status_code=status.HTTP_201_CREATED)
async def create_integration(
    payload: IntegrationCreate, principal: RequireAdmin, session: DbSession
) -> IntegrationOut:
    existing = (
        await session.execute(
            select(Integration).where(
                Integration.tenant_id == principal.tenant_id,
                Integration.provider == payload.provider,
                Integration.name == payload.name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            f"A {payload.provider} integration named '{payload.name}' already exists"
        )

    integration = Integration(
        tenant_id=principal.tenant_id,
        provider=payload.provider,
        name=payload.name,
        description=payload.description,
        config=payload.config,
        allow_write=payload.allow_write,
        scope=payload.scope.model_dump(),
        status=IntegrationStatus.PENDING,
    )
    session.add(integration)
    # The AAD binds the ciphertext to this row, so the id must exist first.
    await session.flush()

    _apply_credentials(integration, payload.credentials, payload.webhook_secret)

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.INTEGRATION_CREATED,
        resource_type="integration",
        resource_id=integration.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=(
            f"Created {payload.provider} integration '{payload.name}' "
            f"({'read-write' if payload.allow_write else 'read-only'})"
        ),
        after={
            "provider": str(payload.provider),
            "name": payload.name,
            "allow_write": payload.allow_write,
            "config_keys": sorted(payload.config),
            "credential_keys": sorted(payload.credentials),
        },
    )
    await session.commit()
    await enqueue_integration_health_check(integration_id=integration.id)
    return _to_out(integration)


@router.get("/{integration_id}", response_model=IntegrationOut)
async def get_integration(
    integration_id: uuid.UUID, principal: CurrentPrincipal, session: DbSession
) -> IntegrationOut:
    return _to_out(await _load(session, principal.tenant_id, integration_id))


@router.patch("/{integration_id}", response_model=IntegrationOut)
async def update_integration(
    integration_id: uuid.UUID,
    payload: IntegrationUpdate,
    principal: RequireAdmin,
    session: DbSession,
) -> IntegrationOut:
    integration = await _load(session, principal.tenant_id, integration_id)
    before = {
        "allow_write": integration.allow_write,
        "is_enabled": integration.is_enabled,
        "scope": integration.scope,
        "config_keys": sorted(integration.config or {}),
    }

    if payload.name is not None:
        integration.name = payload.name
    if payload.description is not None:
        integration.description = payload.description
    if payload.config is not None:
        integration.config = payload.config
    if payload.is_enabled is not None:
        integration.is_enabled = payload.is_enabled
        if not payload.is_enabled:
            integration.status = IntegrationStatus.DISABLED
    if payload.allow_write is not None:
        integration.allow_write = payload.allow_write
    if payload.scope is not None:
        integration.scope = payload.scope.model_dump()

    rotated = False
    if payload.credentials or payload.webhook_secret is not None:
        _apply_credentials(
            integration, payload.credentials or {}, payload.webhook_secret, merge=True
        )
        rotated = True

    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=(
            AuditAction.INTEGRATION_CREDENTIAL_ROTATED
            if rotated
            else AuditAction.INTEGRATION_UPDATED
        ),
        resource_type="integration",
        resource_id=integration.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Updated integration '{integration.name}'"
        + (" (credentials rotated)" if rotated else ""),
        before=before,
        after={
            "allow_write": integration.allow_write,
            "is_enabled": integration.is_enabled,
            "scope": integration.scope,
            "config_keys": sorted(integration.config or {}),
        },
    )
    await session.commit()
    await enqueue_integration_health_check(integration_id=integration.id)
    return _to_out(integration)


@router.delete("/{integration_id}", response_model=Acknowledgement)
async def delete_integration(
    integration_id: uuid.UUID, principal: RequireAdmin, session: DbSession
) -> Acknowledgement:
    integration = await _load(session, principal.tenant_id, integration_id)
    await audit.record(
        session,
        tenant_id=principal.tenant_id,
        action=AuditAction.INTEGRATION_DELETED,
        resource_type="integration",
        resource_id=integration.id,
        actor_type=principal.audit_actor_type,
        actor_id=principal.id,
        actor_label=principal.label,
        summary=f"Deleted {integration.provider} integration '{integration.name}'",
        before={"provider": str(integration.provider), "name": integration.name},
    )
    await session.delete(integration)
    return Acknowledgement(message="Integration deleted")


@router.post("/{integration_id}/test", response_model=IntegrationHealth)
async def test_integration(
    integration_id: uuid.UUID, principal: RequireAdmin, session: DbSession
) -> IntegrationHealth:
    """Live connectivity check. Runs inline so the admin gets an immediate answer."""
    from app.integrations.base import build_client

    integration = await _load(session, principal.tenant_id, integration_id)
    client = None
    try:
        client = build_client(integration)
        if client is None:
            raise NotFoundError(f"No client implementation for {integration.provider}")
        report = await client.health_check()
    except Exception as exc:  # noqa: BLE001 - surfaced to the admin as a result
        integration.status = IntegrationStatus.ERROR
        integration.last_error = str(exc)[:2000]
        integration.consecutive_failures += 1
        integration.last_health_check_at = datetime.now(UTC)
        return IntegrationHealth(
            integration_id=integration.id,
            provider=integration.provider,
            status=IntegrationStatus.ERROR,
            detail=str(exc)[:400],
            checked_at=datetime.now(UTC),
        )
    finally:
        if client is not None:
            await client.aclose()

    integration.status = report.status
    integration.last_error = None if report.healthy else report.detail[:2000]
    integration.consecutive_failures = 0 if report.healthy else integration.consecutive_failures + 1
    integration.last_health_check_at = datetime.now(UTC)

    return IntegrationHealth(
        integration_id=integration.id,
        provider=integration.provider,
        status=report.status,
        latency_ms=report.latency_ms,
        detail=report.detail,
        checked_at=datetime.now(UTC),
        capabilities=report.capabilities,
    )


@router.get("/{integration_id}/webhook-url")
async def webhook_url(
    integration_id: uuid.UUID, principal: RequireAdmin, session: DbSession
) -> dict[str, str]:
    """Where this provider should POST its alerts."""
    integration = await _load(session, principal.tenant_id, integration_id)
    paths = {
        IntegrationProvider.SLACK: "slack",
        IntegrationProvider.GITHUB: "github",
        IntegrationProvider.PROMETHEUS: "alertmanager",
        IntegrationProvider.GRAFANA: "grafana",
        IntegrationProvider.CLOUDWATCH: "cloudwatch",
    }
    provider_path = paths.get(integration.provider)
    if provider_path is None:
        raise NotFoundError(f"{integration.provider} does not send webhooks")
    return {
        "url": f"/api/v1/webhooks/{provider_path}/{integration.id}",
        "signature_header": {
            "slack": "X-Slack-Signature",
            "github": "X-Hub-Signature-256",
        }.get(provider_path, "X-OpsPilot-Signature"),
        "requires_secret": "true",
    }


# --------------------------------------------------------------------------
async def _load(
    session,
    tenant_id: uuid.UUID,
    integration_id: uuid.UUID,  # noqa: ANN001
) -> Integration:
    integration = await session.get(Integration, integration_id)
    if integration is None or integration.tenant_id != tenant_id:
        raise NotFoundError("Integration not found")
    return integration


def _apply_credentials(
    integration: Integration,
    credentials: dict[str, str],
    webhook_secret: str | None,
    *,
    merge: bool = False,
) -> None:
    """Seal credentials into the row. Only the keys supplied are rotated."""
    current: dict[str, str] = {}
    if merge and integration.credentials_sealed:
        try:
            current = open_sealed_json(
                integration.credentials_sealed, context=integration.crypto_context
            )
        except Exception:  # noqa: BLE001 - unreadable blob is replaced wholesale
            log.warning("integration.credentials_unreadable", integration_id=str(integration.id))
            current = {}

    merged = {**current, **{k: v for k, v in credentials.items() if v}}
    if merged:
        integration.credentials_sealed = seal_json(merged, context=integration.crypto_context)
        integration.credential_keys = sorted(merged)
        integration.credential_fingerprints = {k: fingerprint(v) for k, v in merged.items()}
        integration.credentials_rotated_at = datetime.now(UTC)

    if webhook_secret:
        integration.webhook_secret_sealed = seal(webhook_secret, context=integration.crypto_context)
