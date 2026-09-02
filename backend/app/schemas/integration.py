from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field, model_validator

from app.models.enums import IntegrationProvider, IntegrationStatus
from app.schemas.common import ORMModel

# Which credential fields each provider expects. Enforced on create/update so a
# half-configured integration never reaches the agent tools.
PROVIDER_CREDENTIAL_KEYS: dict[IntegrationProvider, tuple[str, ...]] = {
    IntegrationProvider.SLACK: ("bot_token", "signing_secret"),
    IntegrationProvider.GITHUB: ("token",),
    IntegrationProvider.KUBERNETES: ("kubeconfig",),
    IntegrationProvider.PROMETHEUS: (),  # optional bearer_token / basic auth
    IntegrationProvider.GRAFANA: ("api_token",),
    IntegrationProvider.CLOUDWATCH: ("access_key_id", "secret_access_key"),
    IntegrationProvider.POSTGRES: ("dsn",),
}

PROVIDER_CONFIG_KEYS: dict[IntegrationProvider, tuple[str, ...]] = {
    IntegrationProvider.SLACK: ("default_channel",),
    IntegrationProvider.GITHUB: ("owner", "repos"),
    IntegrationProvider.KUBERNETES: ("cluster", "default_namespace"),
    IntegrationProvider.PROMETHEUS: ("base_url",),
    IntegrationProvider.GRAFANA: ("base_url",),
    IntegrationProvider.CLOUDWATCH: ("region", "log_groups"),
    IntegrationProvider.POSTGRES: ("label",),
}


class IntegrationScope(BaseModel):
    """Hard fence on what this integration is allowed to touch."""

    namespaces: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    log_groups: list[str] = Field(default_factory=list)


class IntegrationCreate(BaseModel):
    provider: IntegrationProvider
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    credentials: dict[str, str] = Field(default_factory=dict)
    webhook_secret: str | None = None
    allow_write: bool = False
    scope: IntegrationScope = Field(default_factory=IntegrationScope)

    @model_validator(mode="after")
    def _require_provider_fields(self) -> IntegrationCreate:
        required_creds = PROVIDER_CREDENTIAL_KEYS.get(self.provider, ())
        missing = [k for k in required_creds if not self.credentials.get(k)]
        if missing:
            raise ValueError(f"{self.provider} requires credential fields: {', '.join(missing)}")
        required_config = PROVIDER_CONFIG_KEYS.get(self.provider, ())
        # Only base_url style keys are truly mandatory; the rest are advisory.
        for key in ("base_url", "region"):
            if key in required_config and not self.config.get(key):
                raise ValueError(f"{self.provider} requires config.{key}")
        return self


class IntegrationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    config: dict[str, Any] | None = None
    # Only the keys present are rotated; omitted keys keep their current value.
    credentials: dict[str, str] | None = None
    webhook_secret: str | None = None
    is_enabled: bool | None = None
    allow_write: bool | None = None
    scope: IntegrationScope | None = None


class IntegrationOut(ORMModel):
    """Never contains a secret. ``credential_fingerprints`` proves what is set."""

    id: uuid.UUID
    provider: IntegrationProvider
    name: str
    description: str
    status: IntegrationStatus
    is_enabled: bool
    config: dict[str, Any]
    credential_keys: list[Any]
    credential_fingerprints: dict[str, Any]
    credentials_rotated_at: datetime | None = None
    has_webhook_secret: bool = False
    allow_write: bool
    scope: dict[str, Any]
    last_health_check_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int
    created_at: datetime
    updated_at: datetime


class IntegrationHealth(BaseModel):
    integration_id: uuid.UUID
    provider: IntegrationProvider
    status: IntegrationStatus
    latency_ms: int | None = None
    detail: str = ""
    checked_at: datetime
    capabilities: list[str] = Field(default_factory=list)


class WebhookIngestResult(BaseModel):
    accepted: bool
    incident_id: uuid.UUID | None = None
    incident_reference: str | None = None
    deduplicated: bool = False
    reason: str = ""
