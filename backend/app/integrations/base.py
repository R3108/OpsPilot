"""Provider client base class, retry policy and the per-tenant client registry."""

from __future__ import annotations

import abc
import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from app.core.config import settings
from app.core.crypto import CryptoError, open_sealed_json
from app.core.errors import IntegrationError, IntegrationTimeoutError
from app.core.logging import get_logger
from app.models.enums import IntegrationProvider, IntegrationStatus
from app.models.integration import Integration

log = get_logger(__name__)

T = TypeVar("T")

# Errors worth retrying: transient transport problems and 5xx, never 4xx.
RETRYABLE = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
    IntegrationTimeoutError,
)


@dataclass(slots=True)
class HealthReport:
    healthy: bool
    detail: str = ""
    latency_ms: int | None = None
    capabilities: list[str] = field(default_factory=list)

    @property
    def status(self) -> IntegrationStatus:
        return IntegrationStatus.HEALTHY if self.healthy else IntegrationStatus.ERROR


class ProviderClient(abc.ABC):
    """Base for every external system OpsPilot talks to.

    Two hard rules for subclasses:

    * **Read methods must never mutate.** The investigation agents can call them
      freely and in parallel; anything with a side effect belongs in an action
      executor instead.
    * **No method takes a free-form command.** Query shapes are fixed by the
      method signature; callers supply values, never syntax.
    """

    provider: IntegrationProvider

    def __init__(
        self,
        *,
        integration_id: uuid.UUID | None = None,
        config: dict[str, Any] | None = None,
        credentials: dict[str, str] | None = None,
        scope: dict[str, Any] | None = None,
        allow_write: bool = False,
        timeout_seconds: int | None = None,
    ) -> None:
        self.integration_id = integration_id
        self.config = config or {}
        self._credentials = credentials or {}
        self.scope = scope or {}
        self.allow_write = allow_write
        self.timeout_seconds = timeout_seconds or settings.tool_timeout_seconds

    # -- credential access is deliberately awkward to discourage leaking it ---
    def _credential(self, key: str, *, required: bool = True) -> str:
        value = self._credentials.get(key, "")
        if required and not value:
            raise IntegrationError(
                f"{self.provider} integration is missing credential '{key}'",
                details={"provider": str(self.provider), "credential": key},
            )
        return value

    def _require_write(self) -> None:
        if not self.allow_write:
            raise IntegrationError(
                f"The {self.provider} integration is configured read-only",
                details={"provider": str(self.provider)},
            )

    @abc.abstractmethod
    async def health_check(self) -> HealthReport: ...

    async def aclose(self) -> None:  # pragma: no cover - most clients override
        return None

    # -- shared resilience ---------------------------------------------------
    async def _with_retries(
        self,
        operation: str,
        fn: Callable[[], Awaitable[T]],
        *,
        attempts: int = 3,
        timeout: float | None = None,
    ) -> T:
        timeout = timeout or self.timeout_seconds
        started = time.perf_counter()
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(attempts),
                wait=wait_exponential_jitter(initial=0.4, max=6.0),
                retry=retry_if_exception_type(RETRYABLE),
                reraise=True,
            ):
                with attempt:
                    return await asyncio.wait_for(fn(), timeout=timeout)
        except TimeoutError as exc:
            raise IntegrationTimeoutError(
                f"{self.provider}.{operation} timed out after {timeout:.0f}s",
                details={"provider": str(self.provider), "operation": operation},
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise IntegrationError(
                f"{self.provider}.{operation} failed: HTTP {exc.response.status_code}",
                details={
                    "provider": str(self.provider),
                    "operation": operation,
                    "status": exc.response.status_code,
                    "body": exc.response.text[:500],
                },
            ) from exc
        except RETRYABLE as exc:
            raise IntegrationError(
                f"{self.provider}.{operation} failed: {exc}",
                details={"provider": str(self.provider), "operation": operation},
            ) from exc
        finally:
            log.debug(
                "integration.call",
                provider=str(self.provider),
                operation=operation,
                ms=int((time.perf_counter() - started) * 1000),
            )
        raise AssertionError("unreachable")  # pragma: no cover


class HttpProviderClient(ProviderClient):
    """Provider backed by a REST API."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        url = str(self.config.get("base_url", "")).rstrip("/")
        if not url:
            raise IntegrationError(f"{self.provider} integration has no base_url configured")
        return url

    def _headers(self) -> dict[str, str]:
        return {"User-Agent": f"OpsPilot/{settings.project_name}", "Accept": "application/json"}

    @property
    def http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers(),
                timeout=httpx.Timeout(self.timeout_seconds, connect=10.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                follow_redirects=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_json(self, path: str, **params: Any) -> Any:
        async def _call() -> Any:
            response = await self.http.get(
                path, params={k: v for k, v in params.items() if v is not None}
            )
            response.raise_for_status()
            return response.json()

        return await self._with_retries(f"GET {path}", _call)

    async def _post_json(self, path: str, payload: dict[str, Any]) -> Any:
        async def _call() -> Any:
            response = await self.http.post(path, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}

        return await self._with_retries(f"POST {path}", _call, attempts=2)


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------
class ClientRegistry:
    """Builds and caches provider clients for one tenant, for one unit of work.

    Credentials are decrypted here and nowhere else; the clients hold them in
    memory only for the lifetime of the registry, which the caller closes.
    """

    def __init__(self, tenant_id: uuid.UUID, *, scenario: str | None = None) -> None:
        self.tenant_id = tenant_id
        # Only meaningful for simulation-mode integrations: which scenario world
        # this unit of work is about. Ignored by every real provider client.
        self.scenario = scenario
        self._clients: dict[IntegrationProvider, ProviderClient] = {}
        self._integrations: dict[IntegrationProvider, Integration] = {}

    async def load(
        self,
        session: AsyncSession,
        *,
        providers: set[IntegrationProvider] | None = None,
        require_write: bool = False,
    ) -> ClientRegistry:
        stmt = select(Integration).where(
            Integration.tenant_id == self.tenant_id,
            Integration.is_enabled.is_(True),
        )
        if providers:
            stmt = stmt.where(Integration.provider.in_(providers))
        if require_write:
            stmt = stmt.where(Integration.allow_write.is_(True))

        for integration in (await session.execute(stmt)).scalars():
            # Deterministic pick when a tenant has several of one provider:
            # prefer a write-capable, healthy one.
            existing = self._integrations.get(integration.provider)
            if existing is not None and _rank(existing) >= _rank(integration):
                continue
            self._integrations[integration.provider] = integration
        return self

    def integration(self, provider: IntegrationProvider) -> Integration | None:
        return self._integrations.get(provider)

    def get(self, provider: IntegrationProvider) -> ProviderClient | None:
        if provider in self._clients:
            return self._clients[provider]
        integration = self._integrations.get(provider)
        if integration is None:
            return None
        client = build_client(integration, scenario=self.scenario)
        if client is not None:
            self._clients[provider] = client
        return client

    def as_dict(self) -> dict[IntegrationProvider, ProviderClient]:
        return {
            provider: client
            for provider in self._integrations
            if (client := self.get(provider)) is not None
        }

    def scope_for(self, provider: IntegrationProvider) -> dict[str, list[str]]:
        integration = self._integrations.get(provider)
        if integration is None:
            return {}
        scope = dict(integration.scope or {})
        # Slack's default channel travels as a one-element list for uniformity.
        if provider is IntegrationProvider.SLACK and integration.config.get("default_channel"):
            scope.setdefault("default_channel", [integration.config["default_channel"]])
        if provider is IntegrationProvider.GITHUB and integration.config.get("workflows"):
            scope.setdefault("workflows", list(integration.config["workflows"]))
        return scope

    async def aclose(self) -> None:
        for client in self._clients.values():
            try:
                await client.aclose()
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "integration.close_failed", provider=str(client.provider), error=str(exc)
                )
        self._clients.clear()

    async def __aenter__(self) -> ClientRegistry:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def _rank(integration: Integration) -> int:
    return (2 if integration.allow_write else 0) + (
        1 if integration.status is IntegrationStatus.HEALTHY else 0
    )


def decrypt_credentials(integration: Integration) -> dict[str, str]:
    if not integration.credentials_sealed:
        return {}
    try:
        return open_sealed_json(integration.credentials_sealed, context=integration.crypto_context)
    except CryptoError as exc:
        log.error(
            "integration.credential_decrypt_failed",
            integration_id=str(integration.id),
            provider=str(integration.provider),
            error=str(exc),
        )
        raise IntegrationError(
            f"Stored credentials for {integration.provider} could not be decrypted",
            details={"integration_id": str(integration.id)},
        ) from exc


def build_client(integration: Integration, *, scenario: str | None = None) -> ProviderClient | None:
    """Instantiate the right client for an integration row."""
    from app.integrations import (
        cloudwatch,
        github,
        grafana,
        kubernetes,
        postgres,
        prometheus,
        slack,
    )

    builders: dict[IntegrationProvider, Any] = {
        IntegrationProvider.KUBERNETES: kubernetes.KubernetesClient,
        IntegrationProvider.PROMETHEUS: prometheus.PrometheusClient,
        IntegrationProvider.GITHUB: github.GitHubClient,
        IntegrationProvider.CLOUDWATCH: cloudwatch.CloudWatchClient,
        IntegrationProvider.SLACK: slack.SlackClient,
        IntegrationProvider.POSTGRES: postgres.PostgresTargetClient,
        IntegrationProvider.GRAFANA: grafana.GrafanaClient,
    }
    builder = builders.get(integration.provider)
    if builder is None:
        log.warning("integration.no_builder", provider=str(integration.provider))
        return None

    credentials = decrypt_credentials(integration)

    # A tenant can run any integration in `simulation` mode, which swaps the
    # transport for a deterministic in-process backend. This is what the eval
    # datasets and the local demo run against — it is never a fallback for a
    # misconfigured real integration, it has to be asked for explicitly.
    if integration.config.get("mode") == "simulation":
        from app.integrations.simulation import simulated_client

        return simulated_client(integration, credentials, scenario=scenario)

    return builder(
        integration_id=integration.id,
        config=integration.config,
        credentials=credentials,
        scope=integration.scope,
        allow_write=integration.allow_write,
    )
