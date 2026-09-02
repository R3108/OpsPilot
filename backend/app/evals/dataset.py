"""Eval scenario loading and provisioning.

A scenario is a self-contained description of an incident *and* the world it
happens in: the metrics, logs, deploys, cluster and database state an
investigator would find, plus the one action that actually fixes it.

Provisioning a scenario creates a real tenant with real (simulation-mode)
integration rows, so the run under evaluation exercises the same code path as
production — credentials are sealed and decrypted, the policy engine runs, an
approval is created and resolved. Only the transport at the very edge is
simulated.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.crypto import seal_json
from app.core.logging import get_logger
from app.core.security import hash_password
from app.integrations.simulation import reset_world, world_key_for
from app.models.enums import (
    IncidentSource,
    IntegrationProvider,
    IntegrationStatus,
    TenantPlan,
    UserRole,
)
from app.models.integration import Integration
from app.models.tenant import Tenant, User
from app.schemas.incident import IncidentCreate
from app.services import incidents as incident_service

log = get_logger(__name__)

SCENARIO_DIR = Path(__file__).parent / "scenarios"


@dataclass(slots=True)
class Expectation:
    severity: str | None = None
    root_cause_category: str | None = None
    root_cause_keywords: list[str] = field(default_factory=list)
    action_key: str | None = None
    must_recover: bool = True
    requires_approval: bool = True
    forbidden_action_keys: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Scenario:
    name: str
    title: str
    description: str
    difficulty: str
    incident: dict[str, Any]
    expected: Expectation
    initial_state: dict[str, Any]
    resolution: dict[str, Any]
    resolved_state: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scenario:
        return cls(
            name=data["name"],
            title=data.get("title", data["name"]),
            description=data.get("description", ""),
            difficulty=data.get("difficulty", "medium"),
            incident=data["incident"],
            expected=Expectation(**(data.get("expected") or {})),
            initial_state=data.get("initial_state", {}),
            resolution=data.get("resolution", {}),
            resolved_state=data.get("resolved_state", {}),
            raw=data,
        )

    def world_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "initial_state": self.initial_state,
            "resolution": self.resolution,
            "resolved_state": self.resolved_state,
        }


def load_scenarios(names: list[str] | None = None) -> list[Scenario]:
    scenarios: list[Scenario] = []
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if names and data["name"] not in names:
            continue
        scenarios.append(Scenario.from_dict(data))
    if names:
        missing = set(names) - {s.name for s in scenarios}
        if missing:
            raise ValueError(f"unknown scenario(s): {', '.join(sorted(missing))}")
    return scenarios


def load_scenario(name: str) -> Scenario:
    found = load_scenarios([name])
    if not found:
        raise ValueError(f"unknown scenario '{name}'")
    return found[0]


# --------------------------------------------------------------------------
# provisioning
# --------------------------------------------------------------------------
# Which providers a scenario needs, and the (non-secret) config for each.
PROVIDER_SETUP: dict[IntegrationProvider, dict[str, Any]] = {
    IntegrationProvider.KUBERNETES: {
        "config": {"cluster": "eval-cluster", "default_namespace": "default"},
        "credentials": {"kubeconfig": "simulated"},
        "allow_write": True,
    },
    IntegrationProvider.PROMETHEUS: {
        "config": {"base_url": "http://prometheus.invalid"},
        "credentials": {},
        "allow_write": False,
    },
    IntegrationProvider.GITHUB: {
        "config": {
            "repos": ["acme/checkout-api", "acme/search-api", "acme/orders-api"],
            "workflows": ["redeploy-last-good.yml"],
        },
        "credentials": {"token": "simulated"},
        "allow_write": True,
    },
    IntegrationProvider.POSTGRES: {
        "config": {"label": "primary"},
        "credentials": {"dsn": "postgresql://simulated/eval"},
        "allow_write": True,
    },
    IntegrationProvider.SLACK: {
        "config": {"default_channel": "C0EVAL0001"},
        "credentials": {"bot_token": "simulated", "signing_secret": "simulated"},
        "allow_write": True,
    },
    IntegrationProvider.GRAFANA: {
        "config": {"base_url": "http://grafana.invalid"},
        "credentials": {"api_token": "simulated"},
        "allow_write": False,
    },
}


async def ensure_eval_tenant(
    session: AsyncSession, *, slug: str = "opspilot-evals"
) -> tuple[Tenant, User]:
    """Create (or fetch) the tenant evals run against, plus an approver bot.

    Each scenario gets its *own* tenant. That matters: the history investigator
    searches the tenant's resolved incidents, so a shared tenant would let one
    scenario's outcome contaminate the next one's evidence — the suite would
    score differently depending on the order it ran in. (The behaviour itself is
    correct and desirable in production; it just has to be isolated here.)
    """
    tenant = (await session.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
    if tenant is None:
        tenant = Tenant(
            name="OpsPilot Evals",
            slug=slug,
            plan=TenantPlan.ENTERPRISE,
            settings_json={
                "policy": {
                    # Evals must exercise the approval path, so nothing is
                    # auto-approved above LOW.
                    "auto_approve_low_risk": True,
                    "always_approve_at_or_above": "medium",
                    "max_actions_per_incident": 4,
                    "min_confidence_high_risk": 0.5,
                    "min_confidence_critical_risk": 0.75,
                    "min_evidence_high_risk": 2,
                }
            },
        )
        session.add(tenant)
        await session.flush()

    user = (
        await session.execute(
            select(User).where(User.tenant_id == tenant.id, User.email == "evals@opspilot.dev")
        )
    ).scalar_one_or_none()
    if user is None:
        user = User(
            tenant_id=tenant.id,
            email="evals@opspilot.dev",
            full_name="Eval Approver",
            password_hash=hash_password("eval-harness-not-a-login"),
            role=UserRole.ADMIN,
        )
        session.add(user)
        await session.flush()

    return tenant, user


async def provision_scenario(session: AsyncSession, *, tenant: Tenant, scenario: Scenario) -> str:
    """Give the tenant's integrations access to this scenario's simulated world.

    Worlds *accumulate* under ``config['worlds']`` rather than replacing each
    other, so one organisation can hold several scenarios at once — which is what
    the demo seed does. Each investigation then selects its world by the
    ``scenario`` label on its incident; without that, every incident in the demo
    would be investigated against whichever scenario happened to be provisioned
    last.
    """
    world_key = world_key_for(tenant.id, scenario.name)
    reset_world(world_key, scenario.world_payload())

    for provider, setup in PROVIDER_SETUP.items():
        integration = (
            await session.execute(
                select(Integration).where(
                    Integration.tenant_id == tenant.id,
                    Integration.provider == provider,
                    Integration.name == "eval",
                )
            )
        ).scalar_one_or_none()

        worlds = dict((integration.config or {}).get("worlds") or {}) if integration else {}
        worlds[scenario.name] = scenario.world_payload()

        config = {
            **setup["config"],
            "mode": "simulation",
            # The default when an incident carries no scenario label.
            "scenario": scenario.name,
            "scenario_data": scenario.world_payload(),
            "worlds": worlds,
        }
        if integration is None:
            integration = Integration(
                tenant_id=tenant.id,
                provider=provider,
                name="eval",
                description=f"Simulated {provider} for eval scenarios",
                config=config,
                allow_write=setup["allow_write"],
                status=IntegrationStatus.HEALTHY,
                scope={},
            )
            session.add(integration)
            await session.flush()
        else:
            integration.config = config
            integration.status = IntegrationStatus.HEALTHY
            integration.is_enabled = True
            # config is a JSON column; reassigning is what marks it dirty.
            flag_modified(integration, "config")

        if setup["credentials"]:
            integration.credentials_sealed = seal_json(
                setup["credentials"], context=integration.crypto_context
            )
            integration.credential_keys = sorted(setup["credentials"])

    await session.flush()
    return world_key


async def create_scenario_incident(
    session: AsyncSession, *, tenant: Tenant, scenario: Scenario
) -> Any:
    """Create the incident exactly as an alert webhook would have."""
    spec = scenario.incident
    payload = IncidentCreate(
        title=spec["title"],
        description=spec.get("description", ""),
        source=IncidentSource(spec.get("source", "synthetic")),
        service=spec.get("service"),
        namespace=spec.get("namespace"),
        cluster=spec.get("cluster"),
        environment=spec.get("environment", "production"),
        # The `scenario` label is what routes this incident's investigation to
        # the right simulated world when a tenant holds several.
        labels={**spec.get("labels", {}), "scenario": scenario.name},
        raw_payload={"scenario": scenario.name, **spec.get("raw_payload", {})},
        detected_at=datetime.now(UTC),
        # The harness drives the graph itself so it can score each phase.
        auto_investigate=False,
        dedupe_key=f"eval:{scenario.name}:{uuid.uuid4().hex[:8]}",
    )
    incident, _ = await incident_service.create_incident(
        session,
        tenant_id=tenant.id,
        payload=payload,
        actor_type="system",
        actor_label="eval-harness",
        deduplicate=False,
    )
    return incident
