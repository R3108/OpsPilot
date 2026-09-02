"""The action catalog — the *only* way OpsPilot can change production.

Design contract
---------------
An LLM may emit exactly one thing that leads to a mutation: a
``{"action_key": str, "params": {...}}`` pair. That pair is:

1. looked up in :data:`ACTION_REGISTRY` — an unknown key raises
   :class:`~app.core.errors.UnknownActionError` and the proposal is dropped;
2. coerced through the action's Pydantic ``params_model`` — extra or malformed
   fields are rejected, never silently passed through;
3. scored for blast radius by a *deterministic* Python function;
4. run through the policy engine and (usually) a human;
5. executed by a Python callable that talks to a typed provider SDK.

At no point is model output interpolated into a shell command, a SQL string, a
URL path, or a kubectl invocation. There is no ``exec`` action and no generic
"run this command" escape hatch — adding one would defeat the entire design.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from app.core.errors import UnknownActionError, ValidationError
from app.core.logging import get_logger
from app.models.enums import IntegrationProvider, RiskTier, UserRole

log = get_logger(__name__)

P = TypeVar("P", bound=BaseModel)


# --------------------------------------------------------------------------
# execution plumbing
# --------------------------------------------------------------------------
@dataclass(slots=True)
class ExecutionContext:
    """Everything an executor is allowed to know about.

    Deliberately narrow: an executor gets provider clients and identifiers, not
    a database session or the incident object, so it cannot mutate application
    state as a side effect. All persistence happens in the calling service.
    """

    tenant_id: uuid.UUID
    incident_id: uuid.UUID
    action_id: uuid.UUID
    actor: str
    dry_run: bool = False
    # provider -> client instance, resolved from the tenant's integrations
    clients: dict[IntegrationProvider, Any] = field(default_factory=dict)
    # namespaces/services this run is fenced to, from the integration scope
    scope: dict[str, list[str]] = field(default_factory=dict)
    idempotency_key: str | None = None
    timeout_seconds: int = 60

    def client(self, provider: IntegrationProvider) -> Any:
        client = self.clients.get(provider)
        if client is None:
            raise ValidationError(
                f"No usable {provider} integration is configured for this tenant",
                details={"provider": str(provider)},
            )
        return client


@dataclass(slots=True)
class ExecutionResult:
    succeeded: bool
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    # State captured immediately before mutating, used to build the rollback.
    pre_state: dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    error: str | None = None

    @classmethod
    def ok(cls, summary: str, **detail: Any) -> ExecutionResult:
        return cls(succeeded=True, summary=summary, detail=detail)

    @classmethod
    def failure(cls, summary: str, error: str, **detail: Any) -> ExecutionResult:
        return cls(succeeded=False, summary=summary, error=error, detail=detail)


@dataclass(slots=True)
class BlastRadius:
    """Deterministic estimate of how much an action can affect.

    Computed from the *params*, never from the model's own claims about them.
    The policy engine compares these numbers against tenant limits.
    """

    scope: str  # "pod" | "deployment" | "service" | "cluster" | "database" | "none"
    targets: list[str] = field(default_factory=list)
    estimated_affected_units: int = 1
    environment: str = "production"
    namespace: str | None = None
    service: str | None = None
    causes_downtime: bool = False
    touches_data: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "targets": self.targets,
            "estimated_affected_units": self.estimated_affected_units,
            "environment": self.environment,
            "namespace": self.namespace,
            "service": self.service,
            "causes_downtime": self.causes_downtime,
            "touches_data": self.touches_data,
            "notes": self.notes,
        }


Executor = Callable[[Any, ExecutionContext], Awaitable[ExecutionResult]]
BlastRadiusFn = Callable[[Any], BlastRadius]
RollbackFn = Callable[[Any, ExecutionResult], tuple[str, dict[str, Any]] | None]


@dataclass(slots=True)
class ActionSpec(Generic[P]):
    key: str
    title: str
    description: str
    provider: IntegrationProvider
    params_model: type[P]
    executor: Executor
    risk_tier: RiskTier
    blast_radius_fn: BlastRadiusFn
    is_reversible: bool = False
    rollback_fn: RollbackFn | None = None
    requires_write_integration: bool = True
    # Human guidance shown in the approval UI.
    approval_checklist: list[str] = field(default_factory=list)
    examples: list[dict[str, Any]] = field(default_factory=list)
    timeout_seconds: int = 60
    max_attempts: int = 2

    @property
    def minimum_role(self) -> UserRole:
        return self.risk_tier.minimum_role

    def parse_params(self, raw: dict[str, Any]) -> P:
        """Strict coercion. This is the boundary the model's output has to cross."""
        try:
            return self.params_model.model_validate(raw)
        except PydanticValidationError as exc:
            raise ValidationError(
                f"Invalid parameters for action '{self.key}'",
                details={"action_key": self.key, "errors": exc.errors(include_url=False)},
            ) from exc

    def blast_radius(self, params: P) -> BlastRadius:
        return self.blast_radius_fn(params)

    def build_rollback(
        self, params: P, result: ExecutionResult
    ) -> tuple[str, dict[str, Any]] | None:
        if not self.rollback_fn:
            return None
        return self.rollback_fn(params, result)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "description": self.description,
            "provider": str(self.provider),
            "risk_tier": str(self.risk_tier),
            "is_reversible": self.is_reversible,
            "minimum_role": str(self.minimum_role),
            "requires_write_integration": self.requires_write_integration,
            "params_schema": self.params_model.model_json_schema(),
            "approval_checklist": self.approval_checklist,
            "examples": self.examples,
        }


ACTION_REGISTRY: dict[str, ActionSpec[Any]] = {}


def register_action(spec: ActionSpec[Any]) -> ActionSpec[Any]:
    if spec.key in ACTION_REGISTRY:
        raise RuntimeError(f"duplicate action key {spec.key!r}")
    if not spec.key.replace("_", "").replace(".", "").isalnum():
        raise RuntimeError(f"action key {spec.key!r} must be alphanumeric/underscore/dot")
    ACTION_REGISTRY[spec.key] = spec
    return spec


def get_action(key: str) -> ActionSpec[Any]:
    """Resolve an action key. This is the model-output trust boundary."""
    spec = ACTION_REGISTRY.get(key)
    if spec is None:
        log.warning("action.unknown_key", action_key=key, known=len(ACTION_REGISTRY))
        raise UnknownActionError(
            f"'{key}' is not a registered OpsPilot action",
            details={"action_key": key, "available": sorted(ACTION_REGISTRY)},
        )
    return spec


def list_actions(
    *, providers: set[IntegrationProvider] | None = None, max_risk: RiskTier | None = None
) -> list[ActionSpec[Any]]:
    specs = sorted(ACTION_REGISTRY.values(), key=lambda s: (s.risk_tier.rank, s.key))
    if providers is not None:
        specs = [s for s in specs if s.provider in providers]
    if max_risk is not None:
        specs = [s for s in specs if s.risk_tier.rank <= max_risk.rank]
    return specs


def catalog_for_prompt(specs: list[ActionSpec[Any]] | None = None) -> str:
    """Render the catalog as the compact listing injected into the planner prompt.

    Keeping this in one place means the model can never be told about an action
    that does not exist, and can never be *un*told about one that does.
    """
    specs = specs if specs is not None else list_actions()
    lines: list[str] = []
    for spec in specs:
        props = spec.params_model.model_json_schema().get("properties", {})
        required = set(spec.params_model.model_json_schema().get("required", []))
        params = ", ".join(
            f"{name}: {meta.get('type', 'any')}{'' if name in required else '?'}"
            for name, meta in props.items()
        )
        lines.append(
            f"- {spec.key}({params})\n"
            f"    risk={spec.risk_tier} reversible={str(spec.is_reversible).lower()} "
            f"provider={spec.provider}\n"
            f"    {spec.description}"
        )
    return "\n".join(lines)


def registry_fingerprint() -> str:
    """Hash of the catalog, recorded on every proposal.

    If the catalog changes between a proposal and its approval, the approval is
    invalidated rather than executed against a different meaning of the key.
    """
    import hashlib
    import json

    payload = json.dumps(
        {
            key: {
                "risk": str(spec.risk_tier),
                "schema": spec.params_model.model_json_schema(),
            }
            for key, spec in sorted(ACTION_REGISTRY.items())
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def utcnow() -> datetime:
    return datetime.now(UTC)
