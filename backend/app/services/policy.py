"""Deterministic risk and policy engine.

**No LLM runs here.** This module is pure Python over typed inputs, which is what
makes it auditable: given the same action, params, incident and tenant policy it
always returns the same decision, and every decision names the rule that produced
it.

Evaluation order (first ``deny`` wins, and nothing downstream can un-deny):

1. global kill switch                      → deny
2. tenant kill switch                      → deny
3. write-integration present and enabled   → deny
4. integration scope fence                 → deny
5. protected namespace / environment       → deny
6. change-freeze window                    → deny
7. blast-radius ceilings                   → deny
8. per-incident and per-tenant rate limits → deny
9. evidence & confidence floor             → deny for HIGH/CRITICAL
10. tenant-authored PolicyRule rows        → deny / require_approval / auto_approve
11. residual risk tier                     → require_approval unless auto-approvable
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any

from app.core import metrics
from app.core.config import settings
from app.core.logging import get_logger
from app.models.enums import (
    IncidentSeverity,
    RiskTier,
    UserRole,
    role_satisfies,
)
from app.models.incident import Incident
from app.models.integration import Integration
from app.models.remediation import PolicyRule
from app.models.tenant import Tenant
from app.services.actions.registry import ActionSpec, BlastRadius

log = get_logger(__name__)

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------
@dataclass(slots=True)
class TenantPolicy:
    """Tenant-level knobs, merged over the deployment defaults.

    Sourced from ``Tenant.settings_json['policy']`` so an admin can tighten (or,
    deliberately, loosen) the guardrails without a deploy.
    """

    remediation_enabled: bool = True
    auto_approve_low_risk: bool = True
    # Actions at or above this tier always need a human, even if a rule says otherwise.
    always_approve_at_or_above: RiskTier = RiskTier.MEDIUM
    protected_namespaces: frozenset[str] = frozenset()
    protected_environments: frozenset[str] = frozenset({"production"})
    max_pods_restart: int = 20
    max_replica_delta: int = 10
    max_actions_per_incident: int = 6
    max_actions_per_hour: int = 30
    # A HIGH/CRITICAL action needs at least this much confidence in the hypothesis
    # it is derived from, and at least this many pieces of supporting evidence.
    min_confidence_high_risk: float = 0.6
    min_confidence_critical_risk: float = 0.8
    min_evidence_high_risk: int = 2
    # [{"days": ["mon"], "start": "09:00", "end": "17:00", "reason": "..."}]
    change_freeze_windows: list[dict[str, Any]] = field(default_factory=list)
    # Severities where automation is allowed to act at all.
    automation_severities: frozenset[str] = frozenset({"sev1", "sev2", "sev3", "sev4", "sev5"})

    @classmethod
    def for_tenant(cls, tenant: Tenant | None) -> TenantPolicy:
        base = cls(
            auto_approve_low_risk=settings.auto_approve_low_risk,
            protected_namespaces=settings.protected_namespace_set,
            max_pods_restart=settings.max_pods_restart,
            max_replica_delta=settings.max_replica_delta,
        )
        raw = (tenant.settings_json or {}).get("policy") if tenant else None
        if not isinstance(raw, dict):
            return base

        def _tier(value: Any, fallback: RiskTier) -> RiskTier:
            try:
                return RiskTier(value)
            except (ValueError, TypeError):
                return fallback

        return cls(
            remediation_enabled=bool(raw.get("remediation_enabled", base.remediation_enabled)),
            auto_approve_low_risk=bool(
                raw.get("auto_approve_low_risk", base.auto_approve_low_risk)
            ),
            always_approve_at_or_above=_tier(
                raw.get("always_approve_at_or_above"), base.always_approve_at_or_above
            ),
            protected_namespaces=frozenset(
                raw.get("protected_namespaces", base.protected_namespaces)
            ),
            protected_environments=frozenset(
                raw.get("protected_environments", base.protected_environments)
            ),
            max_pods_restart=int(raw.get("max_pods_restart", base.max_pods_restart)),
            max_replica_delta=int(raw.get("max_replica_delta", base.max_replica_delta)),
            max_actions_per_incident=int(
                raw.get("max_actions_per_incident", base.max_actions_per_incident)
            ),
            max_actions_per_hour=int(raw.get("max_actions_per_hour", base.max_actions_per_hour)),
            min_confidence_high_risk=float(
                raw.get("min_confidence_high_risk", base.min_confidence_high_risk)
            ),
            min_confidence_critical_risk=float(
                raw.get("min_confidence_critical_risk", base.min_confidence_critical_risk)
            ),
            min_evidence_high_risk=int(
                raw.get("min_evidence_high_risk", base.min_evidence_high_risk)
            ),
            change_freeze_windows=list(
                raw.get("change_freeze_windows", base.change_freeze_windows)
            ),
            automation_severities=frozenset(
                raw.get("automation_severities", base.automation_severities)
            ),
        )


@dataclass(slots=True)
class PolicyInput:
    """Everything the engine is allowed to consider. Nothing is fetched in here."""

    spec: ActionSpec[Any]
    params: Any
    blast_radius: BlastRadius
    incident: Incident
    tenant: Tenant | None
    rules: list[PolicyRule] = field(default_factory=list)
    integration: Integration | None = None
    # Confidence of the hypothesis this action was derived from.
    hypothesis_confidence: float | None = None
    supporting_evidence_count: int = 0
    # Counts used by the rate-limit checks.
    actions_this_incident: int = 0
    actions_this_hour: int = 0
    # Live cluster facts that refine the static blast radius (e.g. real replica count).
    live_facts: dict[str, Any] = field(default_factory=dict)
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    requested_by_role: UserRole | None = None


# --------------------------------------------------------------------------
# outputs
# --------------------------------------------------------------------------
@dataclass(slots=True)
class PolicyViolation:
    rule: str
    message: str
    severity: str = "deny"  # "deny" | "warn"
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "message": self.message,
            "severity": self.severity,
            "context": self.context,
        }


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    risk_tier: RiskTier
    required_role: UserRole
    violations: list[PolicyViolation] = field(default_factory=list)
    warnings: list[PolicyViolation] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    reason: str = ""
    effective_blast_radius: dict[str, Any] = field(default_factory=dict)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def auto_executable(self) -> bool:
        return self.allowed and not self.requires_approval

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "risk_tier": str(self.risk_tier),
            "required_role": str(self.required_role),
            "violations": [v.to_dict() for v in self.violations],
            "warnings": [w.to_dict() for w in self.warnings],
            "matched_rules": self.matched_rules,
            "reason": self.reason,
            "effective_blast_radius": self.effective_blast_radius,
            "evaluated_at": self.evaluated_at.isoformat(),
        }

    def deny_summary(self) -> str:
        return "; ".join(v.message for v in self.violations) or self.reason


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------
def evaluate(inp: PolicyInput) -> PolicyDecision:
    """Evaluate one proposed action. Pure function of its inputs."""
    policy = TenantPolicy.for_tenant(inp.tenant)
    radius = _refine_blast_radius(inp)
    violations: list[PolicyViolation] = []
    warnings: list[PolicyViolation] = []
    matched: list[str] = []

    risk = _effective_risk_tier(inp.spec, radius)
    required_role = risk.minimum_role

    # 1 -- global kill switch ------------------------------------------------
    if settings.remediation_disabled:
        violations.append(
            PolicyViolation(
                "global_kill_switch",
                "Remediation is disabled globally (REMEDIATION_DISABLED=true)",
            )
        )

    # 2 -- tenant kill switch ------------------------------------------------
    if not policy.remediation_enabled:
        violations.append(
            PolicyViolation("tenant_kill_switch", "Remediation is disabled for this organisation")
        )

    # 3 -- write integration -------------------------------------------------
    if inp.spec.requires_write_integration:
        if inp.integration is None:
            violations.append(
                PolicyViolation(
                    "missing_integration",
                    f"No {inp.spec.provider} integration is configured",
                    context={"provider": str(inp.spec.provider)},
                )
            )
        elif not inp.integration.is_enabled:
            violations.append(
                PolicyViolation(
                    "integration_disabled",
                    f"The {inp.spec.provider} integration is disabled",
                )
            )
        elif not inp.integration.allow_write:
            violations.append(
                PolicyViolation(
                    "integration_read_only",
                    (
                        f"The {inp.spec.provider} integration is read-only; enable write "
                        f"access to allow remediation through it"
                    ),
                )
            )

    # 4 -- integration scope fence ------------------------------------------
    if inp.integration is not None and radius.namespace:
        allowed_ns = (inp.integration.scope or {}).get("namespaces") or []
        if allowed_ns and radius.namespace not in allowed_ns:
            violations.append(
                PolicyViolation(
                    "integration_scope",
                    (
                        f"Namespace '{radius.namespace}' is outside the integration's "
                        f"configured scope"
                    ),
                    context={"allowed": allowed_ns},
                )
            )

    # 5 -- protected namespaces / environments ------------------------------
    if radius.namespace and radius.namespace in policy.protected_namespaces:
        violations.append(
            PolicyViolation(
                "protected_namespace",
                f"Namespace '{radius.namespace}' is protected and may not be modified",
                context={"protected": sorted(policy.protected_namespaces)},
            )
        )

    if str(inp.incident.severity) not in policy.automation_severities:
        violations.append(
            PolicyViolation(
                "severity_not_automatable",
                (f"Automated remediation is not enabled for {inp.incident.severity} incidents"),
            )
        )

    # 6 -- change freeze -----------------------------------------------------
    freeze = _active_freeze_window(policy.change_freeze_windows, inp.now)
    if freeze is not None and risk.rank >= RiskTier.HIGH.rank:
        violations.append(
            PolicyViolation(
                "change_freeze",
                (
                    f"A change freeze is active"
                    f"{': ' + freeze['reason'] if freeze.get('reason') else ''}"
                ),
                context={"window": freeze},
            )
        )

    # 7 -- blast radius ceilings --------------------------------------------
    units = radius.estimated_affected_units
    if radius.scope in ("pod", "deployment") and units > policy.max_pods_restart:
        violations.append(
            PolicyViolation(
                "blast_radius_pods",
                (f"Action would affect {units} pods, above the limit of {policy.max_pods_restart}"),
                context={"affected": units, "limit": policy.max_pods_restart},
            )
        )

    replica_delta = _replica_delta(inp)
    if replica_delta is not None and abs(replica_delta) > policy.max_replica_delta:
        violations.append(
            PolicyViolation(
                "blast_radius_replicas",
                (
                    f"Replica change of {replica_delta:+d} exceeds the limit of "
                    f"±{policy.max_replica_delta}"
                ),
                context={"delta": replica_delta, "limit": policy.max_replica_delta},
            )
        )

    if radius.causes_downtime and str(inp.incident.environment) in policy.protected_environments:
        violations.append(
            PolicyViolation(
                "downtime_in_protected_environment",
                (
                    f"This action causes downtime and '{inp.incident.environment}' is a "
                    f"protected environment"
                ),
            )
        )

    # 8 -- rate limits -------------------------------------------------------
    if inp.actions_this_incident >= policy.max_actions_per_incident:
        violations.append(
            PolicyViolation(
                "incident_action_budget",
                (
                    f"This incident has already used its budget of "
                    f"{policy.max_actions_per_incident} remediation actions"
                ),
            )
        )
    if inp.actions_this_hour >= policy.max_actions_per_hour:
        violations.append(
            PolicyViolation(
                "tenant_action_rate_limit",
                (
                    f"Organisation-wide limit of {policy.max_actions_per_hour} actions "
                    f"per hour reached"
                ),
            )
        )

    # 9 -- evidence and confidence floor ------------------------------------
    confidence = inp.hypothesis_confidence
    if risk.rank >= RiskTier.HIGH.rank:
        floor = (
            policy.min_confidence_critical_risk
            if risk is RiskTier.CRITICAL
            else policy.min_confidence_high_risk
        )
        if confidence is None:
            warnings.append(
                PolicyViolation(
                    "no_confidence_score",
                    "Action is not linked to a scored hypothesis; a human must judge it",
                    severity="warn",
                )
            )
        elif confidence < floor:
            violations.append(
                PolicyViolation(
                    "confidence_floor",
                    (
                        f"Root-cause confidence {confidence:.0%} is below the "
                        f"{floor:.0%} floor required for {risk} actions"
                    ),
                    context={"confidence": confidence, "floor": floor},
                )
            )
        if inp.supporting_evidence_count < policy.min_evidence_high_risk:
            violations.append(
                PolicyViolation(
                    "insufficient_evidence",
                    (
                        f"Only {inp.supporting_evidence_count} supporting evidence "
                        f"item(s); {policy.min_evidence_high_risk} required for "
                        f"{risk} actions"
                    ),
                )
            )

    # 10 -- tenant-authored rules -------------------------------------------
    rule_effect: str | None = None
    rule_role: UserRole | None = None
    for rule in sorted(inp.rules, key=lambda r: r.priority):
        if not rule.is_enabled or not _rule_matches(rule, inp, radius, risk):
            continue
        matched.append(rule.name)

        limit_violation = _check_rule_limits(rule, inp, radius)
        if limit_violation is not None:
            violations.append(limit_violation)
            continue

        if rule.effect == "deny":
            violations.append(
                PolicyViolation(
                    f"rule:{rule.name}",
                    rule.reason or f"Blocked by policy rule '{rule.name}'",
                    context={"rule_id": str(rule.id)},
                )
            )
        elif rule_effect is None:
            # First matching non-deny rule wins; later ones are informational.
            rule_effect = rule.effect
            if rule.required_role:
                rule_role = UserRole(rule.required_role)

    # 11 -- residual decision ------------------------------------------------
    if violations:
        decision = PolicyDecision(
            allowed=False,
            requires_approval=False,
            risk_tier=risk,
            required_role=required_role,
            violations=violations,
            warnings=warnings,
            matched_rules=matched,
            reason=violations[0].message,
            effective_blast_radius=radius.to_dict(),
            evaluated_at=inp.now,
        )
        log.info(
            "policy.denied",
            action_key=inp.spec.key,
            incident_id=str(inp.incident.id),
            reason=decision.reason,
            violations=[v.rule for v in violations],
        )
        metrics.inc("opspilot_policy_denied_total", labels={"action_key": inp.spec.key})
        return decision

    if rule_role is not None and role_satisfies(rule_role, required_role):
        required_role = rule_role

    requires_approval = _requires_approval(risk, policy, rule_effect)
    reason = _approval_reason(risk, policy, rule_effect, requires_approval)

    decision = PolicyDecision(
        allowed=True,
        requires_approval=requires_approval,
        risk_tier=risk,
        required_role=required_role,
        violations=[],
        warnings=warnings,
        matched_rules=matched,
        reason=reason,
        effective_blast_radius=radius.to_dict(),
        evaluated_at=inp.now,
    )
    log.info(
        "policy.allowed",
        action_key=inp.spec.key,
        incident_id=str(inp.incident.id),
        requires_approval=requires_approval,
        risk_tier=str(risk),
    )
    return decision


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _effective_risk_tier(spec: ActionSpec[Any], radius: BlastRadius) -> RiskTier:
    """Escalate the declared tier when the concrete parameters make it worse.

    The catalog's declared tier is authoritative — the action's author already
    weighed what it does in general. This only raises the tier when the *actual
    arguments* reveal something the general case does not: scaling to zero is an
    outage even though scaling in general is not, and a cluster-scoped target is
    broader than a namespaced one.

    Note that ``touches_data`` deliberately floors at HIGH rather than CRITICAL.
    Escalating every data-touching action to CRITICAL would put
    ``db.terminate_idle_connections`` — the single most common and most useful
    database remediation — permanently above the confidence floor, so the
    guardrail would make the product useless rather than safe. Actions that are
    genuinely irreversible against data (``db.terminate_long_query``) declare
    CRITICAL for themselves.
    """
    tier = spec.risk_tier
    if radius.causes_downtime and tier.rank < RiskTier.CRITICAL.rank:
        tier = RiskTier.CRITICAL
    if radius.touches_data and tier.rank < RiskTier.HIGH.rank:
        tier = RiskTier.HIGH
    if radius.scope == "cluster" and tier.rank < RiskTier.HIGH.rank:
        tier = RiskTier.HIGH
    return tier


def _refine_blast_radius(inp: PolicyInput) -> BlastRadius:
    """Fill in ``estimated_affected_units`` from live facts when we have them."""
    radius = inp.blast_radius
    if radius.estimated_affected_units == 0:
        replicas = inp.live_facts.get("current_replicas")
        if isinstance(replicas, int) and replicas > 0:
            radius.estimated_affected_units = replicas
    if not radius.environment:
        radius.environment = inp.incident.environment
    return radius


def _replica_delta(inp: PolicyInput) -> int | None:
    target = getattr(inp.params, "replicas", None)
    if target is None:
        return None
    current = inp.live_facts.get("current_replicas")
    if not isinstance(current, int):
        return None
    return int(target) - current


def _active_freeze_window(windows: list[dict[str, Any]], now: datetime) -> dict[str, Any] | None:
    if not windows:
        return None
    day = WEEKDAYS[now.weekday()]
    for window in windows:
        days = [d.lower() for d in window.get("days", WEEKDAYS)]
        if day not in days:
            continue
        try:
            start = time.fromisoformat(window.get("start", "00:00"))
            end = time.fromisoformat(window.get("end", "23:59"))
        except ValueError:
            continue
        current = now.timetz().replace(tzinfo=None)
        inside = start <= current <= end if start <= end else (current >= start or current <= end)
        if inside:
            return window
    return None


def _rule_matches(rule: PolicyRule, inp: PolicyInput, radius: BlastRadius, risk: RiskTier) -> bool:
    match = rule.match or {}

    keys = match.get("action_keys")
    if keys and inp.spec.key not in keys and not _any_glob(keys, inp.spec.key):
        return False

    environments = match.get("environments")
    if environments and inp.incident.environment not in environments:
        return False

    namespaces = match.get("namespaces")
    if namespaces and (radius.namespace or "") not in namespaces:
        return False

    services = match.get("services")
    if services and (radius.service or inp.incident.service or "") not in services:
        return False

    providers = match.get("providers")
    if providers and str(inp.spec.provider) not in providers:
        return False

    min_tier = match.get("min_risk_tier")
    if min_tier and risk.rank < RiskTier(min_tier).rank:
        return False

    severities = match.get("severities")
    if severities and str(inp.incident.severity) not in severities:
        return False

    window = rule.active_window or {}
    return not (window and _active_freeze_window([window], inp.now) is None)


def _any_glob(patterns: list[str], value: str) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(value, p) for p in patterns if "*" in p or "?" in p)


def _check_rule_limits(
    rule: PolicyRule, inp: PolicyInput, radius: BlastRadius
) -> PolicyViolation | None:
    limits = rule.limits or {}
    if not limits:
        return None

    max_pods = limits.get("max_pods")
    if isinstance(max_pods, int) and radius.estimated_affected_units > max_pods:
        return PolicyViolation(
            f"rule:{rule.name}:max_pods",
            (
                f"Policy rule '{rule.name}' caps this action at {max_pods} pods; "
                f"it would affect {radius.estimated_affected_units}"
            ),
        )

    max_delta = limits.get("max_replica_delta")
    delta = _replica_delta(inp)
    if isinstance(max_delta, int) and delta is not None and abs(delta) > max_delta:
        return PolicyViolation(
            f"rule:{rule.name}:max_replica_delta",
            (
                f"Policy rule '{rule.name}' caps replica changes at ±{max_delta}; "
                f"this action requests {delta:+d}"
            ),
        )

    min_conf = limits.get("min_confidence")
    if (
        isinstance(min_conf, (int, float))
        and inp.hypothesis_confidence is not None
        and inp.hypothesis_confidence < float(min_conf)
    ):
        return PolicyViolation(
            f"rule:{rule.name}:min_confidence",
            (
                f"Policy rule '{rule.name}' requires {float(min_conf):.0%} confidence; "
                f"this hypothesis is at {inp.hypothesis_confidence:.0%}"
            ),
        )
    return None


def _requires_approval(risk: RiskTier, policy: TenantPolicy, rule_effect: str | None) -> bool:
    # An explicit auto_approve rule can only waive approval strictly *below* the
    # tenant's always-approve threshold. It can never waive CRITICAL.
    if rule_effect == "require_approval":
        return True
    if risk.rank >= policy.always_approve_at_or_above.rank:
        if rule_effect == "auto_approve" and risk is not RiskTier.CRITICAL:
            return risk.rank >= RiskTier.HIGH.rank
        return True
    if rule_effect == "auto_approve":
        return False
    if risk is RiskTier.LOW:
        return not policy.auto_approve_low_risk
    return True


def _approval_reason(
    risk: RiskTier, policy: TenantPolicy, rule_effect: str | None, requires_approval: bool
) -> str:
    if not requires_approval:
        if rule_effect == "auto_approve":
            return "Auto-approved by an explicit policy rule"
        return f"{risk.value.title()}-risk action auto-approved by tenant policy"
    if rule_effect == "require_approval":
        return "A policy rule requires human approval for this action"
    if risk is RiskTier.CRITICAL:
        return "Critical-risk actions always require human approval"
    return (
        f"{risk.value.title()}-risk action requires approval from a "
        f"{risk.minimum_role.value} or above"
    )


def check_approver(
    *, approver_role: UserRole | str, decision_required_role: UserRole | str, approver_id: uuid.UUID
) -> None:
    """Raise if this human is not senior enough to approve this action."""
    from app.core.errors import PermissionDeniedError

    if not role_satisfies(approver_role, decision_required_role):
        raise PermissionDeniedError(
            f"This action requires the '{decision_required_role}' role or above",
            details={
                "required_role": str(decision_required_role),
                "your_role": str(approver_role),
                "user_id": str(approver_id),
            },
        )


def severity_allows_automation(severity: IncidentSeverity, tenant: Tenant | None) -> bool:
    return str(severity) in TenantPolicy.for_tenant(tenant).automation_severities
