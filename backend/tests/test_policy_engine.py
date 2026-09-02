"""The policy engine decides whether production gets touched. It is pure, so it
is tested exhaustively and without any I/O."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.enums import IncidentSeverity, IncidentStatus, RiskTier, UserRole
from app.models.incident import Incident
from app.models.integration import Integration
from app.models.remediation import PolicyRule
from app.models.tenant import Tenant
from app.services.actions import get_action
from app.services.policy import PolicyInput, TenantPolicy, evaluate


def make_incident(**overrides) -> Incident:  # noqa: ANN003
    import uuid

    defaults = dict(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        reference="INC-0001",
        title="test",
        status=IncidentStatus.INVESTIGATING,
        severity=IncidentSeverity.SEV1,
        service="checkout-api",
        environment="production",
        namespace="payments",
        detected_at=datetime.now(UTC),
        root_cause_confidence=0.9,
    )
    defaults.update(overrides)
    return Incident(**defaults)


def make_integration(*, allow_write: bool = True, scope: dict | None = None) -> Integration:
    import uuid

    return Integration(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        provider=get_action("k8s.rollout_restart").provider,
        name="prod",
        is_enabled=True,
        allow_write=allow_write,
        scope=scope or {},
        config={},
    )


def build_input(action_key: str, params: dict, **overrides):  # noqa: ANN003, ANN201
    spec = get_action(action_key)
    parsed = spec.parse_params(params)
    defaults = dict(
        spec=spec,
        params=parsed,
        blast_radius=spec.blast_radius(parsed),
        incident=make_incident(),
        tenant=None,
        rules=[],
        integration=make_integration(),
        hypothesis_confidence=0.9,
        supporting_evidence_count=4,
    )
    defaults.update(overrides)
    return PolicyInput(**defaults)


# --------------------------------------------------------------------------
def test_high_risk_action_is_allowed_but_needs_approval() -> None:
    decision = evaluate(
        build_input("k8s.rollout_restart", {"namespace": "search", "deployment": "search-api"})
    )
    assert decision.allowed is True
    assert decision.requires_approval is True
    assert decision.risk_tier is RiskTier.HIGH
    assert decision.required_role is UserRole.APPROVER


def test_low_risk_action_can_be_auto_approved() -> None:
    decision = evaluate(
        build_input(
            "github.open_revert_pr",
            {"repo": "acme/api", "commit_sha": "abc1234", "reason": "regression"},
        )
    )
    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.auto_executable is True


def test_protected_namespace_is_denied() -> None:
    tenant = Tenant(
        name="t", slug="t", settings_json={"policy": {"protected_namespaces": ["kube-system"]}}
    )
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "kube-system", "deployment": "coredns"},
            tenant=tenant,
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "protected_namespace" for v in decision.violations)


def test_scaling_to_zero_is_treated_as_critical_downtime() -> None:
    decision = evaluate(
        build_input(
            "k8s.scale_deployment",
            {"namespace": "payments", "deployment": "checkout-api", "replicas": 0},
        )
    )
    # Downtime in a protected environment is denied outright.
    assert decision.allowed is False
    assert any(v.rule == "downtime_in_protected_environment" for v in decision.violations)


def test_confidence_floor_blocks_low_confidence_high_risk_actions() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollback_deployment",
            {"namespace": "orders", "deployment": "orders-api"},
            hypothesis_confidence=0.2,
        )
    )
    assert decision.allowed is False
    violation = next(v for v in decision.violations if v.rule == "confidence_floor")
    assert "20%" in violation.message


def test_insufficient_evidence_blocks_high_risk_actions() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollback_deployment",
            {"namespace": "orders", "deployment": "orders-api"},
            supporting_evidence_count=0,
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "insufficient_evidence" for v in decision.violations)


def test_read_only_integration_blocks_remediation() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "search", "deployment": "search-api"},
            integration=make_integration(allow_write=False),
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "integration_read_only" for v in decision.violations)


def test_missing_integration_blocks_remediation() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "search", "deployment": "search-api"},
            integration=None,
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "missing_integration" for v in decision.violations)


def test_integration_scope_fences_namespaces() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "payments", "deployment": "checkout-api"},
            integration=make_integration(scope={"namespaces": ["search", "edge"]}),
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "integration_scope" for v in decision.violations)


def test_replica_delta_ceiling() -> None:
    decision = evaluate(
        build_input(
            "k8s.scale_deployment",
            {"namespace": "edge", "deployment": "api-gateway", "replicas": 50},
            live_facts={"current_replicas": 6},
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "blast_radius_replicas" for v in decision.violations)


def test_incident_action_budget_is_enforced() -> None:
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "search", "deployment": "search-api"},
            actions_this_incident=99,
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "incident_action_budget" for v in decision.violations)


def test_tenant_kill_switch_denies_everything() -> None:
    tenant = Tenant(name="t", slug="t", settings_json={"policy": {"remediation_enabled": False}})
    decision = evaluate(
        build_input(
            "github.open_revert_pr",
            {"repo": "acme/api", "commit_sha": "abc1234", "reason": "x"},
            tenant=tenant,
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "tenant_kill_switch" for v in decision.violations)


def test_global_kill_switch_denies_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "remediation_disabled", True)
    decision = evaluate(
        build_input(
            "github.open_revert_pr",
            {"repo": "acme/api", "commit_sha": "abc1234", "reason": "x"},
        )
    )
    assert decision.allowed is False
    assert any(v.rule == "global_kill_switch" for v in decision.violations)


# --------------------------------------------------------------------------
# tenant-authored rules
# --------------------------------------------------------------------------
def make_rule(**overrides) -> PolicyRule:  # noqa: ANN003
    import uuid

    defaults = dict(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name="rule",
        description="",
        is_enabled=True,
        priority=100,
        match={},
        effect="require_approval",
        reason="",
        limits={},
        active_window={},
        hit_count=0,
    )
    defaults.update(overrides)
    return PolicyRule(**defaults)


def test_deny_rule_wins() -> None:
    rule = make_rule(
        name="no touching payments",
        match={"namespaces": ["payments"]},
        effect="deny",
        reason="PCI scope",
    )
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "payments", "deployment": "checkout-api"},
            rules=[rule],
        )
    )
    assert decision.allowed is False
    assert "PCI scope" in decision.deny_summary()
    assert "no touching payments" in decision.matched_rules


def test_rule_limits_cap_replica_changes() -> None:
    rule = make_rule(name="small steps", limits={"max_replica_delta": 2})
    decision = evaluate(
        build_input(
            "k8s.scale_deployment",
            {"namespace": "edge", "deployment": "api-gateway", "replicas": 12},
            live_facts={"current_replicas": 6},
            rules=[rule],
        )
    )
    assert decision.allowed is False
    assert any("max_replica_delta" in v.rule for v in decision.violations)


def test_auto_approve_rule_cannot_waive_critical_actions() -> None:
    """An auto-approve rule must never remove the human from a CRITICAL action."""
    rule = make_rule(name="trust me", effect="auto_approve")
    decision = evaluate(
        build_input(
            "db.terminate_long_query",
            {"database": "checkout_prod", "pid": 41201},
            rules=[rule],
            hypothesis_confidence=0.95,
        )
    )
    assert decision.allowed is True
    assert decision.requires_approval is True, "CRITICAL actions always need a human"


def test_action_key_glob_matching() -> None:
    rule = make_rule(
        name="all k8s", match={"action_keys": ["k8s.*"]}, effect="deny", reason="no k8s"
    )
    decision = evaluate(
        build_input(
            "k8s.rollout_restart",
            {"namespace": "search", "deployment": "search-api"},
            rules=[rule],
        )
    )
    assert decision.allowed is False


def test_change_freeze_blocks_high_risk_actions() -> None:
    now = datetime.now(UTC)
    weekday = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"][now.weekday()]
    tenant = Tenant(
        name="t",
        slug="t",
        settings_json={
            "policy": {
                "change_freeze_windows": [
                    {
                        "days": [weekday],
                        "start": "00:00",
                        "end": "23:59",
                        "reason": "Black Friday freeze",
                    }
                ]
            }
        },
    )
    decision = evaluate(
        build_input(
            "k8s.rollback_deployment",
            {"namespace": "orders", "deployment": "orders-api"},
            tenant=tenant,
            now=now,
        )
    )
    assert decision.allowed is False
    assert "Black Friday freeze" in decision.deny_summary()


def test_tenant_policy_defaults_and_overrides() -> None:
    default = TenantPolicy.for_tenant(None)
    assert default.remediation_enabled is True

    tenant = Tenant(
        name="t",
        slug="t",
        settings_json={"policy": {"max_replica_delta": 3, "min_confidence_high_risk": 0.9}},
    )
    policy = TenantPolicy.for_tenant(tenant)
    assert policy.max_replica_delta == 3
    assert policy.min_confidence_high_risk == 0.9
    # Unspecified keys keep their deployment defaults.
    assert policy.max_actions_per_incident == 6


def test_decision_serialises_for_storage() -> None:
    decision = evaluate(
        build_input("k8s.rollout_restart", {"namespace": "search", "deployment": "search-api"})
    )
    payload = decision.to_dict()
    assert payload["allowed"] is True
    assert payload["risk_tier"] == "high"
    assert "evaluated_at" in payload
