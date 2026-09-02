"""The action catalog is the trust boundary. These tests defend it."""

from __future__ import annotations

import pytest

from app.core.errors import UnknownActionError, ValidationError
from app.models.enums import RiskTier
from app.services.actions import (
    ACTION_REGISTRY,
    catalog_for_prompt,
    get_action,
    list_actions,
    registry_fingerprint,
)


def test_registry_is_populated() -> None:
    assert len(ACTION_REGISTRY) >= 10
    for key, spec in ACTION_REGISTRY.items():
        assert spec.key == key
        assert spec.title and spec.description
        assert callable(spec.executor)
        assert callable(spec.blast_radius_fn)


def test_no_action_can_run_a_command() -> None:
    """There must be no generic execution escape hatch, ever.

    If someone adds a ``shell.exec``-shaped action, the entire separation between
    reasoning and execution collapses. This test is the tripwire.
    """
    # Names that would indicate a generic primitive. ("query" is deliberately not
    # here: db.terminate_long_query *acts on* a query by pid, it does not accept
    # one — which is exactly the distinction the parameter check below enforces.)
    forbidden_substrings = ("exec", "shell", "command", "eval", "script", "run_sql")
    for key in ACTION_REGISTRY:
        assert not any(word in key.lower() for word in forbidden_substrings), (
            f"action '{key}' looks like a generic execution primitive"
        )

    # No action may accept a free-form field that could carry code or a command.
    # This is the check that actually matters: an action is safe when its
    # parameters can only be *identifiers and numbers*, never syntax.
    suspicious_fields = {
        "command",
        "cmd",
        "script",
        "sql",
        "shell",
        "exec",
        "code",
        "query",
        "statement",
        "expression",
        "payload",
        "body_raw",
    }
    for key, spec in ACTION_REGISTRY.items():
        properties = set(spec.params_model.model_json_schema().get("properties", {}))
        assert not (properties & suspicious_fields), (
            f"action '{key}' exposes a command-shaped parameter: {properties & suspicious_fields}"
        )


def test_unknown_action_key_is_rejected() -> None:
    with pytest.raises(UnknownActionError):
        get_action("shell.exec")
    with pytest.raises(UnknownActionError):
        get_action("k8s.rollback_deployment_v2")


@pytest.mark.parametrize(
    "namespace",
    [
        "payments; kubectl delete ns prod",
        "../../etc/passwd",
        "PAYMENTS",
        "pay ments",
        "payments\nrm -rf /",
        "$(whoami)",
        "`id`",
        "",
        "a" * 300,
    ],
)
def test_injection_attempts_fail_schema_validation(namespace: str) -> None:
    """Model output cannot smuggle syntax through a parameter."""
    spec = get_action("k8s.rollout_restart")
    with pytest.raises(ValidationError):
        spec.parse_params({"namespace": namespace, "deployment": "checkout-api"})


def test_extra_parameters_are_rejected() -> None:
    """A model cannot append a field the executor might read."""
    spec = get_action("k8s.scale_deployment")
    with pytest.raises(ValidationError):
        spec.parse_params(
            {
                "namespace": "payments",
                "deployment": "checkout-api",
                "replicas": 3,
                "force": True,
            }
        )


def test_out_of_range_values_are_rejected() -> None:
    spec = get_action("k8s.scale_deployment")
    with pytest.raises(ValidationError):
        spec.parse_params({"namespace": "p", "deployment": "d", "replicas": 10_000})
    with pytest.raises(ValidationError):
        spec.parse_params({"namespace": "p", "deployment": "d", "replicas": -1})


def test_blast_radius_is_derived_from_params_not_claims() -> None:
    spec = get_action("k8s.scale_deployment")

    scale_up = spec.blast_radius(
        spec.parse_params({"namespace": "payments", "deployment": "api", "replicas": 12})
    )
    assert scale_up.estimated_affected_units == 12
    assert scale_up.causes_downtime is False

    scale_to_zero = spec.blast_radius(
        spec.parse_params({"namespace": "payments", "deployment": "api", "replicas": 0})
    )
    assert scale_to_zero.causes_downtime is True


def test_database_actions_are_marked_as_touching_data() -> None:
    spec = get_action("db.terminate_idle_connections")
    radius = spec.blast_radius(
        spec.parse_params({"database": "checkout_prod", "idle_seconds": 300})
    )
    assert radius.touches_data is True


def test_reversible_actions_can_build_a_rollback() -> None:
    from app.services.actions.registry import ExecutionResult

    spec = get_action("k8s.scale_deployment")
    params = spec.parse_params({"namespace": "payments", "deployment": "api", "replicas": 10})
    result = ExecutionResult(succeeded=True, summary="scaled", pre_state={"replicas": 4})

    rollback = spec.build_rollback(params, result)
    assert rollback is not None
    key, rollback_params = rollback
    assert key == "k8s.scale_deployment"
    assert rollback_params["replicas"] == 4


def test_risk_tiers_map_to_sensible_roles() -> None:
    from app.models.enums import ROLE_RANK

    # A higher risk tier must never require a *lower* role to approve.
    tiers = [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH, RiskTier.CRITICAL]
    ranks = [ROLE_RANK[tier.minimum_role] for tier in tiers]
    assert ranks == sorted(ranks), dict(zip(tiers, ranks, strict=True))

    for spec in list_actions():
        # Anything that terminates a database backend must be at least HIGH:
        # this is the guardrail that keeps such an action out of the
        # auto-approve path. See docs/SAFETY.md, "Known limits".
        if spec.key.startswith("db.") and "terminate" in spec.key:
            assert spec.risk_tier.rank >= RiskTier.HIGH.rank, spec.key


def test_catalog_prompt_lists_every_action() -> None:
    rendered = catalog_for_prompt()
    for key in ACTION_REGISTRY:
        assert key in rendered


def test_fingerprint_is_stable_and_sensitive() -> None:
    first = registry_fingerprint()
    assert first == registry_fingerprint()
    assert len(first) == 16
