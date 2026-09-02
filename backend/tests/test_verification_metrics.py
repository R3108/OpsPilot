"""Recovery checks have to name metrics the verifier can actually query.

``standard_query`` accepts a fixed vocabulary. A check naming anything else comes
back with no data — ``observed: null`` — and a check that cannot be measured cannot
confirm recovery, so the postmortem node parks the incident as ``failed`` no matter
how well the remediation worked. The model is not left to guess Prometheus series
names: it is given the vocabulary and held to it.
"""

from __future__ import annotations

import pathlib
import re

from app.agents import prompts
from app.agents.contracts import VerificationCheck
from app.agents.nodes.remediation import measurable_checks
from app.integrations.prometheus import STANDARD_QUERIES
from app.services.actions import catalog_for_prompt, list_actions


def _render(min_evidence: int = 2) -> str:
    return prompts.REMEDIATION_SYSTEM.format(
        catalog=catalog_for_prompt(list_actions()),
        metrics=", ".join(sorted(STANDARD_QUERIES)),
        min_evidence=min_evidence,
    )


def test_the_prompt_states_the_evidence_bar_the_proposal_is_judged_against() -> None:
    """Regression: a sound proposal was denied for citing 0 evidence ids.

    The policy engine counts `supporting_evidence_count` for high- and
    critical-risk actions; the prompt never mentioned that bar, so the model had
    no reason to treat evidence_ids as anything but decoration.
    """
    assert "evidence_ids" in _render()
    # The tenant's real threshold, not a hardcoded one.
    assert "fewer than 3" in _render(min_evidence=3)


def test_the_propose_prompt_names_every_queryable_metric() -> None:
    """The model can only stay inside the vocabulary if it is shown the vocabulary."""
    rendered = _render()
    for metric in STANDARD_QUERIES:
        assert metric in rendered, f"{metric} is queryable but never offered to the model"


def test_the_metrics_block_did_not_displace_the_action_catalog() -> None:
    rendered = _render()
    for spec in list_actions():
        assert spec.key in rendered


def test_invented_metric_names_are_dropped_before_they_reach_the_verifier() -> None:
    """Regression: these produced `observed: null` for every check on a live incident.

    `search_api_error_rate` and `p99_latency_seconds` are plausible Prometheus
    spellings that the standard-query layer does not know, so verification came back
    INCONCLUSIVE and the incident was parked as failed despite a clean remediation.
    """
    kept, unmeasurable = measurable_checks(
        [
            VerificationCheck(name="real", metric="error_rate", threshold=0.005),
            VerificationCheck(name="invented", metric="search_api_error_rate", threshold=0.001),
            VerificationCheck(name="also invented", metric="p99_latency_seconds", threshold=0.5),
        ]
    )

    assert [c["metric"] for c in kept] == ["error_rate"]
    assert unmeasurable == ["search_api_error_rate", "p99_latency_seconds"]


def test_a_fully_queryable_proposal_survives_untouched() -> None:
    kept, unmeasurable = measurable_checks(
        [
            VerificationCheck(name="errors", metric="error_rate", comparator="lt", threshold=0.005),
            VerificationCheck(name="latency", metric="latency_p99", comparator="lt", threshold=0.5),
        ]
    )

    assert not unmeasurable
    assert [c["name"] for c in kept] == ["errors", "latency"]
    assert kept[0]["comparator"] == "lt"
    assert kept[1]["threshold"] == 0.5


def test_the_offline_engine_only_emits_queryable_metrics() -> None:
    """The heuristic engine is the reference for what a good check looks like.

    It is also why the suite never caught this: the fake LLM always named real
    metrics, so only the live model ever drifted.
    """
    source = pathlib.Path("app/agents/heuristics.py").read_text(encoding="utf-8")
    referenced = set(re.findall(r'"metric":\s*"([^"]+)"', source))
    assert referenced, "expected the offline engine to define recovery checks"
    assert not (referenced - set(STANDARD_QUERIES))
