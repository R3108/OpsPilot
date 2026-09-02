"""Structured-output contracts for every LLM call.

The model never returns free text that we then parse with a regex. Each node asks
for one of these schemas, and anything that does not validate is retried and then
failed closed. In particular :class:`ProposedActionOut` is the *only* channel by
which model output can reach infrastructure, and it carries an action **key**,
not a command.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import IncidentSeverity, InvestigatorKind

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------- triage
class TriageResult(Strict):
    """Severity classification and first-pass framing of the incident."""

    severity: IncidentSeverity = Field(
        description="sev1 = full outage or data-loss risk, sev5 = informational"
    )
    confidence: Confidence
    rationale: str = Field(max_length=2000, description="Why this severity, citing the signals")
    likely_service: str | None = Field(
        default=None, max_length=200, description="Service most likely affected"
    )
    customer_impact: str = Field(
        default="", max_length=1000, description="Concretely, what a user experiences"
    )
    symptoms: list[str] = Field(
        default_factory=list, max_length=10, description="Observable symptoms, one per item"
    )
    is_duplicate_of: str | None = Field(
        default=None, description="Reference of an existing incident this duplicates, if any"
    )
    urgency_reason: str = Field(default="", max_length=500)


# ----------------------------------------------------------------------- plan
class InvestigationTask(Strict):
    investigator: InvestigatorKind
    objective: str = Field(max_length=500, description="What this investigator must find out")
    questions: list[str] = Field(
        default_factory=list, max_length=6, description="Specific questions to answer"
    )
    priority: Annotated[int, Field(ge=1, le=5)] = 3


class InvestigationPlan(Strict):
    """Which specialists to run, and what each is looking for."""

    summary: str = Field(max_length=1000)
    tasks: list[InvestigationTask] = Field(min_length=1, max_length=5)
    time_window_minutes: Annotated[int, Field(ge=5, le=1440)] = 120
    target_service: str | None = Field(default=None, max_length=200)
    target_namespace: str | None = Field(default=None, max_length=200)
    initial_suspicions: list[str] = Field(default_factory=list, max_length=5)

    @field_validator("tasks")
    @classmethod
    def _unique_investigators(cls, tasks: list[InvestigationTask]) -> list[InvestigationTask]:
        seen = {t.investigator for t in tasks}
        if len(seen) != len(tasks):
            raise ValueError("each investigator may appear at most once in a plan")
        return tasks


# ------------------------------------------------------------------- findings
class InvestigatorFinding(Strict):
    """One investigator's read of the evidence *it* collected."""

    summary: str = Field(max_length=2000, description="What the data shows")
    key_observations: list[str] = Field(default_factory=list, max_length=10)
    # Citations must be ids of evidence rows collected this run.
    cited_evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    anomaly_detected: bool = False
    anomaly_description: str = Field(default="", max_length=1000)
    confidence: Confidence = 0.5
    suggests_root_cause: str | None = Field(default=None, max_length=500)
    dead_end: bool = Field(
        default=False, description="True when this line of inquiry found nothing useful"
    )


# ----------------------------------------------------------------- correlation
class CorrelatedSignal(Strict):
    description: str = Field(max_length=500)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    signal_type: Literal["temporal", "causal", "spatial", "pattern"] = "temporal"
    strength: Confidence = 0.5


class Correlation(Strict):
    """Cross-investigator synthesis: what lines up with what, and when."""

    timeline_summary: str = Field(max_length=3000)
    change_point: str | None = Field(
        default=None, max_length=300, description="When the system's behaviour changed"
    )
    signals: list[CorrelatedSignal] = Field(default_factory=list, max_length=12)
    contradictions: list[str] = Field(default_factory=list, max_length=8)
    gaps: list[str] = Field(
        default_factory=list, max_length=8, description="What we still cannot see"
    )


# ------------------------------------------------------------------ hypotheses
class HypothesisOut(Strict):
    title: str = Field(max_length=300)
    statement: str = Field(max_length=2000, description="The causal claim, stated precisely")
    category: Literal[
        "deployment",
        "resource_exhaustion",
        "dependency_failure",
        "configuration",
        "data",
        "infrastructure",
        "capacity",
        "external",
        "unknown",
    ] = "unknown"
    confidence: Confidence
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    contradicting_evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    reasoning: str = Field(max_length=3000)
    disconfirming_test: str = Field(
        default="",
        max_length=500,
        description="An observation that would falsify this hypothesis",
    )


class HypothesisSet(Strict):
    hypotheses: list[HypothesisOut] = Field(min_length=1, max_length=6)
    # Index into `hypotheses`; the node re-checks it is in range.
    selected_index: Annotated[int, Field(ge=0)] = 0
    selection_reasoning: str = Field(max_length=1500)
    needs_more_investigation: bool = False
    additional_questions: list[str] = Field(default_factory=list, max_length=5)


# ----------------------------------------------------------------- remediation
class ProposedActionOut(Strict):
    """The single channel from model reasoning to infrastructure change.

    ``action_key`` is resolved against the signed action catalog and ``params`` is
    validated against that action's schema before anything else happens. Both can
    fail, and failing drops the proposal.
    """

    action_key: str = Field(
        max_length=120, description="Must be a key from the provided action catalog"
    )
    params: dict[str, object] = Field(
        default_factory=dict, description="Must match the action's parameter schema exactly"
    )
    rationale: str = Field(max_length=2000, description="Why this action addresses the root cause")
    expected_effect: str = Field(
        max_length=1000, description="What should measurably change if this works"
    )
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    sequence: Annotated[int, Field(ge=0, le=10)] = 0
    urgency: Literal["immediate", "soon", "when_convenient"] = "soon"

    @field_validator("action_key")
    @classmethod
    def _shape(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.replace("_", "").replace(".", "").isalnum():
            raise ValueError("action_key must be alphanumeric with '.' and '_' only")
        return cleaned


class RemediationProposal(Strict):
    actions: list[ProposedActionOut] = Field(default_factory=list, max_length=5)
    # An explicit "do nothing" is a valid, and often correct, answer.
    no_action_recommended: bool = False
    no_action_reason: str = Field(default="", max_length=1000)
    verification_plan: str = Field(
        default="",
        max_length=1500,
        description="How we will know the incident is actually resolved",
    )
    # Metric thresholds the deterministic verifier will check.
    verification_checks: list[VerificationCheck] = Field(default_factory=list, max_length=6)
    rollback_plan: str = Field(default="", max_length=1000)


class VerificationCheck(Strict):
    """A machine-checkable recovery criterion.

    Evaluated by Python against real metric data — the model proposes the
    threshold, it does not get to declare the result.
    """

    name: str = Field(max_length=120)
    metric: str = Field(
        max_length=120, description="A standard metric name, e.g. error_rate or latency_p99"
    )
    comparator: Literal["lt", "lte", "gt", "gte"] = "lt"
    threshold: float
    description: str = Field(default="", max_length=300)


# ------------------------------------------------------------------ postmortem
class PostmortemActionItem(Strict):
    title: str = Field(max_length=300)
    owner_hint: str = Field(default="", max_length=120)
    priority: Literal["p0", "p1", "p2", "p3"] = "p2"
    rationale: str = Field(default="", max_length=800)


class PostmortemDraft(Strict):
    """Every substantive claim must carry evidence ids; the node enforces it."""

    title: str = Field(max_length=300)
    summary: str = Field(max_length=3000)
    impact: str = Field(max_length=2000)
    root_cause: str = Field(max_length=3000)
    detection: str = Field(max_length=1500)
    resolution: str = Field(max_length=2000)
    lessons_learned: str = Field(max_length=3000)

    @field_validator(
        "summary", "impact", "root_cause", "detection", "resolution", "lessons_learned",
        mode="before",
    )
    @classmethod
    def _prose_may_arrive_as_a_list(cls, value: object) -> object:
        """Accept a list of points where one prose block was asked for.

        These fields sit among ``contributing_factors``, ``what_went_well`` and
        ``action_items``, which *are* lists, and ``lessons_learned`` reads plural,
        so models routinely return a list here. Observed on every first attempt
        from ``openai/gpt-oss-120b``: the retry loop showed it the validation
        error and it complied, costing a whole attempt out of a budget of three
        for the one node that has no fallback. Joining is lossless for the
        strings that were already correct, so it costs nothing when the model
        gets it right.
        """
        if isinstance(value, list):
            return "\n".join(f"- {str(item).strip()}" for item in value if str(item).strip())
        return value
    contributing_factors: list[str] = Field(default_factory=list, max_length=8)
    action_items: list[PostmortemActionItem] = Field(default_factory=list, max_length=10)
    cited_evidence_ids: list[str] = Field(default_factory=list, max_length=40)
    what_went_well: list[str] = Field(default_factory=list, max_length=6)
    what_went_poorly: list[str] = Field(default_factory=list, max_length=6)


# Forward reference used by RemediationProposal.
RemediationProposal.model_rebuild()
