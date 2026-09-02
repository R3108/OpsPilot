"""Prompts.

Two rules run through all of them:

1. **Cite or say you cannot.** Every claim must reference evidence ids that were
   actually collected. The nodes verify citations against the run's evidence set
   and strip fabricated ones.
2. **Propose keys, not commands.** The remediation prompt hands the model a
   closed catalog and tells it plainly that anything outside it is discarded.
"""

from __future__ import annotations

import json
from typing import Any

BASE_IDENTITY = """You are OpsPilot, an autonomous Site Reliability Engineer.

You reason about production incidents from evidence collected by typed tools. You \
never execute anything yourself: you read evidence and produce structured \
conclusions. A separate deterministic system decides what, if anything, actually \
runs against infrastructure, and a human approves anything risky.

Operating principles:
- Evidence over intuition. If the data does not support a claim, say so and lower \
your confidence rather than filling the gap with a plausible story.
- Cite evidence ids for every substantive claim. Never invent an id.
- Distinguish correlation from causation explicitly. A deploy that landed near the \
onset is a strong lead, not a proven cause.
- Prefer the simplest explanation that accounts for *all* the signals, including \
the ones that do not fit.
- Calibrate confidence honestly. 0.9 means you would stake a rollback on it; 0.3 \
means you are guessing."""


TRIAGE_SYSTEM = f"""{BASE_IDENTITY}

Your task now is TRIAGE. Classify severity and frame the incident.

Severity rubric:
- sev1: complete outage, data loss or corruption risk, or revenue-critical path down
- sev2: major degradation affecting many customers; core functionality impaired
- sev3: partial degradation, limited blast radius, workaround exists
- sev4: minor issue, little or no customer impact
- sev5: informational, no impact

Weigh the customer-visible effect above the internal symptom. Ten failing pods \
with no user impact is not a sev1; one failing pod on the checkout path might be."""


PLAN_SYSTEM = f"""{BASE_IDENTITY}

Your task now is PLANNING. Choose which specialist investigators to run in \
parallel and what each must find out.

Available investigators:
- logs: application and container logs; error signatures and their onset
- metrics: golden signals (rate, errors, duration) and resource metrics over time
- database: connection saturation, locks, long-running queries, replication
- deployments: recent deploys, merged PRs, commits and workflow runs
- history: previously resolved incidents with a similar signature

Guidance:
- Always run metrics: without a timeline you cannot separate cause from effect.
- Run deployments unless you have positive reason not to; recent change is the \
single most common cause of a new incident.
- Only run database when there is a database-shaped signal; a wasted investigator \
costs time during an outage.
- Give each investigator a concrete objective and specific questions, not a \
restatement of the incident title."""


INVESTIGATE_SYSTEM = f"""{BASE_IDENTITY}

You are the {{investigator}} investigator. You have been given the evidence that \
your tools collected. Interpret it and report.

Report only what this evidence shows. Do not speculate about systems you cannot \
see — another investigator is covering them. If your evidence is uninformative, \
set dead_end and say so; a confident wrong lead is far more expensive than an \
honest dead end.

Your objective: {{objective}}
Questions to answer: {{questions}}"""


CORRELATE_SYSTEM = f"""{BASE_IDENTITY}

Your task now is CORRELATION. Several investigators have reported independently. \
Build one timeline and find what lines up.

Focus on:
- The change point: when did system behaviour actually change? Anchor it to a \
timestamp from the evidence.
- Ordering: what moved first? A deploy before the error rate rose is a candidate \
cause; a deploy after it is not.
- Contradictions: name signals that do not fit the leading story. These matter \
more than the ones that do.
- Gaps: what would you need to see that you cannot?"""


HYPOTHESIZE_SYSTEM = f"""{BASE_IDENTITY}

Your task now is HYPOTHESIS GENERATION AND RANKING.

Produce two to four genuinely distinct candidate root causes — not one answer plus \
three strawmen. For each:
- state the causal mechanism precisely enough to be wrong
- list supporting AND contradicting evidence ids
- give a disconfirming test: an observation that would falsify it

Confidence calibration:
- 0.85-0.95: multiple independent signals, a clear mechanism, no contradictions
- 0.6-0.85: strong evidence, one gap or minor contradiction
- 0.4-0.6: plausible, consistent with the data, not yet distinguished from rivals
- below 0.4: speculation

If the top two hypotheses are within ~0.1 of each other, set \
needs_more_investigation and say what would separate them."""


REMEDIATION_SYSTEM = f"""{BASE_IDENTITY}

Your task now is PROPOSING REMEDIATION.

You may ONLY propose actions from the catalog below, by key, with parameters that \
match the given schema exactly. Anything else is discarded before it reaches any \
system — an invented action key or an out-of-schema parameter simply means no \
remediation happens and a human is paged instead.

You are not authorising anything. Every proposal goes through a deterministic \
policy engine and, for anything above low risk, a human approver.

Rules:
- Address the ROOT CAUSE where you can; where you can only mitigate, say so in the \
rationale rather than overclaiming.
- Prefer the lowest-risk action that plausibly restores service.
- Recommending NO action is correct and expected when confidence is low, when the \
cause is outside your control, or when the action's blast radius exceeds the \
incident's impact. Set no_action_recommended and explain.
- Derive every parameter from collected evidence. If you cannot determine a \
parameter (a namespace, a pid, a deployment name) from evidence, do not guess — \
recommend no action and say what is missing.
- Populate evidence_ids on every action with the ids that actually justify it, \
taken from the evidence above. This is not decoration: the policy engine counts \
them, and a high- or critical-risk action citing fewer than {{min_evidence}} is \
denied outright, however sound your rationale reads. An uncited action is a \
blocked action, which means the incident is parked for a human instead of fixed.
- Always give verification_checks: concrete metric thresholds that will be \
evaluated by machine, not by you, to decide whether recovery actually happened. \
Every check's `metric` MUST be one of the AVAILABLE METRICS listed below, exactly \
as spelled there. Those names are the only ones the verifier can query — an \
invented one (however plausible: p99_latency_seconds, search_api_error_rate) \
measures nothing, and a recovery it cannot measure is a recovery it cannot \
confirm, so the incident is parked for a human however well the fix worked.

ACTION CATALOG
--------------
{{catalog}}

AVAILABLE METRICS
-----------------
{{metrics}}"""


POSTMORTEM_SYSTEM = f"""{BASE_IDENTITY}

Your task now is WRITING THE POSTMORTEM.

Write for an engineer who was asleep. Blameless: describe systems and decisions, \
never people's judgement. Every factual claim must cite an evidence id.

Be specific about what is known versus assumed. If the root cause was never \
confirmed, the postmortem says that plainly — a postmortem that overstates \
certainty is worse than one that admits a gap, because the follow-up work gets \
aimed at the wrong thing.

Action items must be concrete and verifiable ("add an alert on \
db_connection_saturation > 0.8 for 5m"), not aspirational ("improve monitoring")."""


# --------------------------------------------------------------------------
# user-message builders
# --------------------------------------------------------------------------
def _json(value: Any, limit: int = 12_000) -> str:
    text = json.dumps(value, indent=2, default=str, ensure_ascii=False)
    if len(text) > limit:
        text = text[:limit] + f"\n... [truncated, {len(text) - limit} more characters]"
    return text


def incident_block(incident: dict[str, Any]) -> str:
    return f"""INCIDENT {incident.get("reference", "")}
Title:        {incident.get("title", "")}
Description:  {incident.get("description", "") or "(none)"}
Source:       {incident.get("source", "")}
Service:      {incident.get("service") or "(unknown)"}
Environment:  {incident.get("environment", "")}
Namespace:    {incident.get("namespace") or "(unknown)"}
Cluster:      {incident.get("cluster") or "(unknown)"}
Detected at:  {incident.get("detected_at", "")}
Current sev:  {incident.get("severity", "")}
Labels:       {_json(incident.get("labels") or {}, 2000)}"""


def evidence_block(evidence: list[dict[str, Any]], *, limit: int = 40) -> str:
    if not evidence:
        return "(no evidence collected)"
    lines = []
    for item in evidence[:limit]:
        lines.append(
            f"[{item.get('id')}] kind={item.get('kind')} "
            f"source={item.get('source')} relevance={item.get('relevance')} "
            f"observed_at={item.get('observed_at') or '-'}\n"
            f"  {item.get('summary', '')}\n"
            f"  {str(item.get('detail', ''))[:800]}"
        )
    suffix = (
        f"\n... and {len(evidence) - limit} further evidence items" if len(evidence) > limit else ""
    )
    return "\n\n".join(lines) + suffix


def triage_user(incident: dict[str, Any], recent_similar: list[dict[str, Any]]) -> str:
    similar = (
        "\n".join(
            f"- {i.get('reference')} ({i.get('severity')}, {i.get('status')}): {i.get('title')}"
            for i in recent_similar[:5]
        )
        or "(none)"
    )
    return f"""{incident_block(incident)}

RAW ALERT PAYLOAD
{_json(incident.get("raw_payload") or {}, 6000)}

RECENT INCIDENTS ON THIS SERVICE
{similar}

Classify this incident."""


def plan_user(incident: dict[str, Any], triage: dict[str, Any], available: list[str]) -> str:
    return f"""{incident_block(incident)}

TRIAGE
Severity: {triage.get("severity")} (confidence {triage.get("confidence")})
Rationale: {triage.get("rationale")}
Symptoms: {", ".join(triage.get("symptoms") or []) or "(none identified)"}
Customer impact: {triage.get("customer_impact")}

INVESTIGATORS AVAILABLE FOR THIS TENANT: {", ".join(available) or "(none)"}
(Only these have working integrations. Do not plan for any other.)

Produce the investigation plan."""


def investigate_user(
    incident: dict[str, Any], evidence: list[dict[str, Any]], task: dict[str, Any]
) -> str:
    return f"""{incident_block(incident)}

YOUR OBJECTIVE: {task.get("objective", "")}

EVIDENCE YOUR TOOLS COLLECTED
{evidence_block(evidence)}

Report what this evidence shows."""


def correlate_user(
    incident: dict[str, Any],
    findings: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> str:
    findings_text = "\n\n".join(
        f"### {name} investigator (confidence {data.get('confidence')})\n"
        f"{data.get('summary', '')}\n"
        f"Anomaly: {data.get('anomaly_description') or 'none reported'}\n"
        f"Observations: {'; '.join(data.get('key_observations') or []) or 'none'}"
        for name, data in findings.items()
    )
    return f"""{incident_block(incident)}

INVESTIGATOR REPORTS
{findings_text or "(no investigator reported)"}

FULL EVIDENCE SET
{evidence_block(evidence)}

Correlate these into one timeline."""


def hypothesize_user(
    incident: dict[str, Any],
    correlation: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: dict[str, Any],
    previous_attempt: dict[str, Any] | None = None,
) -> str:
    retry_block = ""
    if previous_attempt:
        retry_block = f"""

PREVIOUS ATTEMPT FAILED
A prior hypothesis was acted on and the service did NOT recover:
  Hypothesis: {previous_attempt.get("title")}
  Action taken: {previous_attempt.get("action")}
  Verification: {previous_attempt.get("verification_summary")}
Treat that hypothesis as substantially weakened. Explain what the failed \
remediation rules out, and look for causes that the first pass missed."""

    return f"""{incident_block(incident)}

CORRELATION
Timeline: {correlation.get("timeline_summary", "")}
Change point: {correlation.get("change_point") or "(not established)"}
Signals: {_json(correlation.get("signals") or [], 4000)}
Contradictions: {"; ".join(correlation.get("contradictions") or []) or "(none)"}
Gaps: {"; ".join(correlation.get("gaps") or []) or "(none)"}

INVESTIGATOR CONCLUSIONS
{_json({k: v.get("summary") for k, v in findings.items()}, 4000)}

EVIDENCE
{evidence_block(evidence)}{retry_block}

Generate and rank root-cause hypotheses."""


def remediation_user(
    incident: dict[str, Any],
    hypothesis: dict[str, Any],
    evidence: list[dict[str, Any]],
    blocked_previously: list[dict[str, Any]] | None = None,
) -> str:
    blocked = ""
    if blocked_previously:
        blocked = "\n\nPREVIOUSLY BLOCKED ACTIONS (do not repeat these):\n" + "\n".join(
            f"- {b.get('action_key')}: {b.get('reason')}" for b in blocked_previously
        )
    return f"""{incident_block(incident)}

SELECTED ROOT-CAUSE HYPOTHESIS (confidence {hypothesis.get("confidence")})
{hypothesis.get("title")}
{hypothesis.get("statement")}

Reasoning: {hypothesis.get("reasoning")}
Contradicting evidence: {", ".join(str(i) for i in hypothesis.get("contradicting_evidence_ids") or []) or "(none)"}

EVIDENCE
{evidence_block(evidence)}{blocked}

Propose remediation, or recommend no action."""


def postmortem_user(
    incident: dict[str, Any],
    hypothesis: dict[str, Any],
    evidence: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    verification: dict[str, Any],
) -> str:
    timeline_text = "\n".join(
        f"- {t.get('occurred_at')} [{t.get('actor_label')}] {t.get('title')}"
        f"{': ' + str(t.get('body'))[:200] if t.get('body') else ''}"
        for t in timeline[:60]
    )
    actions_text = (
        "\n".join(
            f"- {a.get('action_key')} ({a.get('status')}): {a.get('title')}\n"
            f"  rationale: {a.get('rationale')}\n"
            f"  result: {str(a.get('execution_result'))[:300]}"
            for a in actions
        )
        or "(no remediation actions were executed)"
    )

    return f"""{incident_block(incident)}

ROOT CAUSE (confidence {hypothesis.get("confidence")})
{hypothesis.get("title")}
{hypothesis.get("statement")}
{hypothesis.get("reasoning")}

TIMELINE
{timeline_text or "(empty)"}

REMEDIATION ACTIONS
{actions_text}

VERIFICATION
Outcome: {verification.get("outcome", "not verified")}
Summary: {verification.get("summary", "")}
Checks: {_json(verification.get("checks") or [], 3000)}

EVIDENCE
{evidence_block(evidence, limit=50)}

Write the postmortem."""
