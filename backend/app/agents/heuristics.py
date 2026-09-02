"""Offline reasoning engine used when ``LLM_PROVIDER=fake``.

This is not a stub that returns fixtures. It reads the same evidence the real
model reads and applies a documented set of SRE heuristics: score the incident
against known failure signatures, pick the best-supported signature, and derive
a hypothesis and a remediation from it. Everything downstream — the catalog
lookup, the policy engine, approvals, execution, verification, the postmortem —
then runs for real.

That makes the whole product exercisable, and testable, without an API key. What
it deliberately cannot do is generalise past its signature table; the eval suite
(``app/evals``) reports fake-vs-live scores side by side so the gap is visible
rather than hidden.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class Signature:
    """A known failure mode and how to recognise it."""

    key: str
    title: str
    category: str
    # (regex, weight) pairs matched against evidence summaries and details.
    patterns: list[tuple[str, float]]
    # Metric conditions: (metric name substring, comparator, threshold, weight).
    metric_rules: list[tuple[str, str, float, float]] = field(default_factory=list)
    statement: str = ""
    remediation_action: str | None = None
    remediation_rationale: str = ""
    expected_effect: str = ""
    verification: list[dict[str, Any]] = field(default_factory=list)
    severity_floor: str = "sev3"
    disconfirming_test: str = ""


SIGNATURES: list[Signature] = [
    Signature(
        key="db_connection_exhaustion",
        title="Database connection pool exhausted by leaked transactions",
        category="resource_exhaustion",
        patterns=[
            (r"too many connections|connection pool|pool exhaust|remaining connection slots", 3.0),
            (r"idle in transaction", 3.0),
            (r"could not obtain a connection|timeout acquiring connection", 2.5),
            (r"FATAL:\s+sorry, too many clients", 3.0),
            (r"psycopg|asyncpg|sqlalchemy.*pool", 1.0),
        ],
        metric_rules=[
            ("db_connection_saturation", "gte", 0.9, 3.0),
            ("db_connections", "gte", 90, 1.5),
        ],
        statement=(
            "A code path is opening transactions and not committing or rolling them back, so "
            "backends accumulate in 'idle in transaction' until the connection pool is "
            "exhausted and every new request fails to acquire a connection."
        ),
        remediation_action="db.terminate_idle_connections",
        remediation_rationale=(
            "Terminating the leaked idle-in-transaction backends immediately frees pool "
            "capacity and restores service while the leaking code path is fixed properly."
        ),
        expected_effect=(
            "Connection saturation drops below 70% within a minute and the error rate returns "
            "to baseline."
        ),
        verification=[
            {
                "name": "connection saturation recovered",
                "metric": "db_connection_saturation",
                "comparator": "lt",
                "threshold": 0.7,
            },
            {
                "name": "error rate recovered",
                "metric": "error_rate",
                "comparator": "lt",
                "threshold": 0.02,
            },
        ],
        severity_floor="sev1",
        disconfirming_test=(
            "If pg_stat_activity shows few idle-in-transaction backends and saturation is low, "
            "the pool is not the constraint."
        ),
    ),
    Signature(
        key="memory_leak",
        title="Memory leak driving OOMKill restarts",
        category="resource_exhaustion",
        patterns=[
            (r"OOMKilled|out of memory|OutOfMemory", 3.5),
            (r"exit code 137", 3.0),
            (r"memory (usage|working set) (climb|grow|increas)", 2.0),
            (r"container restart|CrashLoopBackOff", 1.0),
        ],
        metric_rules=[
            ("memory_limit_ratio", "gte", 0.9, 3.0),
            ("memory_usage", "gte", 0.0, 0.5),
            ("pod_restarts", "gte", 3, 2.0),
        ],
        statement=(
            "Working-set memory grows monotonically after each deploy without plateauing, "
            "reaching the container limit and triggering OOMKill; the kubelet restarts the "
            "container, the cycle repeats, and capacity is lost each time."
        ),
        remediation_action="k8s.rollout_restart",
        remediation_rationale=(
            "A rolling restart resets the leaked heap across all replicas and buys time; it is "
            "a mitigation, not a fix — the leak itself needs a code change."
        ),
        expected_effect=(
            "Memory-to-limit ratio drops back to its post-start baseline and OOMKill restarts stop."
        ),
        verification=[
            {
                "name": "memory below limit",
                "metric": "memory_limit_ratio",
                "comparator": "lt",
                "threshold": 0.75,
            },
            {
                "name": "restarts stopped",
                "metric": "pod_restarts",
                "comparator": "lt",
                "threshold": 1,
            },
        ],
        severity_floor="sev2",
        disconfirming_test=(
            "If memory plateaus well below the limit and restarts have a non-OOM reason, this "
            "is not a leak."
        ),
    ),
    Signature(
        key="bad_deployment",
        title="Recent deployment introduced the regression",
        category="deployment",
        patterns=[
            (r"deploy(ed|ment)?\s+(at|completed|rolled out)", 2.0),
            (r"new revision|revision \d+|image tag", 1.5),
            (r"NullPointer|TypeError|AttributeError|panic:|unhandled exception", 2.0),
            (r"500 Internal Server Error|5xx", 1.5),
            (r"rollout|ReplicaSet", 1.0),
        ],
        metric_rules=[("error_rate", "gte", 0.05, 3.0)],
        statement=(
            "The error rate steps up sharply at the moment a new revision finished rolling out, "
            "with no corresponding change in traffic — the change itself, not load, is the cause."
        ),
        remediation_action="k8s.rollback_deployment",
        remediation_rationale=(
            "Rolling back to the last known-good revision is the fastest way to restore service; "
            "the suspect change can then be debugged off the critical path."
        ),
        expected_effect="Error rate returns to its pre-deploy baseline within one rollout period.",
        verification=[
            {
                "name": "error rate recovered",
                "metric": "error_rate",
                "comparator": "lt",
                "threshold": 0.02,
            },
            {
                "name": "latency recovered",
                "metric": "latency_p99",
                "comparator": "lt",
                "threshold": 1.0,
            },
        ],
        severity_floor="sev2",
        disconfirming_test=(
            "If the error rate rose measurably before the rollout completed, the deploy is "
            "correlated but not causal."
        ),
    ),
    Signature(
        key="latency_saturation",
        title="Capacity saturation causing latency spike",
        category="capacity",
        patterns=[
            (r"timeout|deadline exceeded|context canceled", 2.0),
            (r"queue depth|backlog|saturat", 2.5),
            (r"throttl|rate limit|429", 1.5),
            (r"cpu (throttl|pressure)", 2.0),
        ],
        metric_rules=[
            ("latency_p99", "gte", 1.0, 3.0),
            ("cpu_usage", "gte", 0.8, 2.0),
            ("request_rate", "gte", 0.0, 0.5),
        ],
        statement=(
            "Request rate rose beyond what the current replica count can serve; queueing pushes "
            "tail latency up while the error rate stays comparatively low, which is the "
            "signature of saturation rather than failure."
        ),
        remediation_action="k8s.scale_deployment",
        remediation_rationale=(
            "Adding replicas restores headroom immediately. Latency, not errors, is the "
            "presenting symptom, so capacity is the constraint."
        ),
        expected_effect="p99 latency falls back under its SLO and queue depth drains.",
        verification=[
            {
                "name": "p99 latency recovered",
                "metric": "latency_p99",
                "comparator": "lt",
                "threshold": 1.0,
            },
            {
                "name": "error rate healthy",
                "metric": "error_rate",
                "comparator": "lt",
                "threshold": 0.02,
            },
        ],
        severity_floor="sev2",
        disconfirming_test=(
            "If latency is high while request rate is flat or falling, the bottleneck is "
            "downstream, not capacity."
        ),
    ),
    Signature(
        key="node_failure",
        title="Unhealthy node degrading the pods scheduled on it",
        category="infrastructure",
        patterns=[
            (r"NodeNotReady|node.*not ready|kubelet.*stopped", 3.5),
            (r"DiskPressure|MemoryPressure|PIDPressure", 3.0),
            (r"FailedScheduling|Insufficient (cpu|memory)", 2.0),
            (r"network unreachable|connection refused.*node", 1.5),
        ],
        metric_rules=[("pod_restarts", "gte", 5, 1.5)],
        statement=(
            "A single node reports a pressure or NotReady condition and every failing pod is "
            "scheduled on it, while identical pods on other nodes are healthy — the fault is "
            "the node, not the workload."
        ),
        remediation_action="k8s.cordon_node",
        remediation_rationale=(
            "Cordoning stops new pods landing on the bad node; draining then moves the affected "
            "workload onto healthy capacity."
        ),
        expected_effect="Affected pods reschedule onto healthy nodes and stop restarting.",
        verification=[
            {
                "name": "restarts stopped",
                "metric": "pod_restarts",
                "comparator": "lt",
                "threshold": 1,
            },
            {
                "name": "error rate recovered",
                "metric": "error_rate",
                "comparator": "lt",
                "threshold": 0.02,
            },
        ],
        severity_floor="sev2",
        disconfirming_test=(
            "If failing pods are spread across several nodes, a single node is not the cause."
        ),
    ),
    Signature(
        key="dependency_failure",
        title="Upstream dependency failing",
        category="dependency_failure",
        patterns=[
            (r"upstream|downstream (service|dependency)", 2.0),
            (r"connection refused|ECONNREFUSED|no route to host", 2.5),
            (r"circuit breaker|fallback triggered", 2.5),
            (r"DNS|resolve.*failed|NXDOMAIN", 2.0),
            (r"502 Bad Gateway|503 Service Unavailable", 2.0),
        ],
        metric_rules=[("error_rate", "gte", 0.1, 1.5)],
        statement=(
            "Failures concentrate on calls to one dependency while the service's own resources "
            "are healthy, so the fault originates outside this service."
        ),
        remediation_action=None,
        remediation_rationale="",
        expected_effect="",
        verification=[
            {
                "name": "error rate recovered",
                "metric": "error_rate",
                "comparator": "lt",
                "threshold": 0.02,
            }
        ],
        severity_floor="sev2",
        disconfirming_test=(
            "If the dependency's own dashboards are green, the failure is in this service's "
            "client configuration instead."
        ),
    ),
]

SEVERITY_ORDER = ["sev5", "sev4", "sev3", "sev2", "sev1"]

# Which investigators are worth running for which signature-ish keywords.
INVESTIGATOR_HINTS: dict[str, list[str]] = {
    "database": ["connection", "postgres", "query", "deadlock", "transaction", "pool", "sql"],
    "deployments": ["deploy", "release", "rollout", "revision", "commit", "version", "regression"],
    "metrics": [
        "latency",
        "cpu",
        "memory",
        "throughput",
        "saturation",
        "slow",
        "spike",
        "error rate",
    ],
    "logs": ["error", "exception", "trace", "panic", "crash", "oom", "timeout"],
    "history": ["again", "recurring", "similar", "last time", "previously"],
}


@dataclass(slots=True)
class Score:
    signature: Signature
    score: float
    matched_evidence: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


class HeuristicEngine:
    """Deterministic reasoning over collected evidence."""

    def respond(
        self, *, schema: type[BaseModel], purpose: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        handler = {
            "triage": self._triage,
            "plan": self._plan,
            "investigate": self._finding,
            "correlate": self._correlate,
            "hypothesize": self._hypothesize,
            "propose_remediation": self._propose,
            "postmortem": self._postmortem,
        }.get(purpose.split(".")[0])

        if handler is None:  # pragma: no cover - every purpose is mapped
            raise ValueError(f"heuristic engine has no handler for purpose '{purpose}'")
        return handler(context)

    # ------------------------------------------------------------------ scoring
    def _score_signatures(self, context: dict[str, Any]) -> list[Score]:
        evidence = context.get("evidence") or []
        text_blobs: list[tuple[str, str]] = []
        for item in evidence:
            blob = " ".join(
                str(item.get(field, "")) for field in ("summary", "detail", "source_ref")
            )
            raw = item.get("raw")
            if isinstance(raw, dict):
                blob += " " + _flatten(raw)
            text_blobs.append((str(item.get("id", "")), blob))

        incident = context.get("incident") or {}
        incident_text = " ".join(str(incident.get(field, "")) for field in ("title", "description"))
        text_blobs.append(("__incident__", incident_text))

        metrics = _metric_index(evidence)

        scores: list[Score] = []
        for signature in SIGNATURES:
            total = 0.0
            matched: list[str] = []
            reasons: list[str] = []

            for pattern, weight in signature.patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                for evidence_id, blob in text_blobs:
                    if regex.search(blob):
                        total += weight
                        if evidence_id != "__incident__" and evidence_id not in matched:
                            matched.append(evidence_id)
                        reasons.append(f"matched /{pattern}/")
                        break

            for metric_name, comparator, threshold, weight in signature.metric_rules:
                observed = _lookup_metric(metrics, metric_name)
                if observed is None:
                    continue
                value, evidence_id = observed
                if _compare(value, comparator, threshold):
                    total += weight
                    if evidence_id and evidence_id not in matched:
                        matched.append(evidence_id)
                    reasons.append(f"{metric_name}={value:.4g} {comparator} {threshold:g}")

            if total > 0:
                scores.append(Score(signature, total, matched, reasons))

        scores.sort(key=lambda s: s.score, reverse=True)
        return scores

    # ------------------------------------------------------------------- triage
    def _triage(self, context: dict[str, Any]) -> dict[str, Any]:
        incident = context.get("incident") or {}
        text = f"{incident.get('title', '')} {incident.get('description', '')}".lower()
        labels = {k.lower(): str(v).lower() for k, v in (incident.get("labels") or {}).items()}

        severity = "sev3"
        rationale_parts: list[str] = []

        # An alert that already carries a severity label is authoritative input.
        label_sev = labels.get("severity") or labels.get("priority") or ""
        mapping = {
            "critical": "sev1",
            "page": "sev1",
            "p1": "sev1",
            "high": "sev2",
            "error": "sev2",
            "p2": "sev2",
            "warning": "sev3",
            "p3": "sev3",
            "info": "sev4",
            "low": "sev4",
        }
        if label_sev in mapping:
            severity = mapping[label_sev]
            rationale_parts.append(f"alert carries severity label '{label_sev}'")

        outage_terms = [
            "outage",
            "down",
            "unavailable",
            "all requests",
            "total failure",
            "data loss",
        ]
        major_terms = [
            "error rate",
            "5xx",
            "elevated",
            "degraded",
            "timeout",
            "oomkill",
            "crashloop",
        ]
        if any(term in text for term in outage_terms):
            severity = "sev1"
            rationale_parts.append("wording indicates a full or near-full outage")
        elif any(term in text for term in major_terms) and severity not in ("sev1",):
            severity = _max_severity(severity, "sev2")
            rationale_parts.append("customer-visible degradation is described")

        if incident.get("environment") not in (None, "production"):
            severity = _min_severity(severity, "sev3")
            rationale_parts.append(f"non-production environment ({incident.get('environment')})")

        scores = self._score_signatures(context)
        if scores:
            severity = _max_severity(severity, scores[0].signature.severity_floor)
            rationale_parts.append(f"symptoms resemble '{scores[0].signature.title}'")

        symptoms = _extract_symptoms(text)
        return {
            "severity": severity,
            "confidence": 0.72 if scores else 0.5,
            "rationale": "; ".join(rationale_parts)
            or "no strong severity signal; defaulting to sev3",
            "likely_service": incident.get("service"),
            "customer_impact": (
                "Requests to this service are failing or slow for end users"
                if severity in ("sev1", "sev2")
                else "Limited or internal-only impact"
            ),
            "symptoms": symptoms,
            "is_duplicate_of": None,
            "urgency_reason": rationale_parts[0] if rationale_parts else "",
        }

    # --------------------------------------------------------------------- plan
    def _plan(self, context: dict[str, Any]) -> dict[str, Any]:
        incident = context.get("incident") or {}
        text = f"{incident.get('title', '')} {incident.get('description', '')}".lower()
        available = set(context.get("available_investigators") or [])

        chosen: list[tuple[str, int]] = []
        for investigator, keywords in INVESTIGATOR_HINTS.items():
            if available and investigator not in available:
                continue
            hits = sum(1 for keyword in keywords if keyword in text)
            # logs and metrics are always worth running; the rest need a signal.
            priority = 1 if investigator in ("logs", "metrics") else (2 if hits else 4)
            if investigator in ("logs", "metrics") or hits:
                chosen.append((investigator, priority))

        if not chosen:
            chosen = [("logs", 1), ("metrics", 1)]
        # Always look for a recent deploy: it is the single highest-prior cause.
        if not any(c[0] == "deployments" for c in chosen) and (
            not available or "deployments" in available
        ):
            chosen.append(("deployments", 2))
        if not any(c[0] == "history" for c in chosen) and (not available or "history" in available):
            chosen.append(("history", 4))

        chosen.sort(key=lambda c: c[1])
        objectives = {
            "logs": "Find error signatures, stack traces and their onset time",
            "metrics": "Establish when behaviour changed and which golden signal moved first",
            "database": "Check connection saturation, blocking locks and long-running queries",
            "deployments": "Identify deploys and merged changes in the incident window",
            "history": "Find previously resolved incidents with the same signature",
        }
        return {
            "summary": (
                f"Investigate {incident.get('service') or 'the affected service'} across "
                f"{len(chosen)} parallel tracks, anchored on when the change occurred."
            ),
            "tasks": [
                {
                    "investigator": name,
                    "objective": objectives.get(name, "Collect relevant evidence"),
                    "questions": _questions_for(name, incident),
                    "priority": priority,
                }
                for name, priority in chosen[:5]
            ],
            "time_window_minutes": 120,
            "target_service": incident.get("service"),
            "target_namespace": incident.get("namespace"),
            "initial_suspicions": [s.signature.title for s in self._score_signatures(context)[:3]],
        }

    # ------------------------------------------------------------------ finding
    def _finding(self, context: dict[str, Any]) -> dict[str, Any]:
        evidence = context.get("evidence") or []
        investigator = context.get("investigator", "unknown")
        scores = self._score_signatures(context)

        if not evidence:
            return {
                "summary": f"The {investigator} investigator collected no usable evidence.",
                "key_observations": [],
                "cited_evidence_ids": [],
                "anomaly_detected": False,
                "anomaly_description": "",
                "confidence": 0.1,
                "suggests_root_cause": None,
                "dead_end": True,
            }

        top = scores[0] if scores else None
        observations = [
            str(item.get("summary", ""))[:200] for item in evidence[:6] if item.get("summary")
        ]
        anomalies = [
            item for item in evidence if str(item.get("relevance")) in ("critical", "high")
        ]
        return {
            "summary": (
                f"The {investigator} investigator collected {len(evidence)} evidence items. "
                + (
                    f"The strongest pattern is '{top.signature.title}' "
                    f"({', '.join(top.reasons[:3])})."
                    if top
                    else "No known failure signature matched."
                )
            ),
            "key_observations": observations,
            "cited_evidence_ids": [str(i.get("id")) for i in evidence[:15] if i.get("id")],
            "anomaly_detected": bool(anomalies or top),
            "anomaly_description": (
                anomalies[0].get("summary", "")[:500]
                if anomalies
                else (top.signature.title if top else "")
            ),
            "confidence": min(0.9, 0.35 + 0.1 * len(anomalies) + (0.15 if top else 0)),
            "suggests_root_cause": top.signature.title if top and top.score >= 3 else None,
            "dead_end": not anomalies and not top,
        }

    # ---------------------------------------------------------------- correlate
    def _correlate(self, context: dict[str, Any]) -> dict[str, Any]:
        evidence = context.get("evidence") or []
        scores = self._score_signatures(context)
        deploys = [e for e in evidence if str(e.get("kind")) in ("deployment", "commit")]
        change_point = None
        if deploys:
            newest = max(deploys, key=lambda e: str(e.get("observed_at") or ""))
            change_point = f"{newest.get('observed_at')} — {str(newest.get('summary'))[:150]}"

        signals = []
        for score in scores[:4]:
            signals.append(
                {
                    "description": f"{score.signature.title} ({'; '.join(score.reasons[:3])})",
                    "evidence_ids": score.matched_evidence[:10],
                    "signal_type": "causal" if score.score >= 4 else "pattern",
                    "strength": min(0.95, score.score / 8.0),
                }
            )

        contradictions: list[str] = []
        if len(scores) >= 2 and abs(scores[0].score - scores[1].score) < 1.0:
            contradictions.append(
                f"'{scores[0].signature.title}' and '{scores[1].signature.title}' are "
                f"supported almost equally; the evidence does not yet separate them."
            )

        gaps: list[str] = []
        kinds = {str(e.get("kind")) for e in evidence}
        for kind, gap in (
            (
                "metric_series",
                "no metric series were collected, so the change point is inferred from logs alone",
            ),
            ("deployment", "no deployment history was available for the incident window"),
            ("db_health", "database health was not sampled"),
        ):
            if kind not in kinds:
                gaps.append(gap)

        return {
            "timeline_summary": (
                f"Collected {len(evidence)} evidence items across "
                f"{len({str(e.get('investigator')) for e in evidence})} investigators. "
                + (f"The clearest change point is {change_point}. " if change_point else "")
                + (
                    f"Signals point most strongly at {scores[0].signature.title}."
                    if scores
                    else "No known signature dominates."
                )
            ),
            "change_point": change_point,
            "signals": signals,
            "contradictions": contradictions,
            "gaps": gaps,
        }

    # -------------------------------------------------------------- hypothesize
    def _hypothesize(self, context: dict[str, Any]) -> dict[str, Any]:
        scores = self._score_signatures(context)
        evidence = context.get("evidence") or []

        if not scores:
            return {
                "hypotheses": [
                    {
                        "title": "Root cause not determined from available evidence",
                        "statement": (
                            "The collected evidence does not match a known failure signature. "
                            "Further investigation, or a human with service context, is needed."
                        ),
                        "category": "unknown",
                        "confidence": 0.15,
                        "supporting_evidence_ids": [
                            str(e.get("id")) for e in evidence[:5] if e.get("id")
                        ],
                        "contradicting_evidence_ids": [],
                        "reasoning": "No signature scored above zero against the evidence.",
                        "disconfirming_test": "",
                    }
                ],
                "selected_index": 0,
                "selection_reasoning": "Only one candidate; confidence is deliberately low.",
                "needs_more_investigation": True,
                "additional_questions": [
                    "Which downstream dependency changed in the incident window?",
                    "Are other services in the same namespace also degraded?",
                ],
            }

        total = sum(s.score for s in scores) or 1.0
        hypotheses = []
        for score in scores[:4]:
            # Confidence blends relative share with absolute evidential strength,
            # so a single weak match never reads as high confidence.
            share = score.score / total
            absolute = min(1.0, score.score / 7.0)
            confidence = round(min(0.95, 0.6 * share + 0.4 * absolute), 3)
            contradicting = [
                e_id
                for other in scores[1:3]
                for e_id in other.matched_evidence
                if other is not score and e_id not in score.matched_evidence
            ][:5]
            hypotheses.append(
                {
                    "title": score.signature.title,
                    "statement": score.signature.statement,
                    "category": score.signature.category,
                    "confidence": confidence,
                    "supporting_evidence_ids": score.matched_evidence[:20],
                    "contradicting_evidence_ids": contradicting,
                    "reasoning": (
                        f"Signature '{score.signature.key}' scored {score.score:.1f} on: "
                        + "; ".join(score.reasons[:5])
                    ),
                    "disconfirming_test": score.signature.disconfirming_test,
                }
            )

        top_confidence = hypotheses[0]["confidence"]
        return {
            "hypotheses": hypotheses,
            "selected_index": 0,
            "selection_reasoning": (
                f"'{hypotheses[0]['title']}' has the strongest evidential support "
                f"({scores[0].score:.1f} vs "
                f"{scores[1].score:.1f} for the runner-up)."
                if len(scores) > 1
                else f"'{hypotheses[0]['title']}' is the only supported signature."
            ),
            "needs_more_investigation": top_confidence < 0.5,
            "additional_questions": (
                ["What changed in the dependency graph during the incident window?"]
                if top_confidence < 0.5
                else []
            ),
        }

    # ------------------------------------------------------------------ propose
    def _propose(self, context: dict[str, Any]) -> dict[str, Any]:
        hypothesis = context.get("selected_hypothesis") or {}
        catalog: list[str] = list(context.get("available_action_keys") or [])
        incident = context.get("incident") or {}
        evidence = context.get("evidence") or []

        signature = next((s for s in SIGNATURES if s.title == hypothesis.get("title")), None)
        confidence = float(hypothesis.get("confidence") or 0)

        if signature is None or signature.remediation_action is None:
            return {
                "actions": [],
                "no_action_recommended": True,
                "no_action_reason": (
                    "The root cause is outside this service's control, or is not confidently "
                    "identified. Automated remediation would be guessing."
                ),
                "verification_plan": "Monitor error rate and latency; escalate to a human owner.",
                "verification_checks": (signature.verification if signature else []),
                "rollback_plan": "",
            }

        action_key = signature.remediation_action
        if catalog and action_key not in catalog:
            return {
                "actions": [],
                "no_action_recommended": True,
                "no_action_reason": (
                    f"The indicated remediation ('{action_key}') is not available in this "
                    f"organisation's action catalog."
                ),
                "verification_plan": "Escalate to a human responder.",
                "verification_checks": signature.verification,
                "rollback_plan": "",
            }

        params = _params_for(action_key, incident, context)
        if params is None:
            return {
                "actions": [],
                "no_action_recommended": True,
                "no_action_reason": (
                    f"Could not determine safe parameters for '{action_key}' from the evidence "
                    f"(missing namespace, deployment or database identifiers)."
                ),
                "verification_plan": "Escalate to a human responder.",
                "verification_checks": signature.verification,
                "rollback_plan": "",
            }

        return {
            "actions": [
                {
                    "action_key": action_key,
                    "params": params,
                    "rationale": signature.remediation_rationale,
                    "expected_effect": signature.expected_effect,
                    "evidence_ids": [
                        str(e_id) for e_id in (hypothesis.get("supporting_evidence_ids") or [])
                    ][:10]
                    or [str(e.get("id")) for e in evidence[:3] if e.get("id")],
                    "sequence": 0,
                    "urgency": "immediate" if confidence >= 0.7 else "soon",
                }
            ],
            "no_action_recommended": False,
            "no_action_reason": "",
            "verification_plan": signature.expected_effect,
            "verification_checks": signature.verification,
            "rollback_plan": (
                "If the action does not improve the signals within one verification window, "
                "restore the pre-action state and escalate."
            ),
        }

    # --------------------------------------------------------------- postmortem
    def _postmortem(self, context: dict[str, Any]) -> dict[str, Any]:
        incident = context.get("incident") or {}
        hypothesis = context.get("selected_hypothesis") or {}
        evidence = context.get("evidence") or []
        actions = context.get("actions") or []
        verification = context.get("verification") or {}

        executed = [a for a in actions if str(a.get("status")) == "succeeded"]
        cited = [str(e.get("id")) for e in evidence[:30] if e.get("id")]
        signature = next((s for s in SIGNATURES if s.title == hypothesis.get("title")), None)

        resolution = (
            "; ".join(f"{a.get('title')} ({a.get('action_key')})" for a in executed)
            if executed
            else "No automated remediation was executed; the incident was resolved by other means."
        )

        return {
            "title": f"{incident.get('reference', 'Incident')}: {incident.get('title', '')}"[:300],
            "summary": (
                f"{incident.get('title', 'An incident')} affected "
                f"{incident.get('service') or 'the platform'} in "
                f"{incident.get('environment', 'production')}. "
                f"{hypothesis.get('statement', 'The root cause was not established.')}"
            ),
            "impact": (
                f"Severity {str(incident.get('severity', '')).upper()}. "
                f"{context.get('customer_impact') or 'Impact scope was not quantified.'}"
            ),
            "root_cause": hypothesis.get("statement") or "Root cause was not established.",
            "detection": (
                f"Detected via {incident.get('source', 'an alert')} at "
                f"{incident.get('detected_at', 'an unrecorded time')}."
            ),
            "resolution": resolution,
            "lessons_learned": ((signature.disconfirming_test + " ") if signature else "")
            + (
                "Recovery was verified against explicit metric thresholds."
                if verification.get("outcome") == "recovered"
                else "Recovery could not be confirmed automatically and needed human judgement."
            ),
            "contributing_factors": list(context.get("gaps") or [])[:8],
            "action_items": _action_items_for(signature, incident),
            "cited_evidence_ids": cited,
            "what_went_well": [
                "Investigation ran in parallel across logs, metrics and deploys",
                "Every remediation passed deterministic policy checks before execution",
            ],
            "what_went_poorly": (
                [str(g) for g in (context.get("gaps") or [])[:3]]
                or ["Detection relied on a symptom alert rather than a leading indicator"]
            ),
        }


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _flatten(data: Any, depth: int = 0) -> str:
    if depth > 3:
        return ""
    if isinstance(data, dict):
        return " ".join(f"{k} {_flatten(v, depth + 1)}" for k, v in list(data.items())[:40])
    if isinstance(data, (list, tuple)):
        return " ".join(_flatten(v, depth + 1) for v in list(data)[:40])
    return str(data)[:500]


def _metric_index(evidence: list[dict[str, Any]]) -> dict[str, tuple[float, str]]:
    """Map metric name -> (latest value, evidence id) from metric_series evidence."""
    index: dict[str, tuple[float, str]] = {}
    for item in evidence:
        if str(item.get("kind")) != "metric_series":
            continue
        raw = item.get("raw") or {}
        name = str(raw.get("name") or item.get("source_ref") or "")
        value = raw.get("last")
        if value is None:
            series = raw.get("series") or []
            if series and isinstance(series[0], dict):
                value = series[0].get("last")
        if name and isinstance(value, (int, float)):
            index[name] = (float(value), str(item.get("id", "")))
    return index


def _lookup_metric(metrics: dict[str, tuple[float, str]], name: str) -> tuple[float, str] | None:
    if name in metrics:
        return metrics[name]
    for key, value in metrics.items():
        if name in key or key in name:
            return value
    return None


def _compare(value: float, comparator: str, threshold: float) -> bool:
    return {
        "lt": value < threshold,
        "lte": value <= threshold,
        "gt": value > threshold,
        "gte": value >= threshold,
    }[comparator]


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def _min_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) <= SEVERITY_ORDER.index(b) else b


def _extract_symptoms(text: str) -> list[str]:
    symptoms = []
    checks = [
        ("elevated error rate", ["error rate", "5xx", "500s", "errors"]),
        ("increased latency", ["latency", "slow", "p99", "timeout"]),
        ("pods restarting", ["crashloop", "restart", "oomkill"]),
        ("connection failures", ["connection", "refused", "pool"]),
        ("service unavailable", ["down", "unavailable", "outage"]),
    ]
    for label, needles in checks:
        if any(needle in text for needle in needles):
            symptoms.append(label)
    return symptoms[:10]


def _questions_for(investigator: str, incident: dict[str, Any]) -> list[str]:
    service = incident.get("service") or "the service"
    return {
        "logs": [
            f"What error signatures appear in {service}'s logs in the incident window?",
            "When does the first occurrence of the dominant error appear?",
        ],
        "metrics": [
            "Which golden signal moved first, and at what time?",
            "Did request rate change, or only error rate and latency?",
        ],
        "database": [
            "Is connection saturation above 90%?",
            "Are there blocking locks or long-running queries?",
        ],
        "deployments": [
            f"Was {service} deployed in the last two hours?",
            "Does the deploy time line up with the metric change point?",
        ],
        "history": [
            "Has this signature been seen and resolved before?",
            "What fixed it last time?",
        ],
    }.get(investigator, [])


def _params_for(
    action_key: str, incident: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any] | None:
    """Derive concrete, schema-valid parameters from the incident and evidence.

    Returns ``None`` rather than guessing when a required identifier is missing —
    a proposal with fabricated parameters would be rejected by the catalog anyway,
    and refusing here produces a much clearer message for the responder.
    """
    namespace = incident.get("namespace")
    service = incident.get("service")
    evidence = context.get("evidence") or []

    if action_key == "db.terminate_idle_connections":
        database = _find_database(evidence) or incident.get("labels", {}).get("database")
        if not database:
            return None
        return {"database": database, "idle_seconds": 300, "max_terminations": 25}

    if action_key in ("k8s.rollout_restart", "k8s.rollback_deployment"):
        deployment = _find_deployment(evidence) or service
        if not namespace or not deployment:
            return None
        params: dict[str, Any] = {"namespace": namespace, "deployment": deployment}
        if action_key == "k8s.rollback_deployment":
            params["to_revision"] = None
        return params

    if action_key == "k8s.scale_deployment":
        deployment = _find_deployment(evidence) or service
        current = _find_current_replicas(evidence)
        if not namespace or not deployment or current is None:
            return None
        # Scale by 50%, at least +2, capped so the policy engine's delta limit is
        # respected rather than tripped.
        target = min(current + max(2, current // 2), current + 8)
        return {"namespace": namespace, "deployment": deployment, "replicas": target}

    if action_key == "k8s.cordon_node":
        node = _find_unhealthy_node(evidence)
        if not node:
            return None
        return {"node_name": node, "drain": False}

    if action_key == "k8s.restart_pod":
        pod = _find_failing_pod(evidence)
        if not namespace or not pod:
            return None
        return {"namespace": namespace, "pod_name": pod}

    return None


def _find_database(evidence: list[dict[str, Any]]) -> str | None:
    for item in evidence:
        raw = item.get("raw") or {}
        for candidate in (
            raw.get("database"),
            (raw.get("connections") or {}).get("database")
            if isinstance(raw.get("connections"), dict)
            else None,
        ):
            if candidate:
                return str(candidate)
    return None


def _find_deployment(evidence: list[dict[str, Any]]) -> str | None:
    for item in evidence:
        raw = item.get("raw") or {}
        if raw.get("deployment"):
            return str(raw["deployment"])
        if str(item.get("kind")) == "deployment" and raw.get("name"):
            return str(raw["name"])
    return None


def _find_current_replicas(evidence: list[dict[str, Any]]) -> int | None:
    for item in evidence:
        raw = item.get("raw") or {}
        value = raw.get("replicas")
        if isinstance(value, int):
            return value
    return None


def _find_unhealthy_node(evidence: list[dict[str, Any]]) -> str | None:
    for item in evidence:
        raw = item.get("raw") or {}
        conditions = raw.get("conditions") or {}
        if isinstance(conditions, dict) and (
            conditions.get("Ready") == "False"
            or conditions.get("MemoryPressure") == "True"
            or conditions.get("DiskPressure") == "True"
        ):
            name = raw.get("name")
            if name:
                return str(name)
        if raw.get("unhealthy_node"):
            return str(raw["unhealthy_node"])
    return None


def _find_failing_pod(evidence: list[dict[str, Any]]) -> str | None:
    for item in evidence:
        raw = item.get("raw") or {}
        if raw.get("pod"):
            return str(raw["pod"])
        if raw.get("phase") in ("Failed", "CrashLoopBackOff") and raw.get("name"):
            return str(raw["name"])
    return None


def _action_items_for(
    signature: Signature | None, incident: dict[str, Any]
) -> list[dict[str, Any]]:
    service = incident.get("service") or "the service"
    generic = [
        {
            "title": f"Add a leading-indicator alert for {service} so this is caught before impact",
            "owner_hint": "service owner",
            "priority": "p2",
            "rationale": "Detection came from a symptom alert, which means impact had already started.",
        }
    ]
    if signature is None:
        return generic

    specific = {
        "db_connection_exhaustion": [
            {
                "title": "Fix the code path leaking transactions",
                "owner_hint": "service owner",
                "priority": "p0",
                "rationale": "Terminating backends is mitigation; the leak recurs until the code is fixed.",
            },
            {
                "title": "Add a statement/idle-in-transaction timeout on the connection pool",
                "owner_hint": "platform",
                "priority": "p1",
                "rationale": "A timeout converts a silent leak into a bounded, self-healing failure.",
            },
        ],
        "memory_leak": [
            {
                "title": "Profile the heap and fix the leak",
                "owner_hint": "service owner",
                "priority": "p0",
                "rationale": "Rolling restarts only reset the clock on the leak.",
            },
            {
                "title": "Alert on memory-to-limit ratio trend, not just OOMKill events",
                "owner_hint": "platform",
                "priority": "p2",
                "rationale": "The ratio climbs for a long time before the first kill.",
            },
        ],
        "bad_deployment": [
            {
                "title": "Add automated canary analysis to the deploy pipeline",
                "owner_hint": "platform",
                "priority": "p1",
                "rationale": "The regression reached 100% of traffic before anyone noticed.",
            },
            {
                "title": "Add a regression test covering the failing path",
                "owner_hint": "service owner",
                "priority": "p1",
                "rationale": "The change shipped without a test that would have caught it.",
            },
        ],
        "latency_saturation": [
            {
                "title": "Review HPA thresholds and minimum replica count",
                "owner_hint": "service owner",
                "priority": "p1",
                "rationale": "Autoscaling did not add capacity before latency breached the SLO.",
            },
        ],
        "node_failure": [
            {
                "title": "Add node-condition alerting and automated cordoning",
                "owner_hint": "platform",
                "priority": "p1",
                "rationale": "The node was unhealthy for some time before workloads were moved.",
            },
        ],
    }.get(signature.key, [])
    return (specific + generic)[:10]
