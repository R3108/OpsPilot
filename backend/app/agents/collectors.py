"""Evidence collectors — the read-only tools the investigators run.

These are the *only* things that produce Evidence rows. The LLM cannot write
evidence; it can only read what these functions retrieved from real systems and
cite it by id. That inversion is what makes a postmortem verifiable.

Each collector:
* takes a typed :class:`CollectContext`, never a free-form query;
* is read-only, so the five investigators can run concurrently without ordering
  constraints;
* degrades gracefully — a missing integration yields a note, not an exception,
  so one absent provider cannot abort an investigation.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.integrations.base import ClientRegistry
from app.models.enums import (
    EvidenceKind,
    EvidenceRelevance,
    IncidentStatus,
    IntegrationProvider,
    InvestigatorKind,
)
from app.models.incident import Incident

log = get_logger(__name__)


@dataclass(slots=True)
class EvidenceDraft:
    kind: EvidenceKind
    source: str
    summary: str
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    relevance: EvidenceRelevance = EvidenceRelevance.MEDIUM
    source_ref: str | None = None
    source_url: str | None = None
    observed_at: datetime | None = None
    investigator: InvestigatorKind | None = None


@dataclass(slots=True)
class CollectContext:
    incident: Incident
    registry: ClientRegistry
    session: AsyncSession
    window_minutes: int = 120
    objective: str = ""
    questions: list[str] = field(default_factory=list)

    @property
    def service(self) -> str:
        return self.incident.service or ""

    @property
    def namespace(self) -> str:
        return self.incident.namespace or self.incident.labels.get("namespace") or "default"

    @property
    def since(self) -> datetime:
        return datetime.now(UTC) - timedelta(minutes=self.window_minutes)


# ==========================================================================
# logs
# ==========================================================================
# Ordered most-severe first; the first match wins so a stack trace containing
# both "error" and "OOMKilled" is classified as the latter.
LOG_SIGNATURES: list[tuple[str, str, EvidenceRelevance]] = [
    (r"OOMKilled|out of memory|exit code 137", "OOM kill", EvidenceRelevance.CRITICAL),
    (r"FATAL|PANIC|panic:", "fatal error", EvidenceRelevance.CRITICAL),
    (
        r"too many (clients|connections)|connection pool (exhaust|timeout)"
        r"|remaining connection slots",
        "connection exhaustion",
        EvidenceRelevance.CRITICAL,
    ),
    (r"deadlock detected", "database deadlock", EvidenceRelevance.CRITICAL),
    (r"CrashLoopBackOff|BackOff restarting", "crash loop", EvidenceRelevance.CRITICAL),
    (r"idle in transaction", "idle transaction", EvidenceRelevance.HIGH),
    (
        r"Traceback|Exception|NullPointerException|TypeError|AttributeError",
        "unhandled exception",
        EvidenceRelevance.HIGH,
    ),
    (r"timeout|timed out|deadline exceeded|context canceled", "timeout", EvidenceRelevance.HIGH),
    (
        r"connection refused|ECONNREFUSED|no route to host",
        "connection refused",
        EvidenceRelevance.HIGH,
    ),
    (
        r"5\d{2} (Internal|Bad Gateway|Service Unavailable)|status=5\d{2}",
        "5xx response",
        EvidenceRelevance.HIGH,
    ),
    (r"\bERROR\b|\berror\b", "generic error", EvidenceRelevance.MEDIUM),
    (r"\bWARN(ING)?\b", "warning", EvidenceRelevance.LOW),
]


async def collect_logs(ctx: CollectContext) -> list[EvidenceDraft]:
    drafts: list[EvidenceDraft] = []
    k8s = ctx.registry.get(IntegrationProvider.KUBERNETES)
    cloudwatch = ctx.registry.get(IntegrationProvider.CLOUDWATCH)

    if k8s is None and cloudwatch is None:
        return [_note(InvestigatorKind.LOGS, "No log source is configured for this tenant.")]

    if k8s is not None:
        try:
            pods = await k8s.list_pods(ctx.namespace, limit=40)
        except Exception as exc:  # noqa: BLE001
            pods = []
            drafts.append(
                _note(InvestigatorKind.LOGS, f"Could not list pods: {exc}", EvidenceRelevance.LOW)
            )

        # Prioritise pods that look unhappy; fall back to the service's pods.
        interesting = [
            p
            for p in pods
            if p.get("phase") != "Running"
            or (p.get("restart_count") or 0) > 0
            or any(not c.get("ready") for c in p.get("containers") or [])
        ]
        if not interesting:
            interesting = [p for p in pods if ctx.service and ctx.service in str(p.get("name", ""))]
        targets = (interesting or pods)[:5]

        for pod in targets:
            drafts.extend(await _collect_pod_logs(ctx, k8s, pod))

        if any((p.get("restart_count") or 0) > 0 for p in pods):
            restarting = [
                {
                    "name": p["name"],
                    "pod": p["name"],
                    "restarts": p.get("restart_count"),
                    "phase": p.get("phase"),
                    "node": p.get("node"),
                    "reasons": [
                        c.get("reason") for c in p.get("containers") or [] if c.get("reason")
                    ],
                }
                for p in pods
                if (p.get("restart_count") or 0) > 0
            ]
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.K8S_EVENT,
                    source="kubernetes",
                    source_ref=f"{ctx.namespace}/pod-restarts",
                    summary=f"{len(restarting)} pod(s) in {ctx.namespace} have restarted",
                    detail="; ".join(
                        f"{r['name']}: {r['restarts']} restart(s), phase {r['phase']}"
                        + (f", reasons {r['reasons']}" if r["reasons"] else "")
                        + (f", node {r['node']}" if r.get("node") else "")
                        for r in restarting[:10]
                    ),
                    raw={"pods": restarting, "pod": restarting[0]["name"]},
                    relevance=EvidenceRelevance.HIGH,
                    investigator=InvestigatorKind.LOGS,
                    observed_at=datetime.now(UTC),
                )
            )

        drafts.extend(await _collect_k8s_events(ctx, k8s))
        drafts.extend(await _collect_node_health(ctx, k8s, pods))

    if cloudwatch is not None:
        for log_group in (cloudwatch.config.get("log_groups") or [])[:3]:
            try:
                events = await cloudwatch.filter_log_events(
                    log_group=log_group, pattern="ERROR", minutes=ctx.window_minutes, limit=200
                )
            except Exception as exc:  # noqa: BLE001
                drafts.append(
                    _note(
                        InvestigatorKind.LOGS,
                        f"CloudWatch group {log_group} unavailable: {exc}",
                        EvidenceRelevance.LOW,
                    )
                )
                continue
            if events:
                drafts.extend(
                    _summarise_log_lines(
                        [e["message"] for e in events],
                        source="cloudwatch",
                        source_ref=log_group,
                        investigator=InvestigatorKind.LOGS,
                    )
                )
    return drafts


async def _collect_k8s_events(ctx: CollectContext, k8s: Any) -> list[EvidenceDraft]:
    """Cluster events name the failure mode outright (OOMKilling, NodeNotReady...)."""
    try:
        events = await k8s.get_events(ctx.namespace, since_minutes=ctx.window_minutes)
    except Exception as exc:  # noqa: BLE001
        return [
            _note(
                InvestigatorKind.LOGS,
                f"Could not read cluster events: {exc}",
                EvidenceRelevance.LOW,
            )
        ]

    warnings = [e for e in events if str(e.get("type")) == "Warning"]
    if not warnings:
        return []

    by_reason = Counter(str(e.get("reason")) for e in warnings)
    critical_reasons = {
        "OOMKilling",
        "Failed",
        "FailedScheduling",
        "NodeNotReady",
        "Unhealthy",
        "BackOff",
        "FailedMount",
        "Evicted",
    }
    relevance = (
        EvidenceRelevance.CRITICAL if critical_reasons & set(by_reason) else EvidenceRelevance.HIGH
    )
    return [
        EvidenceDraft(
            kind=EvidenceKind.K8S_EVENT,
            source="kubernetes",
            source_ref=f"{ctx.namespace}/events",
            summary=(
                f"{len(warnings)} warning event(s) in {ctx.namespace}: "
                + ", ".join(f"{reason} x{count}" for reason, count in by_reason.most_common(5))
            ),
            detail="\n".join(
                f"{e.get('at')} {e.get('reason')} {e.get('object')}: {e.get('message')}"
                for e in warnings[:15]
            ),
            raw={"events": warnings[:30], "by_reason": dict(by_reason)},
            relevance=relevance,
            investigator=InvestigatorKind.LOGS,
            observed_at=datetime.now(UTC),
        )
    ]


async def _collect_node_health(
    ctx: CollectContext, k8s: Any, pods: list[dict[str, Any]]
) -> list[EvidenceDraft]:
    """Check the nodes hosting unhealthy pods.

    This is what separates "the app is broken" from "the node under the app is
    broken": if every failing pod shares one node and that node reports a
    pressure condition, the workload is a victim, not the cause.
    """
    unhealthy = [
        p for p in pods if p.get("phase") != "Running" or (p.get("restart_count") or 0) > 0
    ]
    node_names = {p.get("node") for p in unhealthy if p.get("node")}
    if not node_names:
        return []

    drafts: list[EvidenceDraft] = []
    for node_name in list(node_names)[:5]:
        node = await _safe(k8s.get_node(node_name))
        if not node or node.get("error"):
            continue

        conditions = node.get("conditions") or {}
        problems = [
            f"{name}={value}"
            for name, value in conditions.items()
            if (name == "Ready" and value != "True") or (name != "Ready" and value == "True")
        ]
        affected = [p["name"] for p in unhealthy if p.get("node") == node_name]
        drafts.append(
            EvidenceDraft(
                kind=EvidenceKind.K8S_EVENT,
                source="kubernetes",
                source_ref=f"node/{node_name}",
                summary=(
                    f"Node {node_name} is unhealthy ({', '.join(problems)}); "
                    f"{len(affected)} affected pod(s) are scheduled on it"
                    if problems
                    else f"Node {node_name} reports healthy conditions"
                ),
                detail=(
                    f"conditions={conditions}\nunschedulable={node.get('unschedulable')}\n"
                    f"affected pods: {', '.join(affected[:10])}"
                ),
                raw={
                    **node,
                    "unhealthy_node": node_name if problems else None,
                    "affected_pods": affected,
                },
                relevance=(EvidenceRelevance.CRITICAL if problems else EvidenceRelevance.LOW),
                investigator=InvestigatorKind.LOGS,
                observed_at=datetime.now(UTC),
            )
        )
    return drafts


async def _collect_pod_logs(
    ctx: CollectContext, k8s: Any, pod: dict[str, Any]
) -> list[EvidenceDraft]:
    name = pod.get("name")
    drafts: list[EvidenceDraft] = []
    try:
        text = await k8s.get_pod_logs(
            ctx.namespace, name, tail_lines=400, since_seconds=ctx.window_minutes * 60
        )
    except Exception as exc:  # noqa: BLE001
        return [
            _note(
                InvestigatorKind.LOGS,
                f"Could not read logs for {name}: {exc}",
                EvidenceRelevance.LOW,
            )
        ]

    lines = [line for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return []

    drafts.extend(
        _summarise_log_lines(
            lines,
            source="kubernetes",
            source_ref=f"{ctx.namespace}/{name}",
            investigator=InvestigatorKind.LOGS,
            extra_raw={"pod": name, "namespace": ctx.namespace},
        )
    )

    # A container that died has its story in the *previous* container's logs.
    if any(
        (c.get("restart_count") or 0) > 0 or c.get("reason") in ("OOMKilled", "Error")
        for c in pod.get("containers") or []
    ):
        try:
            previous = await k8s.get_pod_logs(
                ctx.namespace, name, tail_lines=100, previous=True, since_seconds=None
            )
        except Exception:  # noqa: BLE001 - no previous container is normal
            previous = ""
        if previous:
            tail = "\n".join(previous.splitlines()[-30:])
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.LOG_PATTERN,
                    source="kubernetes",
                    source_ref=f"{ctx.namespace}/{name}#previous",
                    summary=f"Final log lines before {name} last terminated",
                    detail=tail[:4000],
                    raw={"pod": name, "namespace": ctx.namespace, "previous_container": True},
                    relevance=EvidenceRelevance.CRITICAL,
                    investigator=InvestigatorKind.LOGS,
                    observed_at=datetime.now(UTC),
                )
            )
    return drafts


def _summarise_log_lines(
    lines: list[str],
    *,
    source: str,
    source_ref: str,
    investigator: InvestigatorKind,
    extra_raw: dict[str, Any] | None = None,
) -> list[EvidenceDraft]:
    """Cluster log lines by signature rather than dumping raw text at the model."""
    buckets: dict[str, list[str]] = {}
    relevances: dict[str, EvidenceRelevance] = {}

    for line in lines:
        for pattern, label, relevance in LOG_SIGNATURES:
            if re.search(pattern, line, re.IGNORECASE):
                buckets.setdefault(label, []).append(line)
                relevances[label] = relevance
                break

    drafts: list[EvidenceDraft] = []
    for label, matched in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        # Collapse near-identical lines so 4000 copies of one error read as one fact.
        normalised = Counter(_normalise_log_line(line) for line in matched)
        top_variants = normalised.most_common(5)
        first, last = _line_time(matched[0]), _line_time(matched[-1])
        drafts.append(
            EvidenceDraft(
                kind=EvidenceKind.LOG_PATTERN,
                source=source,
                source_ref=f"{source_ref}#{label.replace(' ', '_')}",
                summary=(
                    f"{len(matched)} log line(s) matching '{label}' in {source_ref}"
                    + (f", first at {first}" if first else "")
                ),
                detail="\n".join(f"[x{count}] {variant}" for variant, count in top_variants)[:4000],
                raw={
                    "label": label,
                    "count": len(matched),
                    "distinct_variants": len(normalised),
                    "first_seen": first,
                    "last_seen": last,
                    "samples": matched[:5],
                    **(extra_raw or {}),
                },
                relevance=relevances[label],
                investigator=investigator,
                observed_at=datetime.now(UTC),
            )
        )
    return drafts[:8]


_TS = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_VOLATILE = [
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
        "<uuid>",
    ),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<addr>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<ts>"),
    (re.compile(r"\b\d{5,}\b"), "<num>"),
]


def _normalise_log_line(line: str) -> str:
    text = line
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text.strip()[:300]


def _line_time(line: str) -> str | None:
    match = _TS.match(line)
    return match.group(1) if match else None


# ==========================================================================
# metrics
# ==========================================================================
METRIC_PLAN: list[tuple[str, str]] = [
    ("error_rate", "Error rate"),
    ("request_rate", "Request rate"),
    ("latency_p99", "p99 latency"),
    ("latency_p50", "p50 latency"),
    ("cpu_usage", "CPU usage"),
    ("memory_usage", "Memory usage"),
    ("memory_limit_ratio", "Memory vs limit"),
    ("pod_restarts", "Pod restarts"),
]


async def collect_metrics(ctx: CollectContext) -> list[EvidenceDraft]:
    prom = ctx.registry.get(IntegrationProvider.PROMETHEUS)
    cloudwatch = ctx.registry.get(IntegrationProvider.CLOUDWATCH)
    if prom is None and cloudwatch is None:
        return [_note(InvestigatorKind.METRICS, "No metrics source is configured for this tenant.")]

    drafts: list[EvidenceDraft] = []

    # Database metrics are only meaningful (and only exist) when the incident is
    # associated with a database, so they are added to the plan conditionally
    # rather than queried blindly for every service.
    plan = list(METRIC_PLAN)
    database = ctx.incident.labels.get("database", "")
    if database:
        plan.extend(
            [
                ("db_connections", "Database connections"),
                ("db_connection_saturation", "Connection pool saturation"),
            ]
        )

    if prom is not None:
        results = await asyncio.gather(
            *[
                prom.standard_query(
                    name,
                    service=ctx.service,
                    namespace=ctx.namespace,
                    database=database,
                    minutes=ctx.window_minutes,
                )
                for name, _ in plan
            ],
            return_exceptions=True,
        )
        for (name, label), result in zip(plan, results, strict=True):
            if isinstance(result, BaseException):
                log.debug("collector.metric_failed", metric=name, error=str(result))
                continue
            draft = _metric_draft(name, label, result)
            if draft is not None:
                drafts.append(draft)

        try:
            alerts = await prom.active_alerts()
        except Exception:  # noqa: BLE001
            alerts = []
        if alerts:
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.ALERT,
                    source="prometheus",
                    source_ref="active_alerts",
                    summary=f"{len(alerts)} alert(s) currently firing",
                    detail="; ".join(f"{a.get('name')} ({a.get('severity')})" for a in alerts[:10]),
                    raw={"alerts": alerts[:20]},
                    relevance=EvidenceRelevance.HIGH,
                    investigator=InvestigatorKind.METRICS,
                    observed_at=datetime.now(UTC),
                )
            )

    if cloudwatch is not None and not drafts:
        try:
            alarms = await cloudwatch.describe_alarms()
        except Exception:  # noqa: BLE001
            alarms = []
        if alarms:
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.ALERT,
                    source="cloudwatch",
                    source_ref="alarms",
                    summary=f"{len(alarms)} CloudWatch alarm(s) in ALARM state",
                    detail="; ".join(f"{a.get('name')}: {a.get('reason')}" for a in alarms[:8]),
                    raw={"alarms": alarms[:20]},
                    relevance=EvidenceRelevance.HIGH,
                    investigator=InvestigatorKind.METRICS,
                    observed_at=datetime.now(UTC),
                )
            )

    return drafts or [_note(InvestigatorKind.METRICS, "Metrics sources returned no series.")]


def _metric_draft(name: str, label: str, result: dict[str, Any]) -> EvidenceDraft | None:
    series = result.get("series") or []
    if not series:
        return None
    primary = series[0]
    points = primary.get("points") or []
    if not points:
        return None

    values = [p["v"] for p in points if p.get("v") is not None]
    if not values:
        return None

    analysis = _analyse_series(values)
    relevance = (
        EvidenceRelevance.CRITICAL
        if analysis["change_ratio"] is not None and abs(analysis["change_ratio"]) >= 2.0
        else EvidenceRelevance.HIGH
        if analysis["change_ratio"] is not None and abs(analysis["change_ratio"]) >= 0.5
        else EvidenceRelevance.MEDIUM
    )
    direction = (
        "rose"
        if (analysis["change_ratio"] or 0) > 0
        else "fell"
        if (analysis["change_ratio"] or 0) < 0
        else "was flat"
    )
    change_text = (
        f"{direction} {abs(analysis['change_ratio']):.1%} vs the start of the window"
        if analysis["change_ratio"] is not None
        else "had no comparable baseline"
    )

    return EvidenceDraft(
        kind=EvidenceKind.METRIC_SERIES,
        source="prometheus",
        source_ref=name,
        summary=(
            f"{label}: now {analysis['last']:.4g} (baseline {analysis['baseline']:.4g}); "
            f"it {change_text}"
        ),
        detail=(
            f"min={analysis['min']:.4g} max={analysis['max']:.4g} "
            f"mean={analysis['mean']:.4g} points={len(values)}"
            + (
                f"\nStep change detected at point {analysis['breakpoint_index']} of {len(values)}"
                if analysis["breakpoint_index"] is not None
                else "\nNo clear step change in this window"
            )
        ),
        raw={
            "name": name,
            "promql": result.get("promql"),
            "last": analysis["last"],
            "baseline": analysis["baseline"],
            "min": analysis["min"],
            "max": analysis["max"],
            "change_ratio": analysis["change_ratio"],
            "breakpoint_index": analysis["breakpoint_index"],
            "points": points[-60:],
            "labels": primary.get("metric", {}),
        },
        relevance=relevance,
        investigator=InvestigatorKind.METRICS,
        observed_at=datetime.now(UTC),
    )


def _analyse_series(values: list[float]) -> dict[str, Any]:
    """Baseline, current level, and a simple change-point index.

    The change point is the split that maximises the difference between the two
    halves' means — enough to tell a step change from noise, and cheap enough to
    run on every metric.
    """
    last = values[-1]
    head = values[: max(1, len(values) // 4)]
    baseline = sum(head) / len(head)
    change_ratio = (last - baseline) / abs(baseline) if baseline else None

    breakpoint_index: int | None = None
    if len(values) >= 8:
        best_delta = 0.0
        for split in range(3, len(values) - 3):
            left = sum(values[:split]) / split
            right = sum(values[split:]) / (len(values) - split)
            delta = abs(right - left)
            if delta > best_delta:
                best_delta = delta
                breakpoint_index = split
        spread = max(values) - min(values)
        if spread == 0 or best_delta < spread * 0.4:
            breakpoint_index = None

    return {
        "last": last,
        "baseline": baseline,
        "min": min(values),
        "max": max(values),
        "mean": sum(values) / len(values),
        "change_ratio": change_ratio,
        "breakpoint_index": breakpoint_index,
    }


# ==========================================================================
# database
# ==========================================================================
async def collect_database(ctx: CollectContext) -> list[EvidenceDraft]:
    client = ctx.registry.get(IntegrationProvider.POSTGRES)
    if client is None:
        return [_note(InvestigatorKind.DATABASE, "No database integration is configured.")]

    database = (
        ctx.incident.labels.get("database")
        or client.config.get("database")
        or ctx.service
        or "postgres"
    )
    try:
        snapshot = await client.full_health_snapshot(database)
    except Exception as exc:  # noqa: BLE001
        return [
            _note(
                InvestigatorKind.DATABASE,
                f"Database health snapshot failed: {exc}",
                EvidenceRelevance.LOW,
            )
        ]

    drafts: list[EvidenceDraft] = []
    connections = snapshot.get("connections") or {}
    saturation = connections.get("saturation")
    if saturation is not None:
        relevance = (
            EvidenceRelevance.CRITICAL
            if saturation >= 0.9
            else EvidenceRelevance.HIGH
            if saturation >= 0.75
            else EvidenceRelevance.MEDIUM
        )
        by_state = connections.get("by_state") or {}
        drafts.append(
            EvidenceDraft(
                kind=EvidenceKind.DB_HEALTH,
                source="postgres",
                source_ref=f"{database}/connections",
                summary=(
                    f"Connection pool at {saturation:.0%} "
                    f"({connections.get('total')}/{connections.get('max_connections')})"
                ),
                detail="; ".join(
                    f"{state}: {info.get('count')} "
                    f"(max age {info.get('max_state_seconds', 0):.0f}s)"
                    for state, info in by_state.items()
                ),
                raw={"database": database, **connections},
                relevance=relevance,
                investigator=InvestigatorKind.DATABASE,
                observed_at=datetime.now(UTC),
            )
        )

    idle = (connections.get("by_state") or {}).get("idle in transaction") or {}
    if idle.get("count"):
        try:
            rows = await client.list_idle_in_transaction(
                database=database, idle_seconds=60, limit=25
            )
        except Exception:  # noqa: BLE001
            rows = []
        if rows:
            oldest = max(float(r.get("idle_seconds") or 0) for r in rows)
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.DB_HEALTH,
                    source="postgres",
                    source_ref=f"{database}/idle_in_transaction",
                    summary=(
                        f"{len(rows)} backend(s) idle in transaction, oldest {oldest:.0f}s — "
                        f"a leaked-transaction signature"
                    ),
                    detail="\n".join(
                        f"pid={r.get('pid')} app={r.get('application_name')} "
                        f"idle={float(r.get('idle_seconds') or 0):.0f}s "
                        f":: {str(r.get('query'))[:150]}"
                        for r in rows[:10]
                    ),
                    raw={"database": database, "backends": rows[:25], "oldest_seconds": oldest},
                    relevance=EvidenceRelevance.CRITICAL,
                    investigator=InvestigatorKind.DATABASE,
                    observed_at=datetime.now(UTC),
                )
            )

    for key, kind_label, relevance in (
        ("blocking_locks", "blocking lock", EvidenceRelevance.CRITICAL),
        ("long_running_queries", "long-running query", EvidenceRelevance.HIGH),
    ):
        rows = snapshot.get(key)
        if isinstance(rows, list) and rows:
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.DB_HEALTH,
                    source="postgres",
                    source_ref=f"{database}/{key}",
                    summary=f"{len(rows)} {kind_label}(s) detected on {database}",
                    detail="\n".join(str(r)[:250] for r in rows[:8]),
                    raw={"database": database, key: rows[:20]},
                    relevance=relevance,
                    investigator=InvestigatorKind.DATABASE,
                    observed_at=datetime.now(UTC),
                )
            )

    cache = snapshot.get("cache") or {}
    hit_ratio = cache.get("hit_ratio")
    if hit_ratio is not None and float(hit_ratio) < 0.95:
        drafts.append(
            EvidenceDraft(
                kind=EvidenceKind.DB_HEALTH,
                source="postgres",
                source_ref=f"{database}/cache",
                summary=f"Buffer cache hit ratio is {float(hit_ratio):.1%} (below the 95% norm)",
                detail=str(cache),
                raw={"database": database, **cache},
                relevance=EvidenceRelevance.MEDIUM,
                investigator=InvestigatorKind.DATABASE,
                observed_at=datetime.now(UTC),
            )
        )

    replication = snapshot.get("replication")
    if isinstance(replication, list) and replication:
        lagging = [r for r in replication if float(r.get("reply_lag_seconds") or 0) > 10]
        if lagging:
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.DB_HEALTH,
                    source="postgres",
                    source_ref=f"{database}/replication",
                    summary=f"{len(lagging)} replica(s) lagging more than 10s",
                    detail=str(lagging)[:1000],
                    raw={"replicas": replication},
                    relevance=EvidenceRelevance.HIGH,
                    investigator=InvestigatorKind.DATABASE,
                    observed_at=datetime.now(UTC),
                )
            )

    return drafts or [
        _note(
            InvestigatorKind.DATABASE,
            f"Database {database} looks healthy: no saturation, locks or lag detected.",
            EvidenceRelevance.LOW,
        )
    ]


# ==========================================================================
# deployments
# ==========================================================================
async def collect_deployments(ctx: CollectContext) -> list[EvidenceDraft]:
    drafts: list[EvidenceDraft] = []
    github = ctx.registry.get(IntegrationProvider.GITHUB)
    k8s = ctx.registry.get(IntegrationProvider.KUBERNETES)
    grafana = ctx.registry.get(IntegrationProvider.GRAFANA)

    if github is None and k8s is None:
        return [_note(InvestigatorKind.DEPLOYMENTS, "No deployment source is configured.")]

    hours = max(1, ctx.window_minutes // 60)

    if k8s is not None:
        deployment_name = ctx.service or ctx.incident.labels.get("deployment") or ""
        if deployment_name:
            try:
                deployment = await k8s.get_deployment(ctx.namespace, deployment_name)
                history = await k8s.get_rollout_history(ctx.namespace, deployment_name)
            except Exception as exc:  # noqa: BLE001
                deployment, history = {"error": str(exc)}, []

            if deployment and not deployment.get("error"):
                drafts.append(
                    EvidenceDraft(
                        kind=EvidenceKind.DEPLOYMENT,
                        source="kubernetes",
                        source_ref=f"{ctx.namespace}/{deployment_name}",
                        summary=(
                            f"Deployment {deployment_name} at revision "
                            f"{deployment.get('revision')}, "
                            f"{deployment.get('ready_replicas')}/{deployment.get('replicas')} ready"
                        ),
                        detail=(
                            f"images={deployment.get('images')} "
                            f"unavailable={deployment.get('unavailable_replicas')} "
                            f"change_cause={deployment.get('change_cause')}"
                        ),
                        raw={"deployment": deployment_name, **deployment},
                        relevance=(
                            EvidenceRelevance.HIGH
                            if (deployment.get("unavailable_replicas") or 0) > 0
                            else EvidenceRelevance.MEDIUM
                        ),
                        investigator=InvestigatorKind.DEPLOYMENTS,
                        observed_at=datetime.now(UTC),
                    )
                )
            if history:
                latest = history[-1]
                drafts.append(
                    EvidenceDraft(
                        kind=EvidenceKind.DEPLOYMENT,
                        source="kubernetes",
                        source_ref=f"{ctx.namespace}/{deployment_name}#history",
                        summary=(
                            f"Latest rollout is revision {latest.get('revision')} "
                            f"created {latest.get('created_at')}"
                        ),
                        detail="\n".join(
                            f"rev {h.get('revision')}: {h.get('images')} at {h.get('created_at')}"
                            for h in history[-5:]
                        ),
                        raw={"deployment": deployment_name, "history": history},
                        relevance=EvidenceRelevance.HIGH,
                        investigator=InvestigatorKind.DEPLOYMENTS,
                        observed_at=_parse_dt(latest.get("created_at")),
                    )
                )

    if github is not None:
        repos = github.config.get("repos") or []
        for repo in repos[:3]:
            commits, deployments, prs = await asyncio.gather(
                _safe(github.list_recent_commits(repo, hours=hours)),
                _safe(github.list_deployments(repo, environment=ctx.incident.environment)),
                _safe(github.list_recent_pull_requests(repo, hours=hours * 2)),
            )
            if commits:
                drafts.append(
                    EvidenceDraft(
                        kind=EvidenceKind.COMMIT,
                        source="github",
                        source_ref=repo,
                        summary=f"{len(commits)} commit(s) landed in {repo} in the last {hours}h",
                        detail="\n".join(
                            f"{c['short_sha']} {str(c['message']).splitlines()[0][:120]} "
                            f"({c.get('author')}, {c.get('committed_at')})"
                            for c in commits[:10]
                        ),
                        raw={"repo": repo, "commits": commits[:20]},
                        relevance=EvidenceRelevance.HIGH if commits else EvidenceRelevance.LOW,
                        source_url=commits[0].get("url"),
                        investigator=InvestigatorKind.DEPLOYMENTS,
                        observed_at=_parse_dt(commits[0].get("committed_at")),
                    )
                )
            if deployments:
                recent = deployments[:5]
                drafts.append(
                    EvidenceDraft(
                        kind=EvidenceKind.DEPLOYMENT,
                        source="github",
                        source_ref=f"{repo}#deployments",
                        summary=(
                            f"Most recent {ctx.incident.environment} deployment of {repo}: "
                            f"{recent[0].get('short_sha')} at {recent[0].get('created_at')} "
                            f"({recent[0].get('state')})"
                        ),
                        detail="\n".join(
                            f"{d.get('short_sha')} {d.get('environment')} {d.get('state')} "
                            f"at {d.get('created_at')} by {d.get('creator')}"
                            for d in recent
                        ),
                        raw={"repo": repo, "deployments": recent},
                        relevance=EvidenceRelevance.CRITICAL,
                        investigator=InvestigatorKind.DEPLOYMENTS,
                        observed_at=_parse_dt(recent[0].get("created_at")),
                    )
                )
            if prs:
                drafts.append(
                    EvidenceDraft(
                        kind=EvidenceKind.COMMIT,
                        source="github",
                        source_ref=f"{repo}#pulls",
                        summary=f"{len(prs)} PR(s) merged into {repo} recently",
                        detail="\n".join(
                            f"#{p['number']} {p['title'][:100]} "
                            f"({p.get('author')}, {p.get('merged_at')})"
                            for p in prs[:8]
                        ),
                        raw={"repo": repo, "pull_requests": prs[:15]},
                        relevance=EvidenceRelevance.MEDIUM,
                        investigator=InvestigatorKind.DEPLOYMENTS,
                        observed_at=_parse_dt(prs[0].get("merged_at")),
                    )
                )

    if grafana is not None:
        annotations = await _safe(
            grafana.get_annotations(minutes=ctx.window_minutes, tags=["deploy"])
        )
        if annotations:
            drafts.append(
                EvidenceDraft(
                    kind=EvidenceKind.DEPLOYMENT,
                    source="grafana",
                    source_ref="annotations",
                    summary=f"{len(annotations)} deploy annotation(s) in the incident window",
                    detail="\n".join(f"{a.get('at')}: {a.get('text')}" for a in annotations[:8]),
                    raw={"annotations": annotations[:20]},
                    relevance=EvidenceRelevance.HIGH,
                    investigator=InvestigatorKind.DEPLOYMENTS,
                    observed_at=_parse_dt(annotations[0].get("at")),
                )
            )

    return drafts or [
        _note(
            InvestigatorKind.DEPLOYMENTS,
            "No deploys, commits or rollouts found in the incident window — a change is "
            "unlikely to be the trigger.",
            EvidenceRelevance.MEDIUM,
        )
    ]


# ==========================================================================
# history
# ==========================================================================
async def collect_history(ctx: CollectContext) -> list[EvidenceDraft]:
    """Find previously resolved incidents with a similar signature."""
    from app.services.similarity import find_similar_incidents

    matches = await find_similar_incidents(
        ctx.session,
        tenant_id=ctx.incident.tenant_id,
        incident=ctx.incident,
        limit=5,
    )
    if not matches:
        return [
            _note(
                InvestigatorKind.HISTORY,
                "No similar resolved incidents found in this organisation's history.",
                EvidenceRelevance.LOW,
            )
        ]

    drafts: list[EvidenceDraft] = []
    for match in matches:
        incident = match["incident"]
        drafts.append(
            EvidenceDraft(
                kind=EvidenceKind.HISTORICAL_INCIDENT,
                source="opspilot",
                source_ref=incident["reference"],
                summary=(
                    f"Similar past incident {incident['reference']} "
                    f"({match['score']:.0%} match): {incident['title']}"
                ),
                detail=(
                    f"Root cause: {incident.get('root_cause_summary') or 'not recorded'}\n"
                    f"Resolved at: {incident.get('resolved_at')}\n"
                    f"Remediation: {incident.get('remediation') or 'not recorded'}\n"
                    f"Matched on: {match.get('reason', '')}"
                ),
                raw=match,
                relevance=(
                    EvidenceRelevance.HIGH if match["score"] >= 0.6 else EvidenceRelevance.MEDIUM
                ),
                investigator=InvestigatorKind.HISTORY,
                observed_at=_parse_dt(incident.get("resolved_at")),
            )
        )

    runbooks = await _matching_runbooks(ctx)
    drafts.extend(runbooks)
    return drafts


async def _matching_runbooks(ctx: CollectContext) -> list[EvidenceDraft]:
    from app.models.knowledge import Runbook

    stmt = select(Runbook).where(
        Runbook.tenant_id == ctx.incident.tenant_id,
        Runbook.is_active.is_(True),
    )
    if ctx.service:
        stmt = stmt.where(Runbook.service == ctx.service)
    runbooks = list((await ctx.session.execute(stmt.limit(3))).scalars().all())
    return [
        EvidenceDraft(
            kind=EvidenceKind.NOTE,
            source="runbook",
            source_ref=str(rb.id),
            summary=f"Runbook: {rb.title}",
            detail=rb.content_markdown[:3000],
            raw={
                "runbook_id": str(rb.id),
                "suggested_action_keys": rb.suggested_action_keys,
                "symptoms": rb.symptoms,
            },
            relevance=EvidenceRelevance.MEDIUM,
            investigator=InvestigatorKind.HISTORY,
        )
        for rb in runbooks
    ]


# ==========================================================================
COLLECTORS = {
    InvestigatorKind.LOGS: collect_logs,
    InvestigatorKind.METRICS: collect_metrics,
    InvestigatorKind.DATABASE: collect_database,
    InvestigatorKind.DEPLOYMENTS: collect_deployments,
    InvestigatorKind.HISTORY: collect_history,
}

# Which providers an investigator needs before it is worth planning.
INVESTIGATOR_REQUIREMENTS: dict[InvestigatorKind, set[IntegrationProvider]] = {
    InvestigatorKind.LOGS: {IntegrationProvider.KUBERNETES, IntegrationProvider.CLOUDWATCH},
    InvestigatorKind.METRICS: {IntegrationProvider.PROMETHEUS, IntegrationProvider.CLOUDWATCH},
    InvestigatorKind.DATABASE: {IntegrationProvider.POSTGRES},
    InvestigatorKind.DEPLOYMENTS: {
        IntegrationProvider.GITHUB,
        IntegrationProvider.KUBERNETES,
        IntegrationProvider.GRAFANA,
    },
    InvestigatorKind.HISTORY: set(),  # always available: it reads our own database
}


def available_investigators(registry: ClientRegistry) -> list[InvestigatorKind]:
    available: list[InvestigatorKind] = []
    for kind, providers in INVESTIGATOR_REQUIREMENTS.items():
        if not providers or any(registry.get(p) is not None for p in providers):
            available.append(kind)
    return available


async def _safe(awaitable: Any) -> Any:
    try:
        return await awaitable
    except Exception as exc:  # noqa: BLE001
        log.debug("collector.call_failed", error=str(exc)[:200])
        return None


def _note(
    investigator: InvestigatorKind,
    message: str,
    relevance: EvidenceRelevance = EvidenceRelevance.LOW,
) -> EvidenceDraft:
    return EvidenceDraft(
        kind=EvidenceKind.NOTE,
        source="opspilot",
        summary=message,
        relevance=relevance,
        investigator=investigator,
        observed_at=datetime.now(UTC),
    )


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


async def recent_incidents_for_service(
    session: AsyncSession, *, tenant_id: uuid.UUID, service: str | None, limit: int = 5
) -> list[dict[str, Any]]:
    """Small helper used by triage to spot duplicate alerts."""
    stmt = (
        select(Incident)
        .where(Incident.tenant_id == tenant_id, Incident.status != IncidentStatus.CLOSED)
        .order_by(Incident.created_at.desc())
        .limit(limit)
    )
    if service:
        stmt = stmt.where(Incident.service == service)
    rows = list((await session.execute(stmt)).scalars().all())
    return [
        {
            "reference": r.reference,
            "title": r.title,
            "severity": str(r.severity),
            "status": str(r.status),
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
