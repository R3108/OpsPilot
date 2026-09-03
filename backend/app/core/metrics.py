"""Minimal Prometheus exposition without a third-party client.

Keeps the dependency footprint flat: counters and gauges rendered in the
Prometheus text format from a process-local registry. For multi-worker
deployments each worker exposes its own counters — aggregate with
`sum by (...)` in PromQL.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

_counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
_gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
_latencies: dict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()

_HELP: dict[str, str] = {}


def _labels_key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((labels or {}).items()))


def describe(metric: str, help_text: str) -> None:
    _HELP[metric] = help_text


def inc(metric: str, *, labels: dict[str, str] | None = None, amount: float = 1.0) -> None:
    with _lock:
        _counters[(metric, _labels_key(labels))] += amount


def set_gauge(metric: str, value: float, *, labels: dict[str, str] | None = None) -> None:
    with _lock:
        _gauges[(metric, _labels_key(labels))] = value


def observe_latency(metric: str, seconds: float, *, max_samples: int = 512) -> None:
    with _lock:
        samples = _latencies[metric]
        samples.append(seconds)
        if len(samples) > max_samples:
            del samples[: len(samples) - max_samples]


def _quantile(sorted_samples: list[float], q: float) -> float:
    if not sorted_samples:
        return 0.0
    idx = min(len(sorted_samples) - 1, int(q * len(sorted_samples)))
    return sorted_samples[idx]


def render() -> str:
    """Render the registry in Prometheus text exposition format."""
    with _lock:
        counters = dict(_counters)
        gauges = dict(_gauges)
        latencies = {k: sorted(v) for k, v in _latencies.items()}
    lines: list[str] = []
    for (metric, label_pairs), value in sorted(counters.items()):
        if metric in _HELP:
            lines.append(f"# HELP {metric} {_HELP[metric]}")
        lines.append(f"# TYPE {metric} counter")
        lines.append(f"{metric}{_format_labels(label_pairs)} {value}")
    for (metric, label_pairs), value in sorted(gauges.items()):
        if metric in _HELP:
            lines.append(f"# HELP {metric} {_HELP[metric]}")
        lines.append(f"# TYPE {metric} gauge")
        lines.append(f"{metric}{_format_labels(label_pairs)} {value}")
    for metric, samples in sorted(latencies.items()):
        if metric in _HELP:
            lines.append(f"# HELP {metric} {_HELP[metric]}")
        lines.append(f"# TYPE {metric} summary")
        count = len(samples)
        total = sum(samples)
        lines.append(f"{metric}_count {count}")
        lines.append(f"{metric}_sum {total:.6f}")
        for q in (0.5, 0.9, 0.99):
            lines.append(f'{metric}{{quantile="{q}"}} {_quantile(samples, q):.6f}')
    return "\n".join(lines) + "\n"


def _format_labels(pairs: tuple[tuple[str, str], ...]) -> str:
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{v}"' for k, v in pairs) + "}"


# Metric catalogue (documented once so dashboards stay stable).
describe("opspilot_http_requests_total", "API requests by route, method and status.")
describe("opspilot_http_request_seconds", "API request latency by route.")
describe("opspilot_investigations_started_total", "Investigations started by trigger.")
describe("opspilot_investigations_completed_total", "Investigations completed by outcome.")
describe("opspilot_approvals_decided_total", "Approval decisions by decision.")
describe("opspilot_policy_denied_total", "Actions blocked by the policy engine.")
describe("opspilot_jobs_failed_total", "Worker jobs recorded as failed by job name.")
describe("opspilot_jobs_retried_total", "Worker jobs redriven via arq Retry.")
describe("opspilot_stuck_runs_rescued_total", "Stuck runs resumed by the reconciler.")
describe("opspilot_webhook_ingested_total", "Webhook deliveries ingested by provider.")
describe("opspilot_llm_cost_usd_total", "LLM spend by provider and purpose.")
describe("opspilot_uptime_seconds", "Seconds since process start.")


_STARTED_AT = time.monotonic()


def uptime_seconds() -> float:
    return time.monotonic() - _STARTED_AT
