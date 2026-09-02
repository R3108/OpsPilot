"""Prometheus client.

PromQL is a query language, and the metrics investigator needs to write queries —
so this is the one place where a model-influenced string reaches a provider. Two
things keep that safe:

* Prometheus's query API is **read-only**. There is no write path, no delete, and
  no admin endpoint exposed here.
* Queries are still validated: length-capped, and screened for the admin/TSDB
  endpoints so a query string can never be smuggled into a different API path.

The metrics investigator also has a library of pre-built queries
(:data:`STANDARD_QUERIES`) which it prefers over free-form PromQL.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.errors import IntegrationError, ValidationError
from app.core.logging import get_logger
from app.integrations.base import HealthReport, HttpProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)

MAX_QUERY_LENGTH = 2000
# Queries must not contain path separators that could escape the /api/v1/query route.
_FORBIDDEN = re.compile(r"(\.\./|/api/v1/admin|/-/reload|/-/quit)", re.IGNORECASE)

STANDARD_QUERIES: dict[str, str] = {
    "error_rate": (
        'sum(rate(http_requests_total{{service="{service}",status=~"5.."}}[5m])) '
        '/ clamp_min(sum(rate(http_requests_total{{service="{service}"}}[5m])), 0.001)'
    ),
    "request_rate": 'sum(rate(http_requests_total{{service="{service}"}}[5m]))',
    "latency_p99": (
        "histogram_quantile(0.99, sum(rate("
        'http_request_duration_seconds_bucket{{service="{service}"}}[5m])) by (le))'
    ),
    "latency_p50": (
        "histogram_quantile(0.50, sum(rate("
        'http_request_duration_seconds_bucket{{service="{service}"}}[5m])) by (le))'
    ),
    "cpu_usage": (
        'sum(rate(container_cpu_usage_seconds_total{{namespace="{namespace}",'
        'pod=~"{service}.*"}}[5m])) by (pod)'
    ),
    "memory_usage": (
        'sum(container_memory_working_set_bytes{{namespace="{namespace}",'
        'pod=~"{service}.*"}}) by (pod)'
    ),
    "memory_limit_ratio": (
        'sum(container_memory_working_set_bytes{{namespace="{namespace}",'
        'pod=~"{service}.*"}}) by (pod) / '
        'sum(container_spec_memory_limit_bytes{{namespace="{namespace}",'
        'pod=~"{service}.*"}}) by (pod)'
    ),
    "pod_restarts": (
        'sum(increase(kube_pod_container_status_restarts_total{{namespace="{namespace}",'
        'pod=~"{service}.*"}}[1h])) by (pod)'
    ),
    "db_connections": ('sum(pg_stat_activity_count{{datname="{database}"}}) by (state)'),
    "db_connection_saturation": (
        'sum(pg_stat_activity_count{{datname="{database}"}}) '
        "/ clamp_min(max(pg_settings_max_connections), 1)"
    ),
    "saturation_queue_depth": ('sum(rate(queue_depth{{service="{service}"}}[5m]))'),
}


class PrometheusClient(HttpProviderClient):
    provider = IntegrationProvider.PROMETHEUS

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        token = self._credentials.get("bearer_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _validate_query(query: str) -> str:
        query = query.strip()
        if not query:
            raise ValidationError("PromQL query is empty")
        if len(query) > MAX_QUERY_LENGTH:
            raise ValidationError(
                f"PromQL query exceeds {MAX_QUERY_LENGTH} characters",
                details={"length": len(query)},
            )
        if _FORBIDDEN.search(query):
            raise ValidationError(
                "PromQL query contains a forbidden sequence",
                details={"query": query[:200]},
            )
        return query

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            data = await self._get_json("/api/v1/query", query="up")
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        healthy = data.get("status") == "success"
        return HealthReport(
            healthy=healthy,
            detail="query API reachable" if healthy else str(data)[:300],
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["instant_query", "range_query", "alerts", "targets"],
        )

    # -- read ---------------------------------------------------------------
    async def query(self, promql: str, *, at: datetime | None = None) -> dict[str, Any]:
        """Instant query."""
        payload = await self._get_json(
            "/api/v1/query",
            query=self._validate_query(promql),
            time=(at or datetime.now(UTC)).timestamp(),
        )
        return _unwrap(payload, promql)

    async def query_range(
        self,
        promql: str,
        *,
        minutes: int = 60,
        step_seconds: int = 60,
        end: datetime | None = None,
    ) -> dict[str, Any]:
        end = end or datetime.now(UTC)
        start = end - timedelta(minutes=minutes)
        # Prometheus rejects >11k points; clamp the step instead of failing.
        step = max(step_seconds, int((end - start).total_seconds() // 10_000) + 1)
        payload = await self._get_json(
            "/api/v1/query_range",
            query=self._validate_query(promql),
            start=start.timestamp(),
            end=end.timestamp(),
            step=step,
        )
        return _unwrap(payload, promql)

    async def standard_query(
        self,
        name: str,
        *,
        service: str = "",
        namespace: str = "",
        database: str = "",
        minutes: int = 60,
        range_query: bool = True,
    ) -> dict[str, Any]:
        """Run one of the vetted queries. Preferred over free-form PromQL."""
        template = STANDARD_QUERIES.get(name)
        if template is None:
            raise ValidationError(
                f"unknown standard query '{name}'",
                details={"available": sorted(STANDARD_QUERIES)},
            )
        promql = template.format(
            service=_escape_label(service),
            namespace=_escape_label(namespace),
            database=_escape_label(database),
        )
        result = (
            await self.query_range(promql, minutes=minutes)
            if range_query
            else await self.query(promql)
        )
        return {"name": name, "promql": promql, **result}

    async def active_alerts(self) -> list[dict[str, Any]]:
        payload = await self._get_json("/api/v1/alerts")
        alerts = (payload.get("data") or {}).get("alerts") or []
        return [
            {
                "name": a.get("labels", {}).get("alertname"),
                "state": a.get("state"),
                "severity": a.get("labels", {}).get("severity"),
                "labels": a.get("labels", {}),
                "annotations": a.get("annotations", {}),
                "active_at": a.get("activeAt"),
                "value": a.get("value"),
            }
            for a in alerts
        ]

    async def series_labels(self, match: str, *, minutes: int = 60) -> list[dict[str, str]]:
        end = datetime.now(UTC)
        payload = await self._get_json(
            "/api/v1/series",
            **{
                "match[]": self._validate_query(match),
                "start": (end - timedelta(minutes=minutes)).timestamp(),
                "end": end.timestamp(),
            },
        )
        return payload.get("data") or []


def _escape_label(value: str) -> str:
    """Neutralise PromQL label-matcher metacharacters in an interpolated value."""
    return re.sub(r"[^A-Za-z0-9_.:\-/]", "", value or "")[:120]


def _unwrap(payload: dict[str, Any], promql: str) -> dict[str, Any]:
    if payload.get("status") != "success":
        raise IntegrationError(
            f"Prometheus rejected the query: {payload.get('error', 'unknown error')}",
            details={"query": promql[:300], "errorType": payload.get("errorType")},
        )
    data = payload.get("data") or {}
    result = data.get("result") or []
    series = []
    for item in result[:50]:
        values = item.get("values") or ([item["value"]] if item.get("value") else [])
        points = [{"t": float(ts), "v": _as_float(val)} for ts, val in values[-500:]]
        series.append(
            {
                "metric": item.get("metric", {}),
                "points": points,
                "last": points[-1]["v"] if points else None,
                "min": min((p["v"] for p in points if p["v"] is not None), default=None),
                "max": max((p["v"] for p in points if p["v"] is not None), default=None),
            }
        )
    return {
        "result_type": data.get("resultType"),
        "series_count": len(result),
        "series": series,
        "query": promql,
    }


def _as_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return None if parsed != parsed else parsed  # NaN check
