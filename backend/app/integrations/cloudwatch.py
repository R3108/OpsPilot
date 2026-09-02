"""CloudWatch Logs + Metrics.

boto3 is synchronous, so calls are pushed to a thread with an explicit timeout
rather than blocking the event loop.
"""

from __future__ import annotations

import asyncio
import functools
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.errors import IntegrationError, ValidationError
from app.core.logging import get_logger
from app.integrations.base import HealthReport, ProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)

MAX_FILTER_PATTERN = 1024


class CloudWatchClient(ProviderClient):
    provider = IntegrationProvider.CLOUDWATCH

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._logs: Any = None
        self._metrics: Any = None

    def _session(self) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise IntegrationError("boto3 is not installed") from exc
        return boto3.session.Session(
            aws_access_key_id=self._credential("access_key_id"),
            aws_secret_access_key=self._credential("secret_access_key"),
            aws_session_token=self._credentials.get("session_token") or None,
            region_name=self.config.get("region", "us-east-1"),
        )

    def _logs_client(self) -> Any:
        if self._logs is None:
            self._logs = self._session().client("logs")
        return self._logs

    def _metrics_client(self) -> Any:
        if self._metrics is None:
            self._metrics = self._session().client("cloudwatch")
        return self._metrics

    async def _call(self, operation: str, fn: Any, /, **kwargs: Any) -> Any:
        bound = functools.partial(fn, **kwargs)
        return await self._with_retries(operation, lambda: asyncio.to_thread(bound), attempts=3)

    def _check_log_group(self, log_group: str) -> None:
        allowed = self.config.get("log_groups") or self.scope.get("log_groups") or []
        if allowed and log_group not in allowed:
            raise IntegrationError(
                f"Log group '{log_group}' is not configured for this integration",
                details={"allowed": allowed},
            )

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            await self._call(
                "describe_log_groups", self._logs_client().describe_log_groups, limit=1
            )
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=True,
            detail=f"region {self.config.get('region', 'us-east-1')}",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["log_search", "log_insights", "metrics"],
        )

    # -- read ---------------------------------------------------------------
    async def filter_log_events(
        self,
        *,
        log_group: str,
        pattern: str = "",
        minutes: int = 60,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        self._check_log_group(log_group)
        if len(pattern) > MAX_FILTER_PATTERN:
            raise ValidationError(f"filter pattern exceeds {MAX_FILTER_PATTERN} characters")

        end = datetime.now(UTC)
        start = end - timedelta(minutes=minutes)
        response = await self._call(
            "filter_log_events",
            self._logs_client().filter_log_events,
            logGroupName=log_group,
            startTime=int(start.timestamp() * 1000),
            endTime=int(end.timestamp() * 1000),
            filterPattern=pattern,
            limit=min(limit, 1000),
        )
        return [
            {
                "timestamp": datetime.fromtimestamp(e["timestamp"] / 1000, tz=UTC).isoformat(),
                "message": e.get("message", "")[:4000],
                "stream": e.get("logStreamName"),
            }
            for e in response.get("events", [])
        ]

    async def run_insights_query(
        self, *, log_group: str, query: str, minutes: int = 60, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Logs Insights. Read-only by construction of the service."""
        self._check_log_group(log_group)
        if len(query) > 8192:
            raise ValidationError("Insights query is too long")

        client = self._logs_client()
        end = datetime.now(UTC)
        start = end - timedelta(minutes=minutes)
        started = await self._call(
            "start_query",
            client.start_query,
            logGroupName=log_group,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=query,
            limit=min(limit, 1000),
        )
        query_id = started["queryId"]

        deadline = time.monotonic() + min(self.timeout_seconds, 60)
        while time.monotonic() < deadline:
            result = await self._call(
                "get_query_results", client.get_query_results, queryId=query_id
            )
            if result.get("status") in ("Complete", "Failed", "Cancelled"):
                if result.get("status") != "Complete":
                    raise IntegrationError(
                        f"Insights query {result.get('status')}",
                        details={"query_id": query_id},
                    )
                return [
                    {field["field"]: field["value"] for field in row}
                    for row in result.get("results", [])
                ]
            await asyncio.sleep(1.5)

        await self._call("stop_query", client.stop_query, queryId=query_id)
        raise IntegrationError("Insights query timed out", details={"query_id": query_id})

    async def get_metric_statistics(
        self,
        *,
        namespace: str,
        metric_name: str,
        dimensions: dict[str, str] | None = None,
        minutes: int = 60,
        period_seconds: int = 300,
        statistics: list[str] | None = None,
    ) -> dict[str, Any]:
        end = datetime.now(UTC)
        start = end - timedelta(minutes=minutes)
        response = await self._call(
            "get_metric_statistics",
            self._metrics_client().get_metric_statistics,
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": k, "Value": v} for k, v in (dimensions or {}).items()],
            StartTime=start,
            EndTime=end,
            Period=max(period_seconds, 60),
            Statistics=statistics or ["Average", "Maximum"],
        )
        points = sorted(response.get("Datapoints", []), key=lambda d: d["Timestamp"])
        return {
            "namespace": namespace,
            "metric": metric_name,
            "dimensions": dimensions or {},
            "unit": points[0].get("Unit") if points else None,
            "points": [
                {
                    "t": p["Timestamp"].isoformat(),
                    "avg": p.get("Average"),
                    "max": p.get("Maximum"),
                }
                for p in points
            ],
        }

    async def describe_alarms(self, *, state: str = "ALARM") -> list[dict[str, Any]]:
        response = await self._call(
            "describe_alarms",
            self._metrics_client().describe_alarms,
            StateValue=state,
            MaxRecords=50,
        )
        return [
            {
                "name": a.get("AlarmName"),
                "state": a.get("StateValue"),
                "reason": a.get("StateReason"),
                "metric": a.get("MetricName"),
                "namespace": a.get("Namespace"),
                "updated_at": a["StateUpdatedTimestamp"].isoformat()
                if a.get("StateUpdatedTimestamp")
                else None,
            }
            for a in response.get("MetricAlarms", [])
        ]
