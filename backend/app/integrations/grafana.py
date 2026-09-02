"""Grafana: alert ingestion, dashboard links and incident annotations."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.logging import get_logger
from app.integrations.base import HealthReport, HttpProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)


class GrafanaClient(HttpProviderClient):
    provider = IntegrationProvider.GRAFANA

    def _headers(self) -> dict[str, str]:
        return {
            **super()._headers(),
            "Authorization": f"Bearer {self._credential('api_token')}",
            "Content-Type": "application/json",
        }

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            health = await self._get_json("/api/health")
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=str(health.get("database")) == "ok",
            detail=f"grafana {health.get('version', '?')}",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["alerts", "dashboards", "annotations"],
        )

    async def list_firing_alerts(self) -> list[dict[str, Any]]:
        payload = await self._get_json("/api/alertmanager/grafana/api/v2/alerts")
        return [
            {
                "name": a.get("labels", {}).get("alertname"),
                "severity": a.get("labels", {}).get("severity"),
                "state": (a.get("status") or {}).get("state"),
                "labels": a.get("labels", {}),
                "annotations": a.get("annotations", {}),
                "starts_at": a.get("startsAt"),
                "generator_url": a.get("generatorURL"),
            }
            for a in payload
            if (a.get("status") or {}).get("state") == "active"
        ]

    async def search_dashboards(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        payload = await self._get_json(
            "/api/search", query=query[:200], limit=limit, type="dash-db"
        )
        return [
            {
                "title": d.get("title"),
                "uid": d.get("uid"),
                "url": f"{self.base_url}{d.get('url', '')}",
                "tags": d.get("tags", []),
            }
            for d in payload
        ]

    async def get_annotations(
        self, *, minutes: int = 120, tags: list[str] | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Deploy markers and manual notes are a cheap, high-signal deploy source."""
        end = datetime.now(UTC)
        start = end - timedelta(minutes=minutes)
        params: dict[str, Any] = {
            "from": int(start.timestamp() * 1000),
            "to": int(end.timestamp() * 1000),
            "limit": limit,
        }
        if tags:
            params["tags"] = tags
        payload = await self._get_json("/api/annotations", **params)
        return [
            {
                "id": a.get("id"),
                "text": a.get("text"),
                "tags": a.get("tags", []),
                "at": datetime.fromtimestamp(a["time"] / 1000, tz=UTC).isoformat()
                if a.get("time")
                else None,
                "dashboard_uid": a.get("dashboardUID"),
                "panel_id": a.get("panelId"),
            }
            for a in payload
        ]

    async def create_annotation(
        self, *, text: str, tags: list[str], at: datetime | None = None
    ) -> dict[str, Any]:
        """Mark the incident on the dashboards so the graphs explain themselves."""
        self._require_write()
        moment = at or datetime.now(UTC)
        return await self._post_json(
            "/api/annotations",
            {
                "time": int(moment.timestamp() * 1000),
                "text": text[:1000],
                "tags": ["opspilot", *tags][:10],
            },
        )
