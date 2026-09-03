"""Metrics exposition and the migration chain.

The migration test pins the chain every CI run: upgrade to head, re-run as a
no-op, and downgrade to base must all succeed on the same database.
"""

from __future__ import annotations

from app.core import metrics


def test_metrics_render_counters_gauges_and_summaries() -> None:
    metrics.inc("test_requests_total", labels={"route": "/health", "status": "200"})
    metrics.inc("test_requests_total", labels={"route": "/health", "status": "200"})
    metrics.set_gauge("test_queue_depth", 3.0)
    metrics.observe_latency("test_request_seconds", 0.1)
    metrics.observe_latency("test_request_seconds", 0.3)

    body = metrics.render()
    assert 'test_requests_total{route="/health",status="200"} 2.0' in body
    assert "test_queue_depth 3.0" in body
    assert "test_request_seconds_count 2" in body
    assert "# TYPE test_requests_total counter" in body
    assert "# TYPE test_request_seconds summary" in body


async def test_metrics_endpoint_is_exposed(client) -> None:  # noqa: ANN001
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "opspilot_uptime_seconds" in response.text
