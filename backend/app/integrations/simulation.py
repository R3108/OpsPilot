"""Deterministic in-process provider backends.

Used by the eval harness, the automated tests and the local demo seed. A tenant
opts in per integration with ``config.mode = "simulation"``; it is never a
fallback for a broken real integration.

Why it exists
-------------
The verification loop is only meaningful if remediation can actually *change* the
world. A scenario therefore declares a ``resolution``: the action (and parameter
constraints) that fixes it. When a matching action executes, the world flips to
its post-remediation metrics, so ``verify_recovery`` observes a genuine recovery
— and observes a genuine *non*-recovery when the agent picked the wrong action.
That is what makes the eval datasets score something real.

Scope note: worlds live in process memory, so simulation mode assumes the graph
runs in a single worker process. That holds for evals, tests and the demo.
"""

from __future__ import annotations

import copy
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.logging import get_logger
from app.integrations.base import HealthReport, ProviderClient
from app.models.enums import IntegrationProvider
from app.models.integration import Integration

log = get_logger(__name__)

_WORLDS: dict[str, SimulatedWorld] = {}
_LOCK = threading.Lock()


class SimulatedWorld:
    """Mutable state for one scenario."""

    def __init__(self, scenario: dict[str, Any]) -> None:
        self.name: str = scenario.get("name", "unnamed")
        self.scenario = copy.deepcopy(scenario)
        self.state: dict[str, Any] = copy.deepcopy(scenario.get("initial_state", {}))
        self.remediated = False
        self.applied_actions: list[dict[str, Any]] = []
        self.created_at = datetime.now(UTC)

    # -- the bit that makes verification honest ------------------------------
    def apply_action(self, action_key: str, params: dict[str, Any]) -> bool:
        """Record an action and, if it is the scenario's fix, heal the world."""
        self.applied_actions.append({"action_key": action_key, "params": params})
        resolution = self.scenario.get("resolution") or {}
        if self.remediated or action_key != resolution.get("action_key"):
            return False
        for key, expected in (resolution.get("params_match") or {}).items():
            actual = params.get(key)
            if isinstance(expected, dict):
                if "min" in expected and (actual is None or actual < expected["min"]):
                    return False
                if "max" in expected and (actual is None or actual > expected["max"]):
                    return False
            elif actual != expected:
                return False

        self.remediated = True
        self.state = _deep_merge(self.state, self.scenario.get("resolved_state", {}))
        log.info("simulation.remediated", scenario=self.name, action_key=action_key)
        return True

    def now(self) -> datetime:
        return datetime.now(UTC)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def get_world(key: str, scenario: dict[str, Any] | None = None) -> SimulatedWorld:
    with _LOCK:
        world = _WORLDS.get(key)
        if world is None:
            world = SimulatedWorld(scenario or {})
            _WORLDS[key] = world
        return world


def reset_world(key: str, scenario: dict[str, Any]) -> SimulatedWorld:
    with _LOCK:
        world = SimulatedWorld(scenario)
        _WORLDS[key] = world
        return world


def clear_worlds() -> None:
    with _LOCK:
        _WORLDS.clear()


# --------------------------------------------------------------------------
class _SimulatedBase(ProviderClient):
    def __init__(self, *, world: SimulatedWorld, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.world = world

    async def health_check(self) -> HealthReport:
        return HealthReport(
            healthy=True,
            detail=f"simulation: {self.world.name}",
            latency_ms=1,
            capabilities=["simulation"],
        )

    def _s(self, *path: str, default: Any = None) -> Any:
        node: Any = self.world.state
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node


class SimulatedKubernetes(_SimulatedBase):
    provider = IntegrationProvider.KUBERNETES

    async def list_pods(self, namespace: str, **_: Any) -> list[dict[str, Any]]:
        return [p for p in self._s("pods", default=[]) if p.get("namespace") == namespace]

    async def get_pod(self, namespace: str, pod_name: str) -> dict[str, Any]:
        for pod in self._s("pods", default=[]):
            if pod.get("namespace") == namespace and pod.get("name") == pod_name:
                return copy.deepcopy(pod)
        return {"name": pod_name, "namespace": namespace, "error": "not found"}

    async def get_pod_logs(self, namespace: str, pod_name: str, **_: Any) -> str:
        logs = self._s("logs", default={})
        lines = logs.get(pod_name) or logs.get("default") or []
        base = self.world.now() - timedelta(minutes=len(lines))
        return "\n".join(
            f"{(base + timedelta(minutes=i)).isoformat()} {line}" for i, line in enumerate(lines)
        )

    async def get_deployment(self, namespace: str, deployment: str) -> dict[str, Any]:
        for dep in self._s("deployments", default=[]):
            if dep.get("namespace") == namespace and dep.get("name") == deployment:
                return copy.deepcopy(dep)
        return {"name": deployment, "namespace": namespace, "error": "not found"}

    async def list_deployments(self, namespace: str) -> list[dict[str, Any]]:
        return [d for d in self._s("deployments", default=[]) if d.get("namespace") == namespace]

    async def get_rollout_history(
        self, namespace: str, deployment: str, **_: Any
    ) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("rollout_history", default={}).get(deployment, []))

    async def get_events(self, namespace: str, **_: Any) -> list[dict[str, Any]]:
        return [
            e for e in self._s("events", default=[]) if e.get("namespace", namespace) == namespace
        ]

    async def get_node(self, node_name: str) -> dict[str, Any]:
        for node in self._s("nodes", default=[]):
            if node.get("name") == node_name:
                return copy.deepcopy(node)
        return {"name": node_name, "error": "not found"}

    # -- writes --------------------------------------------------------------
    async def delete_pod(self, namespace: str, pod_name: str) -> None:
        self._require_write()
        self.world.apply_action("k8s.restart_pod", {"namespace": namespace, "pod_name": pod_name})

    async def rollout_restart(self, namespace: str, deployment: str) -> None:
        self._require_write()
        self.world.apply_action(
            "k8s.rollout_restart", {"namespace": namespace, "deployment": deployment}
        )

    async def scale_deployment(self, namespace: str, deployment: str, replicas: int) -> None:
        self._require_write()
        self.world.apply_action(
            "k8s.scale_deployment",
            {"namespace": namespace, "deployment": deployment, "replicas": replicas},
        )
        for dep in self.world.state.get("deployments", []):
            if dep.get("name") == deployment and dep.get("namespace") == namespace:
                dep["replicas"] = replicas
                dep["ready_replicas"] = replicas

    async def rollback_deployment(self, namespace: str, deployment: str, to_revision: int) -> None:
        self._require_write()
        self.world.apply_action(
            "k8s.rollback_deployment",
            {"namespace": namespace, "deployment": deployment, "to_revision": to_revision},
        )

    async def cordon_node(self, node_name: str) -> None:
        self._require_write()
        self.world.apply_action("k8s.cordon_node", {"node_name": node_name})

    async def uncordon_node(self, node_name: str) -> None:
        self._require_write()
        self.world.apply_action("k8s.uncordon_node", {"node_name": node_name})

    async def drain_node(self, node_name: str, **_: Any) -> dict[str, Any]:
        self._require_write()
        return {"evicted": [], "skipped": []}

    async def wait_for_rollout(self, namespace: str, deployment: str, **_: Any) -> dict[str, Any]:
        dep = await self.get_deployment(namespace, deployment)
        desired = dep.get("replicas", 1)
        return {"complete": True, "desired": desired, "ready": desired, "updated": desired}

    async def wait_for_pod_replacement(
        self, namespace: str, pod_name: str, **_: Any
    ) -> dict[str, Any]:
        return {"deleted": True, "replacement_ready": True}


class SimulatedPrometheus(_SimulatedBase):
    provider = IntegrationProvider.PROMETHEUS

    def _metric_points(self, name: str) -> list[dict[str, float]]:
        """Materialise a series from the scenario's metric spec.

        A spec is ``{"baseline": x, "current": y, "breakpoint_minutes_ago": n}``:
        the series sits at baseline, then steps to current at the breakpoint. That
        gives the correlation node a real change-point to find.
        """
        spec = self._s("metrics", name, default=None)
        if spec is None:
            return []
        if isinstance(spec, list):
            return [{"t": float(i), "v": float(v)} for i, v in enumerate(spec)]

        baseline = float(spec.get("baseline", 0.0))
        current = float(spec.get("current", baseline))
        window = int(spec.get("window_minutes", 60))
        breakpoint_at = int(spec.get("breakpoint_minutes_ago", window // 2))
        now = self.world.now().timestamp()
        points: list[dict[str, float]] = []
        for minute in range(window, 0, -1):
            value = baseline if minute > breakpoint_at else current
            # Deterministic jitter keyed off the metric name and minute.
            jitter = ((hash((name, minute)) % 1000) / 1000.0 - 0.5) * value * 0.04
            points.append({"t": now - minute * 60, "v": round(value + jitter, 6)})
        return points

    async def query(self, promql: str, **_: Any) -> dict[str, Any]:
        return await self.query_range(promql)

    async def query_range(self, promql: str, **_: Any) -> dict[str, Any]:
        name = _guess_metric_name(promql, self._s("metrics", default={}))
        points = self._metric_points(name) if name else []
        return {
            "result_type": "matrix",
            "series_count": 1 if points else 0,
            "series": (
                [
                    {
                        "metric": {"__name__": name},
                        "points": points,
                        "last": points[-1]["v"],
                        "min": min(p["v"] for p in points),
                        "max": max(p["v"] for p in points),
                    }
                ]
                if points
                else []
            ),
            "query": promql,
        }

    async def standard_query(self, name: str, **kwargs: Any) -> dict[str, Any]:
        points = self._metric_points(name)
        return {
            "name": name,
            "promql": f"<simulated {name}>",
            "result_type": "matrix",
            "series_count": 1 if points else 0,
            "series": (
                [
                    {
                        "metric": {"__name__": name},
                        "points": points,
                        "last": points[-1]["v"],
                        "min": min(p["v"] for p in points),
                        "max": max(p["v"] for p in points),
                    }
                ]
                if points
                else []
            ),
        }

    async def active_alerts(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("alerts", default=[]))

    async def series_labels(self, match: str, **_: Any) -> list[dict[str, str]]:
        return []


class SimulatedGitHub(_SimulatedBase):
    provider = IntegrationProvider.GITHUB

    async def list_recent_commits(self, repo: str, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("commits", default=[]))

    async def get_commit(self, repo: str, sha: str) -> dict[str, Any] | None:
        for commit in self._s("commits", default=[]):
            if str(commit.get("sha", "")).startswith(sha[:7]):
                return copy.deepcopy(commit)
        return None

    async def list_deployments(self, repo: str, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("deployments_gh", default=[]))

    async def list_recent_pull_requests(self, repo: str, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("pull_requests", default=[]))

    async def get_workflow_runs(self, repo: str, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("workflow_runs", default=[]))

    async def create_revert_pull_request(
        self, *, repo: str, commit_sha: str, **_: Any
    ) -> dict[str, Any]:
        self._require_write()
        self.world.apply_action("github.open_revert_pr", {"repo": repo, "commit_sha": commit_sha})
        return {"number": 4242, "url": f"https://github.com/{repo}/pull/4242", "state": "open"}

    async def dispatch_workflow(
        self, *, repo: str, workflow: str, ref: str, inputs: dict[str, str]
    ) -> dict[str, Any]:
        self._require_write()
        self.world.apply_action(
            "github.trigger_workflow", {"repo": repo, "workflow": workflow, "ref": ref}
        )
        return {"workflow": workflow, "ref": ref, "dispatched_at": self.world.now().isoformat()}


class SimulatedPostgres(_SimulatedBase):
    provider = IntegrationProvider.POSTGRES

    # Postgres' terminate_backend takes only pids — the database is implied by
    # the connection. The real client inherits that from its DSN; the simulator
    # has no connection, so it remembers the database the caller last asked
    # about and reports it alongside the action. Without this, a scenario could
    # not assert that the agent targeted the *right* database.
    _last_database: str = ""

    async def connection_summary(self, database: str) -> dict[str, Any]:
        self._last_database = database
        return copy.deepcopy(self._s("db", "connections", default={"database": database}))

    async def list_idle_in_transaction(self, **kwargs: Any) -> list[dict[str, Any]]:
        self._last_database = kwargs.get("database") or self._last_database
        rows = copy.deepcopy(self._s("db", "idle_in_transaction", default=[]))
        threshold = kwargs.get("idle_seconds", 0)
        return [r for r in rows if float(r.get("idle_seconds", 0)) >= threshold][
            : kwargs.get("limit", 25)
        ]

    async def list_long_running_queries(self, **kwargs: Any) -> list[dict[str, Any]]:
        rows = copy.deepcopy(self._s("db", "long_queries", default=[]))
        return [
            r for r in rows if float(r.get("duration_seconds", 0)) >= kwargs.get("min_seconds", 0)
        ]

    async def get_backend(self, database: str, pid: int) -> dict[str, Any] | None:
        self._last_database = database
        for row in self._s("db", "long_queries", default=[]):
            if int(row.get("pid", -1)) == pid:
                return copy.deepcopy(row)
        return None

    async def list_blocking_locks(self, database: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("db", "blocking_locks", default=[]))

    async def table_bloat(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("db", "table_bloat", default=[]))

    async def replication_status(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("db", "replication", default=[]))

    async def cache_hit_ratio(self, database: str) -> dict[str, Any]:
        return copy.deepcopy(self._s("db", "cache", default={}))

    async def transaction_stats(self, database: str) -> dict[str, Any]:
        return copy.deepcopy(self._s("db", "transactions", default={}))

    async def get_role_connection_limit(self, database: str, role: str) -> dict[str, Any]:
        return {"role": role, "connection_limit": self._s("db", "role_limits", role, default=-1)}

    async def full_health_snapshot(self, database: str) -> dict[str, Any]:
        return {
            "connections": await self.connection_summary(database),
            "blocking_locks": await self.list_blocking_locks(database),
            "long_running_queries": await self.list_long_running_queries(database=database),
            "cache": await self.cache_hit_ratio(database),
            "transactions": await self.transaction_stats(database),
            "table_bloat": await self.table_bloat(),
            "replication": await self.replication_status(),
        }

    async def terminate_backends(self, pids: list[int]) -> list[int]:
        self._require_write()
        self.world.apply_action(
            "db.terminate_idle_connections",
            {"pids": pids, "database": self._last_database},
        )
        remaining = [
            r
            for r in self.world.state.get("db", {}).get("idle_in_transaction", [])
            if int(r.get("pid", -1)) not in pids
        ]
        self.world.state.setdefault("db", {})["idle_in_transaction"] = remaining
        return list(pids)

    async def set_role_connection_limit(
        self, database: str, role: str, connection_limit: int
    ) -> None:
        self._require_write()
        self.world.apply_action(
            "db.set_connection_limit",
            {"database": database, "role": role, "connection_limit": connection_limit},
        )
        self.world.state.setdefault("db", {}).setdefault("role_limits", {})[role] = connection_limit


class SimulatedSlack(_SimulatedBase):
    provider = IntegrationProvider.SLACK

    async def post_incident_update(self, **kwargs: Any) -> dict[str, Any]:
        self.world.state.setdefault("slack_messages", []).append(kwargs)
        return {"channel": kwargs.get("channel"), "ts": f"{self.world.now().timestamp():.6f}"}

    async def request_approval(self, **kwargs: Any) -> dict[str, Any]:
        self.world.state.setdefault("slack_approvals", []).append(kwargs)
        return {"channel": kwargs.get("channel"), "ts": f"{self.world.now().timestamp():.6f}"}

    async def update_message(self, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    async def resolve_approval_message(self, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    async def get_user(self, user_id: str) -> dict[str, Any]:
        return {"id": user_id, "name": "sim-user", "email": "sim@example.com"}

    async def get_channel_history(self, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("slack_history", default=[]))


class SimulatedCloudWatch(_SimulatedBase):
    provider = IntegrationProvider.CLOUDWATCH

    async def filter_log_events(
        self, *, log_group: str, pattern: str = "", **_: Any
    ) -> list[dict[str, Any]]:
        entries = self._s("cloudwatch_logs", default={}).get(log_group, [])
        if pattern:
            needle = pattern.strip('"').lower()
            entries = [e for e in entries if needle in str(e.get("message", "")).lower()]
        return copy.deepcopy(entries)

    async def run_insights_query(self, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("cloudwatch_insights", default=[]))

    async def get_metric_statistics(
        self, *, namespace: str, metric_name: str, **_: Any
    ) -> dict[str, Any]:
        return {
            "namespace": namespace,
            "metric": metric_name,
            "points": copy.deepcopy(self._s("cloudwatch_metrics", metric_name, default=[])),
        }

    async def describe_alarms(self, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("cloudwatch_alarms", default=[]))


class SimulatedGrafana(_SimulatedBase):
    provider = IntegrationProvider.GRAFANA

    async def list_firing_alerts(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("alerts", default=[]))

    async def search_dashboards(self, query: str, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("dashboards", default=[]))

    async def get_annotations(self, **_: Any) -> list[dict[str, Any]]:
        return copy.deepcopy(self._s("annotations", default=[]))

    async def create_annotation(self, **_: Any) -> dict[str, Any]:
        return {"id": 1}


_SIMULATED: dict[IntegrationProvider, type[_SimulatedBase]] = {
    IntegrationProvider.KUBERNETES: SimulatedKubernetes,
    IntegrationProvider.PROMETHEUS: SimulatedPrometheus,
    IntegrationProvider.GITHUB: SimulatedGitHub,
    IntegrationProvider.POSTGRES: SimulatedPostgres,
    IntegrationProvider.SLACK: SimulatedSlack,
    IntegrationProvider.CLOUDWATCH: SimulatedCloudWatch,
    IntegrationProvider.GRAFANA: SimulatedGrafana,
}


def simulated_client(
    integration: Integration,
    credentials: dict[str, str],
    scenario: str | None = None,
) -> ProviderClient | None:
    """Build a simulated client, optionally for a specific scenario.

    One tenant can hold several scenario worlds at once — the demo seeds five
    incidents into a single organisation — so the caller passes which one this
    investigation is about (normally from ``incident.labels['scenario']``).
    Without that hint every incident would read whichever world was provisioned
    last, and the investigators would be handed another incident's evidence.
    """
    cls = _SIMULATED.get(integration.provider)
    if cls is None:
        return None

    config = integration.config or {}
    name = str(scenario or config.get("scenario") or "default")
    worlds = config.get("worlds") or {}
    payload = worlds.get(name) or config.get("scenario_data") or {}

    world_key = str(config.get("world_key") or f"{integration.tenant_id}:{name}")
    world = get_world(world_key, payload)
    # A cached world left over from a different scenario would silently feed the
    # investigators the wrong evidence; re-seed it rather than serve it.
    if payload and world.name != payload.get("name", name):
        world = reset_world(world_key, payload)

    return cls(
        world=world,
        integration_id=integration.id,
        config=integration.config,
        credentials=credentials,
        scope=integration.scope,
        allow_write=integration.allow_write,
    )


def world_key_for(tenant_id: uuid.UUID | str, scenario: str) -> str:
    return f"{tenant_id}:{scenario}"


def _guess_metric_name(promql: str, metrics: dict[str, Any]) -> str | None:
    """Map an arbitrary PromQL string onto one of the scenario's named metrics."""
    lowered = promql.lower()
    for name in metrics:
        if name.lower() in lowered:
            return name
    keyword_map = {
        "error": "error_rate",
        "5..": "error_rate",
        "duration_seconds_bucket": "latency_p99",
        "quantile": "latency_p99",
        "memory": "memory_usage",
        "cpu": "cpu_usage",
        "restarts": "pod_restarts",
        "pg_stat_activity": "db_connections",
        "requests_total": "request_rate",
    }
    for needle, name in keyword_map.items():
        if re.search(re.escape(needle), lowered) and name in metrics:
            return name
    return next(iter(metrics), None)
