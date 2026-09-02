"""Kubernetes client.

Backed by ``kubernetes_asyncio``. The kubeconfig arrives as an encrypted
credential and is materialised into a private temp file only for the lifetime of
the client, then unlinked.

Read methods (used by investigators) and write methods (used only by action
executors) are separated below, and every write re-checks ``allow_write``.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.errors import IntegrationError
from app.core.logging import get_logger
from app.integrations.base import HealthReport, ProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)


class KubernetesClient(ProviderClient):
    provider = IntegrationProvider.KUBERNETES

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._api_client: Any = None
        self._kubeconfig_path: str | None = None

    # -- lifecycle -----------------------------------------------------------
    async def _api(self) -> Any:
        if self._api_client is not None:
            return self._api_client
        try:
            from kubernetes_asyncio import client as k8s_client
            from kubernetes_asyncio import config as k8s_config
        except ImportError as exc:  # pragma: no cover
            raise IntegrationError("kubernetes_asyncio is not installed") from exc

        kubeconfig = self._credential("kubeconfig")
        fd, path = tempfile.mkstemp(prefix="opspilot-kubeconfig-", suffix=".yaml")
        os.write(fd, kubeconfig.encode("utf-8"))
        os.close(fd)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        self._kubeconfig_path = path

        await k8s_config.load_kube_config(
            config_file=path, context=self.config.get("context") or None
        )
        self._api_client = k8s_client.ApiClient()
        return self._api_client

    async def aclose(self) -> None:
        if self._api_client is not None:
            with contextlib.suppress(Exception):
                await self._api_client.close()
            self._api_client = None
        if self._kubeconfig_path:
            with contextlib.suppress(OSError):
                os.unlink(self._kubeconfig_path)
            self._kubeconfig_path = None

    async def _core(self) -> Any:
        from kubernetes_asyncio import client as k8s_client

        return k8s_client.CoreV1Api(await self._api())

    async def _apps(self) -> Any:
        from kubernetes_asyncio import client as k8s_client

        return k8s_client.AppsV1Api(await self._api())

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            core = await self._core()
            await self._with_retries("list_namespace", lambda: core.list_namespace(limit=1))
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=True,
            detail=f"connected to cluster '{self.config.get('cluster', 'default')}'",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["pods", "deployments", "events", "logs", "nodes"],
        )

    # ======================================================================
    # read
    # ======================================================================
    async def list_pods(
        self, namespace: str, *, label_selector: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        core = await self._core()
        result = await self._with_retries(
            "list_pods",
            lambda: core.list_namespaced_pod(namespace, label_selector=label_selector, limit=limit),
        )
        return [_pod_summary(p) for p in result.items]

    async def get_pod(self, namespace: str, pod_name: str) -> dict[str, Any]:
        core = await self._core()
        try:
            pod = await self._with_retries(
                "get_pod", lambda: core.read_namespaced_pod(pod_name, namespace)
            )
        except Exception as exc:  # noqa: BLE001
            return {"name": pod_name, "namespace": namespace, "error": str(exc)[:300]}
        return _pod_summary(pod)

    async def get_pod_logs(
        self,
        namespace: str,
        pod_name: str,
        *,
        container: str | None = None,
        tail_lines: int = 500,
        since_seconds: int | None = 3600,
        previous: bool = False,
    ) -> str:
        core = await self._core()
        return await self._with_retries(
            "get_pod_logs",
            lambda: core.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container=container,
                tail_lines=min(tail_lines, 5000),
                since_seconds=since_seconds,
                previous=previous,
                timestamps=True,
            ),
        )

    async def get_deployment(self, namespace: str, deployment: str) -> dict[str, Any]:
        apps = await self._apps()
        try:
            dep = await self._with_retries(
                "get_deployment", lambda: apps.read_namespaced_deployment(deployment, namespace)
            )
        except Exception as exc:  # noqa: BLE001
            return {"name": deployment, "namespace": namespace, "error": str(exc)[:300]}
        return _deployment_summary(dep)

    async def list_deployments(self, namespace: str) -> list[dict[str, Any]]:
        apps = await self._apps()
        result = await self._with_retries(
            "list_deployments", lambda: apps.list_namespaced_deployment(namespace)
        )
        return [_deployment_summary(d) for d in result.items]

    async def get_rollout_history(
        self, namespace: str, deployment: str, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Revisions, newest last — from the deployment's ReplicaSets."""
        apps = await self._apps()
        dep = await self._with_retries(
            "get_deployment_for_history",
            lambda: apps.read_namespaced_deployment(deployment, namespace),
        )
        selector = ",".join(f"{k}={v}" for k, v in (dep.spec.selector.match_labels or {}).items())
        replica_sets = await self._with_retries(
            "list_replica_sets",
            lambda: apps.list_namespaced_replica_set(namespace, label_selector=selector),
        )
        history: list[dict[str, Any]] = []
        for rs in replica_sets.items:
            revision = (rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision")
            if revision is None:
                continue
            containers = rs.spec.template.spec.containers or []
            history.append(
                {
                    "revision": int(revision),
                    "replica_set": rs.metadata.name,
                    "created_at": _iso(rs.metadata.creation_timestamp),
                    "images": [c.image for c in containers],
                    "replicas": rs.spec.replicas,
                    "change_cause": (rs.metadata.annotations or {}).get(
                        "kubernetes.io/change-cause"
                    ),
                }
            )
        history.sort(key=lambda h: h["revision"])
        return history[-limit:]

    async def get_events(
        self, namespace: str, *, since_minutes: int = 60, limit: int = 100
    ) -> list[dict[str, Any]]:
        core = await self._core()
        result = await self._with_retries(
            "list_events", lambda: core.list_namespaced_event(namespace, limit=500)
        )
        cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
        events: list[dict[str, Any]] = []
        for event in result.items:
            ts = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
            if ts is not None and ts.replace(tzinfo=ts.tzinfo or UTC) < cutoff:
                continue
            events.append(
                {
                    "type": event.type,
                    "reason": event.reason,
                    "message": event.message,
                    "count": event.count,
                    "object": (
                        f"{event.involved_object.kind}/{event.involved_object.name}"
                        if event.involved_object
                        else None
                    ),
                    "at": _iso(ts),
                }
            )
        events.sort(key=lambda e: e["at"] or "", reverse=True)
        return events[:limit]

    async def get_node(self, node_name: str) -> dict[str, Any]:
        core = await self._core()
        try:
            node = await self._with_retries("get_node", lambda: core.read_node(node_name))
        except Exception as exc:  # noqa: BLE001
            return {"name": node_name, "error": str(exc)[:300]}
        conditions = {c.type: c.status for c in (node.status.conditions or [])}
        return {
            "name": node.metadata.name,
            "unschedulable": bool(node.spec.unschedulable),
            "conditions": conditions,
            "allocatable": dict(node.status.allocatable or {}),
            "capacity": dict(node.status.capacity or {}),
            "kubelet_version": node.status.node_info.kubelet_version
            if node.status.node_info
            else None,
        }

    # ======================================================================
    # write  (only reachable through registered action executors)
    # ======================================================================
    async def delete_pod(self, namespace: str, pod_name: str) -> None:
        self._require_write()
        core = await self._core()
        await self._with_retries(
            "delete_pod", lambda: core.delete_namespaced_pod(pod_name, namespace)
        )

    async def rollout_restart(self, namespace: str, deployment: str) -> None:
        self._require_write()
        apps = await self._apps()
        patch = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {"opspilot.io/restartedAt": datetime.now(UTC).isoformat()}
                    }
                }
            }
        }
        await self._with_retries(
            "rollout_restart",
            lambda: apps.patch_namespaced_deployment(deployment, namespace, patch),
        )

    async def scale_deployment(self, namespace: str, deployment: str, replicas: int) -> None:
        self._require_write()
        apps = await self._apps()
        await self._with_retries(
            "scale_deployment",
            lambda: apps.patch_namespaced_deployment_scale(
                deployment, namespace, {"spec": {"replicas": int(replicas)}}
            ),
        )

    async def rollback_deployment(self, namespace: str, deployment: str, to_revision: int) -> None:
        """Roll back by re-applying the target ReplicaSet's pod template.

        ``kubectl rollout undo`` is client-side sugar for exactly this; doing it
        explicitly keeps the operation inspectable and lets us record which
        ReplicaSet we took the template from.
        """
        self._require_write()
        apps = await self._apps()
        dep = await apps.read_namespaced_deployment(deployment, namespace)
        selector = ",".join(f"{k}={v}" for k, v in (dep.spec.selector.match_labels or {}).items())
        replica_sets = await apps.list_namespaced_replica_set(namespace, label_selector=selector)

        target = next(
            (
                rs
                for rs in replica_sets.items
                if (rs.metadata.annotations or {}).get("deployment.kubernetes.io/revision")
                == str(to_revision)
            ),
            None,
        )
        if target is None:
            raise IntegrationError(
                f"revision {to_revision} not found for {namespace}/{deployment}",
                details={"namespace": namespace, "deployment": deployment},
            )

        template = self._api_client.sanitize_for_serialization(target.spec.template)
        # Drop the pod-template-hash the controller manages itself.
        template.get("metadata", {}).get("labels", {}).pop("pod-template-hash", None)
        patch = {
            "spec": {"template": template},
            "metadata": {
                "annotations": {
                    "kubernetes.io/change-cause": f"OpsPilot rollback to revision {to_revision}"
                }
            },
        }
        await self._with_retries(
            "rollback_deployment",
            lambda: apps.patch_namespaced_deployment(deployment, namespace, patch),
        )

    async def cordon_node(self, node_name: str) -> None:
        self._require_write()
        core = await self._core()
        await self._with_retries(
            "cordon_node",
            lambda: core.patch_node(node_name, {"spec": {"unschedulable": True}}),
        )

    async def uncordon_node(self, node_name: str) -> None:
        self._require_write()
        core = await self._core()
        await self._with_retries(
            "uncordon_node",
            lambda: core.patch_node(node_name, {"spec": {"unschedulable": False}}),
        )

    async def drain_node(self, node_name: str, *, timeout_seconds: int = 300) -> dict[str, Any]:
        """Evict every non-DaemonSet, non-mirror pod from a node."""
        self._require_write()
        from kubernetes_asyncio import client as k8s_client

        core = await self._core()
        pods = await core.list_pod_for_all_namespaces(field_selector=f"spec.nodeName={node_name}")
        evicted: list[str] = []
        skipped: list[str] = []
        for pod in pods.items:
            owners = pod.metadata.owner_references or []
            if any(o.kind == "DaemonSet" for o in owners):
                skipped.append(f"{pod.metadata.namespace}/{pod.metadata.name} (DaemonSet)")
                continue
            body = k8s_client.V1Eviction(
                metadata=k8s_client.V1ObjectMeta(
                    name=pod.metadata.name, namespace=pod.metadata.namespace
                )
            )
            try:
                await core.create_namespaced_pod_eviction(
                    pod.metadata.name, pod.metadata.namespace, body
                )
                evicted.append(f"{pod.metadata.namespace}/{pod.metadata.name}")
            except Exception as exc:  # noqa: BLE001 - PDB rejections are expected
                skipped.append(f"{pod.metadata.namespace}/{pod.metadata.name} ({exc})")
        return {"evicted": evicted, "skipped": skipped, "timeout_seconds": timeout_seconds}

    # ======================================================================
    # waiters
    # ======================================================================
    async def wait_for_rollout(
        self, namespace: str, deployment: str, *, timeout_seconds: int = 300
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        apps = await self._apps()
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            dep = await apps.read_namespaced_deployment(deployment, namespace)
            status = dep.status
            desired = dep.spec.replicas or 0
            last = {
                "desired": desired,
                "updated": status.updated_replicas or 0,
                "ready": status.ready_replicas or 0,
                "available": status.available_replicas or 0,
                "unavailable": status.unavailable_replicas or 0,
                "observed_generation": status.observed_generation,
                "generation": dep.metadata.generation,
            }
            converged = (
                last["observed_generation"] == last["generation"]
                and last["updated"] == desired
                and last["ready"] == desired
                and last["unavailable"] == 0
            )
            if converged:
                return {**last, "complete": True}
            await asyncio.sleep(3)
        return {**last, "complete": False}

    async def wait_for_pod_replacement(
        self, namespace: str, pod_name: str, *, timeout_seconds: int = 120
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        core = await self._core()
        while time.monotonic() < deadline:
            try:
                pod = await core.read_namespaced_pod(pod_name, namespace)
            except Exception:  # noqa: BLE001 - 404 means it is gone, which is the goal
                return {"deleted": True, "replacement_ready": None}
            if pod.metadata.deletion_timestamp is None and pod.status.phase == "Running":
                return {"deleted": True, "replacement_ready": True, **_pod_summary(pod)}
            await asyncio.sleep(2)
        return {"deleted": False, "replacement_ready": False}


# --------------------------------------------------------------------------
def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return value.isoformat()


def _pod_summary(pod: Any) -> dict[str, Any]:
    statuses = pod.status.container_statuses or []
    containers = [
        {
            "name": cs.name,
            "ready": cs.ready,
            "restart_count": cs.restart_count,
            "image": cs.image,
            "state": next(
                (
                    name
                    for name in ("running", "waiting", "terminated")
                    if getattr(cs.state, name, None) is not None
                ),
                "unknown",
            ),
            "reason": (
                getattr(cs.state.waiting, "reason", None)
                or getattr(cs.state.terminated, "reason", None)
                if cs.state
                else None
            ),
            "last_exit_code": (
                getattr(cs.last_state.terminated, "exit_code", None)
                if cs.last_state and cs.last_state.terminated
                else None
            ),
        }
        for cs in statuses
    ]
    return {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "node": pod.spec.node_name,
        "phase": pod.status.phase,
        "start_time": _iso(pod.status.start_time),
        "restart_count": sum(c["restart_count"] or 0 for c in containers),
        "containers": containers,
        "labels": dict(pod.metadata.labels or {}),
        "conditions": {c.type: c.status for c in (pod.status.conditions or [])},
    }


def _deployment_summary(dep: Any) -> dict[str, Any]:
    containers = dep.spec.template.spec.containers or []
    return {
        "name": dep.metadata.name,
        "namespace": dep.metadata.namespace,
        "replicas": dep.spec.replicas,
        "ready_replicas": dep.status.ready_replicas or 0,
        "available_replicas": dep.status.available_replicas or 0,
        "unavailable_replicas": dep.status.unavailable_replicas or 0,
        "updated_replicas": dep.status.updated_replicas or 0,
        "revision": int(
            (dep.metadata.annotations or {}).get("deployment.kubernetes.io/revision", 0)
        ),
        "images": [c.image for c in containers],
        "resources": [
            {
                "container": c.name,
                "requests": dict((c.resources.requests or {}) if c.resources else {}),
                "limits": dict((c.resources.limits or {}) if c.resources else {}),
            }
            for c in containers
        ],
        "strategy": dep.spec.strategy.type if dep.spec.strategy else None,
        "created_at": _iso(dep.metadata.creation_timestamp),
        "change_cause": (dep.metadata.annotations or {}).get("kubernetes.io/change-cause"),
    }
