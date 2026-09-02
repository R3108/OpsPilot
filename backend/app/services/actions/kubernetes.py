"""Kubernetes remediation actions.

Every parameter is a validated identifier, never a free-form string that could
become part of a command line. Names must match the RFC 1123 label pattern, so a
value like ``"; kubectl delete ns prod"`` cannot even be constructed.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IntegrationProvider, RiskTier
from app.services.actions.registry import (
    ActionSpec,
    BlastRadius,
    ExecutionContext,
    ExecutionResult,
    register_action,
)

# RFC 1123: lowercase alphanumeric and '-', must start/end alphanumeric.
DNS_LABEL = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
Name = Annotated[str, Field(min_length=1, max_length=253, pattern=DNS_LABEL)]


class _K8sBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: Name
    cluster: Annotated[str, Field(max_length=120, pattern=DNS_LABEL)] | None = None


def _scope_check(ctx: ExecutionContext, namespace: str) -> None:
    """Second fence: the integration's own namespace allowlist.

    The policy engine already checked protected namespaces; this catches the case
    where an integration was scoped more narrowly than the tenant policy.
    """
    allowed = ctx.scope.get("namespaces") or []
    if allowed and namespace not in allowed:
        raise PermissionError(
            f"namespace '{namespace}' is outside this integration's configured scope"
        )


# --------------------------------------------------------------------------
# restart a single pod
# --------------------------------------------------------------------------
class RestartPodParams(_K8sBase):
    pod_name: Name


async def _restart_pod(params: RestartPodParams, ctx: ExecutionContext) -> ExecutionResult:
    _scope_check(ctx, params.namespace)
    client = ctx.client(IntegrationProvider.KUBERNETES)

    pre = await client.get_pod(params.namespace, params.pod_name)
    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would delete pod {params.namespace}/{params.pod_name}",
            pre_state=pre,
            provider="kubernetes",
        )

    await client.delete_pod(params.namespace, params.pod_name)
    after = await client.wait_for_pod_replacement(
        params.namespace, params.pod_name, timeout_seconds=ctx.timeout_seconds
    )
    return ExecutionResult(
        succeeded=True,
        summary=f"Restarted pod {params.namespace}/{params.pod_name}",
        detail={"replacement": after},
        pre_state=pre,
        provider="kubernetes",
    )


register_action(
    ActionSpec(
        key="k8s.restart_pod",
        title="Restart a single pod",
        description=(
            "Delete one pod so its controller recreates it. Use for a single wedged or "
            "OOM-looping replica when the rest of the deployment is healthy."
        ),
        provider=IntegrationProvider.KUBERNETES,
        params_model=RestartPodParams,
        executor=_restart_pod,
        risk_tier=RiskTier.MEDIUM,
        is_reversible=False,  # you cannot un-delete a pod, but the controller heals it
        blast_radius_fn=lambda p: BlastRadius(
            scope="pod",
            targets=[f"{p.namespace}/{p.pod_name}"],
            estimated_affected_units=1,
            namespace=p.namespace,
            causes_downtime=False,
            notes="Controller recreates the pod; brief capacity reduction of one replica.",
        ),
        approval_checklist=[
            "Is the deployment running more than one replica?",
            "Has this pod already been restarted recently (crash-loop)?",
        ],
        examples=[{"namespace": "payments", "pod_name": "checkout-api-7d9f-abcde"}],
        timeout_seconds=120,
    )
)


# --------------------------------------------------------------------------
# rolling restart of a deployment
# --------------------------------------------------------------------------
class RolloutRestartParams(_K8sBase):
    deployment: Name


async def _rollout_restart(params: RolloutRestartParams, ctx: ExecutionContext) -> ExecutionResult:
    _scope_check(ctx, params.namespace)
    client = ctx.client(IntegrationProvider.KUBERNETES)

    pre = await client.get_deployment(params.namespace, params.deployment)
    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would roll {params.namespace}/{params.deployment}",
            pre_state=pre,
            provider="kubernetes",
        )

    await client.rollout_restart(params.namespace, params.deployment)
    status = await client.wait_for_rollout(
        params.namespace, params.deployment, timeout_seconds=ctx.timeout_seconds
    )
    return ExecutionResult(
        succeeded=bool(status.get("complete")),
        summary=f"Rolling restart of {params.namespace}/{params.deployment}",
        detail=status,
        pre_state=pre,
        provider="kubernetes",
        error=None if status.get("complete") else "rollout did not complete within timeout",
    )


register_action(
    ActionSpec(
        key="k8s.rollout_restart",
        title="Rolling restart of a deployment",
        description=(
            "Trigger a rolling restart of every pod in a deployment. Use for leaked "
            "resources or stale in-process state that a fresh start clears."
        ),
        provider=IntegrationProvider.KUBERNETES,
        params_model=RolloutRestartParams,
        executor=_rollout_restart,
        risk_tier=RiskTier.HIGH,
        is_reversible=False,
        blast_radius_fn=lambda p: BlastRadius(
            scope="deployment",
            targets=[f"{p.namespace}/{p.deployment}"],
            # Refined from live replica count by the policy engine when available.
            estimated_affected_units=0,
            namespace=p.namespace,
            service=p.deployment,
            causes_downtime=False,
            notes="Every replica is cycled; a bad image will roll out to all of them.",
        ),
        approval_checklist=[
            "Is the current image known-good? A rolling restart re-pulls it.",
            "Does the service have a readiness probe that will gate bad replicas?",
        ],
        timeout_seconds=300,
    )
)


# --------------------------------------------------------------------------
# scale a deployment
# --------------------------------------------------------------------------
class ScaleDeploymentParams(_K8sBase):
    deployment: Name
    replicas: Annotated[int, Field(ge=0, le=500)]


async def _scale_deployment(
    params: ScaleDeploymentParams, ctx: ExecutionContext
) -> ExecutionResult:
    _scope_check(ctx, params.namespace)
    client = ctx.client(IntegrationProvider.KUBERNETES)

    pre = await client.get_deployment(params.namespace, params.deployment)
    current = int(pre.get("replicas") or 0)

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=(
                f"[dry-run] would scale {params.namespace}/{params.deployment} "
                f"{current} -> {params.replicas}"
            ),
            pre_state=pre,
            provider="kubernetes",
        )

    await client.scale_deployment(params.namespace, params.deployment, params.replicas)
    status = await client.wait_for_rollout(
        params.namespace, params.deployment, timeout_seconds=ctx.timeout_seconds
    )
    return ExecutionResult(
        succeeded=True,
        summary=(
            f"Scaled {params.namespace}/{params.deployment} from {current} to {params.replicas}"
        ),
        detail={"previous_replicas": current, "new_replicas": params.replicas, **status},
        pre_state=pre,
        provider="kubernetes",
    )


def _scale_rollback(
    params: ScaleDeploymentParams, result: ExecutionResult
) -> tuple[str, dict[str, Any]] | None:
    previous = result.pre_state.get("replicas")
    if previous is None:
        return None
    return (
        "k8s.scale_deployment",
        {
            "namespace": params.namespace,
            "deployment": params.deployment,
            "replicas": int(previous),
            "cluster": params.cluster,
        },
    )


register_action(
    ActionSpec(
        key="k8s.scale_deployment",
        title="Scale a deployment",
        description=(
            "Set the replica count of a deployment. Use to add capacity during a "
            "saturation incident, or to shed load from a failing dependency."
        ),
        provider=IntegrationProvider.KUBERNETES,
        params_model=ScaleDeploymentParams,
        executor=_scale_deployment,
        risk_tier=RiskTier.HIGH,
        is_reversible=True,
        rollback_fn=_scale_rollback,
        blast_radius_fn=lambda p: BlastRadius(
            scope="deployment",
            targets=[f"{p.namespace}/{p.deployment}"],
            estimated_affected_units=p.replicas,
            namespace=p.namespace,
            service=p.deployment,
            causes_downtime=p.replicas == 0,
            notes=(
                "Scaling to zero takes the service fully offline."
                if p.replicas == 0
                else "Adds or removes capacity; downstream quotas may be affected."
            ),
        ),
        approval_checklist=[
            "Will the new replica count fit within cluster resource quota?",
            "Can the downstream database handle the extra connection count?",
        ],
        timeout_seconds=300,
    )
)


# --------------------------------------------------------------------------
# rollback a deployment to its previous revision
# --------------------------------------------------------------------------
class RollbackDeploymentParams(_K8sBase):
    deployment: Name
    # None = previous revision. Explicit revisions must be positive.
    to_revision: Annotated[int, Field(ge=1)] | None = None


async def _rollback_deployment(
    params: RollbackDeploymentParams, ctx: ExecutionContext
) -> ExecutionResult:
    _scope_check(ctx, params.namespace)
    client = ctx.client(IntegrationProvider.KUBERNETES)

    pre = await client.get_deployment(params.namespace, params.deployment)
    history = await client.get_rollout_history(params.namespace, params.deployment)
    if not history:
        return ExecutionResult.failure(
            f"No rollout history for {params.namespace}/{params.deployment}",
            error="no_revision_to_roll_back_to",
        )

    target = params.to_revision or (history[-2]["revision"] if len(history) > 1 else None)
    if target is None:
        return ExecutionResult.failure(
            f"{params.namespace}/{params.deployment} has only one revision",
            error="no_previous_revision",
        )

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=(
                f"[dry-run] would roll {params.namespace}/{params.deployment} "
                f"back to revision {target}"
            ),
            pre_state={**pre, "history": history},
            provider="kubernetes",
        )

    await client.rollback_deployment(params.namespace, params.deployment, target)
    status = await client.wait_for_rollout(
        params.namespace, params.deployment, timeout_seconds=ctx.timeout_seconds
    )
    return ExecutionResult(
        succeeded=bool(status.get("complete")),
        summary=(f"Rolled {params.namespace}/{params.deployment} back to revision {target}"),
        detail={"target_revision": target, "history": history, **status},
        pre_state=pre,
        provider="kubernetes",
        error=None if status.get("complete") else "rollback did not converge within timeout",
    )


def _rollback_undo(
    params: RollbackDeploymentParams, result: ExecutionResult
) -> tuple[str, dict[str, Any]] | None:
    previous_revision = result.pre_state.get("revision")
    if previous_revision is None:
        return None
    return (
        "k8s.rollback_deployment",
        {
            "namespace": params.namespace,
            "deployment": params.deployment,
            "to_revision": int(previous_revision),
            "cluster": params.cluster,
        },
    )


register_action(
    ActionSpec(
        key="k8s.rollback_deployment",
        title="Roll back a deployment",
        description=(
            "Return a deployment to a previous revision. The default remediation when "
            "evidence ties the incident to a recent deploy."
        ),
        provider=IntegrationProvider.KUBERNETES,
        params_model=RollbackDeploymentParams,
        executor=_rollback_deployment,
        risk_tier=RiskTier.HIGH,
        is_reversible=True,
        rollback_fn=_rollback_undo,
        blast_radius_fn=lambda p: BlastRadius(
            scope="deployment",
            targets=[f"{p.namespace}/{p.deployment}"],
            estimated_affected_units=0,
            namespace=p.namespace,
            service=p.deployment,
            causes_downtime=False,
            notes=(
                "Reverts application code. Any schema migration shipped with the bad "
                "release is NOT reverted and may be incompatible with the old code."
            ),
        ),
        approval_checklist=[
            "Did the suspect release include a database migration?",
            "Is the previous revision's image still present in the registry?",
            "Are there feature flags that assume the new code?",
        ],
        timeout_seconds=300,
    )
)


# --------------------------------------------------------------------------
# cordon a node
# --------------------------------------------------------------------------
class CordonNodeParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    node_name: Annotated[str, Field(min_length=1, max_length=253)]
    cluster: Annotated[str, Field(max_length=120, pattern=DNS_LABEL)] | None = None
    drain: bool = False


async def _cordon_node(params: CordonNodeParams, ctx: ExecutionContext) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.KUBERNETES)
    pre = await client.get_node(params.node_name)

    if ctx.dry_run:
        verb = "cordon and drain" if params.drain else "cordon"
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would {verb} node {params.node_name}",
            pre_state=pre,
            provider="kubernetes",
        )

    await client.cordon_node(params.node_name)
    drained: dict[str, Any] = {}
    if params.drain:
        drained = await client.drain_node(params.node_name, timeout_seconds=ctx.timeout_seconds)
    return ExecutionResult(
        succeeded=True,
        summary=f"Cordoned node {params.node_name}" + (" and drained it" if params.drain else ""),
        detail={"drained": drained},
        pre_state=pre,
        provider="kubernetes",
    )


register_action(
    ActionSpec(
        key="k8s.cordon_node",
        title="Cordon (optionally drain) a node",
        description=(
            "Mark a node unschedulable so no new pods land on it. Use when a node's "
            "disk, kubelet or network is degraded and it is poisoning the pods on it."
        ),
        provider=IntegrationProvider.KUBERNETES,
        params_model=CordonNodeParams,
        executor=_cordon_node,
        risk_tier=RiskTier.HIGH,
        is_reversible=True,
        rollback_fn=lambda p, _r: ("k8s.uncordon_node", {"node_name": p.node_name}),
        blast_radius_fn=lambda p: BlastRadius(
            scope="cluster",
            targets=[p.node_name],
            estimated_affected_units=0,
            causes_downtime=p.drain,
            notes=(
                "Draining evicts every pod on the node; ensure the cluster has spare "
                "capacity or workloads will go Pending."
                if p.drain
                else "Cordon alone does not move running pods."
            ),
        ),
        approval_checklist=[
            "Does the cluster have capacity for the evicted pods?",
            "Are any single-replica workloads pinned to this node?",
        ],
        timeout_seconds=600,
    )
)


class UncordonNodeParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    node_name: Annotated[str, Field(min_length=1, max_length=253)]


async def _uncordon_node(params: UncordonNodeParams, ctx: ExecutionContext) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.KUBERNETES)
    if ctx.dry_run:
        return ExecutionResult.ok(f"[dry-run] would uncordon {params.node_name}")
    await client.uncordon_node(params.node_name)
    return ExecutionResult(
        succeeded=True,
        summary=f"Uncordoned node {params.node_name}",
        provider="kubernetes",
    )


register_action(
    ActionSpec(
        key="k8s.uncordon_node",
        title="Uncordon a node",
        description="Make a node schedulable again. The inverse of k8s.cordon_node.",
        provider=IntegrationProvider.KUBERNETES,
        params_model=UncordonNodeParams,
        executor=_uncordon_node,
        risk_tier=RiskTier.MEDIUM,
        is_reversible=True,
        blast_radius_fn=lambda p: BlastRadius(
            scope="cluster", targets=[p.node_name], estimated_affected_units=0
        ),
    )
)
