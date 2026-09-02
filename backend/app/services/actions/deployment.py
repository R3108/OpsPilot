"""Source-control and release actions (GitHub)."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IntegrationProvider, RiskTier
from app.services.actions.registry import (
    ActionSpec,
    BlastRadius,
    ExecutionContext,
    ExecutionResult,
    register_action,
)

SHA = r"^[0-9a-f]{7,40}$"
REPO = r"^[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+$"
REF = r"^[A-Za-z0-9._\-/]{1,255}$"


class OpenRevertPrParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repo: Annotated[str, Field(pattern=REPO)]
    commit_sha: Annotated[str, Field(pattern=SHA)]
    base_branch: Annotated[str, Field(pattern=REF)] = "main"
    reason: Annotated[str, Field(min_length=1, max_length=2000)]


async def _open_revert_pr(params: OpenRevertPrParams, ctx: ExecutionContext) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.GITHUB)

    commit = await client.get_commit(params.repo, params.commit_sha)
    if commit is None:
        return ExecutionResult.failure(
            f"Commit {params.commit_sha} not found in {params.repo}",
            error="commit_not_found",
        )

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would open a revert PR for {params.commit_sha[:8]}",
            pre_state={"commit": commit},
            provider="github",
        )

    pr = await client.create_revert_pull_request(
        repo=params.repo,
        commit_sha=params.commit_sha,
        base_branch=params.base_branch,
        title=f'Revert "{commit.get("message", "").splitlines()[0][:80]}"',
        body=(
            f"Automated revert opened by OpsPilot during incident "
            f"`{ctx.incident_id}`.\n\n**Reason:** {params.reason}\n\n"
            f"This PR does **not** deploy on its own — a human still merges it."
        ),
    )
    return ExecutionResult(
        succeeded=True,
        summary=f"Opened revert PR #{pr.get('number')} in {params.repo}",
        detail={"pull_request": pr, "commit": commit},
        pre_state={"commit": commit},
        provider="github",
    )


register_action(
    ActionSpec(
        key="github.open_revert_pr",
        title="Open a revert pull request",
        description=(
            "Open (not merge) a PR reverting a suspect commit. Safe first move when a "
            "deploy is implicated but you want a human in the merge path."
        ),
        provider=IntegrationProvider.GITHUB,
        params_model=OpenRevertPrParams,
        executor=_open_revert_pr,
        risk_tier=RiskTier.LOW,
        is_reversible=True,
        requires_write_integration=True,
        blast_radius_fn=lambda p: BlastRadius(
            scope="none",
            targets=[f"{p.repo}@{p.commit_sha[:8]}"],
            estimated_affected_units=0,
            causes_downtime=False,
            notes="Creates a branch and a PR. Nothing is deployed by this action.",
        ),
        approval_checklist=["Does the revert conflict with commits landed since?"],
    )
)


class TriggerWorkflowParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repo: Annotated[str, Field(pattern=REPO)]
    # Workflow file name, restricted to the tenant's allowlist at execution time.
    workflow: Annotated[str, Field(pattern=r"^[A-Za-z0-9._\-]{1,100}\.ya?ml$")]
    ref: Annotated[str, Field(pattern=REF)] = "main"
    inputs: dict[str, str] = Field(default_factory=dict, max_length=20)


async def _trigger_workflow(
    params: TriggerWorkflowParams, ctx: ExecutionContext
) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.GITHUB)

    # Third fence: the integration's own workflow allowlist. A workflow that is
    # not explicitly listed cannot be dispatched no matter what the model says.
    allowed = ctx.scope.get("workflows") or []
    if params.workflow not in allowed:
        return ExecutionResult.failure(
            f"Workflow '{params.workflow}' is not in the integration's allowlist",
            error="workflow_not_allowlisted",
            allowed=allowed,
        )

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would dispatch {params.workflow} on {params.ref}",
            provider="github",
        )

    run = await client.dispatch_workflow(
        repo=params.repo, workflow=params.workflow, ref=params.ref, inputs=params.inputs
    )
    return ExecutionResult(
        succeeded=True,
        summary=f"Dispatched {params.workflow} on {params.repo}@{params.ref}",
        detail={"run": run},
        provider="github",
    )


register_action(
    ActionSpec(
        key="github.trigger_workflow",
        title="Dispatch an allowlisted GitHub Actions workflow",
        description=(
            "Run a pre-approved workflow (e.g. a redeploy-last-good or cache-warm job). "
            "Only workflows on the integration's allowlist can be dispatched."
        ),
        provider=IntegrationProvider.GITHUB,
        params_model=TriggerWorkflowParams,
        executor=_trigger_workflow,
        risk_tier=RiskTier.HIGH,
        is_reversible=False,
        blast_radius_fn=lambda p: BlastRadius(
            scope="service",
            targets=[f"{p.repo}:{p.workflow}"],
            estimated_affected_units=0,
            causes_downtime=False,
            notes="Effect depends entirely on what the allowlisted workflow does.",
        ),
        approval_checklist=[
            "Does this workflow deploy? If so, confirm the ref is the known-good one.",
            "Is another run of this workflow already in flight?",
        ],
        timeout_seconds=120,
    )
)
