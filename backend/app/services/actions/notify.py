"""Communication actions. Low risk, but still catalog-gated and audited."""

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

CHANNEL_ID = r"^[CGD][A-Z0-9]{6,20}$"


class PostIncidentUpdateParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    # Either an explicit channel id, or None to use the integration default.
    channel: Annotated[str, Field(pattern=CHANNEL_ID)] | None = None
    headline: Annotated[str, Field(min_length=1, max_length=280)]
    body: Annotated[str, Field(max_length=3000)] = ""
    # Rendered as a status pill, constrained so it cannot become arbitrary markup.
    status: Annotated[str, Field(pattern="^(investigating|identified|mitigating|resolved)$")]


async def _post_update(params: PostIncidentUpdateParams, ctx: ExecutionContext) -> ExecutionResult:
    client = ctx.client(IntegrationProvider.SLACK)
    channel = params.channel or (ctx.scope.get("default_channel") or [None])[0]
    if not channel:
        return ExecutionResult.failure(
            "No Slack channel specified and the integration has no default channel",
            error="no_channel",
        )

    if ctx.dry_run:
        return ExecutionResult(
            succeeded=True,
            summary=f"[dry-run] would post '{params.headline}' to {channel}",
            provider="slack",
        )

    message = await client.post_incident_update(
        channel=channel,
        headline=params.headline,
        body=params.body,
        status=params.status,
        incident_id=str(ctx.incident_id),
    )
    return ExecutionResult(
        succeeded=True,
        summary=f"Posted incident update to {channel}",
        detail={"message": message},
        provider="slack",
    )


register_action(
    ActionSpec(
        key="slack.post_incident_update",
        title="Post a status update to Slack",
        description=(
            "Send a short status update to the incident channel. Communication only — "
            "changes nothing in production."
        ),
        provider=IntegrationProvider.SLACK,
        params_model=PostIncidentUpdateParams,
        executor=_post_update,
        risk_tier=RiskTier.LOW,
        is_reversible=False,
        requires_write_integration=False,
        blast_radius_fn=lambda p: BlastRadius(
            scope="none",
            targets=[p.channel or "default-channel"],
            estimated_affected_units=0,
            causes_downtime=False,
            notes="Notification only.",
        ),
    )
)
