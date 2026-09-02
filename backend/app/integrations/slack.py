"""Slack: alert ingestion source, notification sink, and an approval surface."""

from __future__ import annotations

import time
from typing import Any

from app.core.logging import get_logger
from app.integrations.base import HealthReport, HttpProviderClient
from app.models.enums import IntegrationProvider, RiskTier

log = get_logger(__name__)

STATUS_EMOJI = {
    "investigating": "🔎",
    "identified": "🎯",
    "mitigating": "🛠️",
    "resolved": "✅",
}

SEVERITY_COLOR = {
    "sev1": "#dc2626",
    "sev2": "#ea580c",
    "sev3": "#d97706",
    "sev4": "#0891b2",
    "sev5": "#64748b",
}


class SlackClient(HttpProviderClient):
    provider = IntegrationProvider.SLACK

    @property
    def base_url(self) -> str:
        return str(self.config.get("base_url") or "https://slack.com/api").rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            **super()._headers(),
            "Authorization": f"Bearer {self._credential('bot_token')}",
            "Content-Type": "application/json; charset=utf-8",
        }

    async def _api(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Slack returns HTTP 200 with ``ok: false`` on failure; normalise that."""
        from app.core.errors import IntegrationError

        data = await self._post_json(f"/{method}", payload)
        if not data.get("ok"):
            raise IntegrationError(
                f"Slack {method} failed: {data.get('error', 'unknown')}",
                details={"method": method, "error": data.get("error")},
            )
        return data

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            data = await self._api("auth.test", {})
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=True,
            detail=f"connected to {data.get('team')} as {data.get('user')}",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["post_message", "interactive_approvals", "thread_updates"],
        )

    # -- write ---------------------------------------------------------------
    async def post_incident_update(
        self,
        *,
        channel: str,
        headline: str,
        body: str,
        status: str,
        incident_id: str,
        thread_ts: str | None = None,
    ) -> dict[str, Any]:
        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{STATUS_EMOJI.get(status, '•')} *{headline}*",
                },
            }
        ]
        if body:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}})
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"OpsPilot · status `{status}` · `{incident_id[:8]}`",
                    }
                ],
            }
        )
        data = await self._api(
            "chat.postMessage",
            {
                "channel": channel,
                "text": f"{headline} ({status})",  # notification fallback
                "blocks": blocks,
                "thread_ts": thread_ts,
                "unfurl_links": False,
            },
        )
        return {"channel": data.get("channel"), "ts": data.get("ts")}

    async def request_approval(
        self,
        *,
        channel: str,
        approval_id: str,
        incident_reference: str,
        incident_title: str,
        action_title: str,
        risk_tier: RiskTier | str,
        summary: str,
        blast_radius: dict[str, Any],
        checklist: list[str],
        approve_url: str,
    ) -> dict[str, Any]:
        """Post an interactive approval card.

        The buttons carry only the approval id; the decision is authorised
        server-side against the Slack user's mapped OpsPilot role, so a click
        from someone without the required role is rejected the same way an API
        call would be.
        """
        radius_lines = [
            f"*Scope:* {blast_radius.get('scope', 'unknown')}",
            f"*Affects:* {blast_radius.get('estimated_affected_units', '?')} unit(s)",
        ]
        if blast_radius.get("causes_downtime"):
            radius_lines.append("*⚠️ Causes downtime*")
        if blast_radius.get("touches_data"):
            radius_lines.append("*⚠️ Touches data*")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Approval needed · {str(risk_tier).upper()} risk",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{incident_reference}* — {incident_title}\n\n"
                        f"*Proposed action:* {action_title}\n{summary[:1500]}"
                    ),
                },
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(radius_lines)}},
        ]
        if checklist:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Before you approve:*\n"
                        + "\n".join(f"• {item}" for item in checklist[:5]),
                    },
                }
            )
        blocks.append(
            {
                "type": "actions",
                "block_id": f"opspilot_approval:{approval_id}",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "value": f"approve:{approval_id}",
                        "action_id": "opspilot_approve",
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Approve this action?"},
                            "text": {"type": "mrkdwn", "text": action_title[:300]},
                            "confirm": {"type": "plain_text", "text": "Approve"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                        },
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "value": f"reject:{approval_id}",
                        "action_id": "opspilot_reject",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in OpsPilot"},
                        "url": approve_url,
                        "action_id": "opspilot_open",
                    },
                ],
            }
        )
        data = await self._api(
            "chat.postMessage",
            {
                "channel": channel,
                "text": f"Approval needed: {action_title}",
                "blocks": blocks,
            },
        )
        return {"channel": data.get("channel"), "ts": data.get("ts")}

    async def update_message(
        self, *, channel: str, ts: str, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        return await self._api(
            "chat.update",
            {"channel": channel, "ts": ts, "text": text, "blocks": blocks or []},
        )

    async def resolve_approval_message(
        self, *, channel: str, ts: str, decision: str, decided_by: str, action_title: str
    ) -> dict[str, Any]:
        icon = "✅" if decision == "approved" else "🚫"
        return await self.update_message(
            channel=channel,
            ts=ts,
            text=f"{icon} {decision} by {decided_by}",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{icon} *{action_title}*\n_{decision.title()} by {decided_by}_",
                    },
                }
            ],
        )

    # -- read ----------------------------------------------------------------
    async def get_user(self, user_id: str) -> dict[str, Any]:
        data = await self._api("users.info", {"user": user_id})
        user = data.get("user", {})
        return {
            "id": user.get("id"),
            "name": user.get("name"),
            "real_name": user.get("real_name"),
            "email": (user.get("profile") or {}).get("email"),
        }

    async def get_channel_history(self, *, channel: str, limit: int = 50) -> list[dict[str, Any]]:
        data = await self._api(
            "conversations.history", {"channel": channel, "limit": min(limit, 200)}
        )
        return [
            {"ts": m.get("ts"), "user": m.get("user"), "text": (m.get("text") or "")[:2000]}
            for m in data.get("messages", [])
        ]
