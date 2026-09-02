"""Real-time agent activity fan-out.

Agent nodes publish typed events; the SSE endpoint subscribes and forwards them
to the browser. Redis pub/sub is the transport so any API replica can serve the
stream regardless of which worker is running the graph.

A short replay buffer (a capped Redis list per incident) is kept so a client that
connects mid-investigation, or reconnects after a blip, sees what it missed
instead of a blank console.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.logging import get_logger, redact
from app.core.redis_client import get_redis
from app.models.enums import AgentEventType, AgentPhase

log = get_logger(__name__)

REPLAY_LIMIT = 500
REPLAY_TTL_SECONDS = 86_400


def incident_channel(incident_id: uuid.UUID | str) -> str:
    return f"stream:incident:{incident_id}"


def tenant_channel(tenant_id: uuid.UUID | str) -> str:
    return f"stream:tenant:{tenant_id}"


def replay_key(incident_id: uuid.UUID | str) -> str:
    return f"replay:incident:{incident_id}"


@dataclass(slots=True)
class AgentEvent:
    type: AgentEventType
    incident_id: str
    tenant_id: str
    phase: AgentPhase | None = None
    title: str = ""
    message: str = ""
    investigator: str | None = None
    run_id: str | None = None
    step_id: str | None = None
    sequence: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_json(self) -> str:
        payload = asdict(self)
        payload["type"] = str(self.type)
        payload["phase"] = str(self.phase) if self.phase else None
        # Never let a provider response carrying a token reach a browser.
        payload["data"] = redact(payload.get("data") or {})
        return json.dumps(payload, default=str)


async def publish(event: AgentEvent) -> None:
    """Publish to both the incident and tenant channels, and append to replay."""
    redis = get_redis()
    payload = event.to_json()
    try:
        pipe = redis.pipeline()
        pipe.publish(incident_channel(event.incident_id), payload)
        pipe.publish(tenant_channel(event.tenant_id), payload)
        key = replay_key(event.incident_id)
        pipe.rpush(key, payload)
        pipe.ltrim(key, -REPLAY_LIMIT, -1)
        pipe.expire(key, REPLAY_TTL_SECONDS)
        await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        # Streaming is best-effort: never fail an investigation because the UI
        # transport hiccupped. The durable record is in Postgres.
        log.warning("events.publish_failed", error=str(exc), event_type=str(event.type))


async def emit(
    *,
    type: AgentEventType,
    incident_id: uuid.UUID | str,
    tenant_id: uuid.UUID | str,
    phase: AgentPhase | None = None,
    title: str = "",
    message: str = "",
    investigator: str | None = None,
    run_id: uuid.UUID | str | None = None,
    step_id: uuid.UUID | str | None = None,
    sequence: int | None = None,
    **data: Any,
) -> None:
    await publish(
        AgentEvent(
            type=type,
            incident_id=str(incident_id),
            tenant_id=str(tenant_id),
            phase=phase,
            title=title,
            message=message,
            investigator=investigator,
            run_id=str(run_id) if run_id else None,
            step_id=str(step_id) if step_id else None,
            sequence=sequence,
            data=data,
        )
    )


async def get_replay(incident_id: uuid.UUID | str, *, after_id: str | None = None) -> list[str]:
    """Return buffered events, optionally only those after ``after_id``."""
    try:
        items: list[str] = await get_redis().lrange(replay_key(incident_id), 0, -1)
    except Exception as exc:  # noqa: BLE001
        log.warning("events.replay_failed", error=str(exc))
        return []
    if not after_id:
        return items
    for index, raw in enumerate(items):
        with contextlib.suppress(json.JSONDecodeError):
            if json.loads(raw).get("id") == after_id:
                return items[index + 1 :]
    return items


async def subscribe(
    channel: str,
    *,
    heartbeat_seconds: float = 15.0,
    stop: asyncio.Event | None = None,
) -> AsyncIterator[str]:
    """Yield raw JSON event payloads from ``channel`` until the client goes away.

    A heartbeat is emitted on idle so proxies do not reap the connection and the
    UI can show a live/stale indicator.
    """
    redis = get_redis()
    pubsub = redis.pubsub(ignore_subscribe_messages=True)
    await pubsub.subscribe(channel)
    try:
        while stop is None or not stop.is_set():
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=heartbeat_seconds),
                    timeout=heartbeat_seconds + 5,
                )
            except TimeoutError:
                message = None

            if message and message.get("type") == "message":
                data = message["data"]
                yield data if isinstance(data, str) else data.decode("utf-8")
            else:
                yield json.dumps(
                    {
                        "type": str(AgentEventType.HEARTBEAT),
                        "at": datetime.now(UTC).isoformat(),
                    }
                )
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
