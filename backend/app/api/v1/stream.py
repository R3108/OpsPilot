"""Server-sent events: live agent activity.

SSE rather than WebSockets because the traffic is one-directional, it survives
proxies and reconnects natively in the browser, and the replay buffer plus
``Last-Event-ID`` gives us at-least-once delivery without any client bookkeeping.

Authentication note: ``EventSource`` cannot set headers, so these endpoints also
accept the access token as a query parameter. The token is still a normal
short-lived access token, validated exactly as a bearer header would be.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Header, Query, Request
from sse_starlette.sse import EventSourceResponse

from app.api.deps import DbSession
from app.core.errors import AuthenticationError, NotFoundError
from app.core.logging import get_logger
from app.core.security import decode_token
from app.models.incident import Incident
from app.models.tenant import User
from app.services import events

log = get_logger(__name__)
router = APIRouter(prefix="/stream", tags=["stream"])

HEARTBEAT_SECONDS = 15.0


async def _authenticate(session: DbSession, token: str | None) -> User:
    if not token:
        raise AuthenticationError("A token query parameter is required for the event stream")
    claims = decode_token(token, expected_type="access")
    user = await session.get(User, uuid.UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise AuthenticationError("User not found or deactivated")
    return user


async def _pump(
    channel: str, request: Request, *, replay: list[str] | None = None
) -> AsyncIterator[dict[str, str]]:
    """Yield replayed events first, then live ones, until the client disconnects."""
    for raw in replay or []:
        yield {"event": _event_name(raw), "data": raw, "id": _event_id(raw)}

    stop = asyncio.Event()
    try:
        async for raw in events.subscribe(channel, heartbeat_seconds=HEARTBEAT_SECONDS, stop=stop):
            if await request.is_disconnected():
                break
            yield {"event": _event_name(raw), "data": raw, "id": _event_id(raw)}
    except asyncio.CancelledError:  # pragma: no cover - normal disconnect
        raise
    finally:
        stop.set()
        log.debug("stream.closed", channel=channel)


def _event_name(raw: str) -> str:
    try:
        return str(json.loads(raw).get("type", "message"))
    except json.JSONDecodeError:  # pragma: no cover
        return "message"


def _event_id(raw: str) -> str:
    try:
        return str(json.loads(raw).get("id", ""))
    except json.JSONDecodeError:  # pragma: no cover
        return ""


@router.get("/incidents/{incident_id}")
async def incident_stream(
    incident_id: uuid.UUID,
    request: Request,
    session: DbSession,
    token: Annotated[str | None, Query()] = None,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> EventSourceResponse:
    """Live agent activity for one incident, with replay of what was missed."""
    user = await _authenticate(session, token)

    incident = await session.get(Incident, incident_id)
    if incident is None or incident.tenant_id != user.tenant_id:
        raise NotFoundError("Incident not found")

    # Release the connection before streaming. `get_db` only commits once the
    # response completes, and an SSE response completes when the client
    # disconnects — so without this the reads above leave a backend `idle in
    # transaction` for the whole life of the stream. That blocks anything
    # needing a non-concurrent lock on those tables; in particular the
    # checkpointer's CREATE INDEX CONCURRENTLY waits on every open transaction,
    # so one open console would hang every investigation.
    await session.commit()

    replay = await events.get_replay(incident_id, after_id=last_event_id)
    log.info(
        "stream.opened",
        incident_id=str(incident_id),
        user_id=str(user.id),
        replayed=len(replay),
    )
    return EventSourceResponse(
        _pump(events.incident_channel(incident_id), request, replay=replay),
        ping=int(HEARTBEAT_SECONDS),
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@router.get("/tenant")
async def tenant_stream(
    request: Request,
    session: DbSession,
    token: Annotated[str | None, Query()] = None,
) -> EventSourceResponse:
    """Org-wide firehose: powers the live badge counts and dashboard tiles."""
    user = await _authenticate(session, token)
    # See incident_stream: the session must not stay open for the stream's life.
    await session.commit()

    log.info("stream.opened", scope="tenant", user_id=str(user.id))
    return EventSourceResponse(
        _pump(events.tenant_channel(user.tenant_id), request),
        ping=int(HEARTBEAT_SECONDS),
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )
