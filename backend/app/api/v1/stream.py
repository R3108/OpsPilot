"""Server-sent events: live agent activity.

SSE rather than WebSockets because the traffic is one-directional, it survives
proxies and reconnects natively in the browser, and the replay buffer plus
``Last-Event-ID`` gives us at-least-once delivery without any client bookkeeping.

Authentication note: ``EventSource`` cannot set headers, so clients mint a
single-use ticket via ``POST /stream/ticket`` (authenticated normally) and pass
it as ``?ticket=``. The raw access token never appears in a URL, so it stays
out of browser history, proxy logs and ``Referer`` headers. Tickets live 60
seconds and burn on first use.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Header, Query, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from app.api.deps import CurrentPrincipal, DbSession
from app.core.errors import AuthenticationError, NotFoundError
from app.core.logging import get_logger
from app.core.redis_client import get_redis
from app.core.security import decode_token
from app.models.incident import Incident
from app.models.tenant import User
from app.services import events

log = get_logger(__name__)
router = APIRouter(prefix="/stream", tags=["stream"])

HEARTBEAT_SECONDS = 15.0

STREAM_TICKET_TTL_SECONDS = 60


class StreamTicket(BaseModel):
    ticket: str
    expires_in: int = STREAM_TICKET_TTL_SECONDS


def _ticket_key(ticket: str) -> str:
    return f"stream-ticket:{ticket}"


@router.post("/ticket", response_model=StreamTicket)
async def mint_stream_ticket(principal: CurrentPrincipal) -> StreamTicket:
    """Mint a single-use ticket for opening an SSE stream.

    Called with the normal Authorization header; the returned ticket goes in
    ``?ticket=`` where ``EventSource`` cannot send headers.
    """
    ticket = secrets.token_urlsafe(32)
    payload = json.dumps({"user_id": str(principal.id), "tenant_id": str(principal.tenant_id)})
    await get_redis().set(_ticket_key(ticket), payload, ex=STREAM_TICKET_TTL_SECONDS)
    return StreamTicket(ticket=ticket)


async def _authenticate(session: DbSession, ticket: str | None) -> User:
    if not ticket:
        raise AuthenticationError("A ticket query parameter is required for the event stream")
    try:
        raw = await get_redis().getdel(_ticket_key(ticket))
    except Exception as exc:  # noqa: BLE001 - a probe must not break the stream
        raise AuthenticationError("Stream ticket store is unavailable") from exc
    if raw is None:
        raise AuthenticationError("Invalid or already-used stream ticket")
    try:
        payload = json.loads(raw)
        user = await session.get(User, uuid.UUID(payload["user_id"]))
    except (ValueError, KeyError, AttributeError) as exc:
        raise AuthenticationError("Malformed stream ticket") from exc
    if user is None or not user.is_active or str(user.tenant_id) != payload.get("tenant_id"):
        raise AuthenticationError("User not found or deactivated")
    return user


async def _authenticate_legacy(session: DbSession, token: str | None) -> User:
    """Bearer-token fallback, kept for one release while clients migrate."""
    if not token:
        raise AuthenticationError("A ticket query parameter is required for the event stream")
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
    ticket: Annotated[str | None, Query()] = None,
    token: Annotated[str | None, Query()] = None,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> EventSourceResponse:
    """Live agent activity for one incident, with replay of what was missed."""
    user = (
        await _authenticate(session, ticket)
        if ticket is not None
        else await _authenticate_legacy(session, token)
    )

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
    ticket: Annotated[str | None, Query()] = None,
    token: Annotated[str | None, Query()] = None,
) -> EventSourceResponse:
    """Org-wide firehose: powers the live badge counts and dashboard tiles."""
    user = (
        await _authenticate(session, ticket)
        if ticket is not None
        else await _authenticate_legacy(session, token)
    )
    # See incident_stream: the session must not stay open for the stream's life.
    await session.commit()

    log.info("stream.opened", scope="tenant", user_id=str(user.id))
    return EventSourceResponse(
        _pump(events.tenant_channel(user.tenant_id), request),
        ping=int(HEARTBEAT_SECONDS),
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )
