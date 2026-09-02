"""Shared Redis connection plus the primitives built on it.

Redis carries three things in OpsPilot:

* the arq job queue (see :mod:`app.workers`),
* the agent-activity pub/sub fan-out that feeds the SSE stream,
* short-lived coordination state: idempotency keys, rate limits, distributed locks.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

_redis: aioredis.Redis | None = None

# --------------------------------------------------------------------------
# single-process fallback
# --------------------------------------------------------------------------
# When Redis is unreachable, coordination degrades to in-process structures.
# That is correct for a single-process deployment (the local demo, the test
# suite, the eval harness) and *incorrect* for a multi-replica one — so it is
# logged loudly every time it is used, rather than failing the request. The
# alternative, failing open silently, would let two workers execute the same
# remediation; the alternative of failing closed would make a Redis blip take
# incident response down with it.
_local_locks: dict[str, str] = {}
_local_claims: dict[str, float] = {}
_local_counters: dict[str, int] = {}
_local_mutex = asyncio.Lock()
_degraded_warned = False


def _warn_degraded(operation: str, error: str) -> None:
    global _degraded_warned
    if not _degraded_warned:
        log.warning(
            "redis.degraded",
            operation=operation,
            error=error[:200],
            detail=(
                "Redis is unreachable; coordination has fallen back to in-process "
                "state. This is safe for a single process only."
            ),
        )
        _degraded_warned = True


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
    _redis = None


async def check_redis() -> bool:
    try:
        return bool(await get_redis().ping())
    except Exception as exc:  # noqa: BLE001
        log.warning("redis.healthcheck_failed", error=str(exc))
        return False


# --------------------------------------------------------------------------
# idempotency
# --------------------------------------------------------------------------
async def claim_once(key: str, *, ttl_seconds: int = 3600) -> bool:
    """Return True the first time ``key`` is seen inside the TTL window.

    Used to de-duplicate webhook deliveries, which every provider retries.
    """
    try:
        return bool(await get_redis().set(f"idem:{key}", "1", nx=True, ex=ttl_seconds))
    except Exception as exc:  # noqa: BLE001
        _warn_degraded("claim_once", str(exc))
        async with _local_mutex:
            now = time.monotonic()
            for stale in [k for k, expiry in _local_claims.items() if expiry < now]:
                _local_claims.pop(stale, None)
            if key in _local_claims:
                return False
            _local_claims[key] = now + ttl_seconds
            return True


# --------------------------------------------------------------------------
# rate limiting (fixed window, good enough and cheap)
# --------------------------------------------------------------------------
async def rate_limit_ok(bucket: str, *, limit: int, window_seconds: int) -> tuple[bool, int]:
    """Increment ``bucket`` and report whether it is still under ``limit``."""
    window = int(time.time()) // window_seconds
    key = f"rl:{bucket}:{window}"
    try:
        redis = get_redis()
        pipe = redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds + 1)
        count, _ = await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        _warn_degraded("rate_limit", str(exc))
        async with _local_mutex:
            count = _local_counters.get(key, 0) + 1
            _local_counters[key] = count
            # Keep only the current window's counters.
            for stale in [k for k in _local_counters if not k.endswith(f":{window}")]:
                _local_counters.pop(stale, None)
    return count <= limit, int(count)


# --------------------------------------------------------------------------
# locks
# --------------------------------------------------------------------------
@asynccontextmanager
async def advisory_lock(
    name: str, *, ttl_seconds: int = 300, wait: bool = False, poll: float = 0.25
) -> AsyncIterator[bool]:
    """Best-effort distributed lock.

    Yields whether the lock was acquired; the caller decides what to do when it
    was not. Release is token-guarded so a slow holder cannot free someone
    else's lock after its TTL lapsed.
    """
    key = f"lock:{name}"
    token = uuid.uuid4().hex
    deadline = time.monotonic() + ttl_seconds
    degraded = False

    async def _try_acquire() -> bool:
        nonlocal degraded
        try:
            return bool(await get_redis().set(key, token, nx=True, ex=ttl_seconds))
        except Exception as exc:  # noqa: BLE001
            _warn_degraded("advisory_lock", str(exc))
            degraded = True
            async with _local_mutex:
                if key in _local_locks:
                    return False
                _local_locks[key] = token
                return True

    acquired = await _try_acquire()
    while not acquired and wait and time.monotonic() < deadline:
        await asyncio.sleep(poll)
        acquired = await _try_acquire()

    try:
        yield acquired
    finally:
        if acquired:
            if degraded:
                async with _local_mutex:
                    if _local_locks.get(key) == token:
                        _local_locks.pop(key, None)
            else:
                # Compare-and-delete so a slow holder cannot free a lock that
                # has since been handed to someone else.
                try:
                    await get_redis().eval(
                        "if redis.call('get', KEYS[1]) == ARGV[1] then "
                        "return redis.call('del', KEYS[1]) else return 0 end",
                        1,
                        key,
                        token,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("redis.lock_release_failed", key=key, error=str(exc)[:200])
