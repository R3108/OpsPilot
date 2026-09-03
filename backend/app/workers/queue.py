"""Job enqueueing.

Investigations run in a worker, not in the request path: they take minutes, they
pause for human approval, and they must survive an API restart. The API only ever
enqueues.

If no worker is reachable the enqueue falls back to a detached task in the API
process so a single-container deployment still works — with a loud log line,
because that mode loses jobs on restart.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from arq.connections import ArqRedis, RedisSettings, create_pool
from arq.constants import health_check_key_suffix

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

QUEUE_NAME = "opspilot:jobs"
# arq's worker heartbeat. The worker rewrites it every `health_check_interval`
# seconds with a TTL just past that, and deletes it on a clean shutdown.
HEALTH_CHECK_KEY = f"{QUEUE_NAME}{health_check_key_suffix}"

_pool: ArqRedis | None = None
_background_tasks: set[asyncio.Task[Any]] = set()
# Inline fallback is a last resort, not a second worker pool: cap concurrent
# in-process jobs so a Redis outage degrades instead of OOMing the API.
_inline_semaphore = asyncio.Semaphore(2)


def redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(settings.redis_url)


async def get_pool() -> ArqRedis | None:
    global _pool
    if _pool is None:
        try:
            _pool = await create_pool(redis_settings(), default_queue_name=QUEUE_NAME)
        except Exception as exc:  # noqa: BLE001
            log.warning("queue.unavailable", error=str(exc)[:300])
            return None
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
    _pool = None


async def _worker_alive(pool: ArqRedis) -> bool:
    """Whether a worker has checked in recently enough to drain the queue.

    Redis being up says nothing about a worker existing. Without this, an enqueue
    against an empty queue succeeds and the job simply sits there — the API still
    answers "investigation queued" and the incident never moves.
    """
    try:
        return bool(await pool.exists(HEALTH_CHECK_KEY))
    except Exception as exc:  # noqa: BLE001 - a probe must never block the enqueue
        log.warning("queue.health_probe_failed", error=str(exc)[:300])
        # Fail toward inline execution: a flapping probe must not park jobs on
        # a queue that may have no worker draining it.
        return False


async def _enqueue(job: str, *args: Any, job_id: str | None = None, **kwargs: Any) -> str | None:
    pool = await get_pool()
    if pool is None:
        return _run_inline(job, *args, **kwargs)
    if not await _worker_alive(pool):
        return _run_inline(job, *args, **kwargs)
    try:
        result = await pool.enqueue_job(job, *args, _job_id=job_id, **kwargs)
    except Exception as exc:  # noqa: BLE001
        log.warning("queue.enqueue_failed", job=job, error=str(exc)[:300])
        return _run_inline(job, *args, **kwargs)
    if result is None:
        # arq returns None when a job with this id is already queued/running.
        log.info("queue.job_deduplicated", job=job, job_id=job_id)
        return job_id
    log.info("queue.enqueued", job=job, job_id=result.job_id)
    return result.job_id


def _run_inline(job: str, *args: Any, **kwargs: Any) -> str | None:
    """Last-resort in-process execution when no worker is available."""
    from app.workers import tasks

    fn = getattr(tasks, job, None)
    if fn is None:  # pragma: no cover
        log.error("queue.unknown_job", job=job)
        return None

    if len(_background_tasks) >= 2:
        log.error(
            "queue.inline_saturated",
            job=job,
            detail="Inline fallback is full; dropping the job rather than OOMing the API.",
        )
        return None

    log.warning(
        "queue.running_inline",
        job=job,
        detail="No arq worker reachable; running in the API process. Jobs will be lost on restart.",
    )

    async def _guarded() -> None:
        async with _inline_semaphore:
            await fn(None, *args, **kwargs)

    task = asyncio.create_task(_guarded())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return None


async def enqueue_investigation(
    *,
    incident_id: uuid.UUID,
    tenant_id: uuid.UUID,
    triggered_by: str = "system",
    force: bool = False,
) -> str | None:
    return await _enqueue(
        "run_investigation",
        str(incident_id),
        str(tenant_id),
        triggered_by,
        force,
        # Unique per attempt. A stable id looks like useful de-duplication, but
        # arq refuses any id it has seen while the job or its result is still in
        # Redis (`keep_result`) — so the *second* investigation of an incident is
        # silently dropped while the API still reports it queued. Concurrency is
        # already handled where it belongs: `start_investigation` takes an
        # advisory lock per incident and raises InvestigationBusy.
        job_id=f"investigate:{incident_id}:{uuid.uuid4().hex[:8]}",
    )


async def enqueue_resume(*, incident_id: uuid.UUID, tenant_id: uuid.UUID) -> str | None:
    return await _enqueue(
        "resume_investigation",
        str(incident_id),
        str(tenant_id),
        job_id=f"resume:{incident_id}:{uuid.uuid4().hex[:8]}",
    )


async def enqueue_integration_health_check(*, integration_id: uuid.UUID) -> str | None:
    return await _enqueue(
        "check_integration_health",
        str(integration_id),
        # A stable id: rapid integration edits collapse into one queued check
        # rather than flooding the worker.
        job_id=f"health:{integration_id}",
    )
