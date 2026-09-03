"""arq worker entrypoint: ``arq app.workers.main.WorkerSettings``."""

from __future__ import annotations

from typing import Any

from arq import cron

from app.core.config import settings
from app.core.db import dispose_engine, use_compatible_event_loop
from app.core.logging import configure_logging, get_logger
from app.core.redis_client import close_redis
from app.workers.queue import QUEUE_NAME, redis_settings
from app.workers.tasks import (
    check_integration_health,
    expire_approvals,
    health_check_all_integrations,
    reconcile_stuck_investigations,
    resume_investigation,
    run_investigation,
)

log = get_logger(__name__)

# arq builds the loop when it imports WorkerSettings, so the policy has to be
# set here at import time rather than in `startup`.
use_compatible_event_loop()


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging()
    settings.validate_production()
    # Warm the graph so the first incident does not pay compilation + checkpoint
    # table setup on the critical path.
    from app.agents.graph import get_compiled_graph

    await get_compiled_graph()
    log.info(
        "worker.started",
        environment=settings.environment,
        llm_provider=settings.llm_provider,
        remediation_disabled=settings.remediation_disabled,
    )


async def shutdown(ctx: dict[str, Any]) -> None:
    await dispose_engine()
    await close_redis()
    log.info("worker.stopped")


class WorkerSettings:
    functions = [
        run_investigation,
        resume_investigation,
        check_integration_health,
    ]
    cron_jobs = [
        cron(expire_approvals, minute=set(range(0, 60, 2)), run_at_startup=False),
        cron(reconcile_stuck_investigations, minute=set(range(0, 60, 5))),
        cron(health_check_all_integrations, minute={0, 30}),
    ]

    on_startup = startup
    on_shutdown = shutdown

    redis_settings = redis_settings()
    queue_name = QUEUE_NAME

    # An investigation is long-running and pauses for humans; give it room, and
    # never let arq retry it blindly — the graph's own checkpoint is the retry
    # mechanism.
    job_timeout = max(settings.investigation_timeout_seconds * 2, 1800)
    max_tries = 1
    keep_result = 3600
    max_jobs = 10
    health_check_interval = 60
