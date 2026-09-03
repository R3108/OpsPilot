"""Enqueue behaviour.

The API only ever enqueues, so a job that is silently dropped — or parked on a
queue nothing is draining — looks exactly like a button that does nothing.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.workers import queue as queue_module


class FakeJob:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id


class FakePool:
    """Stands in for arq's pool, including its job-id de-duplication.

    arq refuses an id it has already seen while the job or its kept result is
    still in Redis, and signals that by returning ``None`` rather than raising.
    """

    def __init__(self, *, worker_alive: bool = True) -> None:
        self.worker_alive = worker_alive
        self.seen: set[str] = set()
        self.calls: list[tuple[str, tuple[Any, ...], str | None]] = []

    async def exists(self, key: str) -> int:
        return 1 if self.worker_alive else 0

    async def enqueue_job(
        self, job: str, *args: Any, _job_id: str | None = None, **_: Any
    ) -> FakeJob | None:
        self.calls.append((job, args, _job_id))
        if _job_id is not None:
            if _job_id in self.seen:
                return None
            self.seen.add(_job_id)
        return FakeJob(_job_id or uuid.uuid4().hex)


@pytest.fixture
def pool(monkeypatch: pytest.MonkeyPatch) -> FakePool:
    fake = FakePool()

    async def _get_pool() -> FakePool:
        return fake

    monkeypatch.setattr(queue_module, "get_pool", _get_pool)
    return fake


async def test_re_investigating_an_incident_actually_enqueues_again(pool: FakePool) -> None:
    """Regression: a stable job id made every investigation after the first a no-op.

    One live investigation per incident is enforced by the advisory lock in
    ``start_investigation``, not by the job id — which outlives the run.
    """
    incident_id, tenant_id = uuid.uuid4(), uuid.uuid4()

    first = await queue_module.enqueue_investigation(incident_id=incident_id, tenant_id=tenant_id)
    second = await queue_module.enqueue_investigation(incident_id=incident_id, tenant_id=tenant_id)

    assert len(pool.calls) == 2
    assert first is not None and second is not None
    assert first != second, "the second investigation was de-duplicated away"


async def test_force_reaches_the_worker(pool: FakePool) -> None:
    """Regression: the API gated on `force` and then dropped it.

    Re-investigating a closed or failed incident needs the flag all the way down,
    or the graph refuses the run the API just acknowledged.
    """
    await queue_module.enqueue_investigation(
        incident_id=uuid.uuid4(), tenant_id=uuid.uuid4(), triggered_by="ada", force=True
    )

    job, args, _ = pool.calls[0]
    assert job == "run_investigation"
    assert args[2:] == ("ada", True)


async def test_no_worker_heartbeat_runs_inline_rather_than_parking_the_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redis being up is not the same as a worker existing."""
    fake = FakePool(worker_alive=False)

    async def _get_pool() -> FakePool:
        return fake

    ran: list[tuple[str, tuple[Any, ...]]] = []
    monkeypatch.setattr(queue_module, "get_pool", _get_pool)
    monkeypatch.setattr(
        queue_module,
        "_run_inline",
        lambda job, *args, **kwargs: ran.append((job, args)),
    )

    await queue_module.enqueue_investigation(incident_id=uuid.uuid4(), tenant_id=uuid.uuid4())

    assert not fake.calls, "job was queued with nothing to drain it"
    assert [job for job, _ in ran] == ["run_investigation"]


async def test_repeated_health_checks_for_one_integration_deduplicate(pool: FakePool) -> None:
    """Rapid integration edits collapse into one queued check, not a flood."""
    integration_id = uuid.uuid4()

    first = await queue_module.enqueue_integration_health_check(integration_id=integration_id)
    second = await queue_module.enqueue_integration_health_check(integration_id=integration_id)

    assert len(pool.calls) == 2
    assert first == second == f"health:{integration_id}"
