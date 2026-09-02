"""Health client for a *customer's* database (not OpsPilot's own).

Every statement is a module-level constant with bind parameters. There is no code
path that accepts SQL from a caller, so the database investigator and the
``db.*`` actions can only ask the questions written here.

The connection uses a short statement timeout and a read-only default so an
investigation can never wedge the database it is diagnosing.
"""

from __future__ import annotations

import time
from typing import Any

from app.core.errors import IntegrationError
from app.core.logging import get_logger
from app.integrations.base import HealthReport, ProviderClient
from app.models.enums import IntegrationProvider

log = get_logger(__name__)

# -- fixed statements -------------------------------------------------------
Q_CONNECTION_SUMMARY = """
SELECT state,
       count(*) AS count,
       max(EXTRACT(EPOCH FROM (now() - state_change))) AS max_state_seconds
  FROM pg_stat_activity
 WHERE datname = $1
 GROUP BY state
"""

Q_MAX_CONNECTIONS = (
    "SELECT setting::int AS max_connections FROM pg_settings WHERE name = 'max_connections'"
)

Q_IDLE_IN_TRANSACTION = """
SELECT pid,
       usename,
       application_name,
       client_addr::text AS client_addr,
       state,
       EXTRACT(EPOCH FROM (now() - state_change)) AS idle_seconds,
       EXTRACT(EPOCH FROM (now() - xact_start))   AS xact_seconds,
       left(query, 400) AS query
  FROM pg_stat_activity
 WHERE datname = $1
   AND state IN ('idle in transaction', 'idle in transaction (aborted)')
   AND state_change < now() - ($2 || ' seconds')::interval
   AND ($3::text IS NULL OR application_name = $3)
   AND pid <> pg_backend_pid()
 ORDER BY state_change ASC
 LIMIT $4
"""

Q_LONG_RUNNING = """
SELECT pid,
       usename,
       application_name,
       state,
       EXTRACT(EPOCH FROM (now() - query_start)) AS duration_seconds,
       wait_event_type,
       wait_event,
       left(query, 600) AS query
  FROM pg_stat_activity
 WHERE datname = $1
   AND state = 'active'
   AND query_start < now() - ($2 || ' seconds')::interval
   AND pid <> pg_backend_pid()
 ORDER BY query_start ASC
 LIMIT $3
"""

Q_BACKEND_BY_PID = """
SELECT pid, usename, application_name, state,
       EXTRACT(EPOCH FROM (now() - query_start)) AS duration_seconds,
       left(query, 600) AS query
  FROM pg_stat_activity
 WHERE datname = $1 AND pid = $2
"""

Q_LOCKS = """
SELECT blocked.pid            AS blocked_pid,
       blocked.usename        AS blocked_user,
       blocking.pid           AS blocking_pid,
       blocking.usename       AS blocking_user,
       EXTRACT(EPOCH FROM (now() - blocked.query_start)) AS blocked_seconds,
       left(blocked.query, 300)  AS blocked_query,
       left(blocking.query, 300) AS blocking_query
  FROM pg_stat_activity blocked
  JOIN pg_stat_activity blocking
    ON blocking.pid = ANY(pg_blocking_pids(blocked.pid))
 WHERE blocked.datname = $1
 LIMIT 50
"""

Q_TABLE_BLOAT = """
SELECT schemaname, relname,
       n_live_tup, n_dead_tup,
       CASE WHEN n_live_tup > 0
            THEN round(n_dead_tup::numeric / n_live_tup, 4)
            ELSE NULL END AS dead_ratio,
       last_autovacuum, last_autoanalyze
  FROM pg_stat_user_tables
 WHERE n_dead_tup > 1000
 ORDER BY n_dead_tup DESC
 LIMIT 20
"""

Q_REPLICATION = """
SELECT client_addr::text AS client_addr, state, sync_state,
       EXTRACT(EPOCH FROM (now() - reply_time)) AS reply_lag_seconds,
       pg_wal_lsn_diff(sent_lsn, replay_lsn)    AS replay_lag_bytes
  FROM pg_stat_replication
"""

Q_CACHE_HIT = """
SELECT sum(blks_hit)  AS hits,
       sum(blks_read) AS reads,
       CASE WHEN sum(blks_hit) + sum(blks_read) > 0
            THEN round(sum(blks_hit)::numeric / (sum(blks_hit) + sum(blks_read)), 4)
            ELSE NULL END AS hit_ratio
  FROM pg_stat_database
 WHERE datname = $1
"""

Q_TRANSACTION_STATS = """
SELECT xact_commit, xact_rollback, deadlocks, temp_files, temp_bytes,
       conflicts, blk_read_time, blk_write_time
  FROM pg_stat_database
 WHERE datname = $1
"""

Q_ROLE_CONNECTION_LIMIT = "SELECT rolconnlimit AS connection_limit FROM pg_roles WHERE rolname = $1"

Q_TERMINATE = "SELECT pid, pg_terminate_backend(pid) AS terminated FROM unnest($1::int[]) AS pid"


class PostgresTargetClient(ProviderClient):
    provider = IntegrationProvider.POSTGRES

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._pool: Any = None

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        try:
            import asyncpg
        except ImportError as exc:  # pragma: no cover
            raise IntegrationError("asyncpg is not installed") from exc

        self._pool = await asyncpg.create_pool(
            dsn=self._credential("dsn"),
            min_size=1,
            max_size=3,
            command_timeout=self.timeout_seconds,
            server_settings={
                "application_name": "opspilot-sre",
                # Never let a diagnostic query become the next incident.
                "statement_timeout": str(min(self.timeout_seconds, 30) * 1000),
                "idle_in_transaction_session_timeout": "10000",
            },
        )
        return self._pool

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        pool = await self._get_pool()

        async def _call() -> list[dict[str, Any]]:
            async with pool.acquire() as conn:
                rows = await conn.fetch(sql, *args)
            return [dict(r) for r in rows]

        return await self._with_retries("fetch", _call, attempts=2)

    async def health_check(self) -> HealthReport:
        started = time.perf_counter()
        try:
            rows = await self._fetch("SELECT version() AS version")
        except Exception as exc:  # noqa: BLE001
            return HealthReport(healthy=False, detail=str(exc)[:400])
        return HealthReport(
            healthy=True,
            detail=str(rows[0]["version"])[:200] if rows else "connected",
            latency_ms=int((time.perf_counter() - started) * 1000),
            capabilities=["connections", "locks", "long_queries", "bloat", "replication"],
        )

    # ======================================================================
    # read
    # ======================================================================
    async def connection_summary(self, database: str) -> dict[str, Any]:
        by_state = await self._fetch(Q_CONNECTION_SUMMARY, database)
        max_rows = await self._fetch(Q_MAX_CONNECTIONS)
        max_connections = int(max_rows[0]["max_connections"]) if max_rows else 0
        total = sum(int(r["count"]) for r in by_state)
        return {
            "database": database,
            "total": total,
            "max_connections": max_connections,
            "saturation": round(total / max_connections, 4) if max_connections else None,
            "by_state": {
                str(r["state"]): {
                    "count": int(r["count"]),
                    "max_state_seconds": float(r["max_state_seconds"] or 0),
                }
                for r in by_state
            },
        }

    async def list_idle_in_transaction(
        self,
        *,
        database: str,
        idle_seconds: int = 300,
        application_name: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        return await self._fetch(
            Q_IDLE_IN_TRANSACTION, database, str(idle_seconds), application_name, limit
        )

    async def list_long_running_queries(
        self, *, database: str, min_seconds: int = 60, limit: int = 25
    ) -> list[dict[str, Any]]:
        return await self._fetch(Q_LONG_RUNNING, database, str(min_seconds), limit)

    async def get_backend(self, database: str, pid: int) -> dict[str, Any] | None:
        rows = await self._fetch(Q_BACKEND_BY_PID, database, pid)
        return rows[0] if rows else None

    async def list_blocking_locks(self, database: str) -> list[dict[str, Any]]:
        return await self._fetch(Q_LOCKS, database)

    async def table_bloat(self) -> list[dict[str, Any]]:
        return await self._fetch(Q_TABLE_BLOAT)

    async def replication_status(self) -> list[dict[str, Any]]:
        return await self._fetch(Q_REPLICATION)

    async def cache_hit_ratio(self, database: str) -> dict[str, Any]:
        rows = await self._fetch(Q_CACHE_HIT, database)
        return rows[0] if rows else {}

    async def transaction_stats(self, database: str) -> dict[str, Any]:
        rows = await self._fetch(Q_TRANSACTION_STATS, database)
        return rows[0] if rows else {}

    async def get_role_connection_limit(self, database: str, role: str) -> dict[str, Any]:
        rows = await self._fetch(Q_ROLE_CONNECTION_LIMIT, role)
        return {"role": role, "connection_limit": rows[0]["connection_limit"] if rows else None}

    async def full_health_snapshot(self, database: str) -> dict[str, Any]:
        """One round trip's worth of everything the DB investigator wants."""
        import asyncio

        connections, locks, long_queries, cache, txns, bloat, replication = await asyncio.gather(
            self.connection_summary(database),
            self.list_blocking_locks(database),
            self.list_long_running_queries(database=database, min_seconds=30),
            self.cache_hit_ratio(database),
            self.transaction_stats(database),
            self.table_bloat(),
            self.replication_status(),
            return_exceptions=True,
        )

        def _ok(value: Any) -> Any:
            return {"error": str(value)[:300]} if isinstance(value, BaseException) else value

        return {
            "connections": _ok(connections),
            "blocking_locks": _ok(locks),
            "long_running_queries": _ok(long_queries),
            "cache": _ok(cache),
            "transactions": _ok(txns),
            "table_bloat": _ok(bloat),
            "replication": _ok(replication),
        }

    # ======================================================================
    # write
    # ======================================================================
    async def terminate_backends(self, pids: list[int]) -> list[int]:
        self._require_write()
        if not pids:
            return []
        rows = await self._fetch(Q_TERMINATE, [int(p) for p in pids])
        return [int(r["pid"]) for r in rows if r.get("terminated")]

    async def set_role_connection_limit(
        self, database: str, role: str, connection_limit: int
    ) -> None:
        """ALTER ROLE cannot take a bind parameter for the role name.

        The role is therefore validated against ``pg_roles`` first and quoted
        with ``quote_ident`` server-side, so the identifier can only ever be an
        existing role name.
        """
        self._require_write()
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
            if not exists:
                raise IntegrationError(f"role '{role}' does not exist")
            quoted = await conn.fetchval("SELECT quote_ident($1)", role)
            await conn.execute(f"ALTER ROLE {quoted} CONNECTION LIMIT {int(connection_limit)}")
