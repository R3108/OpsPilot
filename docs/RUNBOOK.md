# OpsPilot Runbook

On-call triage, kill switches, and recovery procedures for beta operators.

## Service map

| Container | Command | Health signal |
|---|---|---|
| `api` | `uvicorn app.main:app --workers 4` | `/health/ready` (200 = DB + Redis reachable) |
| `worker` (×2 via `--scale`) | `arq app.workers.main.WorkerSettings` | arq heartbeat key `opspilot:jobs:health-check` in Redis |
| `migrate` | `alembic upgrade head` (one-shot) | `service_completed_successfully` |
| `web` | `node server.js` | Dockerfile `HEALTHCHECK /login` |
| `postgres` / `redis` | — | compose healthchecks |

`web` waits on `api` healthy. `api` + `worker` wait on `migrate` success. A
failed migration blocks both with manual recovery (see below).

## "I click Investigate, nothing happens"

1. `docker compose ps` — is `worker` up (not crash-looping)?
2. `docker compose logs worker` — import error, DB, or missing LLM key?
3. `docker compose logs api | findstr queue` (Windows) /
   `grep queue` (Linux):
   - `queue.running_inline` — no worker reachable; running in-process.
     Jobs die on API restart.
   - `queue.unavailable` / `queue.enqueue_failed` — Redis down.
   - `queue.enqueued` but incident never moves — job parked, worker dead.
   - `queue.inline_saturated` — inline fallback full (2 cap), job dropped.
4. Preconditions: `docker compose exec api alembic upgrade head`;
   `LLM_PROVIDER=fake` works offline; `anthropic`/`nvidia` need real keys or
   the first LLM call fails the run.

## Kill switches

| Knob | Effect | How |
|---|---|---|
| `REMEDIATION_DISABLED=true` | Agent proposes but never executes | env on api+worker, restart |
| Per-tenant `remediation_enabled=false` | Same, one org | tenant `settings_json` |
| Per-action `allow_write=false` | Catalog-level read-only | action catalog config |
| Approval expiry | Stuck approvals auto-expire (`approval_ttl_minutes`, default 60) | `expire_approvals` cron every 2 min |

## Stuck investigations

- The reconciler (`reconcile_stuck_investigations`, every 5 min) resumes
  `running` runs whose heartbeat is older than 1.25×
  `investigation_timeout_seconds`.
- Heartbeats stamp on every phase change, step, and LLM usage update.
- Watch: `job.reconciling_stuck_run`, `job.superseded_stuck_run`,
  metric `opspilot_stuck_runs_rescued_total`.
- Transient infra failures (LLM 5xx, DB blips) redrive via arq `Retry`
  (30s/60s backoff, 3 tries); metric `opspilot_jobs_retried_total`.

## Auth incidents

- Refresh tokens rotate on every use; reuse of a rotated token revokes **all**
  of that user's sessions (`auth.refresh_reuse_detected`).
- Lock a user out: set `is_active=false` (takes effect immediately —
  roles are DB-authoritative) and their refresh family stops working.
- Brute force: login/signup/refresh are IP-throttled (10/min). Flood shows as
  `rate_limited` 429s.

## Backup and restore

- Nightly dump: `docker compose --profile backup up backup` writes
  `opspilot-<ts>.sql.gz` to the `postgres-backups` volume. Offload to S3 on a
  host cron; retention is yours to set (suggested: 7 daily + 4 weekly).
- Restore: `gunzip -c <dump> | docker compose exec -T postgres psql -U opspilot opspilot`,
  then `docker compose exec api alembic upgrade head` to confirm schema.
- After a restore, stuck runs resume via the reconciler once Redis is back.
- Redis is append-only but single-instance: queue contents are lost on volume
  loss. Re-queue by re-investigating (the advisory lock prevents doubles).

## Failed migration

`migrate` must reach `service_completed_successfully` before api/worker start.
If it fails: `docker compose logs migrate`, fix `DATABASE_URL`/DB, then
`docker compose up migrate` again. Never edit migration history on a live DB;
add a new revision instead.

## What to alert on (Prometheus `/metrics`)

- `opspilot_jobs_failed_total` increasing — worker failures.
- `opspilot_stuck_runs_rescued_total` increasing — workers dying.
- `opspilot_policy_denied_total` spike — misbehaving model or bad rule.
- `opspilot_http_request_seconds{quantile="0.99"}` — API latency.
- `/health/ready` != 200 — DB or Redis unreachable.
- `auth.refresh_reuse_detected` in logs — possible token theft.
