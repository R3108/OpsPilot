# OpsPilot Deployment Guide

## Stacks

- **Dev:** `docker compose up --build`, then
  `docker compose exec api alembic upgrade head` and
  `docker compose exec api python -m app.cli seed`.
- **Prod overlay:** `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build`.

## Required production environment

Every secret comes from the environment with no default; the app refuses to
boot without them (`Settings.validate_production`, called in API lifespan and
worker startup). `DATABASE_URL`, `CHECKPOINT_DATABASE_URL`, `REDIS_URL`,
`SECRET_KEY`, `ENCRYPTION_KEY`, `CORS_ORIGINS` use `${VAR:?…}` in compose —
missing values fail fast at `config` time.

| Variable | Example | Notes |
|---|---|---|
| `ENVIRONMENT` | `production` | enables prod validation |
| `DATABASE_URL` | `postgresql+asyncpg://opspilot:<pw>@postgres:5432/opspilot` | app pool |
| `CHECKPOINT_DATABASE_URL` | `postgresql://opspilot:<pw>@postgres:5432/opspilot` | LangGraph checkpointer (sync driver) |
| `REDIS_URL` | `redis://redis:6379/0` | queue + locks + SSE |
| `SECRET_KEY` | 32+ random chars | signs JWTs; rotation invalidates sessions + API-key hashes |
| `ENCRYPTION_KEY` | base64 32-byte KEK | wraps integration credentials |
| `CORS_ORIGINS` | `https://opspilot.example.com` | never `*` in prod |
| `NEXT_PUBLIC_API_URL` | `https://opspilot.example.com` | **build-time**: changing it requires rebuilding `web` |
| `LLM_PROVIDER` | `anthropic` | `fake` for offline; key required for hosted providers |
| `ANTHROPIC_API_KEY` / `NVIDIA_API_KEY` | — | per `LLM_PROVIDER` |

`validate_production` additionally rejects `localhost`/`sqlite` data URLs and
weak `SECRET_KEY` values.

## Resource limits

`docker-compose.prod.yml` sets both Swarm `deploy.resources` **and**
`mem_limit`/`cpus` — plain `docker compose up` only honours the latter.
`worker replicas: 2` is Swarm-only; with plain compose run
`docker compose up --scale worker=2`.

## TLS edge

`docker compose --profile edge up proxy` starts Caddy with automatic Let's
Encrypt (`DOMAIN` + `CONTACT_EMAIL` required). Caddy terminates 443 and routes
`/api/*` → `api:8000`, everything else → `web:3000`. HSTS is served by the
frontend headers; CSP should be added per deployment in `next.config.ts`.

## Database

- Default `postgres` creds (`opspilot/opspilot`) come from the base file —
  override `POSTGRES_USER`/`POSTGRES_PASSWORD` via environment and keep
  `DATABASE_URL` in sync.
- Redis ships without auth; acceptable only on an isolated compose network.
  Add `requirepass` + `REDIS_URL` password for shared hosts.
- Backups: see `docs/RUNBOOK.md`. The `backup` profile writes timestamped
  `pg_dump` archives to the `postgres-backups` volume.

## Frontend notes

- `NEXT_PUBLIC_API_URL` and `NEXT_PUBLIC_DEMO_MODE` are inlined at build time.
  Promoting one image across environments is not supported — rebuild per env.
- `NEXT_PUBLIC_DEMO_MODE=true` prefills demo credentials on `/login`; never
  set it in production builds.
- `next.config.ts` throws at build when `NEXT_PUBLIC_API_URL` is unset, so a
  misconfigured build fails loudly instead of shipping a localhost client.

## CI gates

`ruff check` + `ruff format --check`, `pytest` with `--cov-fail-under=70`,
`alembic upgrade head` → re-run → `downgrade base` on real Postgres, eval suite
(`--min-score 0.9`), `tsc` + `eslint --max-warnings=0` + `next build`,
`pip-audit` and `npm audit` (blocking), Trivy image scan (CRITICAL/HIGH),
secret grep. `mypy` is currently non-blocking.
