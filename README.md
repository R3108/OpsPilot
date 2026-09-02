# OpsPilot AI

**Autonomous AI SRE / incident-response platform.**

OpsPilot ingests alerts from Slack, GitHub, Kubernetes, Prometheus/Grafana and CloudWatch,
builds persistent incident state, runs a LangGraph investigation swarm over logs, metrics,
database health, recent deploys and historical incidents, correlates the evidence into ranked
root-cause hypotheses, proposes remediation, gates every risky action behind a deterministic
policy engine plus human approval, executes approved actions through typed tools, verifies
recovery, and writes an evidence-backed postmortem.

---

## Core design principle

> **The LLM never touches infrastructure.**

There are two strictly separated planes:

| Plane | What it does | Who controls it |
|---|---|---|
| **Reasoning plane** | Reads evidence, forms hypotheses, ranks them, *proposes* an action by name + typed args | LLM (LangGraph agents) |
| **Execution plane** | Validates the proposal against a signed action catalog, runs deterministic policy checks, requires human approval, executes via a typed executor | Pure Python. No model output is ever interpolated into a command. |

An LLM proposal is a `ProposedAction{action_key, params}` — a *key into a registry*, never a
shell string. Unknown keys, out-of-schema params, out-of-policy blast radius, or missing
approval all fail closed. See `backend/app/services/policy.py` and
`backend/app/services/actions/`.

---

## Architecture

```
                    ┌──────────────── ingest ────────────────┐
  Slack ──┐         │  /api/v1/webhooks/{slack,github,       │
  GitHub ─┤         │   alertmanager,grafana,cloudwatch}     │
  K8s ────┼────────▶│  HMAC-verified, tenant-scoped          │
  Prom ───┤         └───────────────┬───────────────────────┘
  CW ─────┘                         │
                                    ▼
                        ┌───────────────────────┐
                        │ Incident (Postgres)   │  persistent state, timeline,
                        │ + AgentRun            │  evidence, hypotheses, actions
                        └───────────┬───────────┘
                                    │ enqueue (Redis / arq)
                                    ▼
        ┌──────────────────────────────────────────────────────────┐
        │  LangGraph  (AsyncPostgresSaver checkpointer, resumable)  │
        │                                                          │
        │  triage ─▶ plan ─▶ ┌ logs ────────┐                       │
        │                    │ metrics      │  parallel fan-out     │
        │                    │ database     │  (typed read-only     │
        │                    │ deploys      │   integration tools)  │
        │                    └ history ─────┘                       │
        │                        ▼                                 │
        │                    correlate ─▶ hypothesize ─▶ rank       │
        │                        ▼                                 │
        │                    propose_remediation                    │
        │                        ▼                                 │
        │                    policy_check  (deterministic)          │
        │                        ▼                                 │
        │                    ⏸ interrupt → human approval           │
        │                        ▼                                 │
        │                    execute ─▶ verify_recovery             │
        │                        ├─ recovered ─▶ postmortem         │
        │                        └─ not recovered ─▶ back to plan   │
        └──────────────────────────────────────────────────────────┘
                                    │
                       Redis pub/sub ▼  SSE
                        Next.js live agent console
```

## Stack

* **Backend** — Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic, Pydantic v2
* **Agents** — LangGraph (Postgres checkpointer), LangChain, LangSmith tracing
* **Data** — PostgreSQL 16 (+ `pgvector` for historical-incident similarity), Redis 7
* **Workers** — arq (async Redis queue)
* **Frontend** — Next.js 15 (App Router), TypeScript, Tailwind v4, shadcn-style components
* **Infra** — Docker / docker-compose, GitHub Actions CI

## Quick start

```bash
cp .env.example .env          # set a model provider key + SECRET_KEY + ENCRYPTION_KEY
make keys                     # generates SECRET_KEY / ENCRYPTION_KEY for you
docker compose up --build     # api :8000, web :3000, postgres :5432, redis :6379
docker compose exec api alembic upgrade head
docker compose exec api python -m app.cli seed   # demo tenant + user + incidents
```

Login at http://localhost:3000 with `admin@opspilot.dev` / `opspilot`.

### Choosing a model provider

`LLM_PROVIDER` selects one of three clients; compose defaults to `fake`, so the
whole stack runs with no API key at all.

```bash
LLM_PROVIDER=fake                       # offline heuristic engine — no key, what CI runs

LLM_PROVIDER=anthropic                  # ANTHROPIC_API_KEY, OPSPILOT_MODEL

LLM_PROVIDER=nvidia                     # NVIDIA NIM, via its OpenAI-compatible API
NVIDIA_API_KEY=nvapi-...                #   from https://build.nvidia.com
NVIDIA_MODEL=openai/gpt-oss-120b
```

For a NIM container you host yourself, point `NVIDIA_BASE_URL` at it
(`http://localhost:8000/v1`) and leave `NVIDIA_API_KEY` empty — same code path.

Every agent call asks for a Pydantic schema rather than free text, so a NIM model
needs tool calling (the default) or guided decoding
(`NVIDIA_STRUCTURED_OUTPUT_METHOD=json_schema`). `make eval-live
LLM_PROVIDER=nvidia` scores a provider against the incident scenarios in the same
format as the offline run, so swapping models is a measurable change rather than
a hopeful one.

### Local (no Docker)

```bash
make dev-backend    # uvicorn on :8000  (needs local postgres+redis, see .env)
make dev-frontend   # next dev on :3000
```

## Repo layout

```
backend/
  app/
    core/          config, db, redis, security, envelope crypto, logging
    models/        SQLAlchemy models (tenant-scoped, audited)
    schemas/       Pydantic v2 request/response contracts
    api/v1/        REST + SSE endpoints
    agents/        LangGraph state, graph, nodes, LLM-facing tools
    integrations/  Slack, GitHub, K8s, Prometheus, Grafana, CloudWatch clients
    services/      incidents, policy engine, action catalog+executors, audit, events
    workers/       arq worker running the graph
    evals/         LangSmith eval datasets + runner
  tests/
frontend/
  src/app/         App Router pages: incidents, approvals, integrations, settings
  src/components/  UI + incident console
  src/lib/         API client, SSE hook, types
```

## Safety model

1. **Action catalog** — every executable action is a registered `ActionSpec` with a JSON schema,
   a risk tier, a required RBAC role, and a Python executor. Nothing else can run.
2. **Policy engine** — deterministic, no LLM: blast-radius caps, protected-namespace lists,
   maintenance windows, per-tenant kill switch, rate limits, replica-delta bounds.
3. **Approvals** — anything above `RiskTier.LOW` interrupts the graph and persists an
   `Approval` row. The graph resumes only on an explicit human decision.
4. **Credentials** — envelope-encrypted (AES-GCM data key wrapped by a KEK), never returned by
   the API, redacted from logs and traces.
5. **Audit** — every state transition, proposal, decision and execution is an immutable
   `AuditLog` row with actor, tenant, before/after, and request id. Admins can clear the
   trail from Safety & audit; export it first if you need to keep it.

See [`docs/SAFETY.md`](docs/SAFETY.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Tests

```bash
make test          # pytest, async, on a throwaway sqlite/postgres
make lint          # ruff + mypy + eslint + tsc
make eval          # LangSmith eval over the incident datasets
```

## License

Apache-2.0
