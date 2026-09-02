# Architecture

## The shape of the system

```
   Slack   GitHub   K8s   Prometheus   CloudWatch   Grafana
     │        │      │        │            │           │
     └────────┴──────┴────┬───┴────────────┴───────────┘
                          │  HMAC-verified webhooks, per-integration secret
                          ▼
              ┌───────────────────────┐
              │   FastAPI (stateless) │  ingest · REST · SSE
              └───────────┬───────────┘
                          │ enqueue
                          ▼
                    ┌───────────┐
                    │   Redis   │  queue · pub/sub · locks · idempotency
                    └─────┬─────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   arq worker          │  runs the LangGraph investigation
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   PostgreSQL          │  incidents, evidence, hypotheses,
              │   + LangGraph         │  actions, approvals, audit,
              │     checkpoints       │  graph checkpoints, pgvector
              └───────────────────────┘
```

Three processes, one database. The API is stateless and horizontally scalable;
the worker is where anything slow or dangerous happens; Redis is coordination
only — nothing durable lives there.

## Why the worker exists

An investigation takes minutes and can pause for an hour waiting on a human.
Running that in a request would mean:

* a deploy of the API kills in-flight investigations,
* an HTTP timeout is indistinguishable from a failed remediation,
* the approval pause would have to be a poll loop.

Instead the API only ever enqueues. The graph checkpoints to Postgres after every
node, so a worker can die mid-investigation and another picks up exactly where it
stopped — including resuming a run that has been parked on an approval interrupt
since yesterday.

## The graph

```
START ─▶ triage ─▶ plan ─┬─▶ logs ────────┐
                         ├─▶ metrics      │
                         ├─▶ database     ├─▶ correlate ─▶ hypothesize
                         ├─▶ deployments  │                    │
                         └─▶ history ─────┘                    │
                                                               ▼
   ┌───────────── needs more evidence ─────────────────────  propose
   │                                                            │
   │                                                            ▼
   │                                                      policy_check
   │                                                    ┌───────┴───────┐
   │                                              all blocked      needs approval
   │                                                    │               │
   │                                                    │        await_approval ⏸
   │                                                    │               │
   │                                                    │            execute
   │                                                    │               │
   └──────────── recovery failed ◀─────────────────────┼───────────  verify
                                                        │               │
                                                        └───────┬───────┘
                                                                ▼
                                                           postmortem ─▶ END
```

Three design choices worth calling out:

**The fan-out is five separate nodes, not one node with five tool calls.**
LangGraph runs them as a real parallel superstep, each with its own session,
its own error boundary and its own state key. One provider being slow delays one
track. One provider failing produces a "dead end" finding rather than aborting
the investigation.

**The retry loop goes back to `plan`, not to `execute`.** If verification says the
service did not recover, retrying the same action is the wrong move — the
hypothesis was probably wrong. The next pass gets the failed remediation as
evidence, and the prompt explicitly tells the model to treat the previous
hypothesis as weakened. Bounded by `max_iterations`.

**`await_approval` is a real `interrupt()`, not a poll.** The graph writes its
checkpoint and stops. Nothing is running, nothing is holding a connection, and
nothing times out into acting.

## Data model

The durable spine is `Incident`. Everything hangs off it:

| Table | What it holds | Written by |
|---|---|---|
| `incidents` | The incident and its lifecycle timestamps | ingest, agents, humans |
| `timeline_entries` | The human-readable narrative | agents and humans |
| `evidence` | Facts retrieved from real systems, with raw payloads | **typed tools only** |
| `hypotheses` | Ranked causal claims with citations | the model |
| `agent_runs` / `agent_steps` | Execution trace, timings, token cost | the runtime |
| `remediation_actions` | Proposals, policy decisions, execution results | agents and humans |
| `approvals` | The human decision gate | policy engine, humans |
| `action_execution_logs` | One row per *attempt*, including failures | the executor |
| `verifications` | Recovery checks and their observed values | deterministic verifier |
| `postmortems` | The final document | the model, edited by humans |
| `audit_logs` | Activity trail; rows immutable, clearable by an admin | everything |

`Evidence` being writable only by tools is the load-bearing constraint: it is
what makes a postmortem checkable. Every claim resolves to a row with the raw
provider response attached.

## Prompt and context flow

Each node asks for exactly one Pydantic schema (`agents/contracts.py`). Nothing
is parsed out of prose. The context each node sees is deliberately narrow:

* **triage** — the alert and recent incidents on the same service
* **plan** — triage output and the investigators that actually have integrations
* **investigator** — only the evidence *it* collected
* **correlate** — every investigator's report plus the full evidence set
* **hypothesize** — the correlation, the evidence, and (on a retry) what failed
* **propose** — the selected hypothesis, the evidence, and the action catalog
* **postmortem** — everything, plus the verification result

Citations are filtered against the run's real evidence ids at every boundary
(`valid_citations`), so a hallucinated id is dropped rather than propagated into
a hypothesis or a postmortem.

## Model providers

`agents/llm.py` exposes one interface — `LLMClient.structured` — and three
implementations behind `LLM_PROVIDER`:

| `LLM_PROVIDER` | Client | Transport |
| --- | --- | --- |
| `anthropic` | `AnthropicLLM` | `langchain-anthropic`, `OPSPILOT_MODEL` |
| `nvidia` | `NvidiaLLM` | NIM's OpenAI-compatible API at `NVIDIA_BASE_URL`, `NVIDIA_MODEL` |
| `fake` | `HeuristicLLM` | none — see *Offline mode* below |

The two live providers share `_LangChainLLM`, which owns the retry budget, the
schema-repair prompt, usage accounting and the LangSmith metadata. A provider
supplies only its model ids, its chat-model constructor and its token rates, so
the providers cannot drift apart on the parts that matter.

Every call is a schema request, never free text, which is the one thing a NIM
model has to be able to do. Tool-capable models (the default
`openai/gpt-oss-120b`) serve those through function calling; set
`NVIDIA_STRUCTURED_OUTPUT_METHOD=json_schema` for models that expose guided
decoding instead. Not every NIM model implements tool calling — several in the
hosted catalogue answer a tool-call request with a 404, so a model swap is worth
checking against `make eval-live` rather than assuming. `NVIDIA_BASE_URL` defaults to the hosted catalogue and points
just as well at a NIM container you run yourself, in which case the API key is
optional and cost accounting is off unless you set `NVIDIA_PRICE_PER_MTOK_*`.

## Offline mode

`LLM_PROVIDER=fake` swaps the model for `agents/heuristics.py`: a signature-based
reasoning engine that reads the same evidence and applies documented SRE
heuristics. It is not a fixture-returning mock — the graph, policy engine,
approvals, execution and verification all run for real against it.

This is what makes the test suite and the eval harness meaningful without an API
key, and what CI runs. Its limit is that it cannot generalise past its signature
table; the eval harness reports fake and live scores in the same format so the
gap is measurable rather than hidden.

## Simulation mode

An integration with `config.mode = "simulation"` swaps its transport for an
in-process world (`integrations/simulation.py`) driven by a scenario file. The
important property: a scenario declares which action fixes it, and applying that
action *changes the world*, so verification observes real recovery — and real
non-recovery when the agent picks wrong. Without that, the verification loop
would be untestable.

## Observability

* **Structured logs** (structlog) with request id, tenant id, incident id and
  run id bound through contextvars, JSON in production, secrets redacted at the
  processor.
* **LangSmith** tracing on every LLM call, tagged with purpose, incident and
  tenant. The `AgentRun` row carries the trace url so the UI can deep-link.
* **Cost accounting** per run: prompt tokens, completion tokens and estimated
  USD, aggregated onto the dashboard.
* **The agent console** streams every phase, tool call and decision over SSE
  with a replay buffer, so a responder can watch reasoning happen and audit it
  afterwards from the same data.

## Scaling notes

* API: stateless, scale horizontally. SSE fan-out goes through Redis pub/sub, so
  any replica can serve any stream.
* Worker: multiple replicas are safe. Per-incident Redis advisory locks prevent
  two workers driving the same graph, and the checkpointer is shared.
* Postgres is the bottleneck at scale. The hot paths are indexed on
  `(tenant_id, …)`, incident lists use partial indexes on active rows, and
  evidence raw payloads are size-capped so one chatty provider cannot bloat the
  table.
* Historical similarity is IDF-weighted lexical by default and switches to
  pgvector cosine as soon as embeddings exist, with no call-site change.
