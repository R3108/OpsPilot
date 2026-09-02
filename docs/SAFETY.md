# The safety model

OpsPilot is allowed to change production. This document is the argument for why
that is acceptable, and the list of things that have to hold for it to stay
acceptable.

## The one idea

> **A language model's output can select an action. It can never *be* an action.**

Everything else follows from that. The model emits

```json
{ "action_key": "k8s.rollback_deployment",
  "params": { "namespace": "orders", "deployment": "orders-api" } }
```

which is a *key into a registry* plus typed arguments. There is no code path
anywhere in this repository that takes model output and passes it to a shell, an
`eval`, a SQL string, a URL path, or a `kubectl` invocation.

## The seven gates

Between a model proposing something and infrastructure changing, a proposal
passes through seven independent checks. Each one fails closed.

| # | Gate | Where | What it stops |
|---|---|---|---|
| 1 | **Catalog lookup** | `services/actions/registry.py` | An invented or renamed action key. Unknown key → proposal dropped. |
| 2 | **Schema validation** | Pydantic model per action, `extra="forbid"` | Malformed, out-of-range or injected parameters. `namespace="prod; rm -rf /"` fails the RFC-1123 pattern. |
| 3 | **Catalog fingerprint** | `registry_fingerprint()` | The meaning of an action key changing between approval and execution. |
| 4 | **Policy engine** | `services/policy.py` | Protected namespaces, blast-radius ceilings, change freezes, rate limits, confidence and evidence floors, tenant rules. Pure Python, no LLM. |
| 5 | **Human approval** | `services/approvals.py` | Anything above the tenant's risk threshold. The graph *suspends* — it does not poll or time out into acting. |
| 6 | **Idempotency + locking** | Redis advisory lock, `idempotency_key` | The same remediation executing twice because a worker retried or a graph resumed. |
| 7 | **Write-integration check** | `ClientRegistry`, `_require_write()` | Acting through an integration the tenant marked read-only, or one scoped to different namespaces. |

Gates 1, 2, 4, 5 and 7 all run **again** immediately before execution, not just
at proposal time. A policy that changes, an approval that expires, or an
integration that is switched to read-only mid-incident all take effect.

## What the model is allowed to influence

| Decision | Who makes it |
|---|---|
| Severity classification | Model (a human can override) |
| Which investigators to run | Model, filtered to available integrations |
| What the evidence *means* | Model |
| Ranked hypotheses and confidence | Model |
| **Which evidence exists** | **Typed read-only tools. The model cannot write evidence.** |
| **Which action to propose** | Model, but only by key from the catalog |
| **The action's risk tier** | **Deterministic, from the catalog + the concrete parameters** |
| **Blast radius** | **Deterministic, computed from parameters and live cluster facts** |
| **Whether it is allowed** | **Deterministic policy engine** |
| **Whether it runs** | **A human, for anything above low risk** |
| **Whether recovery happened** | **Deterministic threshold checks against real metrics** |

The last row matters more than it looks: a model is never allowed to declare its
own fix successful. It proposes thresholds during remediation; Python fetches the
metrics and evaluates them.

## Blast radius is computed, not claimed

`ActionSpec.blast_radius_fn` is a pure function of the validated parameters. It
does not read the model's rationale, and the model cannot influence it except by
choosing different parameters — which changes the real blast radius too.

The declared risk tier is then escalated when the concrete arguments are worse
than the general case: scaling to zero is an outage, so it becomes `CRITICAL`
even though scaling is `HIGH`. See `_effective_risk_tier`.

## What an approver can and cannot change

An approver can **narrow** an action: fewer replicas, fewer terminations, a lower
connection limit. They cannot **widen** it, and they cannot **retarget** it — a
different namespace or deployment is a different action and has to be proposed
and re-approved. Enforced in `approvals._reject_widening`, tested in
`tests/test_approval_flow.py`.

This exists because approving "restart 2 pods" and executing "restart 40 pods"
would make the approval meaningless.

## Credentials

* Envelope encryption: a per-secret AES-GCM data key, wrapped by the deployment
  KEK. Rotating the KEK rewraps small keys rather than re-encrypting everything.
* The AAD binds each blob to `tenant:{id}:integration:{id}`, so a ciphertext
  cannot be moved between tenants or rows even with database access.
* The API never returns a credential. It returns `credential_keys` and
  short non-reversible `credential_fingerprints` so the UI can show *which*
  secret is configured.
* Structured logging redacts by key name, by bearer-token shape, and by known
  provider token prefixes (`sk-`, `xoxb-`, `ghp_`, `AKIA…`) before anything is
  written or sent to LangSmith.

## Multi-tenancy

Two independent layers:

1. Every query filters on `tenant_id`, and every route resolves a `Principal`
   that carries it. A cross-tenant read returns **404, not 403** — a 403 would
   confirm the resource exists.
2. Postgres row-level security keyed on `current_setting('opspilot.tenant_id')`,
   with the policy denying everything when the setting is absent, so a missing
   `SET` fails closed. See migration `0002`.

## Audit

Every proposal, policy decision, approval, execution attempt and failure is
recorded with its actor, the request id, and before/after state (redacted).

Entries are **immutable but not permanent**:

* No update path. Migration `0003` installs a trigger rejecting `UPDATE` on
  `audit_logs`, so a row that exists is verbatim what was written.
* `DELETE /api/v1/audit` lets an admin clear the tenant's entire trail. A single
  `audit.cleared` entry naming the actor, their IP and an optional reason is
  written afterwards and is all that survives.

This was originally append-only at the database level, and the clear button is a
deliberate trade of that property for operator convenience. The consequence is
stated plainly under *Known limits*: the trail no longer constrains an admin.
Export via `GET /api/v1/audit/export` is the only durable copy — if you need a
trail that an admin cannot erase, ship that CSV to external storage on a
schedule, or revert migration `0003`.

## Kill switches

| Switch | Scope | Effect |
|---|---|---|
| `REMEDIATION_DISABLED=true` | Deployment | Every action is denied by the policy engine. Investigation still runs. |
| `settings_json.policy.remediation_enabled = false` | One tenant | Same, for that tenant. |
| `Integration.allow_write = false` | One integration | The agent can read through it but never write. |
| `Integration.is_enabled = false` | One integration | It disappears from planning entirely. |
| `PolicyRule` with `effect: deny` | Whatever it matches | First matching deny wins and cannot be overridden. |

## Known limits

Stated plainly, because a safety document that only lists strengths is not one.

* **The model can still be wrong about the root cause.** The gates constrain
  *what* can happen, not whether the diagnosis is correct. A confidently wrong
  hypothesis that clears the confidence floor and gets human approval will
  execute the wrong remediation. Mitigations: alternatives are always shown with
  contradicting evidence, verification is independent, and a failed recovery
  forces a fresh investigation rather than a retry.
* **`auto_approve_low_risk` is a real hole if you widen it.** It exists so
  notifications and PR-opening do not page a human. Adding a genuinely dangerous
  action to the LOW tier would bypass gate 5. The catalog is small and reviewed
  for exactly this reason, and `tests/test_action_catalog.py` asserts that
  database-terminating actions stay at HIGH or above.
* **Simulation mode is single-process.** It is for evals, tests and the demo.
  Never enable it against something you care about.
* **The policy engine trusts its inputs.** If `live_facts` cannot reach the
  cluster it falls back to the static blast-radius estimate — which is more
  conservative, not less, but is still an estimate.
* **Prometheus queries are model-influenced strings.** PromQL is read-only by
  construction and queries are length-capped and screened, but this is the one
  place a model-authored string reaches a provider. The investigator prefers the
  vetted `STANDARD_QUERIES` library.

## If you are reviewing this

The highest-leverage files, in order:

1. `backend/app/services/actions/registry.py` — the catalog contract
2. `backend/app/services/policy.py` — every deterministic check
3. `backend/app/services/executor.py` — the seven gates, in order
4. `backend/app/services/approvals.py` — narrowing rules
5. `backend/tests/test_action_catalog.py` — the tripwire that fails if anyone
   adds a generic execution primitive
