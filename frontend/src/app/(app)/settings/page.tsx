"use client";

import { useCallback, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  KeyValue,
  Skeleton,
  Tabs,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePolling } from "@/lib/stream";
import type { ActionSpec } from "@/lib/types";
import { formatDateTime, formatPercent, riskStyles, titleCase } from "@/lib/utils";

export default function SettingsPage() {
  const [tab, setTab] = useState("catalog");

  return (
    <>
      <PageHeader
        title="Safety & audit"
        description="What OpsPilot is capable of, the guardrails it runs under, and everything it has done."
      />

      <div className="p-5 lg:p-8">
        <Card>
          <div className="px-5 pt-2">
            <Tabs
              tabs={[
                { id: "catalog", label: "Action catalog" },
                { id: "policy", label: "Guardrails" },
                { id: "audit", label: "Audit log" },
                { id: "people", label: "People" },
              ]}
              active={tab}
              onChange={setTab}
            />
          </div>
          <CardBody>
            {tab === "catalog" ? <ActionCatalog /> : null}
            {tab === "policy" ? <Guardrails /> : null}
            {tab === "audit" ? <AuditLog /> : null}
            {tab === "people" ? <People /> : null}
          </CardBody>
        </Card>
      </div>
    </>
  );
}

function ActionCatalog() {
  const { data, error, loading, refresh } = usePolling(
    useCallback(() => api.catalog(), []),
    0,
  );

  if (error)
    return <ErrorState message={error.message} onRetry={() => void refresh()} />;
  if (loading && !data) return <Skeleton className="h-64" />;
  if (!data) return null;

  const byRisk = ["critical", "high", "medium", "low"] as const;

  return (
    <div className="space-y-5">
      <p className="text-xs text-[--color-text-muted]">
        This is the complete list of things OpsPilot can do to your
        infrastructure. The agent proposes actions by <em>key</em> from this
        catalog; anything not listed here cannot be executed, and there is no
        generic “run this command” action by design.
      </p>

      {byRisk.map((risk) => {
        const specs = data.filter((spec) => spec.risk_tier === risk);
        if (specs.length === 0) return null;
        return (
          <section key={risk}>
            <h3 className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
              <Badge className={riskStyles[risk]}>{risk} risk</Badge>
              <span>
                requires {specs[0]!.minimum_role} or above to approve
              </span>
            </h3>
            <ul className="space-y-2">
              {specs.map((spec) => (
                <ActionSpecRow key={spec.key} spec={spec} />
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

function ActionSpecRow({ spec }: { spec: ActionSpec }) {
  const properties =
    (spec.params_schema?.properties as Record<string, { type?: string }>) ?? {};
  const required = (spec.params_schema?.required as string[]) ?? [];

  return (
    <li className="rounded-lg border border-[--color-border-subtle] bg-[--color-surface] px-4 py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <code className="font-mono text-xs text-[--color-text-primary]">
          {spec.key}
        </code>
        <div className="flex gap-2 text-[10px] text-[--color-text-muted]">
          <span>{spec.provider}</span>
          {spec.is_reversible ? (
            <span className="text-emerald-400">reversible</span>
          ) : (
            <span className="text-orange-400">not reversible</span>
          )}
        </div>
      </div>
      <p className="mt-1 text-xs text-[--color-text-secondary]">
        {spec.description}
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {Object.entries(properties).map(([name, schema]) => (
          <code
            key={name}
            className="rounded bg-[--color-canvas] px-1.5 py-0.5 font-mono text-[10px] text-[--color-text-muted]"
            title={required.includes(name) ? "required" : "optional"}
          >
            {name}
            {required.includes(name) ? "" : "?"}: {schema?.type ?? "any"}
          </code>
        ))}
      </div>
    </li>
  );
}

function Guardrails() {
  const { data, error, loading, refresh } = usePolling(
    useCallback(
      async () => ({
        policy: await api.effectivePolicy(),
        rules: await api.policyRules(),
      }),
      [],
    ),
    0,
  );

  if (error)
    return <ErrorState message={error.message} onRetry={() => void refresh()} />;
  if (loading && !data) return <Skeleton className="h-64" />;
  if (!data) return null;

  const { policy, rules } = data;

  return (
    <div className="space-y-5">
      <p className="text-xs text-[--color-text-muted]">
        These checks are deterministic Python — no model is involved. They run
        twice: when an action is proposed, and again immediately before it
        executes.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
            Thresholds
          </h3>
          <dl className="divide-y divide-[--color-border-subtle]">
            <KeyValue label="Remediation enabled">
              <span
                className={
                  policy.remediation_enabled ? "text-emerald-300" : "text-red-300"
                }
              >
                {policy.remediation_enabled ? "yes" : "no (kill switch on)"}
              </span>
            </KeyValue>
            <KeyValue label="Always require approval at or above">
              {policy.always_approve_at_or_above}
            </KeyValue>
            <KeyValue label="Auto-approve low risk">
              {policy.auto_approve_low_risk ? "yes" : "no"}
            </KeyValue>
            <KeyValue label="Max pods affected">
              {policy.max_pods_restart}
            </KeyValue>
            <KeyValue label="Max replica change">
              ±{policy.max_replica_delta}
            </KeyValue>
            <KeyValue label="Actions per incident">
              {policy.max_actions_per_incident}
            </KeyValue>
            <KeyValue label="Actions per hour">
              {policy.max_actions_per_hour}
            </KeyValue>
            <KeyValue label="Confidence floor (high risk)">
              {formatPercent(policy.min_confidence_high_risk)}
            </KeyValue>
            <KeyValue label="Confidence floor (critical)">
              {formatPercent(policy.min_confidence_critical_risk)}
            </KeyValue>
            <KeyValue label="Min supporting evidence">
              {policy.min_evidence_high_risk}
            </KeyValue>
          </dl>
        </div>

        <div>
          <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
            Protected scope
          </h3>
          <div className="space-y-3">
            <div>
              <p className="text-[11px] text-[--color-text-muted]">
                Namespaces the agent may never modify
              </p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {policy.protected_namespaces.map((namespace) => (
                  <code
                    key={namespace}
                    className="rounded bg-red-500/10 px-1.5 py-0.5 font-mono text-[10px] text-red-300 ring-1 ring-inset ring-red-500/25"
                  >
                    {namespace}
                  </code>
                ))}
              </div>
            </div>
            <div>
              <p className="text-[11px] text-[--color-text-muted]">
                Environments where downtime-causing actions are denied
              </p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {policy.protected_environments.map((environment) => (
                  <code
                    key={environment}
                    className="rounded bg-[--color-canvas] px-1.5 py-0.5 font-mono text-[10px] text-[--color-text-secondary]"
                  >
                    {environment}
                  </code>
                ))}
              </div>
            </div>
            {policy.change_freeze_windows.length > 0 ? (
              <div>
                <p className="text-[11px] text-[--color-text-muted]">
                  Change freeze windows
                </p>
                <pre className="mt-1 rounded bg-[--color-canvas] p-2 font-mono text-[10px] text-[--color-text-secondary]">
                  {JSON.stringify(policy.change_freeze_windows, null, 2)}
                </pre>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      <div>
        <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
          Custom rules ({rules.length})
        </h3>
        {rules.length === 0 ? (
          <p className="text-xs text-[--color-text-muted]">
            No tenant-specific rules. The thresholds above apply.
          </p>
        ) : (
          <ul className="space-y-2">
            {rules.map((rule) => (
              <li
                key={rule.id}
                className="rounded-lg border border-[--color-border-subtle] px-4 py-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    className={
                      rule.effect === "deny"
                        ? "bg-red-500/15 text-red-300 ring-red-500/30"
                        : rule.effect === "auto_approve"
                          ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
                          : "bg-amber-500/15 text-amber-300 ring-amber-500/30"
                    }
                  >
                    {titleCase(rule.effect)}
                  </Badge>
                  <span className="text-sm font-medium">{rule.name}</span>
                  {!rule.is_enabled ? <Badge>disabled</Badge> : null}
                  <span className="ml-auto text-[10px] text-[--color-text-muted]">
                    priority {rule.priority} · {rule.hit_count} hits
                  </span>
                </div>
                {rule.description ? (
                  <p className="mt-1 text-xs text-[--color-text-secondary]">
                    {rule.description}
                  </p>
                ) : null}
                <pre className="scroll-x mt-2 rounded bg-[--color-canvas] p-2 font-mono text-[10px] text-[--color-text-muted]">
                  match {JSON.stringify(rule.match)}
                  {Object.keys(rule.limits).length > 0
                    ? `\nlimits ${JSON.stringify(rule.limits)}`
                    : ""}
                </pre>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function AuditLog() {
  const { data, error, loading, refresh } = usePolling(
    useCallback(() => api.auditLogs({ limit: 100 }), []),
    30_000,
  );

  if (error)
    return <ErrorState message={error.message} onRetry={() => void refresh()} />;
  if (loading && !data) return <Skeleton className="h-64" />;
  if (!data || data.items.length === 0)
    return (
      <div className="space-y-3">
        <ClearAuditLog total={0} onCleared={refresh} />
        <EmptyState icon="📋" title="No audit entries yet" />
      </div>
    );

  return (
    <div className="space-y-3">
      <ClearAuditLog total={data.total} onCleared={refresh} />
      <p className="text-xs text-[--color-text-muted]">
        Entries are immutable once written, but an admin can clear the log.
        {" "}
        {data.total} total entries.
      </p>
      <div className="scroll-x">
        <table className="w-full min-w-[720px] text-left text-xs">
          <thead className="text-[10px] uppercase tracking-wide text-[--color-text-muted]">
            <tr className="border-b border-[--color-border-subtle]">
              <th className="pb-2 pr-3 font-medium">When</th>
              <th className="pb-2 pr-3 font-medium">Action</th>
              <th className="pb-2 pr-3 font-medium">Actor</th>
              <th className="pb-2 font-medium">Summary</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[--color-border-subtle]">
            {data.items.map((entry) => (
              <tr key={entry.id}>
                <td className="whitespace-nowrap py-2 pr-3 text-[--color-text-muted]">
                  {formatDateTime(entry.occurred_at)}
                </td>
                <td className="py-2 pr-3">
                  <code className="font-mono text-[10px] text-[--color-text-secondary]">
                    {entry.action}
                  </code>
                </td>
                <td className="whitespace-nowrap py-2 pr-3 text-[--color-text-secondary]">
                  {entry.actor_label || entry.actor_type}
                </td>
                <td className="py-2 text-[--color-text-secondary]">
                  {entry.summary}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * "Clear log" — deletes every audit entry for the tenant.
 *
 * Irreversible, so the destructive click is never the first one: the button
 * opens a confirmation naming the number of entries, and the request only fires
 * from a second, explicitly-labelled click. Admin-only, matching the endpoint.
 */
function ClearAuditLog({
  total,
  onCleared,
}: {
  total: number;
  onCleared: () => void | Promise<unknown>;
}) {
  const { can } = useAuth();
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  if (!can("admin")) return null;

  const clear = async () => {
    setBusy(true);
    setFailure(null);
    try {
      await api.clearAuditLogs(reason.trim() || undefined);
      setConfirming(false);
      setReason("");
      await onCleared();
    } catch (caught) {
      setFailure(caught instanceof Error ? caught.message : "Could not clear the log");
    } finally {
      setBusy(false);
    }
  };

  if (!confirming) {
    return (
      <div className="flex justify-end">
        <Button
          size="sm"
          variant="danger"
          disabled={total === 0}
          onClick={() => setConfirming(true)}
        >
          Clear log
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-lg border border-red-500/40 bg-red-500/5 px-4 py-3">
      <div>
        <p className="text-sm font-medium text-[--color-text-primary]">
          Delete all {total} audit {total === 1 ? "entry" : "entries"}?
        </p>
        <p className="mt-1 text-xs text-[--color-text-muted]">
          This cannot be undone. Export the log first if you need the history —
          only a single entry recording this deletion will remain.
        </p>
      </div>
      <input
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        maxLength={500}
        placeholder="Reason (optional, recorded on the remaining entry)"
        className="w-full rounded-lg border border-[--color-border-subtle] bg-[--color-canvas] px-3 py-2 text-xs text-[--color-text-primary] placeholder:text-[--color-text-muted] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[--color-accent]"
      />
      {failure ? <p className="text-xs text-red-300">{failure}</p> : null}
      <div className="flex justify-end gap-2">
        <Button
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={() => {
            setConfirming(false);
            setFailure(null);
          }}
        >
          Cancel
        </Button>
        <Button size="sm" variant="danger" loading={busy} onClick={() => void clear()}>
          Delete {total} {total === 1 ? "entry" : "entries"}
        </Button>
      </div>
    </div>
  );
}

function People() {
  const { data, error, loading, refresh } = usePolling(
    useCallback(() => api.users(), []),
    0,
  );

  if (error)
    return <ErrorState message={error.message} onRetry={() => void refresh()} />;
  if (loading && !data) return <Skeleton className="h-40" />;
  if (!data) return null;

  return (
    <div className="space-y-3">
      <p className="text-xs text-[--color-text-muted]">
        Roles are cumulative: viewer &lt; responder &lt; approver &lt; admin &lt;
        owner. The role required to approve an action comes from its risk tier.
      </p>
      <ul className="divide-y divide-[--color-border-subtle]">
        {data.items.map((user) => (
          <li key={user.id} className="flex items-center gap-3 py-2.5">
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm">
                {user.full_name || user.email}
              </p>
              <p className="truncate text-[11px] text-[--color-text-muted]">
                {user.email}
              </p>
            </div>
            <Badge>{user.role}</Badge>
            {!user.is_active ? (
              <Badge className="bg-red-500/15 text-red-300 ring-red-500/30">
                disabled
              </Badge>
            ) : null}
            <span className="hidden w-32 shrink-0 text-right text-[11px] text-[--color-text-muted] sm:block">
              {user.last_login_at
                ? `seen ${formatDateTime(user.last_login_at)}`
                : "never signed in"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
