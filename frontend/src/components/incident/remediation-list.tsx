"use client";

import { AlertTriangle, Database, RotateCcw, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { Badge, Button, EmptyState } from "@/components/ui/primitives";
import type { ApprovalWithAction, RemediationAction } from "@/lib/types";
import {
  cn,
  formatDateTime,
  remediationStatusStyles,
  riskStyles,
  titleCase,
} from "@/lib/utils";

/**
 * Proposed and executed remediation.
 *
 * Every card leads with the *blast radius* rather than the action name, because
 * that is the thing an approver actually needs to weigh. Policy violations are
 * shown in full when an action was blocked — a silent refusal teaches nobody
 * anything.
 */
export function RemediationList({
  actions,
  approvals,
  onDecide,
  canApprove,
}: {
  actions: RemediationAction[];
  approvals: ApprovalWithAction[];
  onDecide?: (
    approvalId: string,
    decision: "approve" | "reject",
    note: string,
  ) => Promise<void>;
  canApprove: boolean;
}) {
  if (actions.length === 0) {
    return (
      <EmptyState
        icon="🛠"
        title="No remediation proposed"
        description="The agent proposes actions only from a fixed catalog, and only when the evidence supports one. Recommending no action is a valid outcome."
      />
    );
  }

  const approvalByAction = new Map(approvals.map((a) => [a.action_id, a]));

  return (
    <ul className="space-y-3">
      {actions.map((action) => (
        <ActionCard
          key={action.id}
          action={action}
          approval={approvalByAction.get(action.id)}
          onDecide={onDecide}
          canApprove={canApprove}
        />
      ))}
    </ul>
  );
}

function ActionCard({
  action,
  approval,
  onDecide,
  canApprove,
}: {
  action: RemediationAction;
  approval?: ApprovalWithAction;
  onDecide?: (
    approvalId: string,
    decision: "approve" | "reject",
    note: string,
  ) => Promise<void>;
  canApprove: boolean;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const radius = action.blast_radius ?? {};
  const isPending = approval?.status === "pending";
  const blocked = action.status === "blocked_by_policy";

  async function decide(decision: "approve" | "reject") {
    if (!approval || !onDecide) return;
    setBusy(decision);
    try {
      await onDecide(approval.id, decision, note);
    } finally {
      setBusy(null);
    }
  }

  return (
    <li
      className={cn(
        "overflow-hidden rounded-lg border bg-[--color-surface]",
        isPending
          ? "border-amber-500/40 ring-1 ring-amber-500/20"
          : blocked
            ? "border-red-500/30"
            : "border-[--color-border-subtle]",
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={riskStyles[action.risk_tier]}>
              {action.risk_tier} risk
            </Badge>
            <Badge className={remediationStatusStyles[action.status]}>
              {titleCase(action.status)}
            </Badge>
            {action.is_reversible ? (
              <span className="inline-flex items-center gap-1 text-[10px] text-emerald-300">
                <RotateCcw className="h-3 w-3" aria-hidden />
                reversible
              </span>
            ) : null}
          </div>
          <h3 className="mt-1.5 text-sm font-semibold">{action.title}</h3>
          <code className="mt-0.5 block font-mono text-[11px] text-[--color-text-muted]">
            {action.action_key}({formatParams(action.params)})
          </code>
        </div>
      </div>

      <div className="space-y-3 border-t border-[--color-border-subtle] px-4 py-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-[--color-text-muted]">
            Why
          </p>
          <p className="mt-0.5 text-xs text-[--color-text-secondary]">
            {action.rationale || "—"}
          </p>
        </div>

        {action.expected_effect ? (
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-[--color-text-muted]">
              Expected effect
            </p>
            <p className="mt-0.5 text-xs text-[--color-text-secondary]">
              {action.expected_effect}
            </p>
          </div>
        ) : null}

        <BlastRadiusPanel radius={radius} />

        {blocked && action.policy_violations.length > 0 ? (
          <div className="rounded-lg bg-red-500/10 px-3 py-2 ring-1 ring-inset ring-red-500/25">
            <p className="flex items-center gap-1.5 text-[11px] font-medium text-red-300">
              <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
              Blocked by the policy engine
            </p>
            <ul className="mt-1 space-y-0.5">
              {action.policy_violations.map((violation, index) => (
                <li key={index} className="text-[11px] text-red-200/90">
                  <code className="font-mono text-[10px] opacity-70">
                    {violation.rule}
                  </code>{" "}
                  — {violation.message}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {action.execution_error ? (
          <p className="rounded-lg bg-red-500/10 px-3 py-2 text-[11px] text-red-300 ring-1 ring-inset ring-red-500/25">
            Execution failed: {action.execution_error}
          </p>
        ) : null}

        {action.executed_at ? (
          <p className="text-[11px] text-[--color-text-muted]">
            Executed {formatDateTime(action.executed_at)}
            {action.duration_ms !== null ? ` in ${action.duration_ms}ms` : ""}
            {typeof action.execution_result?.summary === "string"
              ? ` — ${action.execution_result.summary}`
              : ""}
          </p>
        ) : null}

        {approval?.context?.checklist && isPending ? (
          <div className="rounded-lg bg-[--color-canvas] px-3 py-2">
            <p className="text-[11px] font-medium text-[--color-text-secondary]">
              Before you approve
            </p>
            <ul className="mt-1 space-y-0.5">
              {approval.context.checklist.map((item, index) => (
                <li key={index} className="text-[11px] text-[--color-text-muted]">
                  • {item}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>

      {isPending && approval ? (
        <div className="space-y-2 border-t border-[--color-border-subtle] bg-[--color-canvas]/50 px-4 py-3">
          {!canApprove ? (
            <p className="text-[11px] text-amber-300">
              This action needs the <strong>{approval.required_role}</strong> role
              or above. Ask someone with that role to decide.
            </p>
          ) : (
            <>
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add a note for the audit trail (optional)"
                className="h-8 w-full rounded-lg border border-[--color-border-subtle] bg-[--color-canvas] px-3 text-xs placeholder:text-[--color-text-muted] focus:border-sky-500 focus:outline-none"
              />
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="success"
                  loading={busy === "approve"}
                  disabled={busy !== null}
                  onClick={() => void decide("approve")}
                >
                  Approve and execute
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  loading={busy === "reject"}
                  disabled={busy !== null}
                  onClick={() => void decide("reject")}
                >
                  Reject
                </Button>
                <span className="self-center text-[11px] text-[--color-text-muted]">
                  Expires {formatDateTime(approval.expires_at)}
                </span>
              </div>
            </>
          )}
        </div>
      ) : null}

      {approval && approval.status !== "pending" ? (
        <p className="border-t border-[--color-border-subtle] px-4 py-2 text-[11px] text-[--color-text-muted]">
          {titleCase(approval.status)} {formatDateTime(approval.decided_at)}
          {approval.decision_note ? ` — “${approval.decision_note}”` : ""}
        </p>
      ) : null}
    </li>
  );
}

export function BlastRadiusPanel({
  radius,
}: {
  radius: Record<string, unknown>;
}) {
  const targets = Array.isArray(radius.targets) ? (radius.targets as string[]) : [];
  const causesDowntime = Boolean(radius.causes_downtime);
  const touchesData = Boolean(radius.touches_data);

  return (
    <div className="rounded-lg bg-[--color-canvas] px-3 py-2">
      <p className="text-[11px] font-medium uppercase tracking-wide text-[--color-text-muted]">
        Blast radius
      </p>
      <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[--color-text-secondary]">
        <span>
          Scope: <strong>{String(radius.scope ?? "unknown")}</strong>
        </span>
        <span>
          Affects:{" "}
          <strong>{String(radius.estimated_affected_units ?? "?")}</strong> unit(s)
        </span>
        {targets.length > 0 ? (
          <span className="truncate">Targets: {targets.join(", ")}</span>
        ) : null}
      </div>

      {(causesDowntime || touchesData) && (
        <div className="mt-1.5 flex flex-wrap gap-2">
          {causesDowntime ? (
            <span className="inline-flex items-center gap-1 rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-medium text-red-300 ring-1 ring-inset ring-red-500/30">
              <AlertTriangle className="h-3 w-3" aria-hidden />
              causes downtime
            </span>
          ) : null}
          {touchesData ? (
            <span className="inline-flex items-center gap-1 rounded bg-orange-500/15 px-1.5 py-0.5 text-[10px] font-medium text-orange-300 ring-1 ring-inset ring-orange-500/30">
              <Database className="h-3 w-3" aria-hidden />
              touches data
            </span>
          ) : null}
        </div>
      )}

      {typeof radius.notes === "string" && radius.notes ? (
        <p className="mt-1.5 text-[11px] text-[--color-text-muted]">
          {radius.notes}
        </p>
      ) : null}
    </div>
  );
}

function formatParams(params: Record<string, unknown>): string {
  return Object.entries(params)
    .filter(([, value]) => value !== null && value !== undefined)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(", ");
}
