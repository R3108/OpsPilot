"use client";

import Link from "next/link";
import { useCallback, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { BlastRadiusPanel } from "@/components/incident/remediation-list";
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  ErrorState,
  Input,
  Skeleton,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePolling, useTenantStream } from "@/lib/stream";
import type { ApprovalWithAction } from "@/lib/types";
import {
  cn,
  formatDateTime,
  formatRelative,
  riskStyles,
  titleCase,
} from "@/lib/utils";

const FILTERS = [
  { id: "pending", label: "Pending" },
  { id: "approved", label: "Approved" },
  { id: "rejected", label: "Rejected" },
  { id: "", label: "All" },
] as const;

export default function ApprovalsPage() {
  const { can } = useAuth();
  const [filter, setFilter] = useState<string>("pending");

  const loader = useCallback(
    () => api.approvals({ status: filter || undefined, limit: 100 }),
    [filter],
  );
  const { data, error, loading, refresh } = usePolling(loader, 15_000, [filter]);

  useTenantStream(
    useCallback(
      (event) => {
        if (event.type.startsWith("approval.")) void refresh();
      },
      [refresh],
    ),
  );

  return (
    <>
      <PageHeader
        title="Approvals"
        description="Every change above low risk stops here until a human decides."
        actions={
          <div className="flex rounded-lg bg-[--color-surface] p-1">
            {FILTERS.map((option) => (
              <button
                key={option.id || "all"}
                onClick={() => setFilter(option.id)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors",
                  filter === option.id
                    ? "bg-[--color-surface-raised] text-[--color-text-primary]"
                    : "text-[--color-text-muted] hover:text-[--color-text-secondary]",
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        }
      />

      <div className="space-y-4 p-5 lg:p-8">
        {error ? (
          <Card>
            <ErrorState message={error.message} onRetry={() => void refresh()} />
          </Card>
        ) : null}

        {loading && !data ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <Skeleton key={index} className="h-52" />
            ))}
          </div>
        ) : null}

        {data && data.items.length === 0 ? (
          <Card>
            <EmptyState
              icon="✅"
              title={
                filter === "pending"
                  ? "Nothing is waiting on you"
                  : "No approvals in this view"
              }
              description={
                filter === "pending"
                  ? "When the agent proposes a risky change, it will appear here and pause until you decide."
                  : undefined
              }
            />
          </Card>
        ) : null}

        {data?.items.map((approval) => (
          <ApprovalCard
            key={approval.id}
            approval={approval}
            canApprove={can("approver")}
            onDecided={() => void refresh()}
          />
        ))}
      </div>
    </>
  );
}

function ApprovalCard({
  approval,
  canApprove,
  onDecided,
}: {
  approval: ApprovalWithAction;
  canApprove: boolean;
  onDecided: () => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pending = approval.status === "pending";
  const expired = new Date(approval.expires_at).getTime() < Date.now();

  async function decide(decision: "approve" | "reject") {
    setBusy(decision);
    setError(null);
    try {
      await api.decide(approval.id, { decision, note });
      onDecided();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record the decision");
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card
      className={cn(
        pending && !expired ? "border-amber-500/40 ring-1 ring-amber-500/20" : "",
      )}
    >
      <CardBody className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={riskStyles[approval.risk_tier]}>
                {approval.risk_tier} risk
              </Badge>
              <Badge>{titleCase(approval.status)}</Badge>
              <Link
                href={`/incidents/${approval.incident_id}`}
                className="font-mono text-[11px] text-sky-400 hover:text-sky-300"
              >
                {approval.incident_reference}
              </Link>
            </div>
            <h2 className="mt-1.5 text-sm font-semibold">
              {approval.action.title}
            </h2>
            <p className="text-xs text-[--color-text-muted]">
              {approval.incident_title}
            </p>
          </div>

          <div className="shrink-0 text-right text-[11px] text-[--color-text-muted]">
            <p>Requested {formatRelative(approval.requested_at)}</p>
            <p className={expired && pending ? "text-red-300" : undefined}>
              {expired && pending ? "Expired " : "Expires "}
              {formatDateTime(approval.expires_at)}
            </p>
          </div>
        </div>

        <pre className="scroll-x rounded-lg bg-[--color-canvas] px-3 py-2 font-mono text-[11px] text-[--color-text-secondary]">
          {approval.action.action_key}(
          {JSON.stringify(approval.action.params, null, 0)})
        </pre>

        <p className="whitespace-pre-wrap text-xs text-[--color-text-secondary]">
          {approval.request_summary}
        </p>

        <BlastRadiusPanel radius={approval.context?.blast_radius ?? {}} />

        {approval.context?.checklist?.length ? (
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

        {approval.context?.warnings?.length ? (
          <ul className="space-y-1">
            {approval.context.warnings.map((warning, index) => (
              <li
                key={index}
                className="rounded bg-amber-500/10 px-2.5 py-1.5 text-[11px] text-amber-200 ring-1 ring-inset ring-amber-500/25"
              >
                {warning.message}
              </li>
            ))}
          </ul>
        ) : null}

        {error ? <p className="text-xs text-red-300">{error}</p> : null}

        {pending && !expired ? (
          canApprove ? (
            <div className="space-y-2 border-t border-[--color-border-subtle] pt-3">
              <Input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Note for the audit trail (optional)"
                className="h-8 text-xs"
              />
              <div className="flex flex-wrap gap-2">
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
              </div>
            </div>
          ) : (
            <p className="border-t border-[--color-border-subtle] pt-3 text-[11px] text-amber-300">
              This needs the <strong>{approval.required_role}</strong> role or
              above.
            </p>
          )
        ) : null}

        {!pending ? (
          <p className="border-t border-[--color-border-subtle] pt-3 text-[11px] text-[--color-text-muted]">
            {titleCase(approval.status)} {formatDateTime(approval.decided_at)}
            {approval.decision_note ? ` — “${approval.decision_note}”` : ""}
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}
