"use client";

import Link from "next/link";
import { useCallback, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { IncidentVolumeChart } from "@/components/incident-volume-chart";
import {
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  KeyValue,
  Skeleton,
  StatTile,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { usePolling } from "@/lib/stream";
import { formatDuration, formatPercent, severityStyles, cn } from "@/lib/utils";

const WINDOWS = [7, 30, 90] as const;

export default function DashboardPage() {
  const [days, setDays] = useState<number>(30);

  const loader = useCallback(() => api.dashboard(days), [days]);
  const { data, error, loading, refresh } = usePolling(loader, 30_000, [days]);

  return (
    <>
      <PageHeader
        title="Operations overview"
        description={
          data
            ? `Last ${data.window_days} days · updated ${new Date(data.generated_at).toLocaleTimeString()}`
            : "Loading…"
        }
        actions={
          <div className="flex rounded-lg bg-[--color-surface] p-1">
            {WINDOWS.map((value) => (
              <button
                key={value}
                onClick={() => setDays(value)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                  days === value
                    ? "bg-[--color-surface-raised] text-[--color-text-primary]"
                    : "text-[--color-text-muted] hover:text-[--color-text-secondary]",
                )}
              >
                {value}d
              </button>
            ))}
          </div>
        }
      />

      <div className="space-y-5 p-5 lg:p-8">
        {error ? (
          <Card>
            <ErrorState message={error.message} onRetry={() => void refresh()} />
          </Card>
        ) : null}

        {loading && !data ? (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-28" />
            ))}
          </div>
        ) : null}

        {data ? (
          <>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatTile
                label="Open incidents"
                value={data.open_incidents}
                tone={data.open_incidents > 0 ? "warn" : "good"}
                hint={`${data.incidents_in_window} opened in the window`}
              />
              <StatTile
                label="Active investigations"
                value={data.active_investigations}
                hint="Agents currently working"
              />
              <StatTile
                label="Awaiting approval"
                value={data.pending_approvals}
                tone={data.pending_approvals > 0 ? "danger" : "neutral"}
                hint={
                  data.pending_approvals > 0
                    ? "Remediation is paused on a human"
                    : "Nothing blocked on a human"
                }
              />
              <StatTile
                label="Mean time to resolve"
                value={formatDuration(data.mttr.mean_time_to_resolve)}
                hint={
                  data.mttr.sample_size > 0
                    ? `p90 ${formatDuration(data.mttr.p90_time_to_resolve)} · n=${data.mttr.sample_size}`
                    : "not enough resolved incidents yet"
                }
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader
                  title="Incident volume"
                  description="Daily count, split by severity"
                />
                <CardBody>
                  <IncidentVolumeChart data={data.volume} />
                </CardBody>
              </Card>

              <Card>
                <CardHeader
                  title="Remediation"
                  description="What the agent proposed, and what happened to it"
                />
                <CardBody>
                  <dl className="divide-y divide-[--color-border-subtle]">
                    <KeyValue label="Proposed">
                      {data.remediation.proposed}
                    </KeyValue>
                    <KeyValue label="Approved by a human">
                      {data.remediation.approved}
                    </KeyValue>
                    <KeyValue label="Rejected">
                      {data.remediation.rejected}
                    </KeyValue>
                    <KeyValue label="Blocked by policy">
                      <span
                        className={
                          data.remediation.blocked_by_policy > 0
                            ? "text-amber-300"
                            : undefined
                        }
                      >
                        {data.remediation.blocked_by_policy}
                      </span>
                    </KeyValue>
                    <KeyValue label="Executed successfully">
                      <span className="text-emerald-300">
                        {data.remediation.succeeded}
                      </span>
                    </KeyValue>
                    <KeyValue label="Execution failed">
                      <span
                        className={
                          data.remediation.failed > 0 ? "text-red-300" : undefined
                        }
                      >
                        {data.remediation.failed}
                      </span>
                    </KeyValue>
                    <KeyValue label="Recovery rate">
                      {formatPercent(data.remediation.recovery_rate)}
                    </KeyValue>
                    <KeyValue label="Median approval latency">
                      {formatDuration(
                        data.remediation.mean_approval_latency_seconds,
                      )}
                    </KeyValue>
                  </dl>
                </CardBody>
              </Card>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Card>
                <CardHeader title="By severity" />
                <CardBody className="space-y-2">
                  {data.by_severity.length === 0 ? (
                    <p className="text-xs text-[--color-text-muted]">
                      No incidents in this window.
                    </p>
                  ) : (
                    data.by_severity.map((row) => (
                      <DistributionRow
                        key={row.key}
                        label={row.key.toUpperCase()}
                        count={row.count}
                        total={data.incidents_in_window}
                        className={
                          severityStyles[
                            row.key as keyof typeof severityStyles
                          ] ?? ""
                        }
                      />
                    ))
                  )}
                </CardBody>
              </Card>

              <Card>
                <CardHeader title="Top affected services" />
                <CardBody className="space-y-2">
                  {data.by_service.length === 0 ? (
                    <p className="text-xs text-[--color-text-muted]">
                      No service attribution yet.
                    </p>
                  ) : (
                    data.by_service.slice(0, 6).map((row) => (
                      <DistributionRow
                        key={row.key}
                        label={row.key}
                        count={row.count}
                        total={data.incidents_in_window}
                      />
                    ))
                  )}
                </CardBody>
              </Card>

              <Card>
                <CardHeader
                  title="Agent activity"
                  description="Investigation runs in this window"
                />
                <CardBody>
                  <dl className="divide-y divide-[--color-border-subtle]">
                    <KeyValue label="Runs">{data.agents.runs_total}</KeyValue>
                    <KeyValue label="Completed">
                      {data.agents.runs_succeeded}
                    </KeyValue>
                    <KeyValue label="Failed">
                      <span
                        className={
                          data.agents.runs_failed > 0 ? "text-red-300" : undefined
                        }
                      >
                        {data.agents.runs_failed}
                      </span>
                    </KeyValue>
                    <KeyValue label="Mean run time">
                      {formatDuration(data.agents.mean_run_seconds)}
                    </KeyValue>
                    <KeyValue label="Tool calls">
                      {data.agents.total_tool_calls}
                    </KeyValue>
                    <KeyValue label="LLM spend">
                      ${data.agents.total_cost_usd.toFixed(4)}
                    </KeyValue>
                  </dl>
                  <Link
                    href="/incidents"
                    className="mt-3 inline-block text-xs text-sky-400 hover:text-sky-300"
                  >
                    View all incidents →
                  </Link>
                </CardBody>
              </Card>
            </div>
          </>
        ) : null}
      </div>
    </>
  );
}

function DistributionRow({
  label,
  count,
  total,
  className,
}: {
  label: string;
  count: number;
  total: number;
  className?: string;
}) {
  const percent = total > 0 ? (count / total) * 100 : 0;
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-3">
        <span className="truncate text-xs text-[--color-text-secondary]">
          {label}
        </span>
        <span className="shrink-0 text-xs tabular-nums text-[--color-text-muted]">
          {count}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[--color-canvas]">
        <div
          className={cn(
            "h-full rounded-full bg-sky-500/60",
            className?.includes("red")
              ? "bg-red-500/70"
              : className?.includes("orange")
                ? "bg-orange-500/70"
                : className?.includes("amber")
                  ? "bg-amber-500/70"
                  : "",
          )}
          style={{ width: `${Math.max(percent, 2)}%` }}
        />
      </div>
    </div>
  );
}
