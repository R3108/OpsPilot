"use client";

import { Trash2 } from "lucide-react";
import { useEffect, useRef } from "react";

import { Badge, Button, EmptyState } from "@/components/ui/primitives";
import type { AgentEvent, AgentRunDetail, AgentStep } from "@/lib/types";
import type { StreamStatus } from "@/lib/stream";
import { cn, formatTime, investigatorIcons, titleCase } from "@/lib/utils";

const EVENT_STYLES: Record<string, { icon: string; className: string }> = {
  "phase.started": { icon: "▶", className: "text-sky-300" },
  "phase.completed": { icon: "✓", className: "text-emerald-300" },
  "phase.failed": { icon: "✕", className: "text-red-300" },
  "tool.started": { icon: "⚙", className: "text-slate-400" },
  "tool.completed": { icon: "⚙", className: "text-slate-300" },
  "tool.failed": { icon: "⚙", className: "text-red-300" },
  "evidence.added": { icon: "🔎", className: "text-violet-300" },
  "hypothesis.added": { icon: "💡", className: "text-amber-300" },
  "action.proposed": { icon: "🛠", className: "text-orange-300" },
  "policy.decision": { icon: "🛡", className: "text-cyan-300" },
  "approval.requested": { icon: "✋", className: "text-amber-200" },
  "approval.resolved": { icon: "✋", className: "text-emerald-300" },
  "execution.result": { icon: "⚡", className: "text-blue-300" },
  "verification.result": { icon: "🩺", className: "text-emerald-300" },
  "postmortem.ready": { icon: "📄", className: "text-slate-300" },
  "incident.updated": { icon: "•", className: "text-slate-400" },
};

/**
 * The live agent console.
 *
 * Two sources, deliberately: the SSE stream while a run is in flight, and the
 * durable `AgentStep` rows once it is done. The stream is a convenience; the
 * steps are the record. An operator who opens the page an hour later sees the
 * same thing someone watching live did.
 */
export function AgentConsole({
  events,
  status,
  runs,
  onClear,
}: {
  events: AgentEvent[];
  status: StreamStatus;
  runs: AgentRunDetail[];
  /**
   * Clears the live event buffer only. The `AgentStep` rows below are the
   * durable record and are deliberately left alone — this is a "quieten my
   * view" control, not a delete.
   */
  onClear?: () => void;
}) {
  const bottomRef = useRef<HTMLDivElement>(null);
  const shouldStick = useRef(true);

  useEffect(() => {
    if (shouldStick.current) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [events.length]);

  const steps = runs.flatMap((run) =>
    (run.steps ?? []).map((step) => ({ step, run })),
  );

  const empty = events.length === 0 && steps.length === 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-[--color-text-muted]">
          {events.length > 0
            ? `${events.length} live event${events.length === 1 ? "" : "s"}`
            : `${steps.length} recorded step${steps.length === 1 ? "" : "s"}`}
        </p>
        <div className="flex items-center gap-3">
          {onClear ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={onClear}
              disabled={events.length === 0}
              title={
                events.length > 0
                  ? "Clear the live event log (recorded steps are kept)"
                  : "Nothing to clear — no live events buffered"
              }
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
              Clear
            </Button>
          ) : null}
          <StreamIndicator status={status} />
        </div>
      </div>

      {empty ? (
        <EmptyState
          icon="🤖"
          title="No agent activity yet"
          description="Start an investigation and the agent's reasoning will stream here in real time."
        />
      ) : null}

      {events.length > 0 ? (
        <div
          className="max-h-[28rem] space-y-1 overflow-y-auto rounded-lg bg-[--color-canvas] p-3 font-mono text-[11px] leading-relaxed"
          onScroll={(e) => {
            const el = e.currentTarget;
            shouldStick.current =
              el.scrollHeight - el.scrollTop - el.clientHeight < 40;
          }}
        >
          {events.map((event) => {
            const style = EVENT_STYLES[event.type] ?? {
              icon: "•",
              className: "text-slate-400",
            };
            return (
              <div key={event.id} className="flex gap-2">
                <span className="shrink-0 text-[--color-text-muted]">
                  {formatTime(event.at)}
                </span>
                <span className={cn("shrink-0 w-4 text-center", style.className)}>
                  {style.icon}
                </span>
                <span className="min-w-0 flex-1">
                  {event.investigator ? (
                    <span className="mr-1">
                      {investigatorIcons[event.investigator] ?? ""}
                    </span>
                  ) : null}
                  <span className={style.className}>{event.title}</span>
                  {event.message ? (
                    <span className="text-[--color-text-muted]">
                      {" — "}
                      {event.message}
                    </span>
                  ) : null}
                </span>
              </div>
            );
          })}
          <div ref={bottomRef} />
        </div>
      ) : null}

      {runs.map((run) => (
        <RunSteps key={run.id} run={run} />
      ))}
    </div>
  );
}

function StreamIndicator({ status }: { status: StreamStatus }) {
  const config = {
    connecting: { label: "connecting", className: "text-slate-400", dot: "bg-slate-400" },
    live: { label: "live", className: "text-emerald-300", dot: "bg-emerald-400 animate-live" },
    stale: { label: "reconnecting", className: "text-amber-300", dot: "bg-amber-400" },
    closed: { label: "not streaming", className: "text-slate-500", dot: "bg-slate-600" },
  }[status];

  return (
    <span
      className={cn("inline-flex items-center gap-1.5 text-[11px]", config.className)}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", config.dot)} />
      {config.label}
    </span>
  );
}

function RunSteps({ run }: { run: AgentRunDetail }) {
  const steps = run.steps ?? [];
  if (steps.length === 0) return null;

  return (
    <div className="rounded-lg border border-[--color-border-subtle]">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[--color-border-subtle] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium">
            Investigation pass {run.attempt}
          </span>
          <Badge
            className={
              run.status === "completed"
                ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
                : run.status === "failed"
                  ? "bg-red-500/15 text-red-300 ring-red-500/30"
                  : "bg-sky-500/15 text-sky-300 ring-sky-500/30"
            }
          >
            {titleCase(run.status)}
          </Badge>
        </div>
        <div className="flex gap-3 text-[11px] text-[--color-text-muted]">
          <span>{steps.length} steps</span>
          <span>{run.tool_call_count} tool calls</span>
          <span>${run.cost_usd.toFixed(4)}</span>
          {run.duration_seconds !== null ? (
            <span>{Math.round(run.duration_seconds)}s</span>
          ) : null}
          {run.trace_url ? (
            <a
              href={run.trace_url}
              target="_blank"
              rel="noreferrer"
              className="text-sky-400 hover:text-sky-300"
            >
              LangSmith trace ↗
            </a>
          ) : null}
        </div>
      </div>
      <ol className="divide-y divide-[--color-border-subtle]">
        {steps.map((step) => (
          <StepRow key={step.id} step={step} />
        ))}
      </ol>
      {run.error ? (
        <p className="border-t border-[--color-border-subtle] px-4 py-2 text-xs text-red-300">
          {run.error}
        </p>
      ) : null}
    </div>
  );
}

function StepRow({ step }: { step: AgentStep }) {
  const failed = step.status === "failed";
  return (
    <li className="flex gap-3 px-4 py-2.5">
      <span
        className={cn(
          "mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-[10px]",
          failed
            ? "bg-red-500/15 text-red-300"
            : "bg-[--color-surface-raised] text-[--color-text-muted]",
        )}
      >
        {step.investigator ? investigatorIcons[step.investigator] : step.sequence}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-xs font-medium text-[--color-text-primary]">
            {step.name}
          </span>
          <span className="text-[10px] uppercase tracking-wide text-[--color-text-muted]">
            {titleCase(step.phase)}
          </span>
          {step.duration_ms !== null ? (
            <span className="text-[10px] tabular-nums text-[--color-text-muted]">
              {step.duration_ms}ms
            </span>
          ) : null}
        </div>
        {step.output_summary ? (
          <p className="mt-0.5 text-xs text-[--color-text-secondary]">
            {step.output_summary}
          </p>
        ) : step.input_summary ? (
          <p className="mt-0.5 text-xs text-[--color-text-muted]">
            {step.input_summary}
          </p>
        ) : null}
        {step.error ? (
          <p className="mt-1 rounded bg-red-500/10 px-2 py-1 text-[11px] text-red-300">
            {step.error}
          </p>
        ) : null}
      </div>
    </li>
  );
}
