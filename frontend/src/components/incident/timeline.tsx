"use client";

import { EmptyState } from "@/components/ui/primitives";
import type { TimelineEntry, Verification } from "@/lib/types";
import { cn, formatDateTime, formatTime, titleCase } from "@/lib/utils";

const ACTOR_STYLES: Record<string, { dot: string; label: string }> = {
  agent: { dot: "bg-sky-400", label: "text-sky-300" },
  user: { dot: "bg-violet-400", label: "text-violet-300" },
  integration: { dot: "bg-emerald-400", label: "text-emerald-300" },
  system: { dot: "bg-slate-400", label: "text-slate-300" },
};

export function IncidentTimeline({
  entries,
  verifications,
}: {
  entries: TimelineEntry[];
  verifications: Verification[];
}) {
  if (entries.length === 0) {
    return (
      <EmptyState
        icon="🕐"
        title="Nothing on the timeline yet"
        description="Agent phases, human decisions and executed actions all land here as they happen."
      />
    );
  }

  return (
    <div className="space-y-4">
      <ol className="relative space-y-0">
        {entries.map((entry, index) => (
          <TimelineRow
            key={entry.id}
            entry={entry}
            isLast={index === entries.length - 1}
          />
        ))}
      </ol>

      {verifications.length > 0 ? (
        <div className="space-y-2">
          <h3 className="text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
            Recovery verification
          </h3>
          {verifications.map((verification) => (
            <VerificationCard key={verification.id} verification={verification} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

function TimelineRow({
  entry,
  isLast,
}: {
  entry: TimelineEntry;
  isLast: boolean;
}) {
  const style = ACTOR_STYLES[entry.actor_type] ?? ACTOR_STYLES.system!;

  return (
    <li className="relative flex gap-3 pb-4">
      {!isLast ? (
        <span
          aria-hidden
          className="absolute left-[5px] top-4 h-full w-px bg-[--color-border-subtle]"
        />
      ) : null}
      <span
        aria-hidden
        className={cn("relative mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full", style.dot)}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-sm font-medium text-[--color-text-primary]">
            {entry.title}
          </span>
          {entry.phase ? (
            <span className="rounded bg-[--color-surface-raised] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-[--color-text-muted]">
              {titleCase(entry.phase)}
            </span>
          ) : null}
        </div>
        <p className="text-[11px] text-[--color-text-muted]">
          <span className={style.label}>{entry.actor_label}</span>
          {" · "}
          <time dateTime={entry.occurred_at} title={formatDateTime(entry.occurred_at)}>
            {formatTime(entry.occurred_at)}
          </time>
        </p>
        {entry.body ? (
          <p className="mt-1 whitespace-pre-wrap text-xs text-[--color-text-secondary]">
            {entry.body}
          </p>
        ) : null}
      </div>
    </li>
  );
}

function VerificationCard({ verification }: { verification: Verification }) {
  const tone = {
    recovered: "border-emerald-500/30 bg-emerald-500/5",
    partial: "border-amber-500/30 bg-amber-500/5",
    not_recovered: "border-red-500/30 bg-red-500/5",
    inconclusive: "border-[--color-border-subtle] bg-[--color-surface]",
  }[verification.outcome];

  return (
    <div className={cn("rounded-lg border px-4 py-3", tone)}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-sm font-medium">
          Attempt {verification.attempt}: {titleCase(verification.outcome)}
        </p>
        <span className="text-[11px] text-[--color-text-muted]">
          {formatDateTime(verification.observed_at)}
        </span>
      </div>
      <p className="mt-1 text-xs text-[--color-text-secondary]">
        {verification.summary}
      </p>

      {verification.checks.length > 0 ? (
        <ul className="mt-2 space-y-1">
          {verification.checks.map((check, index) => (
            <li
              key={index}
              className="flex items-baseline justify-between gap-3 text-[11px]"
            >
              <span className="flex items-center gap-1.5">
                <span
                  className={
                    check.passed ? "text-emerald-400" : "text-red-400"
                  }
                >
                  {check.passed ? "✓" : "✕"}
                </span>
                <span className="text-[--color-text-secondary]">{check.name}</span>
              </span>
              <span className="shrink-0 font-mono text-[--color-text-muted]">
                {check.observed === null
                  ? "not measured"
                  : `${formatMetric(check.observed)} ${symbolFor(check.comparator)} ${formatMetric(check.threshold)}`}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function symbolFor(comparator: string): string {
  return { lt: "<", lte: "≤", gt: ">", gte: "≥" }[comparator] ?? comparator;
}

function formatMetric(value: number): string {
  if (Math.abs(value) >= 1000) return value.toExponential(2);
  if (Number.isInteger(value)) return String(value);
  return value.toPrecision(3);
}
