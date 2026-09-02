"use client";

import { ChevronRight, ExternalLink } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge, EmptyState } from "@/components/ui/primitives";
import type { Evidence } from "@/lib/types";
import {
  cn,
  formatDateTime,
  investigatorIcons,
  relevanceStyles,
  titleCase,
} from "@/lib/utils";

/**
 * Collected evidence, grouped by the investigator that found it.
 *
 * Every item is expandable down to the raw provider payload. That matters more
 * than it looks: it is what lets a responder check the agent's reasoning against
 * the actual data rather than taking the summary on trust.
 */
export function EvidenceList({
  evidence,
  highlightIds,
}: {
  evidence: Evidence[];
  highlightIds?: string[];
}) {
  const [investigator, setInvestigator] = useState<string>("all");
  const highlighted = useMemo(() => new Set(highlightIds ?? []), [highlightIds]);

  const investigators = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of evidence) {
      const key = item.investigator ?? "other";
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()];
  }, [evidence]);

  const visible = useMemo(
    () =>
      investigator === "all"
        ? evidence
        : evidence.filter((e) => (e.investigator ?? "other") === investigator),
    [evidence, investigator],
  );

  if (evidence.length === 0) {
    return (
      <EmptyState
        icon="🔎"
        title="No evidence collected yet"
        description="Evidence is gathered by read-only tools during an investigation. It is never written by the model."
      />
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        <FilterChip
          label={`All (${evidence.length})`}
          active={investigator === "all"}
          onClick={() => setInvestigator("all")}
        />
        {investigators.map(([key, count]) => (
          <FilterChip
            key={key}
            label={`${investigatorIcons[key] ?? ""} ${titleCase(key)} (${count})`}
            active={investigator === key}
            onClick={() => setInvestigator(key)}
          />
        ))}
      </div>

      <ul className="space-y-2">
        {visible.map((item) => (
          <EvidenceItem
            key={item.id}
            evidence={item}
            highlighted={highlighted.has(item.id)}
          />
        ))}
      </ul>
    </div>
  );
}

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full px-3 py-1 text-xs transition-colors",
        active
          ? "bg-[--color-surface-raised] text-[--color-text-primary]"
          : "text-[--color-text-muted] hover:bg-[--color-surface] hover:text-[--color-text-secondary]",
      )}
    >
      {label}
    </button>
  );
}

function EvidenceItem({
  evidence,
  highlighted,
}: {
  evidence: Evidence;
  highlighted: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <li
      id={`evidence-${evidence.id}`}
      className={cn(
        "rounded-lg border bg-[--color-surface] transition-colors",
        highlighted
          ? "border-amber-500/40 ring-1 ring-amber-500/20"
          : "border-[--color-border-subtle]",
      )}
    >
      <button
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <ChevronRight
          className={cn(
            "mt-0.5 h-4 w-4 shrink-0 text-[--color-text-muted] transition-transform",
            open && "rotate-90",
          )}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <code className="rounded bg-[--color-canvas] px-1.5 py-0.5 font-mono text-[10px] text-[--color-text-muted]">
              {evidence.citation}
            </code>
            <Badge className={relevanceStyles[evidence.relevance]}>
              {evidence.relevance}
            </Badge>
            <span className="text-[11px] text-[--color-text-muted]">
              {evidence.source}
              {evidence.source_ref ? ` · ${evidence.source_ref}` : ""}
            </span>
          </div>
          <p className="mt-1 text-sm text-[--color-text-primary]">
            {evidence.summary}
          </p>
          {!open && evidence.detail ? (
            <p className="mt-0.5 line-clamp-1 text-xs text-[--color-text-muted]">
              {evidence.detail}
            </p>
          ) : null}
        </div>
        <span className="shrink-0 text-[10px] text-[--color-text-muted]">
          {formatDateTime(evidence.observed_at ?? evidence.collected_at)}
        </span>
      </button>

      {open ? (
        <div className="space-y-3 border-t border-[--color-border-subtle] px-4 py-3">
          {evidence.detail ? (
            <pre className="scroll-x whitespace-pre-wrap rounded bg-[--color-canvas] p-3 font-mono text-[11px] leading-relaxed text-[--color-text-secondary]">
              {evidence.detail}
            </pre>
          ) : null}

          <details>
            <summary className="cursor-pointer text-[11px] text-[--color-text-muted] hover:text-[--color-text-secondary]">
              Raw provider payload
            </summary>
            <pre className="scroll-x mt-2 max-h-72 overflow-auto rounded bg-[--color-canvas] p-3 font-mono text-[10px] leading-relaxed text-[--color-text-muted]">
              {JSON.stringify(evidence.raw, null, 2)}
            </pre>
          </details>

          {evidence.source_url ? (
            <a
              href={evidence.source_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300"
            >
              Open in {evidence.source}
              <ExternalLink className="h-3 w-3" aria-hidden />
            </a>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}
