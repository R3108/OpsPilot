"use client";

import { CheckCircle2 } from "lucide-react";

import { Badge, EmptyState } from "@/components/ui/primitives";
import type { Evidence, Hypothesis } from "@/lib/types";
import { cn, confidenceLabel, titleCase } from "@/lib/utils";

/**
 * Ranked root-cause hypotheses.
 *
 * Alternatives are shown, not hidden: an agent that only ever displays its
 * winning answer trains people to stop checking it. Contradicting evidence and
 * the disconfirming test get equal billing with the supporting case.
 */
export function HypothesisList({
  hypotheses,
  evidence,
  onCiteEvidence,
}: {
  hypotheses: Hypothesis[];
  evidence: Evidence[];
  onCiteEvidence?: (ids: string[]) => void;
}) {
  if (hypotheses.length === 0) {
    return (
      <EmptyState
        icon="💡"
        title="No hypotheses yet"
        description="Hypotheses are generated once the investigators have collected and correlated evidence."
      />
    );
  }

  const byId = new Map(evidence.map((item) => [item.id, item]));

  return (
    <ol className="space-y-3">
      {hypotheses.map((hypothesis) => (
        <HypothesisCard
          key={hypothesis.id}
          hypothesis={hypothesis}
          evidenceById={byId}
          onCiteEvidence={onCiteEvidence}
        />
      ))}
    </ol>
  );
}

function HypothesisCard({
  hypothesis,
  evidenceById,
  onCiteEvidence,
}: {
  hypothesis: Hypothesis;
  evidenceById: Map<string, Evidence>;
  onCiteEvidence?: (ids: string[]) => void;
}) {
  const confidence = confidenceLabel(hypothesis.confidence);
  const supporting = hypothesis.supporting_evidence_ids
    .map((id) => evidenceById.get(String(id)))
    .filter(Boolean) as Evidence[];
  const contradicting = hypothesis.contradicting_evidence_ids
    .map((id) => evidenceById.get(String(id)))
    .filter(Boolean) as Evidence[];

  return (
    <li
      className={cn(
        "rounded-lg border bg-[--color-surface] p-4",
        hypothesis.is_selected
          ? "border-sky-500/40 ring-1 ring-sky-500/20"
          : "border-[--color-border-subtle]",
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {hypothesis.is_selected ? (
              <span className="inline-flex items-center gap-1 rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-sky-300 ring-1 ring-inset ring-sky-500/30">
                <CheckCircle2 className="h-3 w-3" aria-hidden />
                leading
              </span>
            ) : (
              <span className="text-[10px] uppercase tracking-wide text-[--color-text-muted]">
                alternative #{hypothesis.rank + 1}
              </span>
            )}
            {hypothesis.category ? (
              <Badge>{titleCase(hypothesis.category)}</Badge>
            ) : null}
          </div>
          <h3 className="mt-1.5 text-sm font-semibold text-[--color-text-primary]">
            {hypothesis.title}
          </h3>
        </div>

        <div className="shrink-0 text-right">
          <p className={cn("text-lg font-semibold tabular-nums", confidence.className)}>
            {Math.round(hypothesis.confidence * 100)}%
          </p>
          <p className="text-[10px] uppercase tracking-wide text-[--color-text-muted]">
            {confidence.label} confidence
          </p>
        </div>
      </div>

      <p className="mt-2 text-sm text-[--color-text-secondary]">
        {hypothesis.statement}
      </p>

      {hypothesis.reasoning ? (
        <details className="mt-3">
          <summary className="cursor-pointer text-[11px] text-[--color-text-muted] hover:text-[--color-text-secondary]">
            Reasoning
          </summary>
          <p className="mt-1.5 whitespace-pre-wrap text-xs text-[--color-text-secondary]">
            {hypothesis.reasoning}
          </p>
        </details>
      ) : null}

      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <EvidenceGroup
          label="Supports this"
          tone="support"
          items={supporting}
          onCite={onCiteEvidence}
        />
        <EvidenceGroup
          label="Argues against"
          tone="contradict"
          items={contradicting}
          onCite={onCiteEvidence}
        />
      </div>

      {hypothesis.disconfirming_test ? (
        <p className="mt-3 rounded-lg bg-[--color-canvas] px-3 py-2 text-xs text-[--color-text-secondary]">
          <span className="font-medium text-[--color-text-primary]">
            How to falsify this:{" "}
          </span>
          {hypothesis.disconfirming_test}
        </p>
      ) : null}
    </li>
  );
}

function EvidenceGroup({
  label,
  tone,
  items,
  onCite,
}: {
  label: string;
  tone: "support" | "contradict";
  items: Evidence[];
  onCite?: (ids: string[]) => void;
}) {
  return (
    <div>
      <p className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-[--color-text-muted]">
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            tone === "support" ? "bg-emerald-400" : "bg-orange-400",
          )}
        />
        {label} ({items.length})
      </p>
      {items.length === 0 ? (
        <p className="text-[11px] text-[--color-text-muted]">
          {tone === "contradict" ? "Nothing contradicts it." : "No citations."}
        </p>
      ) : (
        <ul className="space-y-1">
          {items.slice(0, 5).map((item) => (
            <li key={item.id}>
              <button
                onClick={() => onCite?.([item.id])}
                className="w-full truncate text-left text-[11px] text-[--color-text-secondary] hover:text-sky-300"
                title={item.summary}
              >
                <code className="mr-1.5 font-mono text-[10px] text-[--color-text-muted]">
                  {item.citation}
                </code>
                {item.summary}
              </button>
            </li>
          ))}
          {items.length > 5 ? (
            <li className="text-[11px] text-[--color-text-muted]">
              +{items.length - 5} more
            </li>
          ) : null}
        </ul>
      )}
    </div>
  );
}
