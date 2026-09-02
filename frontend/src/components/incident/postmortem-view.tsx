"use client";

import { Copy, Download, Eye, EyeOff } from "lucide-react";
import { useState } from "react";

import { Badge, Button, EmptyState } from "@/components/ui/primitives";
import type { Evidence, Postmortem } from "@/lib/types";
import { cn } from "@/lib/utils";

const PRIORITY_STYLES: Record<string, string> = {
  p0: "bg-red-500/15 text-red-300 ring-red-500/30",
  p1: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  p2: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  p3: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export function PostmortemView({
  postmortem,
  evidence,
  canPublish,
  onPublish,
}: {
  postmortem: Postmortem | null;
  evidence: Evidence[];
  canPublish: boolean;
  onPublish?: (publish: boolean) => Promise<void>;
}) {
  const [copied, setCopied] = useState(false);
  const [publishing, setPublishing] = useState(false);

  if (!postmortem) {
    return (
      <EmptyState
        icon="📄"
        title="No postmortem yet"
        description="A postmortem is generated automatically once the incident is resolved, with every claim tied to collected evidence."
      />
    );
  }

  const cited = new Set(postmortem.evidence_ids.map(String));
  const citedEvidence = evidence.filter((item) => cited.has(item.id));

  async function copyMarkdown() {
    await navigator.clipboard.writeText(postmortem!.markdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Badge
            className={
              postmortem.is_published
                ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
                : "bg-slate-500/15 text-slate-300 ring-slate-500/30"
            }
          >
            {postmortem.is_published ? "published" : "draft"}
          </Badge>
          <span className="text-[11px] text-[--color-text-muted]">
            {citedEvidence.length} evidence item
            {citedEvidence.length === 1 ? "" : "s"} cited
          </span>
        </div>

        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={() => void copyMarkdown()}>
            <Copy className="h-3.5 w-3.5" aria-hidden />
            {copied ? "Copied" : "Copy markdown"}
          </Button>
          {canPublish && onPublish ? (
            <Button
              size="sm"
              variant={postmortem.is_published ? "ghost" : "primary"}
              loading={publishing}
              onClick={async () => {
                setPublishing(true);
                try {
                  await onPublish(!postmortem.is_published);
                } finally {
                  setPublishing(false);
                }
              }}
            >
              {postmortem.is_published ? (
                <>
                  <EyeOff className="h-3.5 w-3.5" aria-hidden />
                  Unpublish
                </>
              ) : (
                <>
                  <Eye className="h-3.5 w-3.5" aria-hidden />
                  Publish
                </>
              )}
            </Button>
          ) : null}
        </div>
      </div>

      <article className="space-y-5">
        <header>
          <h2 className="text-lg font-semibold tracking-tight">
            {postmortem.title}
          </h2>
          <p className="mt-1.5 text-sm text-[--color-text-secondary]">
            {postmortem.summary}
          </p>
        </header>

        <Section title="Impact">{postmortem.impact}</Section>
        <Section title="Root cause" emphasis>
          {postmortem.root_cause}
        </Section>
        <Section title="Detection">{postmortem.detection}</Section>
        <Section title="Resolution">{postmortem.resolution}</Section>
        <Section title="Lessons learned">{postmortem.lessons_learned}</Section>

        {postmortem.action_items.length > 0 ? (
          <section>
            <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
              Action items
            </h3>
            <ul className="space-y-2">
              {postmortem.action_items.map((item, index) => (
                <li
                  key={index}
                  className="rounded-lg border border-[--color-border-subtle] bg-[--color-surface] px-3 py-2"
                >
                  <div className="flex flex-wrap items-start gap-2">
                    <Badge
                      className={
                        PRIORITY_STYLES[item.priority] ?? PRIORITY_STYLES.p2!
                      }
                    >
                      {item.priority}
                    </Badge>
                    <span className="min-w-0 flex-1 text-sm text-[--color-text-primary]">
                      {item.title}
                    </span>
                    {item.owner ? (
                      <span className="text-[11px] text-[--color-text-muted]">
                        {item.owner}
                      </span>
                    ) : null}
                  </div>
                  {item.rationale ? (
                    <p className="mt-1 text-xs text-[--color-text-muted]">
                      {item.rationale}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {citedEvidence.length > 0 ? (
          <section>
            <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
              Evidence cited
            </h3>
            <ul className="space-y-1">
              {citedEvidence.map((item) => (
                <li key={item.id} className="flex gap-2 text-xs">
                  <code className="shrink-0 font-mono text-[10px] text-[--color-text-muted]">
                    {item.citation}
                  </code>
                  <span className="text-[--color-text-secondary]">
                    {item.summary}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <details className="rounded-lg border border-[--color-border-subtle]">
          <summary className="cursor-pointer px-4 py-2.5 text-xs text-[--color-text-muted] hover:text-[--color-text-secondary]">
            <Download className="mr-1.5 inline h-3.5 w-3.5" aria-hidden />
            Full markdown source
          </summary>
          <pre className="scroll-x max-h-96 overflow-auto border-t border-[--color-border-subtle] p-4 font-mono text-[11px] leading-relaxed text-[--color-text-secondary]">
            {postmortem.markdown}
          </pre>
        </details>
      </article>
    </div>
  );
}

function Section({
  title,
  children,
  emphasis,
}: {
  title: string;
  children: React.ReactNode;
  emphasis?: boolean;
}) {
  if (!children) return null;
  return (
    <section>
      <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
        {title}
      </h3>
      <p
        className={cn(
          "whitespace-pre-wrap text-sm",
          emphasis
            ? "rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2.5 text-[--color-text-primary]"
            : "text-[--color-text-secondary]",
        )}
      >
        {children}
      </p>
    </section>
  );
}
