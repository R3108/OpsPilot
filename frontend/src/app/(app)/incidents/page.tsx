"use client";

import { Plus, Search } from "lucide-react";
import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Input,
  Label,
  Skeleton,
} from "@/components/ui/primitives";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePolling, useTenantStream } from "@/lib/stream";
import type { IncidentSummary } from "@/lib/types";
import {
  cn,
  formatRelative,
  severityStyles,
  statusStyles,
  titleCase,
} from "@/lib/utils";

const STATUS_FILTERS = [
  { id: "active", label: "Active", statuses: [
    "open", "triaged", "investigating", "awaiting_approval", "remediating", "verifying",
  ] },
  { id: "all", label: "All", statuses: [] },
  { id: "awaiting_approval", label: "Awaiting approval", statuses: ["awaiting_approval"] },
  { id: "resolved", label: "Resolved", statuses: ["resolved", "closed"] },
] as const;

export default function IncidentsPage() {
  const { can } = useAuth();
  const [filter, setFilter] = useState<string>("active");
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);

  const statuses = useMemo(
    () => STATUS_FILTERS.find((f) => f.id === filter)?.statuses ?? [],
    [filter],
  );

  const loader = useCallback(
    () =>
      api.incidents({
        status: statuses.length ? [...statuses] : undefined,
        q: query || undefined,
        limit: 100,
      }),
    [statuses, query],
  );

  const { data, error, loading, refresh } = usePolling(loader, 20_000, [
    statuses,
    query,
  ]);

  // Any incident-shaped event means the list is stale.
  useTenantStream(
    useCallback(
      (event) => {
        if (
          event.type === "incident.updated" ||
          event.type === "approval.requested" ||
          event.type === "approval.resolved"
        ) {
          void refresh();
        }
      },
      [refresh],
    ),
  );

  return (
    <>
      <PageHeader
        title="Incidents"
        description={
          data ? `${data.total} matching incident${data.total === 1 ? "" : "s"}` : undefined
        }
        actions={
          can("responder") ? (
            <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
              <Plus className="h-3.5 w-3.5" aria-hidden />
              Declare incident
            </Button>
          ) : null
        }
      />

      <div className="space-y-4 p-5 lg:p-8">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex rounded-lg bg-[--color-surface] p-1">
            {STATUS_FILTERS.map((option) => (
              <button
                key={option.id}
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

          <div className="relative min-w-[200px] flex-1 sm:max-w-xs">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[--color-text-muted]"
              aria-hidden
            />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search reference, title, service…"
              className="pl-9"
            />
          </div>
        </div>

        {creating ? (
          <DeclareIncidentForm
            onClose={() => setCreating(false)}
            onCreated={() => {
              setCreating(false);
              void refresh();
            }}
          />
        ) : null}

        <Card className="overflow-hidden">
          {error ? (
            <ErrorState message={error.message} onRetry={() => void refresh()} />
          ) : loading && !data ? (
            <div className="space-y-px">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} className="h-16 rounded-none" />
              ))}
            </div>
          ) : !data || data.items.length === 0 ? (
            <EmptyState
              icon="🌤️"
              title="No incidents here"
              description={
                filter === "active"
                  ? "Nothing is on fire. Alerts from your integrations will appear here automatically."
                  : "Try a different filter or search term."
              }
            />
          ) : (
            <ul className="divide-y divide-[--color-border-subtle]">
              {data.items.map((incident) => (
                <IncidentRow key={incident.id} incident={incident} />
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}

const ACTIVE_STATUSES = new Set([
  "investigating",
  "remediating",
  "verifying",
]);

function IncidentRow({ incident }: { incident: IncidentSummary }) {
  const isWorking = ACTIVE_STATUSES.has(incident.status);

  return (
    <li>
      <Link
        href={`/incidents/${incident.id}`}
        className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3.5 transition-colors hover:bg-[--color-surface-raised]"
      >
        <Badge className={severityStyles[incident.severity]}>
          {incident.severity}
        </Badge>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[11px] text-[--color-text-muted]">
              {incident.reference}
            </span>
            {incident.open_approval_count > 0 ? (
              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-200 ring-1 ring-inset ring-amber-500/30">
                {incident.open_approval_count} awaiting approval
              </span>
            ) : null}
          </div>
          <p className="truncate text-sm font-medium text-[--color-text-primary]">
            {incident.title}
          </p>
          {incident.root_cause_summary ? (
            <p className="truncate text-xs text-[--color-text-muted]">
              Root cause: {incident.root_cause_summary}
              {incident.root_cause_confidence !== null
                ? ` (${Math.round(incident.root_cause_confidence * 100)}%)`
                : ""}
            </p>
          ) : null}
        </div>

        <div className="hidden w-32 shrink-0 text-xs text-[--color-text-muted] sm:block">
          {incident.service ?? "—"}
        </div>

        <Badge className={cn(statusStyles[incident.status], "shrink-0")}>
          {isWorking ? (
            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-current animate-live" />
          ) : null}
          {titleCase(incident.status)}
        </Badge>

        <div className="w-24 shrink-0 text-right text-xs text-[--color-text-muted]">
          {formatRelative(incident.created_at)}
        </div>
      </Link>
    </li>
  );
}

function DeclareIncidentForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [service, setService] = useState("");
  const [namespace, setNamespace] = useState("");
  const [investigate, setInvestigate] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createIncident({
        title,
        description,
        service: service || undefined,
        namespace: namespace || undefined,
        auto_investigate: investigate,
      });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the incident");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card className="p-5">
      <form onSubmit={submit} className="space-y-4">
        <div>
          <Label htmlFor="title">What is broken?</Label>
          <Input
            id="title"
            required
            minLength={3}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="checkout-api returning 500s"
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="service">Service</Label>
            <Input
              id="service"
              value={service}
              onChange={(e) => setService(e.target.value)}
              placeholder="checkout-api"
            />
          </div>
          <div>
            <Label htmlFor="namespace">Namespace</Label>
            <Input
              id="namespace"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              placeholder="payments"
            />
          </div>
        </div>
        <div>
          <Label htmlFor="description">What have you seen so far?</Label>
          <Input
            id="description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Error rate jumped at 14:02, no deploy in 6 hours"
          />
        </div>

        <label className="flex items-center gap-2 text-xs text-[--color-text-secondary]">
          <input
            type="checkbox"
            checked={investigate}
            onChange={(e) => setInvestigate(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-[--color-border-subtle] bg-[--color-canvas]"
          />
          Start an investigation immediately
        </label>

        {error ? <p className="text-xs text-red-300">{error}</p> : null}

        <div className="flex gap-2">
          <Button type="submit" variant="primary" size="sm" loading={submitting}>
            Declare incident
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
    </Card>
  );
}
