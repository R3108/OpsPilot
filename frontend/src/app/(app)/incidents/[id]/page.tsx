"use client";

import { ArrowLeft, Play, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import { AgentConsole } from "@/components/incident/agent-console";
import { EvidenceList } from "@/components/incident/evidence-list";
import { HypothesisList } from "@/components/incident/hypothesis-list";
import { PostmortemView } from "@/components/incident/postmortem-view";
import { RemediationList } from "@/components/incident/remediation-list";
import { IncidentTimeline } from "@/components/incident/timeline";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  KeyValue,
  Skeleton,
  Tabs,
} from "@/components/ui/primitives";
import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useAgentStream, usePolling } from "@/lib/stream";
import { TERMINAL_INCIDENT_STATUSES } from "@/lib/types";
import type {
  AgentEvent,
  AgentRunDetail,
  ApprovalWithAction,
  Postmortem,
  RemediationAction,
} from "@/lib/types";
import {
  cn,
  confidenceLabel,
  formatDateTime,
  formatDuration,
  severityStyles,
  statusStyles,
  titleCase,
} from "@/lib/utils";

const LIVE_STATUSES = new Set([
  "investigating",
  "remediating",
  "verifying",
  "awaiting_approval",
]);

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const incidentId = params.id;
  const { can } = useAuth();

  const [tab, setTab] = useState("timeline");
  const [highlighted, setHighlighted] = useState<string[]>([]);
  const [starting, setStarting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const loader = useCallback(async () => {
    const incident = await api.incident(incidentId);
    const [runs, actions, approvals, postmortem] = await Promise.all([
      api.runs(incidentId).catch(() => [] as AgentRunDetail[]),
      api.actions(incidentId).catch(() => [] as RemediationAction[]),
      api
        .approvals({ incident_id: incidentId, limit: 50 })
        .then((page) => page.items)
        .catch(() => [] as ApprovalWithAction[]),
      api.postmortem(incidentId).catch((error) => {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }) as Promise<Postmortem | null>,
    ]);

    // The list endpoint returns runs without their steps; fetch them for display.
    const detailedRuns = await Promise.all(
      runs.slice(0, 3).map((run) =>
        api.run(incidentId, run.id).catch(() => run),
      ),
    );

    return { incident, runs: detailedRuns, actions, approvals, postmortem };
  }, [incidentId]);

  const { data, error, loading, refresh } = usePolling(loader, 15_000, [incidentId]);

  const incident = data?.incident;
  const live = incident ? LIVE_STATUSES.has(incident.status) : false;

  const {
    events,
    status: streamStatus,
    clear: clearEvents,
  } = useAgentStream(incidentId, {
    onEvent: useCallback(
      (event: AgentEvent) => {
        // Anything that changes durable state means the page is stale.
        if (
          [
            "phase.completed",
            "evidence.added",
            "hypothesis.added",
            "action.proposed",
            "policy.decision",
            "approval.requested",
            "approval.resolved",
            "execution.result",
            "verification.result",
            "postmortem.ready",
            "incident.updated",
          ].includes(event.type)
        ) {
          void refresh();
        }
      },
      [refresh],
    ),
  });

  const pendingApprovals = useMemo(
    () => (data?.approvals ?? []).filter((a) => a.status === "pending"),
    [data?.approvals],
  );

  const selectedHypothesis = useMemo(
    () => incident?.hypotheses.find((h) => h.is_selected) ?? null,
    [incident],
  );

  async function startInvestigation() {
    setStarting(true);
    setActionError(null);
    try {
      // A terminal incident (closed or failed) needs force=true, or the API
      // answers 409 and the button becomes a dead end.
      await api.investigate(
        incidentId,
        incident !== undefined &&
          TERMINAL_INCIDENT_STATUSES.includes(incident.status),
      );
      setTab("console");
      setTimeout(() => void refresh(), 1500);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Could not start");
    } finally {
      setStarting(false);
    }
  }

  const decide = useCallback(
    async (approvalId: string, decision: "approve" | "reject", note: string) => {
      setActionError(null);
      try {
        await api.decide(approvalId, { decision, note });
        await refresh();
      } catch (err) {
        setActionError(
          err instanceof Error ? err.message : "Could not record the decision",
        );
      }
    },
    [refresh],
  );

  if (error && !data) {
    return (
      <div className="p-8">
        <Card>
          <ErrorState message={error.message} onRetry={() => void refresh()} />
        </Card>
      </div>
    );
  }

  if (loading && !incident) {
    return (
      <div className="space-y-4 p-5 lg:p-8">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (!incident || !data) return null;

  const tabs = [
    { id: "timeline", label: "Timeline", count: incident.timeline.length },
    { id: "console", label: "Agent console" },
    { id: "evidence", label: "Evidence", count: incident.evidence.length },
    { id: "hypotheses", label: "Root cause", count: incident.hypotheses.length },
    {
      id: "remediation",
      label: "Remediation",
      count: pendingApprovals.length || data.actions.length,
    },
    { id: "postmortem", label: "Postmortem" },
  ];

  return (
    <>
      <PageHeader
        live={live}
        title={
          <span className="flex items-center gap-2.5">
            <Link
              href="/incidents"
              className="text-[--color-text-muted] hover:text-[--color-text-primary]"
              aria-label="Back to incidents"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <span className="font-mono text-sm text-[--color-text-muted]">
              {incident.reference}
            </span>
            <span className="truncate">{incident.title}</span>
          </span>
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge className={severityStyles[incident.severity]}>
              {incident.severity}
            </Badge>
            <Badge className={statusStyles[incident.status]}>
              {titleCase(incident.status)}
            </Badge>
            <span>{incident.service ?? "unattributed service"}</span>
            <span>·</span>
            <span>detected {formatDateTime(incident.detected_at)}</span>
          </span>
        }
        actions={
          <>
            <Button size="sm" variant="ghost" onClick={() => void refresh()}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              Refresh
            </Button>
            {can("responder") ? (
              <Button
                size="sm"
                variant="primary"
                loading={starting}
                onClick={() => void startInvestigation()}
              >
                <Play className="h-3.5 w-3.5" aria-hidden />
                {incident.investigation_count > 0
                  ? "Re-investigate"
                  : "Investigate"}
              </Button>
            ) : null}
          </>
        }
      />

      <div className="p-5 lg:p-8">
        {actionError ? (
          <p className="mb-4 rounded-lg bg-red-500/10 px-3 py-2 text-xs text-red-300 ring-1 ring-inset ring-red-500/25">
            {actionError}
          </p>
        ) : null}

        {pendingApprovals.length > 0 ? (
          <Card className="mb-5 border-amber-500/40 ring-1 ring-amber-500/20">
            <CardHeader
              title={`${pendingApprovals.length} action${pendingApprovals.length === 1 ? "" : "s"} waiting on a human`}
              description="The investigation is paused. Nothing will run until someone decides."
              actions={
                <Button size="sm" onClick={() => setTab("remediation")}>
                  Review
                </Button>
              }
            />
          </Card>
        ) : null}

        <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
          <div className="min-w-0">
            <Card>
              <div className="px-5 pt-2">
                <Tabs tabs={tabs} active={tab} onChange={setTab} />
              </div>
              <CardBody>
                {tab === "timeline" ? (
                  <IncidentTimeline
                    entries={incident.timeline}
                    verifications={incident.verifications}
                  />
                ) : null}

                {tab === "console" ? (
                  <AgentConsole
                    events={events}
                    status={streamStatus}
                    runs={data.runs}
                    onClear={clearEvents}
                  />
                ) : null}

                {tab === "evidence" ? (
                  <EvidenceList
                    evidence={incident.evidence}
                    highlightIds={highlighted}
                  />
                ) : null}

                {tab === "hypotheses" ? (
                  <HypothesisList
                    hypotheses={incident.hypotheses}
                    evidence={incident.evidence}
                    onCiteEvidence={(ids) => {
                      setHighlighted(ids);
                      setTab("evidence");
                      setTimeout(() => {
                        document
                          .getElementById(`evidence-${ids[0]}`)
                          ?.scrollIntoView({ behavior: "smooth", block: "center" });
                      }, 50);
                    }}
                  />
                ) : null}

                {tab === "remediation" ? (
                  <RemediationList
                    actions={data.actions}
                    approvals={data.approvals}
                    onDecide={decide}
                    canApprove={can("approver")}
                  />
                ) : null}

                {tab === "postmortem" ? (
                  <PostmortemView
                    postmortem={data.postmortem}
                    evidence={incident.evidence}
                    canPublish={can("responder")}
                    onPublish={async (publish) => {
                      await api.publishPostmortem(incidentId, publish);
                      await refresh();
                    }}
                  />
                ) : null}
              </CardBody>
            </Card>
          </div>

          <aside className="space-y-4">
            {selectedHypothesis ? (
              <Card>
                <CardHeader title="Leading root cause" />
                <CardBody>
                  <p className="text-sm font-medium">{selectedHypothesis.title}</p>
                  <p className="mt-1.5 text-xs text-[--color-text-secondary]">
                    {selectedHypothesis.statement}
                  </p>
                  <div className="mt-3 flex items-baseline gap-2">
                    <span
                      className={cn(
                        "text-xl font-semibold tabular-nums",
                        confidenceLabel(selectedHypothesis.confidence).className,
                      )}
                    >
                      {Math.round(selectedHypothesis.confidence * 100)}%
                    </span>
                    <span className="text-[11px] text-[--color-text-muted]">
                      {confidenceLabel(selectedHypothesis.confidence).label}{" "}
                      confidence
                    </span>
                  </div>
                  <button
                    onClick={() => setTab("hypotheses")}
                    className="mt-2 text-[11px] text-sky-400 hover:text-sky-300"
                  >
                    See alternatives and evidence →
                  </button>
                </CardBody>
              </Card>
            ) : null}

            <Card>
              <CardHeader title="Details" />
              <CardBody>
                <dl className="divide-y divide-[--color-border-subtle]">
                  <KeyValue label="Source">{titleCase(incident.source)}</KeyValue>
                  <KeyValue label="Environment">{incident.environment}</KeyValue>
                  <KeyValue label="Namespace">
                    {incident.namespace ?? "—"}
                  </KeyValue>
                  <KeyValue label="Cluster">{incident.cluster ?? "—"}</KeyValue>
                  <KeyValue label="Detected">
                    {formatDateTime(incident.detected_at)}
                  </KeyValue>
                  <KeyValue label="Acknowledged">
                    {formatDateTime(incident.acknowledged_at)}
                  </KeyValue>
                  <KeyValue label="Mitigated">
                    {formatDateTime(incident.mitigated_at)}
                  </KeyValue>
                  <KeyValue label="Resolved">
                    {formatDateTime(incident.resolved_at)}
                  </KeyValue>
                  <KeyValue label="Time to mitigate">
                    {formatDuration(incident.time_to_mitigate_seconds)}
                  </KeyValue>
                  <KeyValue label="Time to resolve">
                    {formatDuration(incident.time_to_resolve_seconds)}
                  </KeyValue>
                  <KeyValue label="Investigation passes">
                    {incident.investigation_count}
                  </KeyValue>
                </dl>
              </CardBody>
            </Card>

            {incident.severity_rationale ? (
              <Card>
                <CardHeader title="Why this severity" />
                <CardBody>
                  <p className="text-xs text-[--color-text-secondary]">
                    {incident.severity_rationale}
                  </p>
                  <p className="mt-2 text-[11px] text-[--color-text-muted]">
                    {Math.round(incident.severity_confidence * 100)}% confidence
                  </p>
                </CardBody>
              </Card>
            ) : null}

            {Object.keys(incident.labels).length > 0 ? (
              <Card>
                <CardHeader title="Labels" />
                <CardBody>
                  <dl className="divide-y divide-[--color-border-subtle]">
                    {Object.entries(incident.labels).map(([key, value]) => (
                      <KeyValue key={key} label={key}>
                        {String(value)}
                      </KeyValue>
                    ))}
                  </dl>
                </CardBody>
              </Card>
            ) : null}
          </aside>
        </div>
      </div>
    </>
  );
}
