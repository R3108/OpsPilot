/**
 * Wire types.
 *
 * These mirror the Pydantic schemas in `backend/app/schemas`. Keeping them
 * hand-written (rather than generated) is deliberate for now: the surface is
 * small, and it keeps the field-by-field mapping reviewable.
 */

export type IncidentStatus =
  | "open"
  | "triaged"
  | "investigating"
  | "awaiting_approval"
  | "remediating"
  | "verifying"
  | "resolved"
  | "closed"
  | "failed";

// Mirrors IncidentStatus.is_terminal in backend/app/models/enums.py: these are
// the statuses the investigate endpoint refuses without force=true.
export const TERMINAL_INCIDENT_STATUSES: readonly IncidentStatus[] = [
  "closed",
  "failed",
];

export type IncidentSeverity = "sev1" | "sev2" | "sev3" | "sev4" | "sev5";

export type IncidentSource =
  | "slack"
  | "github"
  | "kubernetes"
  | "prometheus"
  | "grafana"
  | "cloudwatch"
  | "manual"
  | "api"
  | "synthetic";

export type RiskTier = "low" | "medium" | "high" | "critical";

export type UserRole = "viewer" | "responder" | "approver" | "admin" | "owner";

export type AgentPhase =
  | "ingested"
  | "triage"
  | "plan"
  | "investigate"
  | "correlate"
  | "hypothesize"
  | "propose_remediation"
  | "policy_check"
  | "await_approval"
  | "execute"
  | "verify"
  | "postmortem"
  | "done"
  | "failed";

export type InvestigatorKind =
  | "logs"
  | "metrics"
  | "database"
  | "deployments"
  | "history";

export type RemediationStatus =
  | "proposed"
  | "blocked_by_policy"
  | "awaiting_approval"
  | "approved"
  | "rejected"
  | "executing"
  | "succeeded"
  | "failed"
  | "rolled_back"
  | "skipped";

export type ApprovalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | "cancelled";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan: string;
  is_active: boolean;
  created_at: string;
}

export interface Session {
  user: User;
  tenant: Tenant;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface IncidentSummary {
  id: string;
  reference: string;
  title: string;
  status: IncidentStatus;
  severity: IncidentSeverity;
  source: IncidentSource;
  service: string | null;
  environment: string;
  detected_at: string;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
  root_cause_summary: string | null;
  root_cause_confidence: number | null;
  assignee_id: string | null;
  open_approval_count: number;
}

export interface TimelineEntry {
  id: string;
  occurred_at: string;
  actor_type: string;
  actor_label: string;
  phase: AgentPhase | null;
  title: string;
  body: string;
  metadata_json: Record<string, unknown>;
}

export interface Evidence {
  id: string;
  incident_id: string;
  kind: string;
  investigator: InvestigatorKind | null;
  source: string;
  source_ref: string | null;
  source_url: string | null;
  summary: string;
  detail: string;
  raw: Record<string, unknown>;
  relevance: "critical" | "high" | "medium" | "low" | "noise";
  weight: number;
  observed_at: string | null;
  collected_at: string;
  citation: string;
}

export interface Hypothesis {
  id: string;
  incident_id: string;
  title: string;
  statement: string;
  category: string | null;
  confidence: number;
  rank: number;
  is_selected: boolean;
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  reasoning: string;
  disconfirming_test: string | null;
  created_at: string;
}

export interface AgentStep {
  id: string;
  sequence: number;
  phase: AgentPhase;
  investigator: InvestigatorKind | null;
  name: string;
  kind: string;
  status: string;
  input_summary: string;
  output_summary: string;
  payload: Record<string, unknown>;
  error: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

export interface AgentRun {
  id: string;
  incident_id: string;
  thread_id: string;
  attempt: number;
  phase: AgentPhase;
  status: string;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  trace_url: string | null;
  prompt_tokens: number;
  completion_tokens: number;
  tool_call_count: number;
  cost_usd: number;
  plan: Record<string, unknown>;
  duration_seconds: number | null;
}

export interface AgentRunDetail extends AgentRun {
  steps: AgentStep[];
}

export interface VerificationCheck {
  name: string;
  metric: string;
  comparator: "lt" | "lte" | "gt" | "gte";
  threshold: number;
  observed: number | null;
  passed: boolean;
  error?: string | null;
  description?: string;
}

export interface Verification {
  id: string;
  attempt: number;
  outcome: "recovered" | "partial" | "not_recovered" | "inconclusive";
  summary: string;
  checks: VerificationCheck[];
  observed_at: string;
}

export interface IncidentDetail extends IncidentSummary {
  description: string;
  severity_rationale: string;
  severity_confidence: number;
  cluster: string | null;
  namespace: string | null;
  labels: Record<string, unknown>;
  acknowledged_at: string | null;
  mitigated_at: string | null;
  closed_at: string | null;
  auto_investigate: boolean;
  investigation_count: number;
  time_to_detect_seconds: number | null;
  time_to_mitigate_seconds: number | null;
  time_to_resolve_seconds: number | null;
  timeline: TimelineEntry[];
  evidence: Evidence[];
  hypotheses: Hypothesis[];
  runs: AgentRun[];
  verifications: Verification[];
}

export interface BlastRadius {
  scope: string;
  targets: string[];
  estimated_affected_units: number;
  environment: string;
  namespace: string | null;
  service: string | null;
  causes_downtime: boolean;
  touches_data: boolean;
  notes: string;
}

export interface PolicyViolation {
  rule: string;
  message: string;
  severity: string;
  context: Record<string, unknown>;
}

export interface RemediationAction {
  id: string;
  incident_id: string;
  action_key: string;
  title: string;
  params: Record<string, unknown>;
  rationale: string;
  expected_effect: string;
  evidence_ids: string[];
  sequence: number;
  risk_tier: RiskTier;
  blast_radius: Partial<BlastRadius>;
  is_reversible: boolean;
  status: RemediationStatus;
  policy_decision: Record<string, unknown>;
  policy_violations: PolicyViolation[];
  requires_approval: boolean;
  attempt: number;
  executed_at: string | null;
  execution_result: Record<string, unknown>;
  execution_error: string | null;
  duration_ms: number | null;
  created_at: string;
}

export interface Approval {
  id: string;
  incident_id: string;
  action_id: string;
  status: ApprovalStatus;
  risk_tier: RiskTier;
  required_role: string;
  request_summary: string;
  context: {
    blast_radius?: Partial<BlastRadius>;
    checklist?: string[];
    rationale?: string;
    expected_effect?: string;
    policy_reason?: string;
    is_reversible?: boolean;
    hypothesis?: { title?: string; confidence?: number };
    warnings?: PolicyViolation[];
    params?: Record<string, unknown>;
    action_key?: string;
    proposed_by?: string;
  };
  requested_at: string;
  expires_at: string;
  decided_at: string | null;
  decided_by_id: string | null;
  decision_note: string;
  modified_params: Record<string, unknown> | null;
  created_at: string;
}

export interface ApprovalWithAction extends Approval {
  action: RemediationAction;
  incident_reference: string;
  incident_title: string;
}

export interface Postmortem {
  id: string;
  incident_id: string;
  title: string;
  summary: string;
  impact: string;
  root_cause: string;
  detection: string;
  resolution: string;
  lessons_learned: string;
  timeline_markdown: string;
  action_items: {
    title: string;
    owner?: string;
    priority: string;
    rationale?: string;
  }[];
  evidence_ids: string[];
  metrics: Record<string, unknown>;
  markdown: string;
  is_published: boolean;
  published_at: string | null;
  created_at: string;
}

export interface Integration {
  id: string;
  provider: string;
  name: string;
  description: string;
  status: "pending" | "healthy" | "degraded" | "error" | "disabled";
  is_enabled: boolean;
  config: Record<string, unknown>;
  credential_keys: string[];
  credential_fingerprints: Record<string, string>;
  credentials_rotated_at: string | null;
  has_webhook_secret: boolean;
  allow_write: boolean;
  scope: Record<string, unknown>;
  last_health_check_at: string | null;
  last_error: string | null;
  consecutive_failures: number;
  created_at: string;
  updated_at: string;
}

export interface ActionSpec {
  key: string;
  title: string;
  description: string;
  provider: string;
  risk_tier: RiskTier;
  is_reversible: boolean;
  minimum_role: UserRole;
  requires_write_integration: boolean;
  params_schema: Record<string, unknown>;
  approval_checklist?: string[];
}

export interface DashboardOverview {
  window_days: number;
  generated_at: string;
  open_incidents: number;
  active_investigations: number;
  pending_approvals: number;
  incidents_in_window: number;
  by_status: { key: string; label: string; count: number }[];
  by_severity: { key: string; label: string; count: number }[];
  by_source: { key: string; label: string; count: number }[];
  by_service: { key: string; label: string; count: number }[];
  volume: { bucket: string; count: number; sev1: number; sev2: number }[];
  mttr: {
    mean_time_to_acknowledge: number | null;
    mean_time_to_mitigate: number | null;
    mean_time_to_resolve: number | null;
    p50_time_to_resolve: number | null;
    p90_time_to_resolve: number | null;
    sample_size: number;
  };
  agents: {
    runs_total: number;
    runs_succeeded: number;
    runs_failed: number;
    mean_run_seconds: number | null;
    total_cost_usd: number;
    total_tool_calls: number;
  };
  remediation: {
    proposed: number;
    auto_approved: number;
    approved: number;
    rejected: number;
    blocked_by_policy: number;
    executed: number;
    succeeded: number;
    failed: number;
    mean_approval_latency_seconds: number | null;
    recovery_rate: number | null;
  };
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  is_enabled: boolean;
  priority: number;
  match: Record<string, unknown>;
  effect: string;
  required_role: string | null;
  reason: string;
  limits: Record<string, unknown>;
  active_window: Record<string, unknown>;
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
}

export interface EffectivePolicy {
  remediation_enabled: boolean;
  auto_approve_low_risk: boolean;
  always_approve_at_or_above: RiskTier;
  protected_namespaces: string[];
  protected_environments: string[];
  max_pods_restart: number;
  max_replica_delta: number;
  max_actions_per_incident: number;
  max_actions_per_hour: number;
  min_confidence_high_risk: number;
  min_confidence_critical_risk: number;
  min_evidence_high_risk: number;
  change_freeze_windows: Record<string, unknown>[];
  automation_severities: string[];
}

export interface AuditLog {
  id: string;
  action: string;
  actor_type: string;
  actor_id: string | null;
  actor_label: string;
  resource_type: string;
  resource_id: string | null;
  incident_id: string | null;
  summary: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  context: Record<string, unknown>;
  request_id: string | null;
  ip_address: string | null;
  occurred_at: string;
}

/** A live event from the agent activity stream. */
export interface AgentEvent {
  id: string;
  type: string;
  incident_id: string;
  tenant_id: string;
  phase: AgentPhase | null;
  title: string;
  message: string;
  investigator: string | null;
  run_id: string | null;
  step_id: string | null;
  sequence: number | null;
  data: Record<string, unknown>;
  at: string;
}
