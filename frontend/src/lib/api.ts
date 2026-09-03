/**
 * Typed API client.
 *
 * One place that knows about tokens, refresh and error shape. Every call goes
 * through `request()`, so a 401 triggers exactly one refresh attempt and then
 * either retries or signs the user out — never a refresh storm.
 */

import type {
  ActionSpec,
  AgentRunDetail,
  ApprovalWithAction,
  AuditLog,
  DashboardOverview,
  EffectivePolicy,
  Evidence,
  IncidentDetail,
  IncidentSummary,
  Integration,
  Page,
  PolicyRule,
  Postmortem,
  RemediationAction,
  Session,
  TokenPair,
  User,
} from "./types";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const ACCESS_KEY = "opspilot.access_token";
const REFRESH_KEY = "opspilot.refresh_token";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ApiError";
  }

  get isAuthError(): boolean {
    return this.status === 401;
  }
}

// ---------------------------------------------------------------- token store
export const tokens = {
  access(): string | null {
    if (typeof window === "undefined") return null;
    return window.localStorage.getItem(ACCESS_KEY);
  },
  refresh(): string | null {
    if (typeof window === "undefined") return null;
    return window.localStorage.getItem(REFRESH_KEY);
  },
  set(pair: TokenPair) {
    window.localStorage.setItem(ACCESS_KEY, pair.access_token);
    window.localStorage.setItem(REFRESH_KEY, pair.refresh_token);
  },
  clear() {
    window.localStorage.removeItem(ACCESS_KEY);
    window.localStorage.removeItem(REFRESH_KEY);
  },
};

// A single in-flight refresh shared by every concurrent 401, so a page with six
// parallel requests refreshes once rather than six times.
let refreshInFlight: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  const token = tokens.refresh();
  if (!token) return false;

  refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: token }),
      });
      if (!response.ok) return false;
      tokens.set((await response.json()) as TokenPair);
      return true;
    } catch {
      return false;
    } finally {
      // Allow the next 401 to start a fresh attempt.
      setTimeout(() => (refreshInFlight = null), 0);
    }
  })();

  return refreshInFlight;
}

interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  query?: Record<string, string | number | boolean | string[] | undefined | null>;
  retryOnAuthFailure?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = new URL(`${API_URL}${path}`);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) url.searchParams.append(key, String(item));
    } else {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

export async function request<T>(
  path: string,
  { body, query, retryOnAuthFailure = true, ...init }: RequestOptions = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (body !== undefined) headers.set("Content-Type", "application/json");

  const access = tokens.access();
  if (access) headers.set("Authorization", `Bearer ${access}`);

  const response = await fetch(buildUrl(path, query), {
    ...init,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && retryOnAuthFailure && tokens.refresh()) {
    if (await refreshAccessToken()) {
      return request<T>(path, {
        ...init,
        body,
        query,
        retryOnAuthFailure: false,
      });
    }
    tokens.clear();
  }

  if (!response.ok) {
    let code = "http_error";
    let message = `Request failed with status ${response.status}`;
    let details: Record<string, unknown> | undefined;
    try {
      const payload = await response.json();
      code = payload?.error?.code ?? code;
      message = payload?.error?.message ?? message;
      details = payload?.error?.details;
    } catch {
      /* non-JSON error body; keep the generic message */
    }
    throw new ApiError(response.status, code, message, details);
  }

  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

// -------------------------------------------------------------------- surface
export const api = {
  // auth
  signup: (body: {
    organization_name: string;
    email: string;
    password: string;
    full_name?: string;
  }) => request<TokenPair>("/api/v1/auth/signup", { method: "POST", body }),

  login: (body: { email: string; password: string; tenant_slug?: string }) =>
    request<TokenPair>("/api/v1/auth/login", { method: "POST", body }),

  logout: () => {
    const refresh = tokens.refresh();
    tokens.clear();
    if (!refresh) return Promise.resolve();
    // Best effort: the server revokes the refresh token; the client is already
    // signed out even if this fails.
    return request("/api/v1/auth/logout", {
      method: "POST",
      body: { refresh_token: refresh },
      retryOnAuthFailure: false,
    }).catch(() => undefined);
  },

  session: () => request<Session>("/api/v1/auth/session"),

  users: () => request<Page<User>>("/api/v1/auth/users", { query: { limit: 100 } }),

  updateUser: (id: string, body: Partial<Pick<User, "role" | "is_active" | "full_name">>) =>
    request<User>(`/api/v1/auth/users/${id}`, { method: "PATCH", body }),

  // incidents
  incidents: (query?: {
    status?: string[];
    severity?: string[];
    service?: string;
    q?: string;
    limit?: number;
    offset?: number;
  }) => request<Page<IncidentSummary>>("/api/v1/incidents", { query }),

  incident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${id}`),

  createIncident: (body: {
    title: string;
    description?: string;
    service?: string;
    namespace?: string;
    environment?: string;
    severity?: string;
    auto_investigate?: boolean;
  }) => request<IncidentSummary>("/api/v1/incidents", { method: "POST", body }),

  updateIncident: (
    id: string,
    body: Partial<{ status: string; severity: string; assignee_id: string; title: string }>,
  ) => request<IncidentSummary>(`/api/v1/incidents/${id}`, { method: "PATCH", body }),

  comment: (id: string, body: string) =>
    request(`/api/v1/incidents/${id}/comments`, { method: "POST", body: { body } }),

  investigate: (id: string, force = false) =>
    request<{ ok: boolean; message: string }>(
      `/api/v1/incidents/${id}/investigate`,
      { method: "POST", query: { force } },
    ),

  evidence: (id: string) => request<Evidence[]>(`/api/v1/incidents/${id}/evidence`),

  actions: (id: string) =>
    request<RemediationAction[]>(`/api/v1/incidents/${id}/actions`),

  runs: (id: string) => request<AgentRunDetail[]>(`/api/v1/incidents/${id}/runs`),

  run: (incidentId: string, runId: string) =>
    request<AgentRunDetail>(`/api/v1/incidents/${incidentId}/runs/${runId}`),

  postmortem: (id: string) =>
    request<Postmortem>(`/api/v1/incidents/${id}/postmortem`),

  publishPostmortem: (id: string, isPublished: boolean) =>
    request<Postmortem>(`/api/v1/incidents/${id}/postmortem`, {
      method: "PATCH",
      body: { is_published: isPublished },
    }),

  graphState: (id: string) =>
    request<{ next: string[]; interrupts: unknown[] }>(
      `/api/v1/incidents/${id}/graph-state`,
    ),

  // approvals
  approvals: (query?: { status?: string; incident_id?: string; limit?: number }) =>
    request<Page<ApprovalWithAction>>("/api/v1/approvals", { query }),

  pendingApprovalCount: () =>
    request<{ pending: number }>("/api/v1/approvals/pending/count"),

  decide: (
    id: string,
    body: {
      decision: "approve" | "reject";
      note?: string;
      modified_params?: Record<string, unknown>;
    },
  ) =>
    request<ApprovalWithAction>(`/api/v1/approvals/${id}/decision`, {
      method: "POST",
      body,
    }),

  // catalog & policy
  catalog: () => request<ActionSpec[]>("/api/v1/actions"),

  effectivePolicy: () => request<EffectivePolicy>("/api/v1/policy/effective"),

  policyRules: () => request<PolicyRule[]>("/api/v1/policy/rules"),

  // integrations
  integrations: () => request<Integration[]>("/api/v1/integrations"),

  createIntegration: (body: Record<string, unknown>) =>
    request<Integration>("/api/v1/integrations", { method: "POST", body }),

  updateIntegration: (id: string, body: Record<string, unknown>) =>
    request<Integration>(`/api/v1/integrations/${id}`, { method: "PATCH", body }),

  deleteIntegration: (id: string) =>
    request(`/api/v1/integrations/${id}`, { method: "DELETE" }),

  testIntegration: (id: string) =>
    request<{ status: string; detail: string; latency_ms: number | null }>(
      `/api/v1/integrations/${id}/test`,
      { method: "POST" },
    ),

  webhookUrl: (id: string) =>
    request<{ url: string; signature_header: string }>(
      `/api/v1/integrations/${id}/webhook-url`,
    ),

  // dashboard & audit
  dashboard: (days = 30) =>
    request<DashboardOverview>("/api/v1/dashboard/overview", { query: { days } }),

  auditLogs: (query?: { limit?: number; incident_id?: string }) =>
    request<Page<AuditLog>>("/api/v1/audit", { query }),

  /** Irreversible: deletes every audit entry for the tenant. Admin only. */
  clearAuditLogs: (reason?: string) =>
    request<{ deleted: number; message: string }>("/api/v1/audit", {
      method: "DELETE",
      query: { reason },
    }),
};

/**
 * SSE endpoints need a credential in the query string because EventSource
 * cannot set headers — but the raw access token must never appear in a URL
 * (history, proxy logs, Referer). Mint a single-use ticket instead.
 */
export async function streamUrl(path: string): Promise<string | null> {
  if (!tokens.access()) return null;
  try {
    const { ticket } = await request<{ ticket: string }>("/api/v1/stream/ticket", {
      method: "POST",
      retryOnAuthFailure: true,
    });
    return `${API_URL}/api/v1/stream${path}?ticket=${encodeURIComponent(ticket)}`;
  } catch {
    return null;
  }
}
