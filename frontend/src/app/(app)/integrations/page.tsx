"use client";

import { CheckCircle2, Copy, Plug, XCircle } from "lucide-react";
import { useCallback, useState } from "react";

import { PageHeader } from "@/components/app-shell";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  KeyValue,
  Label,
  Skeleton,
} from "@/components/ui/primitives";
import { API_URL, api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePolling } from "@/lib/stream";
import type { Integration } from "@/lib/types";
import { cn, formatDateTime, titleCase } from "@/lib/utils";

const PROVIDERS = [
  { id: "kubernetes", label: "Kubernetes", icon: "☸️", credentials: ["kubeconfig"], config: ["cluster", "default_namespace"] },
  { id: "prometheus", label: "Prometheus", icon: "🔥", credentials: ["bearer_token"], config: ["base_url"] },
  { id: "github", label: "GitHub", icon: "🐙", credentials: ["token"], config: ["owner", "repos"] },
  { id: "postgres", label: "PostgreSQL", icon: "🐘", credentials: ["dsn"], config: ["label"] },
  { id: "slack", label: "Slack", icon: "💬", credentials: ["bot_token", "signing_secret"], config: ["default_channel"] },
  { id: "cloudwatch", label: "CloudWatch", icon: "☁️", credentials: ["access_key_id", "secret_access_key"], config: ["region", "log_groups"] },
  { id: "grafana", label: "Grafana", icon: "📊", credentials: ["api_token"], config: ["base_url"] },
] as const;

const STATUS_STYLES: Record<string, string> = {
  healthy: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  degraded: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  error: "bg-red-500/15 text-red-300 ring-red-500/30",
  pending: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  disabled: "bg-slate-600/20 text-slate-400 ring-slate-600/30",
};

export default function IntegrationsPage() {
  const { can } = useAuth();
  const [adding, setAdding] = useState(false);

  const { data, error, loading, refresh } = usePolling(
    useCallback(() => api.integrations(), []),
    60_000,
  );

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Where OpsPilot reads evidence from, and what it is allowed to change."
        actions={
          can("admin") ? (
            <Button variant="primary" size="sm" onClick={() => setAdding(true)}>
              <Plug className="h-3.5 w-3.5" aria-hidden />
              Connect a system
            </Button>
          ) : null
        }
      />

      <div className="space-y-4 p-5 lg:p-8">
        {error ? (
          <Card>
            <ErrorState message={error.message} onRetry={() => void refresh()} />
          </Card>
        ) : null}

        {adding ? (
          <AddIntegrationForm
            onClose={() => setAdding(false)}
            onCreated={() => {
              setAdding(false);
              void refresh();
            }}
          />
        ) : null}

        {loading && !data ? (
          <div className="grid gap-4 md:grid-cols-2">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-56" />
            ))}
          </div>
        ) : null}

        {data && data.length === 0 && !adding ? (
          <Card>
            <EmptyState
              icon="🔌"
              title="No integrations connected"
              description="OpsPilot investigates using read-only tools against your real systems. Connect at least a metrics source and a log source to get useful investigations."
              action={
                can("admin") ? (
                  <Button size="sm" variant="primary" onClick={() => setAdding(true)}>
                    Connect your first system
                  </Button>
                ) : null
              }
            />
          </Card>
        ) : null}

        <div className="grid gap-4 md:grid-cols-2">
          {data?.map((integration) => (
            <IntegrationCard
              key={integration.id}
              integration={integration}
              canManage={can("admin")}
              onChanged={() => void refresh()}
            />
          ))}
        </div>
      </div>
    </>
  );
}

function IntegrationCard({
  integration,
  canManage,
  onChanged,
}: {
  integration: Integration;
  canManage: boolean;
  onChanged: () => void;
}) {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [webhook, setWebhook] = useState<string | null>(null);
  const meta = PROVIDERS.find((p) => p.id === integration.provider);

  async function test() {
    setTesting(true);
    setResult(null);
    try {
      const health = await api.testIntegration(integration.id);
      setResult(`${health.status}: ${health.detail}`);
      onChanged();
    } catch (err) {
      setResult(err instanceof Error ? err.message : "Test failed");
    } finally {
      setTesting(false);
    }
  }

  async function loadWebhook() {
    try {
      const { url } = await api.webhookUrl(integration.id);
      setWebhook(`${API_URL}${url}`);
    } catch {
      setWebhook(null);
    }
  }

  const simulated = integration.config?.mode === "simulation";

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <span>{meta?.icon ?? "🔌"}</span>
            {meta?.label ?? titleCase(integration.provider)}
            <span className="text-[--color-text-muted]">/ {integration.name}</span>
          </span>
        }
        description={integration.description || undefined}
        actions={
          <Badge className={STATUS_STYLES[integration.status]}>
            {integration.status}
          </Badge>
        }
      />
      <CardBody className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium ring-1 ring-inset",
              integration.allow_write
                ? "bg-orange-500/15 text-orange-300 ring-orange-500/30"
                : "bg-slate-500/15 text-slate-300 ring-slate-500/30",
            )}
          >
            {integration.allow_write ? "read-write" : "read-only"}
          </span>
          {simulated ? (
            <span className="rounded bg-violet-500/15 px-2 py-0.5 text-[10px] font-medium text-violet-300 ring-1 ring-inset ring-violet-500/30">
              simulation
            </span>
          ) : null}
          {integration.has_webhook_secret ? (
            <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-300 ring-1 ring-inset ring-emerald-500/30">
              webhook secret set
            </span>
          ) : null}
        </div>

        <dl className="divide-y divide-[--color-border-subtle]">
          <KeyValue label="Credentials">
            {integration.credential_keys.length > 0
              ? integration.credential_keys.join(", ")
              : "none"}
          </KeyValue>
          <KeyValue label="Last checked">
            {formatDateTime(integration.last_health_check_at)}
          </KeyValue>
          {integration.consecutive_failures > 0 ? (
            <KeyValue label="Consecutive failures">
              <span className="text-red-300">
                {integration.consecutive_failures}
              </span>
            </KeyValue>
          ) : null}
        </dl>

        {/* Fingerprints prove which secret is configured without ever showing it. */}
        {Object.keys(integration.credential_fingerprints).length > 0 ? (
          <details>
            <summary className="cursor-pointer text-[11px] text-[--color-text-muted] hover:text-[--color-text-secondary]">
              Credential fingerprints
            </summary>
            <dl className="mt-1.5 space-y-1">
              {Object.entries(integration.credential_fingerprints).map(
                ([key, value]) => (
                  <div key={key} className="flex justify-between gap-3 text-[11px]">
                    <dt className="text-[--color-text-muted]">{key}</dt>
                    <dd className="font-mono text-[--color-text-secondary]">
                      {value}
                    </dd>
                  </div>
                ),
              )}
            </dl>
            <p className="mt-1.5 text-[10px] text-[--color-text-muted]">
              Secrets are envelope-encrypted and never returned by the API. These
              fingerprints identify which value is stored.
            </p>
          </details>
        ) : null}

        {integration.last_error ? (
          <p className="rounded bg-red-500/10 px-2.5 py-1.5 text-[11px] text-red-300 ring-1 ring-inset ring-red-500/25">
            {integration.last_error}
          </p>
        ) : null}

        {result ? (
          <p
            className={cn(
              "flex items-start gap-1.5 rounded px-2.5 py-1.5 text-[11px] ring-1 ring-inset",
              result.startsWith("healthy")
                ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25"
                : "bg-red-500/10 text-red-300 ring-red-500/25",
            )}
          >
            {result.startsWith("healthy") ? (
              <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
            ) : (
              <XCircle className="mt-0.5 h-3 w-3 shrink-0" aria-hidden />
            )}
            {result}
          </p>
        ) : null}

        {webhook ? (
          <div className="rounded bg-[--color-canvas] px-2.5 py-2">
            <p className="text-[10px] uppercase tracking-wide text-[--color-text-muted]">
              Send alerts here
            </p>
            <div className="mt-1 flex items-center gap-2">
              <code className="scroll-x flex-1 font-mono text-[10px] text-[--color-text-secondary]">
                {webhook}
              </code>
              <button
                onClick={() => void navigator.clipboard.writeText(webhook)}
                className="text-[--color-text-muted] hover:text-[--color-text-primary]"
                aria-label="Copy webhook URL"
              >
                <Copy className="h-3 w-3" />
              </button>
            </div>
          </div>
        ) : null}

        {canManage ? (
          <div className="flex flex-wrap gap-2 pt-1">
            <Button size="sm" loading={testing} onClick={() => void test()}>
              Test connection
            </Button>
            <Button size="sm" variant="ghost" onClick={() => void loadWebhook()}>
              Webhook URL
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={async () => {
                await api.updateIntegration(integration.id, {
                  allow_write: !integration.allow_write,
                });
                onChanged();
              }}
            >
              Make {integration.allow_write ? "read-only" : "read-write"}
            </Button>
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}

function AddIntegrationForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [provider, setProvider] = useState<string>("prometheus");
  const [name, setName] = useState("production");
  const [allowWrite, setAllowWrite] = useState(false);
  const [config, setConfig] = useState<Record<string, string>>({});
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [webhookSecret, setWebhookSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const meta = PROVIDERS.find((p) => p.id === provider)!;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.createIntegration({
        provider,
        name,
        allow_write: allowWrite,
        config: Object.fromEntries(
          Object.entries(config).filter(([, value]) => value),
        ),
        credentials: Object.fromEntries(
          Object.entries(credentials).filter(([, value]) => value),
        ),
        webhook_secret: webhookSecret || undefined,
      });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create it");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="Connect a system"
        description="Credentials are envelope-encrypted before they touch the database and are never returned by the API."
      />
      <CardBody>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <Label>Provider</Label>
            <div className="flex flex-wrap gap-2">
              {PROVIDERS.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => {
                    setProvider(option.id);
                    setConfig({});
                    setCredentials({});
                  }}
                  className={cn(
                    "rounded-lg border px-3 py-1.5 text-xs transition-colors",
                    provider === option.id
                      ? "border-sky-500/50 bg-sky-500/10 text-sky-200"
                      : "border-[--color-border-subtle] text-[--color-text-secondary] hover:bg-[--color-surface-raised]",
                  )}
                >
                  {option.icon} {option.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          {meta.config.map((key) => (
            <div key={key}>
              <Label htmlFor={`config-${key}`}>{titleCase(key)}</Label>
              <Input
                id={`config-${key}`}
                value={config[key] ?? ""}
                onChange={(e) =>
                  setConfig((current) => ({ ...current, [key]: e.target.value }))
                }
                placeholder={
                  key === "base_url"
                    ? "https://prometheus.internal"
                    : key === "repos"
                      ? "acme/api,acme/web"
                      : ""
                }
              />
            </div>
          ))}

          {meta.credentials.map((key) => (
            <div key={key}>
              <Label htmlFor={`cred-${key}`}>{titleCase(key)}</Label>
              <Input
                id={`cred-${key}`}
                type="password"
                autoComplete="new-password"
                value={credentials[key] ?? ""}
                onChange={(e) =>
                  setCredentials((current) => ({
                    ...current,
                    [key]: e.target.value,
                  }))
                }
              />
            </div>
          ))}

          <div>
            <Label htmlFor="webhook-secret">
              Webhook signing secret (optional)
            </Label>
            <Input
              id="webhook-secret"
              type="password"
              value={webhookSecret}
              onChange={(e) => setWebhookSecret(e.target.value)}
              placeholder="Required if this provider will send you alerts"
            />
          </div>

          <label className="flex items-start gap-2 rounded-lg bg-[--color-canvas] px-3 py-2">
            <input
              type="checkbox"
              checked={allowWrite}
              onChange={(e) => setAllowWrite(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5"
            />
            <span className="text-xs text-[--color-text-secondary]">
              Allow remediation through this integration
              <span className="mt-0.5 block text-[11px] text-[--color-text-muted]">
                Leave this off to keep the integration read-only. The agent can
                always investigate; without this it can never change anything
                here, whatever the policy says.
              </span>
            </span>
          </label>

          {error ? <p className="text-xs text-red-300">{error}</p> : null}

          <div className="flex gap-2">
            <Button type="submit" variant="primary" size="sm" loading={submitting}>
              Connect
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}
