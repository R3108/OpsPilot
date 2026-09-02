import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { IncidentSeverity, IncidentStatus, RiskTier } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ------------------------------------------------------------------ formatting
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${Math.round(seconds % 60)}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const deltaSeconds = (Date.now() - then) / 1000;

  if (Math.abs(deltaSeconds) < 45) return "just now";
  const suffix = deltaSeconds > 0 ? "ago" : "from now";
  return `${formatDuration(Math.abs(deltaSeconds))} ${suffix}`;
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${Math.round(value * 100)}%`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (Math.abs(value) >= 1000) return value.toLocaleString();
  if (Number.isInteger(value)) return String(value);
  return value.toPrecision(3);
}

export function titleCase(value: string): string {
  return value
    .replace(/[_.]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ------------------------------------------------------------------- palettes
// Severity and risk both encode "how much should this worry you", so they share
// one ramp — a sev1 and a critical action read as the same level of alarm.
export const severityStyles: Record<IncidentSeverity, string> = {
  sev1: "bg-red-500/15 text-red-300 ring-red-500/30",
  sev2: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  sev3: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  sev4: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  sev5: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
};

export const riskStyles: Record<RiskTier, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  low: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
};

export const statusStyles: Record<IncidentStatus, string> = {
  open: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  triaged: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  investigating: "bg-violet-500/15 text-violet-300 ring-violet-500/30",
  awaiting_approval: "bg-amber-500/15 text-amber-200 ring-amber-500/40",
  remediating: "bg-blue-500/15 text-blue-300 ring-blue-500/30",
  verifying: "bg-cyan-500/15 text-cyan-300 ring-cyan-500/30",
  resolved: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  closed: "bg-slate-600/20 text-slate-400 ring-slate-600/30",
  failed: "bg-red-500/15 text-red-300 ring-red-500/30",
};

export const relevanceStyles: Record<string, string> = {
  critical: "bg-red-500/15 text-red-300 ring-red-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  low: "bg-slate-600/15 text-slate-400 ring-slate-600/30",
  noise: "bg-slate-700/15 text-slate-500 ring-slate-700/30",
};

export const remediationStatusStyles: Record<string, string> = {
  proposed: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  blocked_by_policy: "bg-red-500/15 text-red-300 ring-red-500/30",
  awaiting_approval: "bg-amber-500/15 text-amber-200 ring-amber-500/40",
  approved: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
  rejected: "bg-slate-600/20 text-slate-400 ring-slate-600/30",
  executing: "bg-blue-500/15 text-blue-300 ring-blue-500/30",
  succeeded: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  failed: "bg-red-500/15 text-red-300 ring-red-500/30",
  rolled_back: "bg-violet-500/15 text-violet-300 ring-violet-500/30",
  skipped: "bg-slate-600/20 text-slate-400 ring-slate-600/30",
};

export const investigatorIcons: Record<string, string> = {
  logs: "📜",
  metrics: "📈",
  database: "🗄️",
  deployments: "🚀",
  history: "🕰️",
};

/** Confidence bands, so the UI never implies more precision than exists. */
export function confidenceLabel(confidence: number | null | undefined): {
  label: string;
  className: string;
} {
  if (confidence === null || confidence === undefined)
    return { label: "unscored", className: "text-slate-500" };
  if (confidence >= 0.85) return { label: "high", className: "text-emerald-400" };
  if (confidence >= 0.6) return { label: "moderate", className: "text-amber-400" };
  if (confidence >= 0.4) return { label: "low", className: "text-orange-400" };
  return { label: "speculative", className: "text-red-400" };
}
