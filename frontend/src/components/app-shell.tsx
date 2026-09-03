"use client";

import {
  Activity,
  AlertTriangle,
  BookLock,
  LayoutDashboard,
  LogOut,
  Plug,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { api } from "@/lib/api";
import { useRequireAuth, useAuth } from "@/lib/auth";
import { useTenantStream } from "@/lib/stream";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/incidents", label: "Incidents", icon: AlertTriangle },
  { href: "/approvals", label: "Approvals", icon: ShieldCheck, badge: "approvals" },
  { href: "/integrations", label: "Integrations", icon: Plug },
  { href: "/settings", label: "Safety & audit", icon: BookLock },
] as const;

export function AppShell({ children }: { children: React.ReactNode }) {
  const { session, loading } = useRequireAuth();
  const { logout } = useAuth();
  const pathname = usePathname();
  const [pendingApprovals, setPendingApprovals] = useState(0);

  const refreshApprovals = useCallback(async () => {
    try {
      const { pending } = await api.pendingApprovalCount();
      setPendingApprovals(pending);
    } catch {
      /* a failed badge count is not worth surfacing */
    }
  }, []);

  // Refresh the badge when the session arrives or the route changes.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (session) void refreshApprovals();
  }, [session, refreshApprovals, pathname]);

  // The badge follows the live stream, so a new approval appears without a reload.
  useTenantStream(
    useCallback(
      (event) => {
        if (
          event.type === "approval.requested" ||
          event.type === "approval.resolved"
        ) {
          void refreshApprovals();
        }
      },
      [refreshApprovals],
    ),
    Boolean(session),
  );

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
      </div>
    );
  }
  if (!session) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-[--color-border-subtle] bg-[--color-surface] lg:flex">
        <div className="flex h-14 items-center gap-2.5 border-b border-[--color-border-subtle] px-5">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-sky-600/15 text-sm ring-1 ring-sky-500/30">
            🛰️
          </span>
          <span className="text-sm font-semibold tracking-tight">OpsPilot</span>
        </div>

        <nav className="flex-1 space-y-0.5 p-3">
          {NAV.map(({ href, label, icon: Icon, ...rest }) => {
            const active = pathname === href || pathname.startsWith(`${href}/`);
            const badge =
              "badge" in rest && rest.badge === "approvals"
                ? pendingApprovals
                : 0;
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-[--color-surface-raised] font-medium text-[--color-text-primary]"
                    : "text-[--color-text-secondary] hover:bg-[--color-surface-raised] hover:text-[--color-text-primary]",
                )}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden />
                <span className="flex-1">{label}</span>
                {badge > 0 ? (
                  <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-amber-200 ring-1 ring-inset ring-amber-500/40">
                    {badge}
                  </span>
                ) : null}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-[--color-border-subtle] p-3">
          <div className="mb-2 px-2">
            <p className="truncate text-xs font-medium text-[--color-text-primary]">
              {session.user.full_name || session.user.email}
            </p>
            <p className="truncate text-[11px] text-[--color-text-muted]">
              {session.tenant.name} · {session.user.role}
            </p>
          </div>
          <button
            onClick={logout}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm text-[--color-text-secondary] transition-colors hover:bg-[--color-surface-raised] hover:text-[--color-text-primary]"
          >
            <LogOut className="h-4 w-4" aria-hidden />
            Sign out
          </button>
        </div>
      </aside>

      {/* Mobile top bar */}
      <header className="fixed inset-x-0 top-0 z-30 flex h-14 items-center gap-3 border-b border-[--color-border-subtle] bg-[--color-surface] px-4 lg:hidden">
        <span className="text-sm font-semibold">🛰️ OpsPilot</span>
        <nav className="ml-auto flex gap-1 overflow-x-auto">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-label={label}
                className={cn(
                  "rounded-lg p-2",
                  active
                    ? "bg-[--color-surface-raised] text-[--color-text-primary]"
                    : "text-[--color-text-muted]",
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
              </Link>
            );
          })}
        </nav>
      </header>

      <main className="flex-1 pt-14 lg:pl-60 lg:pt-0">{children}</main>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  actions,
  live,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  live?: boolean;
}) {
  return (
    <div className="sticky top-14 z-20 border-b border-[--color-border-subtle] bg-[--color-canvas]/85 px-5 py-4 backdrop-blur lg:top-0 lg:px-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="truncate text-lg font-semibold tracking-tight">
              {title}
            </h1>
            {live ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300 ring-1 ring-inset ring-emerald-500/30">
                <Activity className="h-3 w-3 animate-live" aria-hidden />
                live
              </span>
            ) : null}
          </div>
          {description ? (
            <p className="mt-1 text-xs text-[--color-text-muted]">{description}</p>
          ) : null}
        </div>
        {actions ? (
          <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>
        ) : null}
      </div>
    </div>
  );
}
