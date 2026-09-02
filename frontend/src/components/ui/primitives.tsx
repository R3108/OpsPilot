"use client";

/**
 * The small set of primitives the whole app is built from.
 *
 * Hand-written rather than pulled from a component library: there are only a
 * dozen of them, they are all a few lines, and owning them keeps the visual
 * language consistent without a dependency that would still need styling.
 */

import { cva, type VariantProps } from "class-variance-authority";
import type {
  ButtonHTMLAttributes,
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  TextareaHTMLAttributes,
} from "react";
import { forwardRef } from "react";

import { cn } from "@/lib/utils";

// ------------------------------------------------------------------- surfaces
export function Card({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-[--color-border-subtle] bg-[--color-surface] shadow-sm",
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-start justify-between gap-3 border-b border-[--color-border-subtle] px-5 py-4",
        className,
      )}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-semibold tracking-tight text-[--color-text-primary]">
          {title}
        </h2>
        {description ? (
          <p className="mt-1 text-xs text-[--color-text-muted]">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 gap-2">{actions}</div> : null}
    </div>
  );
}

export function CardBody({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 py-4", className)} {...props} />;
}

// --------------------------------------------------------------------- button
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[--color-accent] focus-visible:ring-offset-2 focus-visible:ring-offset-[--color-canvas] disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "bg-sky-600 text-white hover:bg-sky-500",
        secondary:
          "border border-[--color-border-subtle] bg-[--color-surface-raised] text-[--color-text-primary] hover:bg-[--color-surface]",
        ghost:
          "text-[--color-text-secondary] hover:bg-[--color-surface-raised] hover:text-[--color-text-primary]",
        danger: "bg-red-600 text-white hover:bg-red-500",
        success: "bg-emerald-600 text-white hover:bg-emerald-500",
      },
      size: {
        sm: "h-8 px-3 text-xs",
        md: "h-9 px-4",
        lg: "h-10 px-5",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, children, disabled, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <span
          aria-hidden
          className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
        />
      ) : null}
      {children}
    </button>
  ),
);
Button.displayName = "Button";

// ---------------------------------------------------------------------- badge
export function Badge({
  className,
  children,
  title,
}: {
  className?: string;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ring-1 ring-inset",
        "bg-slate-500/15 text-slate-300 ring-slate-500/30",
        className,
      )}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------- input
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-lg border border-[--color-border-subtle] bg-[--color-canvas] px-3 text-sm text-[--color-text-primary] placeholder:text-[--color-text-muted] focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(
      "w-full rounded-lg border border-[--color-border-subtle] bg-[--color-canvas] px-3 py-2 text-sm text-[--color-text-primary] placeholder:text-[--color-text-muted] focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500",
      className,
    )}
    {...props}
  />
));
Textarea.displayName = "Textarea";

export function Label({
  children,
  htmlFor,
  className,
}: {
  children: ReactNode;
  htmlFor?: string;
  className?: string;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className={cn(
        "mb-1.5 block text-xs font-medium text-[--color-text-secondary]",
        className,
      )}
    >
      {children}
    </label>
  );
}

// ------------------------------------------------------------------ feedback
export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton rounded-md", className)} />;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {icon ? <div className="text-3xl opacity-50">{icon}</div> : null}
      <p className="text-sm font-medium text-[--color-text-secondary]">{title}</p>
      {description ? (
        <p className="max-w-md text-xs text-[--color-text-muted]">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <p className="text-sm text-red-300">{message}</p>
      {onRetry ? (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

// ----------------------------------------------------------------------- misc
export function StatTile({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "neutral" | "warn" | "danger" | "good";
}) {
  const toneClass = {
    neutral: "text-[--color-text-primary]",
    warn: "text-amber-300",
    danger: "text-red-300",
    good: "text-emerald-300",
  }[tone];

  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[--color-text-muted]">
        {label}
      </p>
      <p className={cn("mt-2 text-2xl font-semibold tabular-nums", toneClass)}>
        {value}
      </p>
      {hint ? (
        <p className="mt-1 text-xs text-[--color-text-muted]">{hint}</p>
      ) : null}
    </Card>
  );
}

export function Divider({ className }: { className?: string }) {
  return (
    <hr className={cn("border-t border-[--color-border-subtle]", className)} />
  );
}

export function KeyValue({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <dt className="shrink-0 text-xs text-[--color-text-muted]">{label}</dt>
      <dd className="min-w-0 truncate text-right text-xs text-[--color-text-secondary]">
        {children}
      </dd>
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-[--color-canvas] px-1.5 py-0.5 font-mono text-[11px] text-[--color-text-secondary]">
      {children}
    </code>
  );
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: string; label: string; count?: number }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div
      role="tablist"
      className="flex gap-1 overflow-x-auto border-b border-[--color-border-subtle]"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={active === tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            "shrink-0 border-b-2 px-3 py-2 text-sm font-medium transition-colors",
            active === tab.id
              ? "border-sky-500 text-[--color-text-primary]"
              : "border-transparent text-[--color-text-muted] hover:text-[--color-text-secondary]",
          )}
        >
          {tab.label}
          {tab.count !== undefined && tab.count > 0 ? (
            <span className="ml-1.5 rounded bg-[--color-surface-raised] px-1.5 py-0.5 text-[10px] tabular-nums">
              {tab.count}
            </span>
          ) : null}
        </button>
      ))}
    </div>
  );
}
