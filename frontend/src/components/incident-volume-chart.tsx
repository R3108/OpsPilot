"use client";

import { useMemo, useState } from "react";

import { cn } from "@/lib/utils";

interface Bucket {
  bucket: string;
  count: number;
  sev1: number;
  sev2: number;
}

/**
 * Daily incident volume, split by severity.
 *
 * Hand-drawn SVG rather than a charting library: the shape is a simple stacked
 * column chart, and owning it keeps the palette identical to the rest of the app
 * and the bundle free of a dependency that would still need restyling. Severity
 * uses the same red→amber→slate ramp as every badge, so the chart reads without
 * a legend lookup.
 */
export function IncidentVolumeChart({
  data,
  height = 160,
}: {
  data: Bucket[];
  height?: number;
}) {
  const [hovered, setHovered] = useState<number | null>(null);

  const { max, series } = useMemo(() => {
    const maximum = Math.max(1, ...data.map((d) => d.count));
    return {
      max: maximum,
      series: data.map((d) => ({
        ...d,
        other: Math.max(0, d.count - d.sev1 - d.sev2),
      })),
    };
  }, [data]);

  if (data.length === 0) {
    return (
      <div
        className="flex items-center justify-center text-xs text-[--color-text-muted]"
        style={{ height }}
      >
        No incidents in this window.
      </div>
    );
  }

  const gap = series.length > 40 ? 1 : 3;
  const active = hovered !== null ? series[hovered] : null;

  return (
    <div className="relative">
      <div
        className="flex items-end gap-[var(--bar-gap)]"
        style={
          {
            height,
            "--bar-gap": `${gap}px`,
          } as React.CSSProperties
        }
        onMouseLeave={() => setHovered(null)}
      >
        {series.map((bucket, index) => {
          const total = (bucket.count / max) * 100;
          const segments = [
            { key: "sev1", value: bucket.sev1, className: "bg-red-500/80" },
            { key: "sev2", value: bucket.sev2, className: "bg-orange-500/70" },
            { key: "other", value: bucket.other, className: "bg-slate-500/50" },
          ].filter((segment) => segment.value > 0);

          return (
            <button
              key={bucket.bucket}
              type="button"
              aria-label={`${new Date(bucket.bucket).toLocaleDateString()}: ${bucket.count} incidents`}
              onMouseEnter={() => setHovered(index)}
              onFocus={() => setHovered(index)}
              className="group relative flex flex-1 flex-col justify-end rounded-sm focus:outline-none focus-visible:ring-1 focus-visible:ring-sky-500"
              style={{ height: "100%" }}
            >
              <div
                className={cn(
                  "flex w-full flex-col-reverse overflow-hidden rounded-t-sm transition-opacity",
                  hovered !== null && hovered !== index ? "opacity-50" : "",
                )}
                style={{ height: `${Math.max(total, bucket.count > 0 ? 3 : 0)}%` }}
              >
                {segments.map((segment) => (
                  <div
                    key={segment.key}
                    className={segment.className}
                    style={{
                      height: `${(segment.value / Math.max(bucket.count, 1)) * 100}%`,
                    }}
                  />
                ))}
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] text-[--color-text-muted]">
        <span>
          {new Date(series[0]!.bucket).toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
          })}
        </span>
        <div className="flex items-center gap-3">
          <Legend className="bg-red-500/80" label="sev1" />
          <Legend className="bg-orange-500/70" label="sev2" />
          <Legend className="bg-slate-500/50" label="other" />
        </div>
        <span>
          {new Date(series[series.length - 1]!.bucket).toLocaleDateString(
            undefined,
            { month: "short", day: "numeric" },
          )}
        </span>
      </div>

      {active ? (
        <div className="pointer-events-none absolute -top-1 left-1/2 -translate-x-1/2 rounded-lg border border-[--color-border-subtle] bg-[--color-surface-raised] px-2.5 py-1.5 text-[11px] shadow-lg">
          <p className="font-medium">
            {new Date(active.bucket).toLocaleDateString(undefined, {
              weekday: "short",
              month: "short",
              day: "numeric",
            })}
          </p>
          <p className="text-[--color-text-muted]">
            {active.count} incident{active.count === 1 ? "" : "s"}
            {active.sev1 > 0 ? ` · ${active.sev1} sev1` : ""}
            {active.sev2 > 0 ? ` · ${active.sev2} sev2` : ""}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function Legend({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={cn("h-2 w-2 rounded-sm", className)} />
      {label}
    </span>
  );
}
