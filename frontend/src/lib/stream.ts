"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { streamUrl } from "./api";
import type { AgentEvent } from "./types";

export type StreamStatus = "connecting" | "live" | "stale" | "closed";

interface UseAgentStreamOptions {
  /** Called for every event, including ones already in the buffer. */
  onEvent?: (event: AgentEvent) => void;
  /** Retain at most this many events in the returned buffer. */
  limit?: number;
  enabled?: boolean;
}

/**
 * Subscribes to the agent activity stream for one incident.
 *
 * The server replays what was missed on connect (and on reconnect, via
 * `Last-Event-ID`), so a client that joins mid-investigation still sees the
 * whole run rather than only what happens next.
 */
export function useAgentStream(
  incidentId: string | null,
  { onEvent, limit = 500, enabled = true }: UseAgentStreamOptions = {},
) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const [lastHeartbeat, setLastHeartbeat] = useState<number>(Date.now());
  const onEventRef = useRef(onEvent);
  const seenIds = useRef<Set<string>>(new Set());

  // Keep the callback fresh without making it a dependency of the connection,
  // which would tear down and rebuild the EventSource on every render.
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (!incidentId || !enabled) return;

    const url = streamUrl(`/incidents/${incidentId}`);
    if (!url) return;

    seenIds.current = new Set();
    setEvents([]);
    setStatus("connecting");

    const source = new EventSource(url);

    const handle = (raw: MessageEvent<string>) => {
      setLastHeartbeat(Date.now());
      setStatus("live");

      let payload: AgentEvent;
      try {
        payload = JSON.parse(raw.data) as AgentEvent;
      } catch {
        return;
      }
      if (payload.type === "heartbeat") return;

      // The replay buffer can overlap with live events after a reconnect.
      if (payload.id && seenIds.current.has(payload.id)) return;
      if (payload.id) seenIds.current.add(payload.id);

      onEventRef.current?.(payload);
      setEvents((current) => {
        const next = [...current, payload];
        return next.length > limit ? next.slice(next.length - limit) : next;
      });
    };

    source.onmessage = handle;
    source.onopen = () => setStatus("live");
    source.onerror = () => {
      // EventSource reconnects on its own; surface it rather than tearing down.
      setStatus((current) => (current === "live" ? "stale" : current));
    };

    return () => {
      source.close();
      setStatus("closed");
    };
  }, [incidentId, enabled, limit]);

  // Mark the stream stale if the heartbeat stops arriving.
  useEffect(() => {
    const timer = setInterval(() => {
      setStatus((current) =>
        current === "live" && Date.now() - lastHeartbeat > 45_000
          ? "stale"
          : current,
      );
    }, 10_000);
    return () => clearInterval(timer);
  }, [lastHeartbeat]);

  const clear = useCallback(() => {
    setEvents([]);
    seenIds.current = new Set();
  }, []);

  return { events, status, clear };
}

/** Org-wide stream, used for live badge counts. */
export function useTenantStream(onEvent: (event: AgentEvent) => void, enabled = true) {
  const onEventRef = useRef(onEvent);
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (!enabled) return;
    const url = streamUrl("/tenant");
    if (!url) return;

    const source = new EventSource(url);
    source.onmessage = (raw: MessageEvent<string>) => {
      try {
        const payload = JSON.parse(raw.data) as AgentEvent;
        if (payload.type !== "heartbeat") onEventRef.current(payload);
      } catch {
        /* ignore malformed frames */
      }
    };
    return () => source.close();
  }, [enabled]);
}

/** Poll a loader on an interval, pausing while the tab is hidden. */
export function usePolling<T>(
  loader: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setData(await loader());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    void refresh();
    if (!intervalMs) return;

    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, intervalMs);
    return () => clearInterval(timer);
  }, [refresh, intervalMs]);

  return { data, error, loading, refresh };
}
