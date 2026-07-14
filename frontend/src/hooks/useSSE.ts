import { useCallback, useEffect, useRef, useState } from 'react';
import { SSEEvent } from '@/types';

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');
const SSE_EVENT_TYPES = ['scan_started', 'phase_change', 'phase_complete', 'surface_update', 'finding', 'agent_status', 'agent_decision', 'log', 'tool_log', 'scan_complete', 'scan_failed', 'scan_deleted', 'ping'] as const;

export type SSEChannel = 'all' | 'control' | 'telemetry';

interface UseSSEOptions {
  channel?: SSEChannel;
  enabled?: boolean;
}

/**
 * Own exactly one EventSource for the lifetime of the hook.
 *
 * The event callback deliberately lives in a ref. A callback created by a
 * parent render must never become an EventSource dependency: doing so closes
 * and reopens the socket during an event burst, replays history, and can turn
 * one scanner line into many React updates.
 */
export function useSSE(
  onEvent?: (event: SSEEvent) => void,
  { channel = 'all', enabled = true }: UseSSEOptions = {},
) {
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const onEventRef = useRef(onEvent);
  const listenersRef = useRef<Set<(event: SSEEvent) => void>>(new Set());
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef(0);
  const lastSequenceRef = useRef(0);
  const stoppedRef = useRef(false);

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const handleMessage = useCallback((raw: MessageEvent) => {
    try {
      const data = JSON.parse(raw.data);
      const eventType = data.type || data.event || raw.type;
      const event: SSEEvent = { type: eventType, scan_id: data.scan_id, timestamp: data.timestamp, ...data };
      const sequence = Number(data.sequence || 0);
      if (sequence > 0) {
        if (sequence <= lastSequenceRef.current) return;
        lastSequenceRef.current = sequence;
      }
      listenersRef.current.forEach(fn => fn(event));
      onEventRef.current?.(event);
    } catch {
      // Malformed telemetry is isolated from the application render tree.
    }
  }, []);

  const disconnect = useCallback(() => {
    stoppedRef.current = true;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
    setConnected(false);
  }, []);

  const connect = useCallback(() => {
    if (!enabled || typeof window === 'undefined') return;
    stoppedRef.current = false;
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    eventSourceRef.current?.close();

    const query = new URLSearchParams({ channel });
    if (lastSequenceRef.current > 0) query.set('after_sequence', String(lastSequenceRef.current));
    const es = new EventSource(`${API_BASE}/api/stream?${query.toString()}`);
    eventSourceRef.current = es;

    es.onopen = () => {
      reconnectAttemptRef.current = 0;
      setConnected(true);
    };
    es.onmessage = handleMessage;
    SSE_EVENT_TYPES.forEach(type => es.addEventListener(type, handleMessage as EventListener));
    es.onerror = () => {
      setConnected(false);
      es.close();
      if (eventSourceRef.current === es) eventSourceRef.current = null;
      if (stoppedRef.current) return;
      const attempt = reconnectAttemptRef.current++;
      const backoff = Math.min(30_000, 1_000 * (2 ** Math.min(attempt, 5)));
      const jitter = Math.floor(Math.random() * 500);
      reconnectTimeoutRef.current = setTimeout(connect, backoff + jitter);
    };
  }, [channel, enabled, handleMessage]);

  const subscribe = useCallback((fn: (event: SSEEvent) => void) => {
    listenersRef.current.add(fn);
    return () => { listenersRef.current.delete(fn); };
  }, []);

  useEffect(() => {
    if (enabled) connect();
    return () => disconnect();
  }, [connect, disconnect, enabled]);

  return { connected, subscribe, disconnect, reconnect: connect };
}
