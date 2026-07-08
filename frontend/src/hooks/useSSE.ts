import { useEffect, useRef, useCallback, useState } from 'react';
import { SSEEvent } from '@/types';

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');
const SSE_EVENT_TYPES = ['scan_started', 'phase_change', 'finding', 'agent_status', 'log', 'tool_log', 'scan_complete', 'scan_failed', 'ping'] as const;

export function useSSE(onEvent?: (event: SSEEvent) => void) {
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const listenersRef = useRef<Set<(event: SSEEvent) => void>>(new Set());
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleMessage = useCallback((raw: MessageEvent) => {
    try {
      const data = JSON.parse(raw.data);
      const eventType = data.type || data.event || raw.type;
      const event: SSEEvent = { type: eventType, scan_id: data.scan_id, timestamp: data.timestamp, ...data };
      listenersRef.current.forEach(fn => fn(event));
      onEvent?.(event);
    } catch {}
  }, [onEvent]);

  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = new EventSource(`${API_BASE}/api/stream`);
    es.onopen = () => setConnected(true);
    es.onmessage = handleMessage;
    SSE_EVENT_TYPES.forEach(type => {
      es.addEventListener(type, handleMessage as EventListener);
    });
    es.onerror = () => {
      setConnected(false);
      es.close();
      eventSourceRef.current = null;
      // Reconnect after 3s
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
    };

    eventSourceRef.current = es;
  }, [handleMessage]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setConnected(false);
  }, []);

  const subscribe = useCallback((fn: (event: SSEEvent) => void) => {
    listenersRef.current.add(fn);
    return () => { listenersRef.current.delete(fn); };
  }, []);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return { connected, subscribe, disconnect, reconnect: connect };
}
