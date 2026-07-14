'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSSE } from '@/hooks/useSSE';
import type { Scan, SSEEvent } from '@/types';
import { LiveFeed, type LogMessage } from '@/components/features/LiveFeed';

const MAX_VISIBLE_EVENTS = 240;
const FLUSH_INTERVAL_MS = 150;

function formatPhase(phase?: string) {
  return (phase || 'standby').replace(/_/g, ' ');
}

function toLogMessage(event: SSEEvent): LogMessage | null {
  if (event.type === 'ping') return null;
  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  if (event.type === 'finding') {
    return { msg: `${event.title || 'new issue'} on ${event.target_host || event.scan_id || 'target'}`, level: event.severity || 'info', time, source: 'finding', eventType: event.type };
  }
  if (event.type === 'agent_status') {
    const source = event.agent_type || event.data?.agent_type || 'agent';
    const status = event.status || event.data?.status || 'updated';
    const count = event.findings_count || event.data?.findings_count;
    return { msg: `${status}${count ? ` (${count} findings)` : ''}`, level: status === 'failed' ? 'error' : status === 'completed' ? 'success' : 'info', time, source, eventType: event.type };
  }
  if (event.type === 'log') {
    return { msg: event.message || event.data?.message || '', level: event.level || event.data?.level || 'info', time, source: event.agent || event.data?.agent || 'platform', phase: event.phase || event.data?.phase, eventType: event.type };
  }
  if (event.type === 'tool_log') {
    const line = event.line || event.data?.line || '';
    if (!line) return null;
    return {
      msg: line,
      level: event.level || event.data?.level || 'info',
      time,
      source: event.tool || event.data?.tool || 'tool',
      phase: event.phase || event.data?.phase,
      stream: event.stream || event.data?.stream || 'stdout',
      eventType: event.type,
    };
  }
  if (event.type === 'phase_change') {
    const phase = event.phase || event.data?.phase;
    return phase ? { msg: `Started ${formatPhase(phase)}`, level: 'info', time, source: 'orchestrator', phase, eventType: event.type } : null;
  }
  if (event.type === 'phase_complete' || event.type === 'surface_update') {
    const health = event.target_health?.status;
    return { msg: event.message || `${formatPhase(event.phase)} evidence persisted`, level: health === 'unreachable' ? 'warn' : 'success', time, source: 'platform', eventType: event.type };
  }
  if (event.type === 'scan_started') return { msg: 'Assessment started', level: 'success', time, source: 'platform', eventType: event.type };
  if (event.type === 'scan_complete') return { msg: 'Assessment completed', level: 'success', time, source: 'platform', eventType: event.type };
  if (event.type === 'scan_failed') return { msg: `Assessment failed: ${event.error || 'unknown error'}`, level: 'error', time, source: 'platform', eventType: event.type };
  if (event.type === 'scan_deleted') return { msg: 'Assessment deleted', level: 'warn', time, source: 'platform', eventType: event.type };
  return null;
}

interface LiveTelemetryProps {
  selectedScan?: Scan;
  apiHealthy: boolean | null;
}

/**
 * Isolated telemetry render island. Scanner output can only rerender this
 * component, never the command center or active workspace.
 */
export function LiveTelemetry({ selectedScan, apiHealthy }: LiveTelemetryProps) {
  const [logs, setLogs] = useState<LogMessage[]>([]);
  const pendingRef = useRef<LogMessage[]>([]);
  const selectedScanIdRef = useRef(selectedScan?.scan_id);
  selectedScanIdRef.current = selectedScan?.scan_id;

  const onEvent = useCallback((event: SSEEvent) => {
    const selectedId = selectedScanIdRef.current;
    if (selectedId && event.scan_id && event.scan_id !== selectedId) return;
    const log = toLogMessage(event);
    if (log?.msg) pendingRef.current.push(log);
  }, []);

  const { connected } = useSSE(onEvent, { channel: 'all' });

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (pendingRef.current.length === 0) return;
      const batch = pendingRef.current.splice(0, pendingRef.current.length);
      setLogs(previous => [...previous, ...batch].slice(-MAX_VISIBLE_EVENTS));
    }, FLUSH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    pendingRef.current = [];
    setLogs([]);
  }, [selectedScan?.scan_id]);

  const visibleLogs = useMemo(() => logs.length ? logs : [
    { msg: connected ? 'Operational stream connected' : 'Operational stream reconnecting', level: connected ? 'success' : 'warn', time: '—', source: 'platform' },
    { msg: apiHealthy ? 'Backend API healthy' : apiHealthy === false ? 'Backend API unavailable' : 'Checking backend API', level: apiHealthy ? 'success' : apiHealthy === false ? 'error' : 'info', time: '—', source: 'platform' },
    { msg: 'Full scanner stdout is retained in tool-run artifacts, not rendered in this console', level: 'info', time: '—', source: 'retention' },
  ], [apiHealthy, connected, logs]);

  return (
    <LiveFeed
      logs={visibleLogs}
      selectedScan={selectedScan}
      connected={connected}
      onClear={() => { pendingRef.current = []; setLogs([]); }}
    />
  );
}
