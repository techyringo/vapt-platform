import type React from 'react';
import { Activity, AlertTriangle, CheckCircle2, TerminalSquare, XCircle } from 'lucide-react';
import type { Scan } from '@/types';

export interface LogMessage {
  msg: string;
  level: string;
  time: string;
}

function statusBadgeClass(status?: string) {
  if (status === 'running')   return 'badge-running';
  if (status === 'completed') return 'badge-completed';
  if (status === 'failed' || status === 'cancelled') return 'badge-failed';
  return 'badge-idle';
}

function formatPhase(phase?: string) {
  return (phase || 'standby').replace(/_/g, ' ');
}

interface LiveFeedProps {
  logs: LogMessage[];
  logRef: React.RefObject<HTMLDivElement | null>;
  selectedScan?: Scan;
}

export function LiveFeed({ logs, logRef, selectedScan }: LiveFeedProps) {
  return (
    <div className="card-glass" style={{ padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <TerminalSquare size={15} style={{ color: 'var(--accent)', flexShrink: 0 }} aria-hidden="true" />
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Live Feed</span>
        </div>
        {selectedScan && (
          <span className={`badge ${statusBadgeClass(selectedScan.status)}`} aria-live="polite">
            {formatPhase(selectedScan.current_phase)}
          </span>
        )}
      </div>

      <div
        ref={logRef}
        className="terminal-feed"
        role="log"
        aria-label="Live event log"
        aria-live="polite"
        aria-atomic="false"
      >
        {logs.map((log, i) => {
          const level = log.level === 'error'   ? 'error' :
                        log.level === 'warn'    ? 'warn' :
                        log.level === 'success' || log.level === 'low' ? 'success' : 'info';

          return (
            <div key={`${log.time}-${i}`} className={`log-line ${level}`}>
              <span style={{ color: 'var(--text-muted)', userSelect: 'none', fontVariantNumeric: 'tabular-nums' }}>
                {log.time}
              </span>
              <span style={{ marginTop: 2 }} aria-hidden="true">
                {level === 'error'   ? <XCircle      size={11} style={{ color: 'var(--critical)' }} /> :
                 level === 'warn'    ? <AlertTriangle size={11} style={{ color: 'var(--medium)' }} /> :
                 level === 'success' ? <CheckCircle2  size={11} style={{ color: 'var(--low)' }} /> :
                                       <Activity      size={11} style={{ color: 'var(--accent)' }} />}
              </span>
              <span style={{ color: 'var(--text-secondary)', wordBreak: 'break-word' }}>{log.msg}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
