'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Circle,
  Pause,
  Play,
  Search,
  TerminalSquare,
  Trash2,
  XCircle,
} from 'lucide-react';
import type { Scan } from '@/types';

export interface LogMessage {
  msg: string;
  level: string;
  time: string;
  source?: string;
  phase?: string;
  stream?: string;
  eventType?: string;
}

type FeedFilter = 'all' | 'tools' | 'issues';

function statusBadgeClass(status?: string) {
  if (status === 'running') return 'badge-running';
  if (status === 'completed') return 'badge-completed';
  if (status === 'failed' || status === 'cancelled') return 'badge-failed';
  return 'badge-idle';
}

function formatPhase(phase?: string) {
  return (phase || 'standby').replace(/_/g, ' ');
}

function normalizedLevel(level: string) {
  if (level === 'error' || level === 'critical' || level === 'high') return 'error';
  if (level === 'warn' || level === 'medium') return 'warn';
  if (level === 'success' || level === 'low') return 'success';
  return 'info';
}

interface LiveFeedProps {
  logs: LogMessage[];
  selectedScan?: Scan;
  connected: boolean;
  onClear?: () => void;
}

export function LiveFeed({ logs, selectedScan, connected, onClear }: LiveFeedProps) {
  const [filter, setFilter] = useState<FeedFilter>('all');
  const [query, setQuery] = useState('');
  const [paused, setPaused] = useState(false);
  const [pausedLogs, setPausedLogs] = useState<LogMessage[]>([]);
  const [open, setOpen] = useState(false);
  const [autoFollow, setAutoFollow] = useState(true);
  const logRef = useRef<HTMLDivElement>(null);

  const displayedLogs = paused ? pausedLogs : logs;
  const visibleLogs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return displayedLogs.filter(log => {
      const level = normalizedLevel(log.level);
      if (filter === 'tools' && log.eventType !== 'tool_log') return false;
      if (filter === 'issues' && level !== 'error' && level !== 'warn') return false;
      if (!needle) return true;
      return `${log.source || ''} ${log.phase || ''} ${log.msg}`.toLowerCase().includes(needle);
    });
  }, [displayedLogs, filter, query]);

  const issueCount = displayedLogs.filter(log => ['error', 'warn'].includes(normalizedLevel(log.level))).length;

  useEffect(() => {
    const node = logRef.current;
    if (open && autoFollow && !paused && node) node.scrollTop = node.scrollHeight;
  }, [autoFollow, open, paused, visibleLogs]);

  const togglePause = () => {
    if (!paused) setPausedLogs(logs);
    setPaused(value => !value);
  };

  return (
    <section className={`telemetry-drawer${open ? ' open' : ''}`} aria-label="Live assessment telemetry">
      <div className="telemetry-rail">
        <button type="button" className="telemetry-toggle" onClick={() => setOpen(value => !value)} aria-expanded={open}>
          <TerminalSquare size={15} aria-hidden="true" />
          <strong>Live Telemetry</strong>
          <span>[{logs.length}]</span>
          {open ? <ChevronDown size={14} aria-hidden="true" /> : <ChevronUp size={14} aria-hidden="true" />}
        </button>
        <div className={`telemetry-stream-state${connected ? ' connected' : ''}`} role="status">
          <Circle size={8} fill="currentColor" aria-hidden="true" />
          {connected ? 'STREAM' : 'RECONNECTING'}
        </div>
        {selectedScan && (
          <span className={`badge ${statusBadgeClass(selectedScan.status)}`}>
            {formatPhase(selectedScan.current_phase)}
          </span>
        )}
        {issueCount > 0 && <span className="telemetry-issue-count">{issueCount} need attention</span>}
        <div className="telemetry-rail-actions">
          <button type="button" onClick={() => setAutoFollow(value => !value)} className={autoFollow ? 'active' : ''}>
            {autoFollow ? 'AUTO' : 'HOLD'}
          </button>
          <button type="button" onClick={togglePause}>
            {paused ? <Play size={12} aria-hidden="true" /> : <Pause size={12} aria-hidden="true" />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button type="button" onClick={onClear} disabled={!onClear || logs.length === 0} title="Clear this browser view; persisted audit events are retained">
            <Trash2 size={12} aria-hidden="true" />Clear view
          </button>
        </div>
      </div>

      {open && (
        <div className="telemetry-body">
          <div className="telemetry-toolbar" aria-label="Telemetry filters">
            <div className="live-feed-filters">
              {(['all', 'tools', 'issues'] as FeedFilter[]).map(option => (
                <button type="button" key={option} className={filter === option ? 'active' : ''} onClick={() => setFilter(option)}>
                  {option}
                </button>
              ))}
            </div>
            <label className="live-feed-search">
              <Search size={12} aria-hidden="true" />
              <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter source, phase or output" />
            </label>
            <span className="telemetry-retention-note">View clear does not delete audit evidence</span>
          </div>

          <div
            ref={logRef}
            className="terminal-feed telemetry-feed"
            role="log"
            aria-label="Live assessment event log"
            aria-live={paused ? 'off' : 'polite'}
            aria-atomic="false"
            onWheel={event => { if (event.deltaY < 0) setAutoFollow(false); }}
          >
            {visibleLogs.length === 0 && (
              <div className="live-feed-empty">
                {selectedScan
                  ? `${connected ? 'Stream connected' : 'Stream reconnecting'} · no event matches this view for ${selectedScan.scan_id.slice(0, 14)}.`
                  : 'No assessment selected. Telemetry will replay after an operation is selected.'}
              </div>
            )}
            {visibleLogs.map((log, index) => {
              const level = normalizedLevel(log.level);
              const source = log.source || (log.eventType === 'tool_log' ? 'tool' : 'platform');
              return (
                <div key={`${log.time}-${index}-${log.msg.slice(0, 24)}`} className={`log-line ${level}`}>
                  <span className="log-time">{log.time}</span>
                  <span className="log-icon" aria-hidden="true">
                    {level === 'error' ? <XCircle size={12} /> :
                     level === 'warn' ? <AlertTriangle size={12} /> :
                     level === 'success' ? <CheckCircle2 size={12} /> :
                     <Activity size={12} />}
                  </span>
                  <span className={`log-source ${log.eventType === 'tool_log' ? 'tool' : ''}`}>{source}</span>
                  <span className="log-phase">{formatPhase(log.phase)}</span>
                  <span className="log-message">{log.msg}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
