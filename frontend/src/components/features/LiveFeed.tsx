import { useMemo, useState } from 'react';
import type React from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Pause,
  Play,
  Search,
  TerminalSquare,
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
  logRef: React.RefObject<HTMLDivElement | null>;
  selectedScan?: Scan;
}

export function LiveFeed({ logs, logRef, selectedScan }: LiveFeedProps) {
  const [filter, setFilter] = useState<FeedFilter>('all');
  const [query, setQuery] = useState('');
  const [paused, setPaused] = useState(false);
  const [pausedLogs, setPausedLogs] = useState<LogMessage[]>([]);

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
  const togglePause = () => {
    if (!paused) setPausedLogs(logs);
    setPaused(value => !value);
  };

  return (
    <div className="card-glass live-feed-card">
      <div className="live-feed-header">
        <div className="live-feed-title">
          <TerminalSquare size={15} aria-hidden="true" />
          <div>
            <strong>Mission Control</strong>
            <span>{displayedLogs.length} events · {issueCount} need attention</span>
          </div>
        </div>
        <div className="live-feed-status">
          {paused && <span className="badge badge-idle">paused</span>}
          {selectedScan && (
            <span className={`badge ${statusBadgeClass(selectedScan.status)}`} aria-live="polite">
              {formatPhase(selectedScan.current_phase)}
            </span>
          )}
        </div>
      </div>

      <div className="live-feed-toolbar" aria-label="Live feed controls">
        <div className="live-feed-filters">
          {(['all', 'tools', 'issues'] as FeedFilter[]).map(option => (
            <button
              type="button"
              key={option}
              className={filter === option ? 'active' : ''}
              onClick={() => setFilter(option)}
            >
              {option}
            </button>
          ))}
        </div>
        <label className="live-feed-search">
          <Search size={12} aria-hidden="true" />
          <input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter source or output" />
        </label>
        <button type="button" className="live-feed-pause" onClick={togglePause}>
          {paused ? <Play size={12} aria-hidden="true" /> : <Pause size={12} aria-hidden="true" />}
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      <div
        ref={logRef}
        className="terminal-feed"
        role="log"
        aria-label="Live assessment event log"
        aria-live={paused ? 'off' : 'polite'}
        aria-atomic="false"
      >
        {visibleLogs.length === 0 && <div className="live-feed-empty">No events match this view.</div>}
        {visibleLogs.map((log, i) => {
          const level = normalizedLevel(log.level);
          const source = log.source || (log.eventType === 'tool_log' ? 'tool' : 'platform');
          return (
            <div key={`${log.time}-${i}`} className={`log-line ${level}`}>
              <span className="log-time">{log.time}</span>
              <span className="log-icon" aria-hidden="true">
                {level === 'error' ? <XCircle size={12} /> :
                 level === 'warn' ? <AlertTriangle size={12} /> :
                 level === 'success' ? <CheckCircle2 size={12} /> :
                 <Activity size={12} />}
              </span>
              <span className={`log-source ${log.eventType === 'tool_log' ? 'tool' : ''}`}>{source}</span>
              <span className="log-message">{log.msg}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
