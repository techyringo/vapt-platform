'use client';

import { Boxes, Download, RefreshCw, Server, Trash2, Wrench } from 'lucide-react';
import { MetricCard } from '@/components/ui/MetricCard';
import { StateView } from '@/components/ui/StateView';
import { api } from '@/lib/api';
import type { RuntimeLogFile } from '@/types';

export interface CapabilityItem { name: string; displayName: string; state: 'ready' | 'on_demand' | 'blocked'; reason: string; }
export interface CapabilityGroup { label: string; total: number; ready: number; onDemand: number; blocked: number; items: CapabilityItem[]; }
interface Props {
  dockerReady: boolean;
  dockerInfo: { socket_available?: boolean } | null;
  totals: { ready: number; onDemand: number; blocked: number };
  runtimeLogs: RuntimeLogFile[];
  coverage: Array<[string, CapabilityGroup]>;
  apiHealthy: boolean | null;
  onRefreshLogs: () => void;
  onDeleteLog: (file: RuntimeLogFile) => void;
  onRetry: () => void;
}

function age(value?: string) {
  if (!value) return 'not started';
  const explicitZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  const ms = Date.now() - Date.parse(explicitZone ? value : `${value}Z`);
  if (!Number.isFinite(ms) || ms < 60_000) return 'just now';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `${hours}h ago` : `${Math.floor(hours / 24)}d ago`;
}

export function OperationsWorkspace({ dockerReady, dockerInfo, totals, runtimeLogs, coverage, apiHealthy, onRefreshLogs, onDeleteLog, onRetry }: Props) {
  return <section>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}><Wrench size={20} style={{ color: 'var(--accent)' }} aria-hidden="true" /><div><h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Operations</h2><p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>Administrative health for approved local, container and API runners</p></div></div>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 12, marginBottom: 16 }}>
      <MetricCard icon={Boxes} label="Docker Ready" value={dockerReady ? 'Ready' : 'Check'} sub={dockerInfo?.socket_available ? 'socket mounted' : 'socket missing'} tone={dockerReady ? 'emerald' : 'amber'} />
      <MetricCard icon={Server} label="Ready Runtimes" value={totals.ready} sub="loaded capability adapters" tone="cyan" />
      <MetricCard icon={Download} label="On demand / unavailable" value={`${totals.onDemand} / ${totals.blocked}`} sub="policy-approved pull · configuration required" tone="amber" />
    </div>
    <details className="card-glass operator-diagnostics" style={{ marginBottom: 16 }}>
      <summary><div><h3>Operator diagnostics</h3><p>Runtime logs are restricted operational evidence, not part of the customer assessment view.</p></div><span className="badge badge-idle">{runtimeLogs.length} log file{runtimeLogs.length === 1 ? '' : 's'}</span></summary>
      <div className="operator-diagnostics-body">
        <div className="operator-diagnostics-actions"><span>Use these artifacts only for runner troubleshooting.</span><button onClick={onRefreshLogs} className="btn btn-secondary"><RefreshCw size={14} aria-hidden="true" />Refresh</button></div>
        {runtimeLogs.length === 0 ? <div className="quiet-empty">Runtime log file appears after the rebuilt containers start.</div> : <div style={{ display: 'grid', gap: 8 }}>{runtimeLogs.slice(0, 6).map(file => <div key={file.name} className="tool-row"><div style={{ minWidth: 0 }}><div style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12, color: 'var(--text-primary)' }}>{file.name}</div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{(file.size / 1024).toFixed(1)} KB · {age(file.modified_at)}</div></div><div className="tool-run-actions"><a className="tool-run-link" href={api.downloadLog(file.name)} target="_blank" rel="noreferrer"><Download size={12} aria-hidden="true" />download</a><button type="button" className="tool-run-link runtime-log-delete" onClick={() => onDeleteLog(file)}><Trash2 size={12} aria-hidden="true" />{file.name === 'vapt-runtime.log' ? 'clear' : 'delete'}</button></div></div>)}</div>}
      </div>
    </details>
    {coverage.length === 0 ? (apiHealthy === false ? <StateView variant="offline" title="Backend unreachable" body="Tool status will appear once the connection to the backend is restored." onRetry={onRetry} /> : <StateView variant="empty" icon={Wrench} title="No tool data" body="No tools have reported status yet." />)
      : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 8 }}>{coverage.map(([phase, group]) => { const actionable = group.items.filter(item => item.state !== 'ready'); return <details key={phase} className="capability-group"><summary><div style={{ minWidth: 0 }}><div className="capability-group-title">{group.label}</div><div className="capability-group-meta">{group.ready} ready · {group.onDemand} on demand · {group.blocked} unavailable</div></div><span className={`badge ${group.blocked === 0 ? 'badge-completed' : 'badge-running'}`}>{group.blocked === 0 ? 'policy-ready' : `${group.blocked} unavailable`}</span></summary><div className="capability-group-body">{actionable.length === 0 ? <div className="capability-action-row">All registered adapters in this lane are ready.</div> : actionable.map(item => <div key={item.name} className="capability-action-row"><div><strong>{item.displayName}</strong><span>{item.reason}</span></div><span className={`badge ${item.state === 'on_demand' ? 'badge-idle' : 'badge-running'}`}>{item.state === 'on_demand' ? 'available on demand' : 'configuration required'}</span></div>)}</div></details>; })}</div>}
  </section>;
}
