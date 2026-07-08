import { Bot, CheckCircle2, XCircle, Zap } from 'lucide-react';
import type { AgentStatus } from '@/types';

function agentBadgeClass(status?: string) {
  if (status === 'running')   return 'badge-running';
  if (status === 'completed') return 'badge-completed';
  if (status === 'failed' || status === 'cancelled') return 'badge-failed';
  if (status === 'skipped')   return 'badge-skipped';
  return 'badge-idle';
}

function statusColor(status: string) {
  if (status === 'running')   return '#eab308';
  if (status === 'completed') return '#22c55e';
  if (status === 'failed')    return '#f43f5e';
  if (status === 'cancelled') return '#f97316';
  if (status === 'skipped')   return '#4b5e74';
  return '#94a3b8';
}

function AgentIcon({ status }: { status: string }) {
  const size = 16;
  if (status === 'running')   return <Zap size={size} aria-hidden="true" />;
  if (status === 'completed') return <CheckCircle2 size={size} aria-hidden="true" />;
  if (status === 'failed' || status === 'cancelled') return <XCircle size={size} aria-hidden="true" />;
  return <Bot size={size} aria-hidden="true" />;
}

interface AgentCardProps {
  name: string;
  status: AgentStatus;
  index: number;
}

export function AgentCard({ name, status, index }: AgentCardProps) {
  const color = statusColor(status.status);

  return (
    <div className="agent-card" style={{ animationDelay: `${index * 60}ms` }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <div style={{
            display: 'grid', placeItems: 'center',
            width: 34, height: 34, borderRadius: 8,
            border: `1px solid ${color}44`,
            background: `${color}11`,
            flexShrink: 0, color,
          }}>
            <AgentIcon status={status.status} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
              {name}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              {status.agent_type || name}
            </div>
          </div>
        </div>
        <span className={`badge ${agentBadgeClass(status.status)}`}>{status.status}</span>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gap: 8, fontSize: 12, marginBottom: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
          <span style={{ color: 'var(--text-muted)' }}>Findings</span>
          <span style={{ fontFamily: 'var(--font-jetbrains), monospace', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}>
            {status.findings_count || 0}
          </span>
        </div>
        {status.current_tool && (
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
            <span style={{ color: 'var(--text-muted)' }}>Active tool</span>
            <span style={{
              fontFamily: 'var(--font-jetbrains), monospace', fontSize: 11,
              color: 'var(--accent)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 120,
            }}>
              {status.current_tool}
            </span>
          </div>
        )}
      </div>

      {/* Progress */}
      <div className="progress-bar" style={{ marginBottom: status.tools_run?.length ? 10 : 0 }}>
        <div
          className="progress-fill"
          style={{
            width: `${status.progress_pct || (status.status === 'completed' ? 100 : 0)}%`,
            background: color,
          }}
        />
      </div>

      {/* Tools run tags */}
      {status.tools_run?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
          {status.tools_run.slice(0, 6).map(tool => (
            <span key={tool} style={{
              fontFamily: 'var(--font-jetbrains), monospace', fontSize: 9,
              padding: '2px 6px', borderRadius: 4,
              border: '1px solid var(--border)',
              background: 'var(--bg-elevated)',
              color: 'var(--text-muted)',
            }}>
              {tool}
            </span>
          ))}
          {status.tools_run.length > 6 && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)', alignSelf: 'center' }}>
              +{status.tools_run.length - 6}
            </span>
          )}
        </div>
      )}

      {/* Error */}
      {status.error && (
        <div style={{
          marginTop: 10, padding: '8px 10px', borderRadius: 7,
          border: '1px solid rgba(244,63,94,0.25)',
          background: 'rgba(244,63,94,0.07)',
          fontSize: 11, color: 'var(--critical)', lineHeight: 1.5,
        }}
          role="alert"
        >
          {status.error}
        </div>
      )}
    </div>
  );
}
