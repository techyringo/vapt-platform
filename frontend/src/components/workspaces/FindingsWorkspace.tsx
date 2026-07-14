'use client';

import { FileText, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { FindingCard } from '@/components/features/FindingCard';
import { SkeletonFindingCard } from '@/components/ui/Skeleton';
import { StateView } from '@/components/ui/StateView';
import type { Finding, Scan, SeverityKey } from '@/types';
import { SEVERITIES } from '@/types';

export type SeverityFilter = SeverityKey | 'all';
const FILTERS = ['all', ...SEVERITIES] as const;
const COLORS: Record<string, string> = { critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#22c55e', informational: '#06b6d4' };

function label(value: SeverityFilter) {
  if (value === 'all') return 'All';
  return value === 'informational' ? 'Info' : value.charAt(0).toUpperCase() + value.slice(1);
}

interface Props {
  findings: Finding[];
  filteredFindings: Finding[];
  severityCounts: Record<SeverityKey, number>;
  severityFilter: SeverityFilter;
  onSeverityFilter: (filter: SeverityFilter) => void;
  showQuarantined: boolean;
  onShowQuarantined: (show: boolean) => void;
  quarantinedCount: number;
  expandedFindings: Set<string>;
  onToggleFinding: (key: string) => void;
  loading: boolean;
  apiHealthy: boolean | null;
  selectedScan?: Scan;
  refreshing: boolean;
  onRefresh: () => void;
  onReport: () => void;
}

export function FindingsWorkspace(props: Props) {
  const {
    findings, filteredFindings, severityCounts, severityFilter, onSeverityFilter,
    showQuarantined, onShowQuarantined, quarantinedCount, expandedFindings,
    onToggleFinding, loading, apiHealthy, selectedScan, refreshing, onRefresh, onReport,
  } = props;
  return (
    <section>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={20} style={{ color: 'var(--accent)', flexShrink: 0 }} aria-hidden="true" />
          <div><h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Findings</h2><p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>{filteredFindings.length} of {findings.length} findings</p></div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={onRefresh} disabled={refreshing} className="btn btn-secondary"><RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />Refresh</button>
          {selectedScan && <button onClick={onReport} disabled={selectedScan.status !== 'completed'} title={selectedScan.status === 'completed' ? 'Download final report' : 'Available after all scan phases complete'} className="btn btn-secondary"><FileText size={14} aria-hidden="true" />Report</button>}
        </div>
      </div>

      <div className="sev-filter-bar" style={{ marginBottom: 14 }} role="group" aria-label="Filter by severity">
        {FILTERS.map(filter => (
          <button key={filter} onClick={() => onSeverityFilter(filter)} className={`sev-filter-btn${severityFilter === filter ? ' active' : ''}`} aria-pressed={severityFilter === filter}>
            {filter !== 'all' && <span style={{ width: 6, height: 6, borderRadius: '50%', background: COLORS[filter], display: 'inline-block', flexShrink: 0 }} aria-hidden="true" />}
            {label(filter)}<span className="sev-filter-count">{filter === 'all' ? findings.length : severityCounts[filter]}</span>
          </button>
        ))}
        {quarantinedCount > 0 && (
          <button onClick={() => onShowQuarantined(!showQuarantined)} className={`sev-filter-btn${showQuarantined ? ' active' : ''}`} aria-pressed={showQuarantined} title="Low-evidence findings excluded from reports" style={{ marginLeft: 'auto' }}>
            {showQuarantined ? 'Hiding' : 'Show'} quarantined <span className="sev-filter-count">{quarantinedCount}</span>
          </button>
        )}
      </div>

      {loading ? <div style={{ display: 'grid', gap: 8 }}>{Array.from({ length: 5 }).map((_, index) => <SkeletonFindingCard key={index} />)}</div>
        : findings.length === 0 ? (apiHealthy === false
          ? <StateView variant="error" title="Couldn’t load findings" body="The backend is unreachable. Findings will appear once the connection is restored." onRetry={onRefresh} />
          : <StateView variant="empty" icon={ShieldCheck} title="No findings loaded" body="Select a completed scan, or launch one—findings surface here in real time." />)
        : filteredFindings.length === 0 ? <StateView variant="no-results" title="No matching findings" body={`Nothing matches the "${label(severityFilter)}" filter${showQuarantined ? '' : '—quarantined findings are hidden.'}`} action={<button className="btn btn-secondary" onClick={() => { onSeverityFilter('all'); onShowQuarantined(true); }}>Clear filters</button>} />
        : <div style={{ display: 'grid', gap: 8 }}>{filteredFindings.map((finding, index) => { const key = `${finding.title}|${finding.target_host}|${finding.created_at || index}`; return <FindingCard key={key} finding={finding} expanded={expandedFindings.has(key)} onToggle={() => onToggleFinding(key)} />; })}</div>}
    </section>
  );
}
