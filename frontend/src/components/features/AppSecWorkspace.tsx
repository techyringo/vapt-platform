'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, ArrowRight, CheckCircle2, Code2, ExternalLink,
  FileCode2, GitBranch, KeyRound, PackageSearch, Play, RefreshCw,
  SearchCode, ShieldCheck, XCircle,
} from 'lucide-react';

import { api } from '@/lib/api';
import type { AppSecAssessment, AppSecFinding } from '@/types';

const severityRank: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
};

const laneMeta = {
  sast: { label: 'Source analysis', icon: SearchCode, description: 'Unsafe code patterns and data-flow candidates' },
  sca: { label: 'Dependencies & IaC', icon: PackageSearch, description: 'Known CVEs and configuration weaknesses' },
  secrets: { label: 'Secret exposure', icon: KeyRound, description: 'Credential patterns with values always redacted' },
} as const;

function statusTone(status: string) {
  if (status === 'completed') return 'complete';
  if (status === 'running') return 'running';
  if (status === 'failed' || status === 'unavailable') return 'failed';
  if (status === 'partial') return 'partial';
  return 'planned';
}

function shortRepository(value: string) {
  return value.replace(/^https:\/\//, '').replace(/\.git$/, '');
}

export function AppSecWorkspace() {
  const [assessments, setAssessments] = useState<AppSecAssessment[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AppSecAssessment | null>(null);
  const [repository, setRepository] = useState('https://github.com/techyringo/vapt-platform');
  const [ref, setRef] = useState('main');
  const [name, setName] = useState('');
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  const refresh = useCallback(async () => {
    try {
      const response = await api.listAppSecAssessments();
      setAssessments(response.assessments);
      setSelectedId(current => current || response.assessments[0]?.assessment_id || null);
      setError('');
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'Unable to load assessments');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    let active = true;
    const load = async () => {
      try {
        const response = await api.getAppSecAssessment(selectedId);
        if (active) setDetail(response);
      } catch (exc) {
        if (active) setError(exc instanceof Error ? exc.message : 'Unable to load assessment');
      }
    };
    void load();
    const interval = window.setInterval(() => void load().then(refresh), 3000);
    return () => { active = false; window.clearInterval(interval); };
  }, [refresh, selectedId]);

  const start = async () => {
    if (!repository.trim()) return;
    setStarting(true);
    setError('');
    try {
      const response = await api.startAppSecAssessment(repository.trim(), ref.trim() || 'main', name.trim());
      setSelectedId(response.assessment_id);
      setName('');
      await refresh();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : 'Unable to start assessment');
    } finally {
      setStarting(false);
    }
  };

  const findings = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return [...(detail?.findings || [])]
      .filter(item => !needle || [item.title, item.rule_id, item.path, item.package, ...item.cve_ids]
        .join(' ').toLowerCase().includes(needle))
      .sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
  }, [detail?.findings, query]);

  const severity = detail?.summary?.severities || {};
  const cveCount = (detail?.findings || []).reduce((sum, item) => sum + item.cve_ids.length, 0);
  const running = detail && ['queued', 'running'].includes(detail.status);

  return (
    <div className="appsec-shell">
      <section className="appsec-hero">
        <div>
          <div className="appsec-eyebrow"><ShieldCheck size={13} /> Unified application security</div>
          <h2>Trace risk from source to runtime</h2>
          <p>Run evidence-producing code, dependency, IaC and secret analysis. Runtime DAST remains in Assessments; the next correlation layer will link both surfaces by application and evidence.</p>
        </div>
        <div className="appsec-principle">
          <span>Evidence policy</span>
          <strong>Candidate until verified</strong>
          <small>Unavailable scanners remain visible as coverage gaps.</small>
        </div>
      </section>

      {error && (
        <div className="appsec-alert" role="alert">
          <AlertTriangle size={15} />
          <span>{error}</span>
          <button onClick={() => setError('')} aria-label="Dismiss error"><XCircle size={15} /></button>
        </div>
      )}

      <section className="appsec-launch card-glass">
        <div className="appsec-section-heading">
          <div>
            <span className="section-label">New code assessment</span>
            <h3>Connect an approved repository</h3>
          </div>
          <span className="appsec-scope-pill">Public GitHub / GitLab · read-only</span>
        </div>
        <div className="appsec-launch-grid">
          <label className="appsec-field-wide">
            <span>Repository URL</span>
            <div className="appsec-input-wrap"><Code2 size={15} /><input className="field" value={repository} onChange={event => setRepository(event.target.value)} placeholder="https://github.com/org/repository" /></div>
          </label>
          <label>
            <span>Branch or tag</span>
            <div className="appsec-input-wrap"><GitBranch size={15} /><input className="field" value={ref} onChange={event => setRef(event.target.value)} /></div>
          </label>
          <label>
            <span>Assessment name</span>
            <input className="field" value={name} onChange={event => setName(event.target.value)} placeholder="Optional" />
          </label>
          <button className="btn btn-primary appsec-launch-button" onClick={start} disabled={starting || !repository.trim()}>
            {starting ? <RefreshCw size={15} className="animate-spin" /> : <Play size={15} />}
            {starting ? 'Queueing…' : 'Start assessment'}
          </button>
        </div>
      </section>

      <div className="appsec-workspace-grid">
        <aside className="appsec-runs card-glass">
          <div className="appsec-section-heading compact">
            <div><span className="section-label">Engagements</span><h3>Code assessments</h3></div>
            <button className="btn btn-icon" onClick={() => void refresh()} title="Refresh assessments"><RefreshCw size={14} /></button>
          </div>
          <div className="appsec-run-list">
            {loading && <div className="appsec-empty">Loading assessments…</div>}
            {!loading && assessments.length === 0 && <div className="appsec-empty">No repository assessment yet.</div>}
            {assessments.map(item => (
              <button key={item.assessment_id} className={`appsec-run ${selectedId === item.assessment_id ? 'active' : ''}`} onClick={() => setSelectedId(item.assessment_id)}>
                <div className="appsec-run-top"><strong>{item.name}</strong><span className={`appsec-status ${statusTone(item.status)}`}>{item.status}</span></div>
                <span>{shortRepository(item.repository)}</span>
                <div className="appsec-run-progress"><i style={{ width: `${item.progress}%` }} /></div>
                <small>{item.phase.replace(/_/g, ' ')} · {item.progress}%</small>
              </button>
            ))}
          </div>
        </aside>

        <section className="appsec-detail card-glass">
          {!detail ? (
            <div className="appsec-empty appsec-empty-large"><FileCode2 size={30} /><strong>Select or start an assessment</strong><span>The evidence workspace will appear here.</span></div>
          ) : (
            <>
              <header className="appsec-detail-header">
                <div>
                  <div className="appsec-detail-meta"><span className={`appsec-status ${statusTone(detail.status)}`}>{detail.status}</span><code>{detail.commit_sha ? detail.commit_sha.slice(0, 12) : detail.ref}</code></div>
                  <h3>{detail.name}</h3>
                  <a href={detail.repository} target="_blank" rel="noreferrer">{shortRepository(detail.repository)} <ExternalLink size={12} /></a>
                </div>
                {running && <div className="appsec-active"><RefreshCw size={14} className="animate-spin" /><span>{detail.phase.replace(/_/g, ' ')}</span><strong>{detail.progress}%</strong></div>}
              </header>

              <div className="appsec-metrics">
                <Metric label="Total candidates" value={detail.summary?.total || 0} />
                <Metric label="Critical / high" value={(severity.critical || 0) + (severity.high || 0)} tone="danger" />
                <Metric label="Known CVEs" value={cveCount} tone="amber" />
                <Metric label="Coverage lanes" value={`${Object.values(detail.coverage || {}).filter(item => item.status === 'completed').length}/3`} tone="cyan" />
              </div>

              <div className="appsec-lanes">
                {Object.entries(laneMeta).map(([key, meta]) => {
                  const state = detail.coverage?.[key] || { status: 'planned', tool: key };
                  const Icon = meta.icon;
                  return (
                    <article className={`appsec-lane ${statusTone(state.status)}`} key={key}>
                      <div className="appsec-lane-icon"><Icon size={17} /></div>
                      <div><strong>{meta.label}</strong><span>{meta.description}</span><small>{state.tool} · {state.findings || 0} candidates</small></div>
                      <LaneStatus status={state.status} />
                    </article>
                  );
                })}
              </div>

              <div className="appsec-findings-header">
                <div><span className="section-label">Evidence ledger</span><h3>Normalized findings</h3></div>
                <div className="appsec-search"><SearchCode size={14} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter CVE, rule, file or package" /></div>
              </div>
              <div className="appsec-finding-list">
                {findings.length === 0 && <div className="appsec-empty">{running ? 'Findings will appear after scanner evidence is normalized.' : 'No findings match this view.'}</div>}
                {findings.map(item => <FindingRow finding={item} key={item.fingerprint} />)}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value, tone = '' }: { label: string; value: string | number; tone?: string }) {
  return <div className={`appsec-metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>;
}

function LaneStatus({ status }: { status: string }) {
  if (status === 'completed') return <CheckCircle2 size={17} />;
  if (status === 'running') return <RefreshCw size={17} className="animate-spin" />;
  if (status === 'failed' || status === 'unavailable') return <AlertTriangle size={17} />;
  return <ArrowRight size={17} />;
}

function FindingRow({ finding }: { finding: AppSecFinding }) {
  return (
    <details className="appsec-finding">
      <summary>
        <span className={`appsec-severity ${finding.severity}`}>{finding.severity === 'informational' ? 'info' : finding.severity}</span>
        <div><strong>{finding.title}</strong><span>{finding.path || finding.package || finding.rule_id}{finding.start_line ? `:${finding.start_line}` : ''}</span></div>
        <div className="appsec-finding-tags"><span>{finding.category}</span>{finding.cve_ids.slice(0, 2).map(cve => <code key={cve}>{cve}</code>)}</div>
      </summary>
      <div className="appsec-finding-body">
        <p>{finding.description}</p>
        <dl>
          <div><dt>Rule</dt><dd>{finding.rule_id}</dd></div>
          <div><dt>Evidence</dt><dd>{finding.evidence}</dd></div>
          <div><dt>Remediation</dt><dd>{finding.remediation}</dd></div>
          {finding.package && <div><dt>Dependency</dt><dd>{finding.package} {finding.installed_version}{finding.fixed_version ? ` → ${finding.fixed_version}` : ''}</dd></div>}
        </dl>
      </div>
    </details>
  );
}
