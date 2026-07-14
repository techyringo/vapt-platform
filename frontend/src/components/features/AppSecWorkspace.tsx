'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, ArrowRight, CheckCircle2, Code2, Download, ExternalLink,
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

  const cveCount = (detail?.findings || []).reduce((sum, item) => sum + item.cve_ids.length, 0);
  const verifiedCount = (detail?.findings || []).filter(item => item.status === 'verified').length;
  const candidateCount = (detail?.findings || []).filter(item => item.status === 'candidate').length;
  const running = detail && ['queued', 'running'].includes(detail.status);

  return (
    <div className="appsec-shell">
      <section className="appsec-hero">
        <div>
          <div className="appsec-eyebrow"><ShieldCheck size={13} /> Unified application security</div>
          <h2>Trace risk from source to runtime</h2>
          <p>Assess source code, dependencies, infrastructure configuration and secret exposure with reproducible scanner evidence. Candidate observations stay separate from verified customer findings.</p>
        </div>
        <div className="appsec-principle">
          <span>Evidence policy</span>
          <strong>Candidate until verified</strong>
          <small>Only completed evidence-producing checks contribute to assessment coverage.</small>
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
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {running && <div className="appsec-active"><RefreshCw size={14} className="animate-spin" /><span>{detail.phase.replace(/_/g, ' ')}</span><strong>{detail.progress}%</strong></div>}
                  {!running && (
                    <a className="btn btn-secondary" href={api.downloadAppSecSarif(detail.assessment_id)}>
                      <Download size={14} />SARIF
                    </a>
                  )}
                  {!running && detail.artifacts?.some(item => item.kind === 'sbom') && (
                    <a className="btn btn-secondary" href={api.downloadAppSecArtifact(detail.assessment_id, 'sbom')}>
                      <Download size={14} />SBOM
                    </a>
                  )}
                </div>
              </header>

              <div className="appsec-metrics">
                <Metric label="Security observations" value={detail.summary?.total || 0} />
                <Metric label="Needs triage" value={candidateCount} tone="danger" />
                <Metric label="CVE observations" value={cveCount} tone="amber" />
                <Metric label="Coverage lanes" value={`${Object.values(detail.coverage || {}).filter(item => item.status === 'completed').length}/3`} tone="cyan" />
              </div>

              {detail.summary?.diff && (
                <div className="appsec-diff" aria-label="Baseline comparison">
                  <div>
                    <span className="section-label">Scan diff</span>
                    <strong>{detail.summary.diff.has_baseline ? 'Compared with previous assessment' : 'First baseline captured'}</strong>
                    {detail.summary.baseline_assessment_id && <small>{detail.summary.baseline_assessment_id}</small>}
                  </div>
                  <div><span>New</span><strong className="new">{detail.summary.diff.new}</strong></div>
                  <div><span>Unchanged</span><strong>{detail.summary.diff.unchanged}</strong></div>
                  <div><span>Resolved</span><strong className="resolved">{detail.summary.diff.resolved}</strong></div>
                </div>
              )}

              <div className="appsec-lanes">
                {Object.entries(laneMeta).map(([key, meta]) => {
                  const state = detail.coverage?.[key] || { status: 'planned', tool: key };
                  const Icon = meta.icon;
                  const profile = key === 'sast' && state.languages
                    ? `${state.scanned_files ?? state.source_files ?? state.files ?? '?'} analyzed · ${Object.keys(state.languages).slice(0, 4).join(', ')}`
                    : key === 'sca' && state.manifests?.length
                      ? `${state.manifests.length} manifest${state.manifests.length === 1 ? '' : 's'}${state.sbom?.components !== undefined ? ` · ${state.sbom.components} SBOM components` : ''}`
                      : state.verification || '';
                  return (
                    <article className={`appsec-lane ${statusTone(state.status)}`} key={key}>
                      <div className="appsec-lane-icon"><Icon size={17} /></div>
                      <div><strong>{meta.label}</strong><span>{state.limitation || meta.description}</span><small>{state.tool} · {state.findings || 0} observations{profile ? ` · ${profile}` : ''}{state.duration_seconds !== undefined ? ` · ${state.duration_seconds}s` : ''}</small></div>
                      <LaneStatus status={state.status} />
                    </article>
                  );
                })}
              </div>

              <details className="card-glass" style={{ marginTop: 12, padding: 12 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--text-primary)', fontSize: 12, fontWeight: 700 }}>
                  Scanner evidence · {detail.tool_runs?.length || 0} runs · {verifiedCount} provider-verified
                </summary>
                <div className="coverage-list" style={{ marginTop: 10 }}>
                  {(detail.tool_runs || []).map((run, index) => (
                    <div className="coverage-row" key={`${String(run.tool || 'scanner')}-${index}`}>
                      <div>
                        <div className="coverage-title">{String(run.tool || 'scanner')}</div>
                        <div className="coverage-meta">{String(run.lane || 'analysis')} · {Number(run.duration || 0).toFixed(1)}s{run.timed_out ? ' · timed out' : ''}</div>
                      </div>
                      <span className={`badge ${run.success ? 'badge-running' : 'badge-failed'}`}>{run.success ? 'captured' : 'failed'}</span>
                    </div>
                  ))}
                  {!detail.tool_runs?.length && <div className="appsec-empty">Scanner run evidence appears here as each lane completes.</div>}
                </div>
              </details>

              <div className="appsec-findings-header">
                <div><span className="section-label">Evidence ledger</span><h3>Normalized findings</h3></div>
                <div className="appsec-search"><SearchCode size={14} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter CVE, rule, file or package" /></div>
              </div>
              <div className="appsec-finding-list">
                {findings.length === 0 && <div className="appsec-empty">{
                  running
                    ? 'Findings will appear after scanner evidence is normalized.'
                    : Object.values(detail.coverage || {}).some(item => ['partial', 'unavailable', 'failed'].includes(item.status))
                      ? 'No finding claim is possible while one or more analysis lanes have incomplete evidence.'
                      : 'No observations matched the configured scanners and rulepacks. Zero observations is not proof that the code is secure.'
                }</div>}
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
  if (status === 'partial' || status === 'failed' || status === 'unavailable') return <AlertTriangle size={17} />;
  return <ArrowRight size={17} />;
}

function FindingRow({ finding }: { finding: AppSecFinding }) {
  return (
    <details className="appsec-finding">
      <summary>
        <span className={`appsec-severity ${finding.severity}`}>{finding.severity === 'informational' ? 'info' : finding.severity}</span>
        <div><strong>{finding.title}</strong><span>{finding.path || finding.package || finding.rule_id}{finding.start_line ? `:${finding.start_line}` : ''}</span></div>
        <div className="appsec-finding-tags"><span>{finding.status}</span><span>{finding.confidence} confidence</span><span>{finding.category}</span>{finding.cve_ids.slice(0, 2).map(cve => <code key={cve}>{cve}</code>)}</div>
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
