'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, CheckCircle2, Download, FileArchive, FileJson, FileText,
  LoaderCircle, RefreshCw, ShieldCheck, Sparkles, UploadCloud, X,
} from 'lucide-react';

import { api } from '@/lib/api';
import type { ReportStudioJob, ReportStudioTemplate, SeverityKey } from '@/types';

type PendingSource = { filename: string; media_type: string; content: string; size: number };
const ACTIVE = new Set(['queued', 'running']);
const ACCEPT = ['.json', '.txt', '.md', '.csv'];

function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
function statusClass(status: string) {
  if (status === 'completed') return 'badge-completed';
  if (status === 'failed') return 'badge-failed';
  if (status === 'partial') return 'badge-running';
  return 'badge-idle';
}

export function ReportStudioWorkspace() {
  const [templates, setTemplates] = useState<ReportStudioTemplate[]>([]);
  const [reports, setReports] = useState<ReportStudioJob[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [sources, setSources] = useState<PendingSource[]>([]);
  const [name, setName] = useState('');
  const [clientName, setClientName] = useState('');
  const [assessmentType, setAssessmentType] = useState('Web Application VAPT');
  const [templateId, setTemplateId] = useState('vapt_standard');
  const [scope, setScope] = useState('');
  const [preparedBy, setPreparedBy] = useState('');
  const [reportPeriod, setReportPeriod] = useState('');
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const selected = reports.find(report => report.report_id === selectedId) || reports[0];

  const refresh = useCallback(async () => {
    try {
      const [templateResult, reportResult] = await Promise.all([
        templates.length ? Promise.resolve({ templates }) : api.getReportStudioTemplates(),
        api.listReportStudioReports(),
      ]);
      setTemplates(templateResult.templates || []);
      setReports(reportResult.reports || []);
      setSelectedId(current => current || reportResult.reports?.[0]?.report_id || '');
      setError('');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not load Report Studio');
    } finally {
      setLoading(false);
    }
  }, [templates]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!reports.some(report => ACTIVE.has(report.status))) return;
    const timer = window.setInterval(() => { void refresh(); }, 3000);
    return () => window.clearInterval(timer);
  }, [reports, refresh]);

  const addFiles = async (files: FileList | File[]) => {
    const next: PendingSource[] = [];
    for (const file of Array.from(files)) {
      const suffix = `.${file.name.split('.').pop()?.toLowerCase()}`;
      if (!ACCEPT.includes(suffix)) {
        setError(`${file.name}: only JSON, TXT, Markdown and CSV evidence is accepted.`);
        continue;
      }
      if (file.size > 4 * 1024 * 1024) {
        setError(`${file.name}: file exceeds the 4 MB per-file limit.`);
        continue;
      }
      next.push({ filename: file.name, media_type: file.type || 'text/plain', content: await file.text(), size: file.size });
    }
    setSources(current => {
      const merged = [...current];
      next.forEach(file => {
        const index = merged.findIndex(item => item.filename === file.filename);
        if (index >= 0) merged[index] = file;
        else merged.push(file);
      });
      return merged.slice(0, 20);
    });
  };

  const submit = async () => {
    if (!name.trim() || sources.length === 0) {
      setError('Add a report name and at least one evidence file.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const result = await api.createReportStudioReport({
        name: name.trim(), client_name: clientName.trim(), assessment_type: assessmentType.trim(),
        template_id: templateId, scope: scope.split(/[,\n]/).map(value => value.trim()).filter(Boolean),
        prepared_by: preparedBy.trim(), report_period: reportPeriod.trim(), notes: notes.trim(),
        sources: sources.map(({ filename, media_type, content }) => ({ filename, media_type, content })),
      });
      setSelectedId(result.report_id);
      setName(''); setSources([]); setNotes('');
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not queue report');
    } finally {
      setSubmitting(false);
    }
  };

  const severityCounts = useMemo(() => {
    const values = selected?.summary?.severities || {};
    return (['critical', 'high', 'medium', 'low', 'informational'] as SeverityKey[])
      .map(severity => ({ severity, count: values[severity] || 0 }));
  }, [selected]);

  return (
    <section className="report-studio">
      <div className="report-studio-hero">
        <div className="report-studio-hero-icon"><FileArchive size={22} /></div>
        <div>
          <span className="section-label">Independent evidence compiler</span>
          <h1>Report Studio</h1>
          <p>Upload existing assessment evidence and generate an audit-ready report without launching a scan.</p>
        </div>
        <div className="report-studio-boundary"><ShieldCheck size={15} /><span><strong>Evidence boundary</strong>No imported observation is silently promoted to verified.</span></div>
      </div>

      {error && <div className="report-studio-error" role="alert"><AlertTriangle size={15} /><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss"><X size={14} /></button></div>}

      <div className="report-studio-grid">
        <div className="card-glass report-composer">
          <div className="workspace-panel-head"><div><span className="section-label">New report job</span><h2>Compile supplied evidence</h2></div><span className="truth-chip">No scanner dependency</span></div>
          <div className="report-form-grid">
            <label><span>Report name *</span><input className="field" value={name} onChange={event => setName(event.target.value)} placeholder="Q3 External VAPT Report" /></label>
            <label><span>Client</span><input className="field" value={clientName} onChange={event => setClientName(event.target.value)} placeholder="Client or business unit" /></label>
            <label><span>Assessment type</span><input className="field" value={assessmentType} onChange={event => setAssessmentType(event.target.value)} /></label>
            <label><span>Template</span><select className="field" value={templateId} onChange={event => setTemplateId(event.target.value)}>{templates.map(template => <option value={template.id} key={template.id}>{template.name}</option>)}</select></label>
            <label><span>Prepared by</span><input className="field" value={preparedBy} onChange={event => setPreparedBy(event.target.value)} placeholder="Assessment team" /></label>
            <label><span>Report period</span><input className="field" value={reportPeriod} onChange={event => setReportPeriod(event.target.value)} placeholder="1–15 July 2026" /></label>
          </div>
          <label className="report-full-field"><span>Scope</span><textarea className="field" value={scope} onChange={event => setScope(event.target.value)} rows={2} placeholder="app.example.com, API gateway, mobile backend" /></label>
          <label className="report-full-field"><span>Analyst context</span><textarea className="field" value={notes} onChange={event => setNotes(event.target.value)} rows={2} placeholder="Engagement constraints or report context. This does not create findings." /></label>

          <div
            className="report-dropzone"
            onDragOver={event => event.preventDefault()}
            onDrop={event => { event.preventDefault(); void addFiles(event.dataTransfer.files); }}
          >
            <UploadCloud size={24} />
            <strong>Drop evidence files here</strong>
            <span>JSON, TXT, Markdown or CSV · 4 MB each · maximum 20 files</span>
            <label className="btn btn-secondary">Choose files<input type="file" multiple accept={ACCEPT.join(',')} onChange={event => event.target.files && void addFiles(event.target.files)} /></label>
          </div>

          {sources.length > 0 && <div className="report-source-list">{sources.map(source => <div key={source.filename}><FileJson size={14} /><span><strong>{source.filename}</strong><small>{bytes(source.size)}</small></span><button onClick={() => setSources(current => current.filter(item => item.filename !== source.filename))} aria-label={`Remove ${source.filename}`}><X size={14} /></button></div>)}</div>}
          <button className="btn btn-primary report-generate" onClick={submit} disabled={submitting || !name.trim() || sources.length === 0}>{submitting ? <LoaderCircle size={15} className="animate-spin" /> : <Sparkles size={15} />}Queue audit report</button>
        </div>

        <div className="card-glass report-history">
          <div className="workspace-panel-head"><div><span className="section-label">Durable jobs</span><h2>Report history</h2></div><button className="btn btn-secondary" onClick={() => void refresh()}><RefreshCw size={13} />Refresh</button></div>
          {loading ? <div className="report-empty"><LoaderCircle size={20} className="animate-spin" />Loading reports</div> : reports.length === 0 ? <div className="report-empty"><FileText size={22} /><strong>No reports yet</strong><span>Uploaded evidence jobs will remain available here.</span></div> : <div className="report-job-list">{reports.map(report => <button key={report.report_id} className={selected?.report_id === report.report_id ? 'active' : ''} onClick={() => setSelectedId(report.report_id)}><span className={`report-job-state ${report.status}`}>{ACTIVE.has(report.status) ? <LoaderCircle size={13} className="animate-spin" /> : report.status === 'failed' ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}</span><span><strong>{report.name}</strong><small>{report.client_name || 'Client not specified'} · {report.source_manifest?.length || 0} source(s)</small></span><em className={`badge ${statusClass(report.status)}`}>{report.status}</em></button>)}</div>}
        </div>
      </div>

      {selected && <div className="card-glass report-result">
        <div className="workspace-panel-head"><div><span className="section-label">{selected.report_id}</span><h2>{selected.name}</h2><p>{selected.client_name || 'Client not specified'} · {selected.assessment_type}</p></div><span className={`badge ${statusClass(selected.status)}`}>{selected.phase} · {selected.progress}%</span></div>
        {ACTIVE.has(selected.status) && <div className="report-progress"><span style={{ width: `${selected.progress}%` }} /></div>}
        {selected.error && <div className="report-studio-error"><AlertTriangle size={15} />{selected.error}</div>}
        <div className="report-result-metrics">{severityCounts.map(item => <div key={item.severity} className={item.severity}><span>{item.severity}</span><strong>{item.count}</strong></div>)}<div><span>Confirmed</span><strong>{selected.summary?.confirmed || 0}</strong></div><div><span>Observed</span><strong>{selected.summary?.observed || 0}</strong></div></div>
        <div className="report-result-body">
          <div><span className="section-label">Executive narrative</span><p>{selected.narrative?.executive_summary || 'Narrative will appear when evidence normalization completes.'}</p>{selected.narrative?.llm_used && <span className="truth-chip"><Sparkles size={11} />Configured LLM used</span>}</div>
          <div><span className="section-label">Artifacts</span><div className="report-artifacts">{selected.artifacts?.length ? selected.artifacts.map(artifact => <a className="btn btn-secondary" key={artifact.kind} href={api.downloadReportStudioArtifact(selected.report_id, artifact.kind)}><Download size={13} />{artifact.kind.toUpperCase()}<small>{bytes(artifact.size)}</small></a>) : <span>Artifacts are generated after the job completes.</span>}</div></div>
        </div>
        {!!selected.summary?.limitations?.length && <details className="report-limitations"><summary>Evidence and generation limitations ({selected.summary.limitations.length})</summary><ul>{selected.summary.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul></details>}
      </div>}
    </section>
  );
}
