'use client';

import { useState } from 'react';
import { Check, ChevronDown, ExternalLink, Flag, Globe2, Target, X } from 'lucide-react';
import type { Finding, SeverityKey } from '@/types';
import { SEV_HEX } from './SeverityDonut';

const SEV_BADGE_CLASS: Record<string, string> = {
  critical:      'badge-critical',
  high:          'badge-high',
  medium:        'badge-medium',
  low:           'badge-low',
  informational: 'badge-informational',
};

interface FindingCardProps {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onTriage: (finding: Finding, disposition: string, reason: string) => Promise<void>;
}

export function FindingCard({ finding, expanded, onToggle, onTriage }: FindingCardProps) {
  const [reason, setReason] = useState(finding.triage_reason || '');
  const [saving, setSaving] = useState(false);
  const accent = SEV_HEX[finding.severity as SeverityKey] || '#06b6d4';
  const targetLabel = finding.target_display || `${finding.target_host}${finding.target_port ? `:${finding.target_port}` : ''}`;
  const validationNotes = finding.validation_notes || [];
  const llmReasoning = finding.llm_reasoning && Object.keys(finding.llm_reasoning).length
    ? (finding.llm_reasoning as Record<string, any>)
    : null;
  const applyTriage = async (disposition: string) => {
    setSaving(true);
    try {
      await onTriage(finding, disposition, reason);
    } finally {
      setSaving(false);
    }
  };

  return (
    <article
      className="finding-card"
      style={{ borderColor: `${accent}44` }}
    >
      {/* Header row — always visible */}
      <button
        className="finding-header"
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={`finding-body-${finding.title}`}
      >
        <span className="sev-dot" style={{ background: accent, flexShrink: 0 }} aria-hidden="true" />

        <span className={`badge ${SEV_BADGE_CLASS[finding.severity] || 'badge-informational'}`} style={{ flexShrink: 0 }}>
          {finding.severity === 'informational' ? 'info' : finding.severity}
        </span>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{finding.title}</span>
            {finding.cvss_score && (
              <span style={{
                fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10,
                padding: '2px 7px', borderRadius: 5, fontWeight: 600,
                border: '1px solid var(--border)',
                background: 'var(--bg-elevated)',
                color: 'var(--text-secondary)',
                fontVariantNumeric: 'tabular-nums',
              }}>
                CVSS {finding.cvss_score}
              </span>
            )}
            {finding.nvd_verified && (
              <span style={{
                fontSize: 10, padding: '2px 7px', borderRadius: 5,
                border: '1px solid rgba(34,197,94,0.3)',
                background: 'rgba(34,197,94,0.07)',
                color: 'var(--low)',
              }}>
                CVE catalogued
              </span>
            )}
            {finding.evidence_grade && (
              <span style={{
                fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10,
                padding: '2px 7px', borderRadius: 5, fontWeight: 600,
                border: '1px solid rgba(34,211,238,0.22)',
                background: 'rgba(34,211,238,0.07)',
                color: 'var(--accent)',
                fontVariantNumeric: 'tabular-nums',
              }}>
                EV {finding.evidence_grade}{typeof finding.evidence_score === 'number' ? ` ${Math.round(finding.evidence_score)}` : ''}
              </span>
            )}
            {finding.quarantined && (
              <span style={{
                fontSize: 10, padding: '2px 7px', borderRadius: 5, fontWeight: 600,
                border: '1px solid rgba(245,158,11,0.35)',
                background: 'rgba(245,158,11,0.08)',
                color: 'var(--medium)',
              }} title="Low-evidence — excluded from reports until validated">
                Quarantined
              </span>
            )}
            <span className={`badge ${finding.status === 'confirmed' ? 'badge-completed' : 'badge-running'}`}>
              {finding.status === 'confirmed' ? 'behavior verified' : (finding.tags || []).includes('version-applicability-candidate') ? 'version matched' : finding.status || 'candidate'}
            </span>
            {finding.triage_status && finding.triage_status !== 'untriaged' && (
              <span className={`badge ${finding.triage_status === 'true_positive' ? 'badge-completed' : finding.triage_status === 'false_positive' ? 'badge-idle' : 'badge-running'}`}>
                analyst: {finding.triage_status.replace(/_/g, ' ')}
              </span>
            )}
          </div>
          <div style={{ marginTop: 5, display: 'flex', flexWrap: 'wrap', gap: 8, fontSize: 11 }}>
            <span style={{ fontFamily: 'var(--font-jetbrains), monospace', color: 'var(--text-muted)' }}>
              {targetLabel}
            </span>
            {finding.agent_source && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--text-secondary)' }}>
                <Globe2 size={10} aria-hidden="true" />{finding.agent_source}
              </span>
            )}
            <span style={{ color: 'var(--text-muted)' }}>{finding.confidence || '—'} confidence</span>
          </div>
        </div>

        <ChevronDown
          size={15}
          className={`finding-chevron${expanded ? ' open' : ''}`}
          aria-hidden="true"
        />
      </button>

      {/* Expanded body */}
      {expanded && (
        <div
          id={`finding-body-${finding.title}`}
          className="finding-expand-body"
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 260px', gap: 16 }}>
            {/* Left column */}
            <div style={{ display: 'grid', gap: 12 }}>
              {finding.description && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>Description</div>
                  <p style={{ fontSize: 13, lineHeight: 1.65, color: 'var(--text-secondary)' }}>{finding.description}</p>
                </div>
              )}

              {finding.evidence && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>Evidence</div>
                  <pre style={{
                    maxHeight: 200, overflowY: 'auto', fontSize: 11, lineHeight: 1.6,
                    padding: '10px 12px', borderRadius: 8,
                    border: '1px solid var(--border)',
                    background: 'rgba(0,0,0,0.22)',
                    color: 'var(--text-secondary)',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                    fontFamily: 'var(--font-jetbrains), monospace',
                  }}>
                    {finding.evidence}
                  </pre>
                </div>
              )}

              {(finding.request_proof || finding.response_proof) && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>Replay Proof</div>
                  <div className="finding-proof-grid">
                    {finding.request_proof && (
                      <div>
                        <span>Sanitised request</span>
                        <pre>{finding.request_proof}</pre>
                      </div>
                    )}
                    {finding.response_proof && (
                      <div>
                        <span>Bounded response evidence</span>
                        <pre>{finding.response_proof}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {finding.poc_steps && finding.poc_steps.length > 0 && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>Reproduce Safely</div>
                  <ol className="finding-poc-steps">
                    {finding.poc_steps.map((step, index) => <li key={`${index}-${step}`}>{step}</li>)}
                  </ol>
                </div>
              )}

              {finding.remediation && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>Remediation</div>
                  <p style={{
                    fontSize: 13, lineHeight: 1.65, padding: '10px 12px', borderRadius: 8,
                    border: '1px solid rgba(34,197,94,0.25)',
                    background: 'rgba(34,197,94,0.06)',
                    color: 'var(--low)',
                    borderLeft: '3px solid rgba(34,197,94,0.5)',
                  }}>
                    {finding.remediation}
                  </p>
                </div>
              )}

              {llmReasoning && (
                <div>
                  <div className="section-label" style={{ marginBottom: 6 }}>
                    AI Reasoning
                    {(llmReasoning.provider || llmReasoning.model) ? (
                      <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 6, fontSize: 11 }}>
                        {[llmReasoning.provider, llmReasoning.model].filter(Boolean).join(' · ')}
                      </span>
                    ) : null}
                  </div>
                  <p style={{
                    fontSize: 12.5, lineHeight: 1.6, padding: '10px 12px', borderRadius: 8,
                    border: '1px solid rgba(34,211,238,0.22)',
                    background: 'rgba(34,211,238,0.05)',
                    color: 'var(--text-secondary)',
                    borderLeft: '3px solid rgba(34,211,238,0.5)',
                  }}>
                    {String(llmReasoning.response_summary || llmReasoning.prompt_summary || 'LLM analysis applied.')}
                  </p>
                </div>
              )}
            </div>

            {/* Right column */}
            <div style={{ display: 'grid', gap: 12, alignContent: 'start' }}>
              {/* Target info */}
              <div style={{
                padding: '10px 12px', borderRadius: 8,
                border: '1px solid var(--border)',
                background: 'rgba(0,0,0,0.1)',
              }}>
                <div className="section-label" style={{ marginBottom: 8 }}>Target</div>
                <div style={{ display: 'grid', gap: 5, fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--text-secondary)' }}>
                    <Target size={12} aria-hidden="true" />
                    <span style={{ fontFamily: 'var(--font-jetbrains), monospace' }}>{targetLabel || '—'}</span>
                  </div>
                  <div style={{ fontFamily: 'var(--font-jetbrains), monospace', color: 'var(--text-muted)', fontSize: 11 }}>
                    {finding.target_display || finding.target_url || `:${finding.target_port || '—'}`}
                  </div>
                  {finding.cvss_vector && (
                    <div style={{ fontFamily: 'var(--font-jetbrains), monospace', color: 'var(--text-muted)', fontSize: 10, wordBreak: 'break-all' }}>
                      {finding.cvss_vector}
                    </div>
                  )}
                  {validationNotes.length > 0 && (
                    <div style={{ display: 'grid', gap: 3, color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.45 }}>
                      {validationNotes.slice(0, 3).map(note => (
                        <span key={note}>• {note}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div className="finding-triage-panel">
                <div className="section-label">Analyst disposition</div>
                <p>Scanner evidence stays immutable. The decision records actor, reason and time.</p>
                <textarea
                  value={reason}
                  onChange={event => setReason(event.target.value)}
                  placeholder="Reason, ticket, duplicate or compensating control"
                  rows={3}
                  disabled={saving}
                />
                <div>
                  <button type="button" disabled={saving} onClick={() => applyTriage('true_positive')}><Check size={12} />True positive</button>
                  <button type="button" disabled={saving} onClick={() => applyTriage('false_positive')}><X size={12} />False positive</button>
                  <button type="button" disabled={saving} onClick={() => applyTriage('accepted_risk')}><Flag size={12} />Accept risk</button>
                </div>
                {finding.triage_actor && <small>{finding.triage_actor} · {finding.triage_updated_at ? new Date(finding.triage_updated_at).toLocaleString() : 'recorded'}</small>}
              </div>

              {/* CVEs / CWEs */}
              {(finding.cve_ids?.length > 0 || finding.cwe_ids?.length > 0) && (
                <div style={{
                  padding: '10px 12px', borderRadius: 8,
                  border: '1px solid var(--border)',
                  background: 'rgba(0,0,0,0.1)',
                }}>
                  <div className="section-label" style={{ marginBottom: 8 }}>Identifiers</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {(finding.cve_ids || []).map(cve => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank" rel="noreferrer"
                        className="tag-link"
                      >
                        {cve}<ExternalLink size={10} aria-hidden="true" />
                      </a>
                    ))}
                    {(finding.cwe_ids || []).map(cwe => (
                      <a
                        key={cwe}
                        href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, '')}.html`}
                        target="_blank" rel="noreferrer"
                        className="tag-link"
                      >
                        {cwe}<ExternalLink size={10} aria-hidden="true" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* References */}
              {finding.references?.length > 0 && (
                <div style={{
                  padding: '10px 12px', borderRadius: 8,
                  border: '1px solid var(--border)',
                  background: 'rgba(0,0,0,0.1)',
                }}>
                  <div className="section-label" style={{ marginBottom: 8 }}>References</div>
                  <div style={{ display: 'grid', gap: 6 }}>
                    {finding.references.map(ref => {
                      let hostname = ref;
                      try { hostname = new URL(ref).hostname; } catch {}
                      return (
                        <a
                          key={ref}
                          href={ref}
                          target="_blank" rel="noreferrer"
                          style={{
                            display: 'inline-flex', alignItems: 'center', gap: 5,
                            fontSize: 11, color: 'var(--accent)', wordBreak: 'break-all',
                            textDecoration: 'none',
                          }}
                        >
                          <ExternalLink size={11} style={{ flexShrink: 0 }} aria-hidden="true" />
                          {hostname}
                        </a>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </article>
  );
}

export { SEV_BADGE_CLASS };
