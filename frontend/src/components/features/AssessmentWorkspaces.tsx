'use client';

import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CircleStop,
  CodeXml,
  Download,
  ExternalLink,
  FileWarning,
  Fingerprint,
  GitBranch,
  Globe2,
  Network,
  Radar,
  ScanSearch,
  Server,
  ShieldCheck,
  Target,
  TerminalSquare,
} from 'lucide-react';
import type {
  AgentDecision,
  AssetGraph,
  AssetNode,
  AssuranceCoverage,
  DurableOperation,
  Finding,
  Scan,
  ToolRun,
} from '@/types';

const PHASES = ['recon', 'enumeration', 'vuln_scanning', 'fuzzing', 'exploitation', 'intelligence', 'reporting', 'completed'];

function formatLabel(value?: string) {
  return (value || 'unknown').replaceAll('_', ' ');
}

function findingIsVerified(finding: Finding) {
  const tags = new Set((finding.tags || []).map(tag => tag.toLowerCase()));
  return finding.status === 'confirmed'
    && !finding.quarantined
    && Boolean((finding.request_proof && finding.response_proof)
      || tags.has('dast-proof')
      || tags.has('provider-verified')
      || tags.has('replay-proof'));
}

function actionBadge(status: string) {
  if (status === 'completed') return 'badge-completed';
  if (status === 'running' || status === 'retrying') return 'badge-running';
  if (status === 'failed' || status === 'timed_out' || status === 'resource_exhausted') return 'badge-failed';
  return 'badge-idle';
}

function evidenceGrade(finding: Finding) {
  if (findingIsVerified(finding)) return 'behavior verified';
  if (finding.quarantined) return 'quarantined';
  return finding.evidence_grade || 'candidate';
}

function WorkspaceHeading({ icon: Icon, eyebrow, title, description, right }: {
  icon: typeof Activity;
  eyebrow: string;
  title: string;
  description: string;
  right?: ReactNode;
}) {
  return (
    <div className="workspace-hero">
      <div className="workspace-hero-icon"><Icon size={20} aria-hidden="true" /></div>
      <div className="workspace-hero-copy">
        <span>{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {right && <div className="workspace-hero-actions">{right}</div>}
    </div>
  );
}

export function LiveScanWorkspace({
  selectedScan,
  scans,
  operation,
  toolRuns,
  findings,
  assetGraph,
  decisions,
  onSelectScan,
  onStop,
  onReport,
}: {
  selectedScan?: Scan;
  scans: Scan[];
  operation: DurableOperation | null;
  toolRuns: ToolRun[];
  findings: Finding[];
  assetGraph: AssetGraph | null;
  decisions: AgentDecision[];
  onSelectScan: (id: string) => void;
  onStop: () => void;
  onReport: () => void;
}) {
  const currentIndex = selectedScan ? PHASES.indexOf(selectedScan.current_phase) : -1;
  const verified = findings.filter(findingIsVerified);
  const candidates = findings.filter(item => !findingIsVerified(item));
  const activeToolRuns = [...toolRuns].sort((a, b) => b.id - a.id).slice(0, 10);

  return (
    <section className="enterprise-workspace">
      <WorkspaceHeading
        icon={Activity}
        eyebrow="Durable operation"
        title="Live Scan"
        description="Reconnectable execution state, exact runner outcomes and evidence as it is persisted. Leaving this screen does not interrupt the assessment."
        right={selectedScan && (
          <>
            {selectedScan.status === 'running' && <button className="btn btn-danger" onClick={onStop}><CircleStop size={14} />Stop safely</button>}
            <button className="btn btn-secondary" onClick={onReport} disabled={selectedScan.status !== 'completed'}><Download size={14} />Report</button>
          </>
        )}
      />

      {!selectedScan ? (
        <div className="workspace-empty"><Activity size={30} /><strong>No assessment selected</strong><span>Launch or select an authorised assessment in Command Center.</span></div>
      ) : (
        <>
          <div className="live-operation-strip">
            <div>
              <span className="section-label">Active context</span>
              <h2>{selectedScan.name || selectedScan.scan_id}</h2>
              <p>{selectedScan.targets.join(', ')} · {formatLabel(selectedScan.mode)}</p>
            </div>
            <div className="live-operation-state">
              <span className={`badge ${actionBadge(selectedScan.status)}`}>{selectedScan.status}</span>
              <strong>{formatLabel(selectedScan.current_phase)}</strong>
              <small>{operation ? `replay cursor ${operation.reconnect_cursor}` : 'loading durable ledger'}</small>
            </div>
          </div>

          <div className="phase-track" aria-label="Assessment phases">
            {PHASES.map((phase, index) => {
              const done = selectedScan.status === 'completed' || currentIndex > index;
              const active = currentIndex === index && selectedScan.status === 'running';
              return (
                <div key={phase} className={`phase-track-step${done ? ' done' : ''}${active ? ' active' : ''}`}>
                  <span>{done ? <CheckCircle2 size={13} /> : index + 1}</span>
                  <strong>{formatLabel(phase)}</strong>
                </div>
              );
            })}
          </div>

          <div className="workspace-metric-grid">
            <div><Activity /><span>Durable actions</span><strong>{operation?.summary.total_actions || 0}</strong><small>{operation?.summary.running || 0} running · {operation?.summary.retrying || 0} retrying</small></div>
            <div><ShieldCheck /><span>Verified findings</span><strong>{verified.length}</strong><small>replayable or provider proof</small></div>
            <div><FileWarning /><span>Candidate leads</span><strong>{candidates.length}</strong><small>not report-eligible as confirmed</small></div>
            <div><Network /><span>Observed surface</span><strong>{assetGraph?.total_assets || 0}</strong><small>{assetGraph?.total_edges || 0} persisted relations</small></div>
          </div>

          <div className="workspace-grid workspace-grid-live">
            <div className="card-glass workspace-panel">
              <div className="workspace-panel-head"><div><span className="section-label">Execution ledger</span><h3>Approved actions and checkpoints</h3></div><span className="truth-chip">persisted</span></div>
              {!operation?.actions.length ? <div className="quiet-empty">Actions appear after the policy engine queues an eligible capability.</div> : (
                <div className="action-ledger">
                  {[...operation.actions].reverse().slice(0, 16).map(action => (
                    <article key={action.action_id} className="action-ledger-row">
                      <span className={`action-state action-state-${action.status}`} />
                      <div><strong>{action.capability || action.tool}</strong><span>{formatLabel(action.phase)} · {action.runner} · attempt {action.attempt}/{action.max_attempts}</span><small>{action.reason || action.error || 'Policy-approved execution'}</small></div>
                      <span className={`badge ${actionBadge(action.status)}`}>{formatLabel(action.status)}</span>
                    </article>
                  ))}
                </div>
              )}
            </div>

            <div className="card-glass workspace-panel">
              <div className="workspace-panel-head"><div><span className="section-label">Runner evidence</span><h3>Recent tool outcomes</h3></div><TerminalSquare size={17} /></div>
              {!activeToolRuns.length ? <div className="quiet-empty">No tool outcomes have been persisted for this assessment.</div> : (
                <div className="compact-run-list">
                  {activeToolRuns.map(run => (
                    <article key={run.id}>
                      <div><strong>{run.tool}</strong><span>{formatLabel(run.phase)} · {Math.round(run.duration * 10) / 10}s</span></div>
                      <span className={`badge ${run.success ? 'badge-completed' : run.partial ? 'badge-running' : 'badge-failed'}`}>{run.outcome || (run.success ? 'completed' : 'failed')}</span>
                    </article>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="workspace-grid workspace-grid-live">
            <div className="card-glass workspace-panel">
              <div className="workspace-panel-head"><div><span className="section-label">Evidence stream</span><h3>Latest security observations</h3></div><span className="truth-chip">{findings.length} total</span></div>
              {!findings.length ? <div className="quiet-empty">No security observations have passed normalization yet.</div> : (
                <div className="evidence-stream">
                  {findings.slice(0, 10).map((finding, index) => (
                    <article key={`${finding.title}-${finding.target_url}-${index}`}>
                      <span className={`finding-state ${findingIsVerified(finding) ? 'verified' : 'candidate'}`} />
                      <div><strong>{finding.title}</strong><span>{finding.target_display || finding.target_url || finding.target_host}</span></div>
                      <small>{evidenceGrade(finding)}</small>
                    </article>
                  ))}
                </div>
              )}
            </div>

            <div className="card-glass workspace-panel">
              <div className="workspace-panel-head"><div><span className="section-label">Adaptive decisions</span><h3>Why the plan changed</h3></div><GitBranch size={17} /></div>
              {!decisions.length ? <div className="quiet-empty">No adaptive decision has been recorded for this assessment.</div> : (
                <div className="decision-stream">
                  {decisions.slice(0, 8).map(decision => (
                    <article key={decision.decision_id}>
                      <div><strong>{formatLabel(decision.decision_type || decision.status)}</strong><span>{formatLabel(decision.phase)} · {decision.policy?.decision_authority || 'deterministic policy'}</span></div>
                      <p>{decision.hypotheses?.[0] || decision.selected?.[0]?.reason || decision.recovery_actions?.[0]?.action || 'Decision recorded without an explanatory summary.'}</p>
                    </article>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="card-glass scan-selector-panel">
            <span className="section-label">Assessment history</span>
            <div className="scan-selector-row">
              {scans.slice(0, 12).map(scan => (
                <button key={scan.scan_id} onClick={() => onSelectScan(scan.scan_id)} className={scan.scan_id === selectedScan.scan_id ? 'active' : ''}>
                  <span className={`action-state action-state-${scan.status}`} /><strong>{scan.name || scan.scan_id}</strong><small>{scan.status} · {formatLabel(scan.current_phase)}</small>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function assetIcon(type: string) {
  if (type === 'technology') return CodeXml;
  if (type === 'service') return Server;
  if (type === 'api_endpoint') return Boxes;
  if (type === 'parameter') return Fingerprint;
  return Globe2;
}

export function ReconIntelWorkspace({ selectedScan, graph, toolRuns }: {
  selectedScan?: Scan;
  graph: AssetGraph | null;
  toolRuns: ToolRun[];
}) {
  const assets = graph?.assets || [];
  const grouped = assets.reduce<Record<string, AssetNode[]>>((result, asset) => {
    (result[asset.asset_type] ||= []).push(asset);
    return result;
  }, {});
  const reconRuns = toolRuns.filter(run => ['recon', 'enumeration'].includes(run.phase));

  return (
    <section className="enterprise-workspace">
      <WorkspaceHeading icon={Radar} eyebrow="Verified attack surface" title="Recon Intel" description="Canonical assets and relationships observed by real discovery capabilities. Counts are deduplicated identities—not raw output lines." />
      {!selectedScan ? <div className="workspace-empty"><Radar size={30} /><strong>No assessment selected</strong><span>Select an assessment to inspect its persisted attack surface.</span></div> : !graph ? (
        <div className="workspace-empty"><Radar size={30} /><strong>Loading attack surface</strong><span>Waiting for the canonical asset projection.</span></div>
      ) : (
        <>
          <div className="recon-summary-band">
            <div><span className="section-label">Scope</span><strong>{selectedScan.targets.join(', ')}</strong><small>{selectedScan.scan_id}</small></div>
            <div><span>Canonical assets</span><strong>{graph.total_assets}</strong><small>{graph.raw_observations} raw observations</small></div>
            <div><span>Evidence edges</span><strong>{graph.total_edges}</strong><small>{graph.raw_relationships} raw relationships</small></div>
            <div><span>Recon runs</span><strong>{reconRuns.length}</strong><small>{reconRuns.filter(run => run.success).length} completed</small></div>
          </div>

          {assets.length === 0 ? <div className="workspace-empty"><Target size={30} /><strong>No verified surface yet</strong><span>Assets appear only after a discovery capability emits persisted evidence.</span></div> : (
            <div className="asset-columns">
              {Object.entries(grouped).sort((a, b) => b[1].length - a[1].length).map(([type, items]) => {
                const Icon = assetIcon(type);
                return (
                  <div className="card-glass asset-column" key={type}>
                    <div className="asset-column-head"><Icon size={16} /><div><strong>{formatLabel(type)}</strong><span>{items.length} canonical</span></div></div>
                    <div className="asset-list">
                      {items.slice(0, 30).map(asset => (
                        <article key={asset.asset_key}>
                          <div><strong>{asset.value}</strong><span>{asset.source} · {asset.confidence} confidence</span></div>
                          <small>{asset.metadata?.status || asset.metadata?.method || asset.metadata?.version || 'observed'}</small>
                        </article>
                      ))}
                    </div>
                    {items.length > 30 && <div className="asset-overflow">+{items.length - 30} more persisted assets</div>}
                  </div>
                );
              })}
            </div>
          )}

          <div className="card-glass relation-ledger">
            <div className="workspace-panel-head"><div><span className="section-label">Evidence graph</span><h3>Observed relationships</h3></div><span className="truth-chip">no inferred decorative nodes</span></div>
            {!graph.edges.length ? <div className="quiet-empty">No persisted asset relationship has been established.</div> : (
              <div className="relation-list">
                {graph.edges.slice(0, 50).map(edge => (
                  <article key={edge.edge_key}><code>{edge.source_key}</code><span>{formatLabel(edge.relation)} <ArrowRight size={12} /></span><code>{edge.target_key}</code><small>{edge.evidence}</small></article>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export function DastWorkspace({ selectedScan, assurance, findings, toolRuns, decisions, onStartAssessment }: {
  selectedScan?: Scan;
  assurance: AssuranceCoverage | null;
  findings: Finding[];
  toolRuns: ToolRun[];
  decisions: AgentDecision[];
  onStartAssessment: () => void;
}) {
  const verified = findings.filter(findingIsVerified);
  const candidates = findings.filter(item => !findingIsVerified(item) && !item.quarantined);
  const quarantined = findings.filter(item => item.quarantined);
  const dastRuns = toolRuns.filter(run => ['vuln_scanning', 'fuzzing', 'exploitation'].includes(run.phase));
  const latestPlan = decisions.find(item => item.decision_type === 'adaptive_capability_plan') || decisions[0];

  return (
    <section className="enterprise-workspace">
      <WorkspaceHeading
        icon={ScanSearch}
        eyebrow="Evidence-gated dynamic testing"
        title="Adaptive DAST"
        description="Observed surface selects eligible tests; deterministic policy authorises execution; issue-specific validators decide whether evidence is sufficient for confirmation."
        right={<button className="btn btn-primary" onClick={onStartAssessment}><ScanSearch size={14} />New authorised assessment</button>}
      />

      {!selectedScan ? <div className="workspace-empty"><ScanSearch size={30} /><strong>No assessment selected</strong><span>Launch an authorised assessment to populate the dynamic testing matrix.</span></div> : (
        <>
          <div className="workspace-metric-grid">
            <div><ShieldCheck /><span>Behavior verified</span><strong>{verified.length}</strong><small>request + response or independent proof</small></div>
            <div><AlertTriangle /><span>Candidate leads</span><strong>{candidates.length}</strong><small>requires typed validation</small></div>
            <div><FileWarning /><span>Quarantined</span><strong>{quarantined.length}</strong><small>insufficient or contradictory evidence</small></div>
            <div><TerminalSquare /><span>Dynamic tool runs</span><strong>{dastRuns.length}</strong><small>{dastRuns.filter(run => run.evidence_captured).length} produced evidence</small></div>
          </div>

          <div className="card-glass dast-methodology">
            <div className="workspace-panel-head"><div><span className="section-label">Adaptive methodology</span><h3>Observe → hypothesise → authorise → execute → validate</h3></div><span className="truth-chip">policy owns execution</span></div>
            <div className="methodology-flow">
              {[
                ['1', 'Observe', 'Persist endpoints, parameters, technologies and response behavior.'],
                ['2', 'Select', 'Choose eligible WSTG tests from observed evidence and engagement policy.'],
                ['3', 'Execute', 'Run bounded capabilities with rate, time and scope enforcement.'],
                ['4', 'Validate', 'Use negative controls and replayable request/response evidence.'],
                ['5', 'Promote', 'Confirm only when the issue-specific evidence threshold is met.'],
              ].map(([number, title, copy]) => <article key={number}><span>{number}</span><strong>{title}</strong><p>{copy}</p></article>)}
            </div>
          </div>

          <div className="card-glass adaptive-plan-panel">
            <div className="workspace-panel-head"><div><span className="section-label">Current decision trace</span><h3>Policy-eligible hypotheses and capabilities</h3></div><span className="truth-chip">AI ranks · policy authorises</span></div>
            {!latestPlan ? <div className="quiet-empty">No adaptive decision has been persisted for this assessment.</div> : (
              <div className="adaptive-plan-grid">
                <div>
                  <span>Selected capabilities</span>
                  {latestPlan.selected?.length ? latestPlan.selected.map(item => (
                    <article key={`${item.tool}-${item.capability}`}><strong>{item.capability || item.tool}</strong><small>{item.tool} · {item.reason}</small></article>
                  )) : <p>No capability was eligible under the current evidence and policy.</p>}
                </div>
                <div>
                  <span>Testable hypotheses</span>
                  {latestPlan.hypotheses?.length ? latestPlan.hypotheses.slice(0, 12).map((item, index) => (
                    <article key={`${item}-${index}`}><strong>Hypothesis {index + 1}</strong><small>{item}</small></article>
                  )) : <p>No hypothesis has been recorded yet.</p>}
                </div>
                <div>
                  <span>Decision authority</span>
                  <article><strong>{latestPlan.policy?.decision_authority || 'deterministic policy'}</strong><small>{latestPlan.model_trace?.used ? `${latestPlan.model_trace.provider}/${latestPlan.model_trace.model} ranked eligible actions` : 'No model was needed for this decision'}</small></article>
                  <article><strong>{latestPlan.execution?.automatically_executed ? 'Automatically executed' : 'Advisory or approval-bound'}</strong><small>{latestPlan.execution?.note || 'Exact actions remain constrained by the engagement policy.'}</small></article>
                </div>
              </div>
            )}
          </div>

          <div className="card-glass dast-matrix">
            <div className="workspace-panel-head"><div><span className="section-label">OWASP testing matrix</span><h3>Executed, observed and untested domains</h3></div>{assurance && <span className="truth-chip">{assurance.catalog} {assurance.catalog_version}</span>}</div>
            {!assurance ? <div className="quiet-empty">Coverage projection is loading or has not been produced.</div> : (
              <>
                <div className="dast-matrix-grid">
                  {assurance.categories.map(category => (
                    <article key={category.category_id} className={category.status}>
                      <div><code>{category.category_id}</code><span className={`coverage-signal ${category.status}`} /></div>
                      <strong>{category.title}</strong>
                      <p>{category.limitation}</p>
                      <footer>{category.executed_tools.length ? category.executed_tools.join(', ') : category.observed_assets.length ? `${category.observed_assets.length} observed assets` : 'No execution evidence'}</footer>
                    </article>
                  ))}
                </div>
                <div className="evidence-disclaimer" role="note"><AlertTriangle size={15} /><div><strong>Coverage is not proof of absence</strong><span>{assurance.disclaimer}</span></div></div>
              </>
            )}
          </div>

          <div className="card-glass proof-ledger">
            <div className="workspace-panel-head"><div><span className="section-label">Validator proof ledger</span><h3>Confirmed dynamic findings</h3></div><span className="truth-chip">{verified.length} report-eligible</span></div>
            {!verified.length ? <div className="workspace-empty compact"><ShieldCheck size={24} /><strong>No behavior-verified finding yet</strong><span>This does not mean the target is secure. Review untested domains and candidate leads.</span></div> : (
              <div className="proof-list">
                {verified.map((finding, index) => (
                  <details key={`${finding.title}-${index}`}>
                    <summary><span className={`badge badge-${finding.severity}`}>{finding.severity}</span><div><strong>{finding.title}</strong><small>{finding.target_url || finding.target_display || finding.target_host}</small></div><span>{finding.evidence_grade || 'verified'} <ExternalLink size={12} /></span></summary>
                    <div className="proof-detail"><div><span>Request proof</span><pre>{finding.request_proof || 'Captured in provider evidence artifact.'}</pre></div><div><span>Response proof</span><pre>{finding.response_proof || finding.evidence}</pre></div><div><span>Validation notes</span><p>{finding.validation_notes?.join(' · ') || 'Evidence gate accepted the provider proof.'}</p></div></div>
                  </details>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}
