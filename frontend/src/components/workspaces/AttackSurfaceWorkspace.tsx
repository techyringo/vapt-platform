'use client';

import { Bot, Download, RefreshCw } from 'lucide-react';
import { AgentCard } from '@/components/features/AgentCard';
import { SkeletonAgentCard } from '@/components/ui/Skeleton';
import { StateView } from '@/components/ui/StateView';
import { api } from '@/lib/api';
import type { AgentDecision, AgentStatus, AssetGraph, AttackChainResult, Scan, ScanCoverage, ToolRun } from '@/types';

function formatPhase(phase?: string) {
  return (phase || 'standby').replace(/_/g, ' ');
}

function formatExecutedCapabilities(items: Array<{ tool: string; outcome: string }>) {
  const grouped = new Map<string, { count: number; outcomes: Set<string> }>();
  items.forEach(item => {
    const current = grouped.get(item.tool) || { count: 0, outcomes: new Set<string>() };
    current.count += 1;
    current.outcomes.add(item.outcome.replaceAll('_', ' '));
    grouped.set(item.tool, current);
  });
  return [...grouped.entries()].map(([tool, value]) =>
    `${tool}${value.count > 1 ? ` ×${value.count}` : ''}: ${[...value.outcomes].join('/')}`,
  ).join(' · ');
}

interface Props {
  selectedScan?: Scan;
  loadingInitial: boolean;
  agentEntries: Array<[string, AgentStatus]>;
  agentProgress: number;
  assetGraph: AssetGraph | null;
  mappedSurfaceAssets: AssetGraph['assets'];
  assetLabelByKey: Map<string, string>;
  decisions: AgentDecision[];
  attackChains: AttackChainResult | null;
  coverage: ScanCoverage | null;
  toolRuns: ToolRun[];
  partialToolRuns: ToolRun[];
  failedToolRuns: ToolRun[];
  onRefreshToolRuns: () => void;
}

export function AttackSurfaceWorkspace({
  selectedScan, loadingInitial, agentEntries, agentProgress, assetGraph,
  mappedSurfaceAssets, assetLabelByKey, decisions, attackChains, coverage,
  toolRuns, partialToolRuns, failedToolRuns, onRefreshToolRuns,
}: Props) {
  return (
            <section>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <Bot size={20} style={{ color: 'var(--accent)' }} aria-hidden="true" />
                  <div>
                    <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Attack Paths & Decisions</h2>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                      {attackChains?.summary.verified || 0} verified paths · {decisions.length} recorded decisions
                    </p>
                  </div>
                </div>
                {agentEntries.length > 0 && (
                  <span style={{
                    fontFamily: 'var(--font-jetbrains), monospace', fontSize: 11,
                    padding: '4px 10px', borderRadius: 6,
                    border: '1px solid var(--accent-border)',
                    background: 'var(--accent-dim)',
                    color: 'var(--accent)',
                  }}>
                    {agentProgress}% complete
                  </span>
                )}
              </div>

              {!selectedScan ? (
                <StateView variant="empty" icon={Bot} title="No assessment selected" body="Select an assessment to inspect its evidence paths and policy-bound decisions." />
              ) : loadingInitial ? (
                <div className="agents-grid">
                  {Array.from({ length: 6 }).map((_, i) => <SkeletonAgentCard key={i} />)}
                </div>
              ) : (
                <div style={{ display: 'grid', gap: 16 }}>
                    <div className="card-glass" style={{ padding: 14 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
                        <div>
                          <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Technology & Attack Surface Map</h3>
                          <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                            Persisted assets and observed relationships · no inferred decorative nodes
                          </p>
                        </div>
                        <span className="badge badge-informational">{assetGraph?.raw_observations || 0} observations → {assetGraph?.total_assets || 0} canonical assets · {assetGraph?.total_edges || 0} relations</span>
                      </div>
                      {mappedSurfaceAssets.length === 0 ? (
                        <div className="quiet-empty">The map appears after body-verified discovery evidence is persisted.</div>
                      ) : (
                        <div className="surface-map">
                          <div className="surface-map-nodes">
                            {mappedSurfaceAssets.map(asset => (
                              <div className={`surface-node surface-node-${asset.asset_type}`} key={asset.asset_key}>
                                <span>{asset.asset_type.replaceAll('_', ' ')}</span>
                                <strong title={asset.value}>{asset.value}</strong>
                                <small>{asset.source} · {asset.confidence}</small>
                              </div>
                            ))}
                          </div>
                          <div className="surface-map-edges">
                            {(assetGraph?.edges || []).slice(0, 12).map(edge => (
                              <div key={edge.edge_key}>
                                <code title={edge.source_key}>{assetLabelByKey.get(edge.source_key) || edge.source_key}</code>
                                <span>{edge.relation.replaceAll('_', ' ')} →</span>
                                <code title={edge.target_key}>{assetLabelByKey.get(edge.target_key) || edge.target_key}</code>
                              </div>
                            ))}
                            {!assetGraph?.edges?.length && <div className="quiet-empty">Assets are real; relationship evidence has not been captured yet.</div>}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="card-glass" style={{ padding: 14 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
                        <div>
                          <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Adaptive Decision Ledger</h3>
                          <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                            Approved recommendations paired with observed execution outcomes
                          </p>
                        </div>
                        <span className="badge badge-informational">{decisions.length} entr{decisions.length === 1 ? 'y' : 'ies'}</span>
                      </div>
                      {decisions.length === 0 ? (
                        <div className="quiet-empty">Policy decisions appear as evidence becomes available; only the approved capability set can enter the execution queue.</div>
                      ) : (
                        <div className="coverage-list">
                          {[...decisions].reverse().slice(0, 6).map(decision => (
                            <div key={decision.decision_id} className="coverage-row">
                              <div style={{ minWidth: 0 }}>
                                <div className="coverage-title">
                                  {formatPhase(decision.phase)} · {decision.decision_type === 'execution_outcome' ? 'observed outcome' : 'approved plan'}
                                </div>
                                <div className="coverage-meta">
                                  {decision.decision_type === 'execution_outcome'
                                    ? formatExecutedCapabilities(decision.executed_capabilities || []) || 'No tool artifact captured'
                                    : (decision.selected || []).map(item => item.capability).join(', ') || 'No eligible capability'}
                                </div>
                              </div>
                              <span className={`badge ${decision.status === 'completed' ? 'badge-completed' : decision.status === 'failed' ? 'badge-failed' : 'badge-informational'}`}>
                                {decision.status}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                      {decisions.length > 0 && (
                        <div className="quiet-empty" style={{ marginTop: 10 }}>
                          Policy owns execution. AI ranks only eligible actions; the selected allowlist and every real outcome are written back here.
                        </div>
                      )}
                    </div>

                    {attackChains && (
                      <div className="card-glass" style={{ padding: 14 }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
                          <div>
                            <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Evidence-backed Attack Paths</h3>
                            <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                              {attackChains.summary.verified} verified · {attackChains.summary.hypotheses} hypotheses
                            </p>
                          </div>
                          <span className={`badge ${attackChains.summary.verified ? 'badge-failed' : 'badge-idle'}`}>
                            {attackChains.summary.total} path{attackChains.summary.total === 1 ? '' : 's'}
                          </span>
                        </div>
                        {attackChains.chains.length === 0 ? (
                          <div className="quiet-empty">No compatible evidence chain has been established.</div>
                        ) : (
                          <div className="coverage-list">
                            {attackChains.chains.slice(0, 8).map(chain => (
                              <div key={chain.chain_id} className="coverage-row">
                                <div style={{ minWidth: 0 }}>
                                  <div className="coverage-title">{chain.name}</div>
                                  <div className="coverage-meta">
                                    {chain.nodes.map(node => node.title).join(' → ')}
                                  </div>
                                </div>
                                <span className={`badge ${chain.status === 'verified' ? 'badge-failed' : 'badge-running'}`}>
                                  {chain.status}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    <details className="card-glass" style={{ padding: 14 }}>
                      <summary style={{ cursor: 'pointer', color: 'var(--text-primary)', fontSize: 13, fontWeight: 700 }}>
                        Execution stages · {agentEntries.length || 0} · {agentProgress}% complete
                      </summary>
                      <p style={{ margin: '7px 0 12px', fontSize: 11, color: 'var(--text-secondary)' }}>
                        Internal workflow health is shown for troubleshooting; findings and evidence remain the customer record.
                      </p>
                      {agentEntries.length === 0 ? (
                        <div className="quiet-empty">Execution stages appear when the assessment is dispatched.</div>
                      ) : (
                        <div className="agents-grid">
                          {agentEntries.map(([name, status], index) => (
                            <AgentCard key={name} name={name} status={status} index={index} />
                          ))}
                        </div>
                      )}
                    </details>

	                  {coverage && (
	                    <div className="card-glass" style={{ padding: 14 }}>
	                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
	                        <div>
                          <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Assessment Completeness</h3>
	                          <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                            {coverage.summary.completed}/{coverage.summary.total} complete · {coverage.summary.partial || 0} partial · {coverage.summary.running || 0} running · {coverage.summary.blind_spots || 0} limitations
	                          </p>
	                        </div>
	                        <span className={`badge ${(coverage.summary.blind_spots || 0) ? 'badge-failed' : 'badge-completed'}`}>
	                          {(coverage.summary.blind_spots || 0) ? 'attention' : 'covered'}
	                        </span>
	                      </div>
	                      <div className="coverage-list">
	                        {coverage.checks.slice(0, 9).map(check => (
	                          <div key={check.id} className="coverage-row">
	                            <div style={{ minWidth: 0 }}>
	                              <div className="coverage-title">{check.label}</div>
	                              <div className="coverage-meta">
	                                {check.phase} · {(check.successful_tools?.length ? check.successful_tools : check.tools_observed || check.expected_tools || []).join(', ') || 'no tool evidence'}
	                              </div>
	                            </div>
	                            <span className={`badge ${check.status === 'completed' ? 'badge-completed' : check.status === 'running' || check.status === 'partial' ? 'badge-running' : 'badge-idle'}`}>
	                              {check.status.replaceAll('_', ' ')}
	                            </span>
	                          </div>
	                        ))}
	                      </div>
	                    </div>
	                  )}

	                  <details className="card-glass operator-diagnostics">
                    <summary>
                      <div>
                        <h3>Operator scanner artifacts</h3>
                        <p>
                          {toolRuns.length} captured · {partialToolRuns.length} partial · {failedToolRuns.length} failed
                        </p>
                      </div>
                      <span className="badge badge-idle">restricted diagnostics</span>
                    </summary>
                    <div className="operator-diagnostics-body">
                      <div className="operator-diagnostics-actions"><span>Commands and raw output are implementation diagnostics, not customer findings.</span>
                      <button
                        onClick={onRefreshToolRuns}
                        className="btn btn-secondary"
                      >
                        <RefreshCw size={14} aria-hidden="true" />Refresh
                      </button>
                      </div>
                    {toolRuns.length === 0 ? (
                      <div className="quiet-empty">Tool output appears after agents finish their current phase.</div>
                    ) : (
                      <div className="tool-run-list">
                        {[...toolRuns].sort((a, b) => Number(a.success) - Number(b.success) || b.id - a.id).slice(0, 80).map(run => {
                          const snippet = run.stderr_snippet || run.stdout_snippet || '';
                          return (
                            <div key={run.id} className={`tool-run-row${run.partial ? ' partial' : run.success ? '' : ' failed'}`}>
	                              <div className="tool-run-head">
	                                <span className="tool-run-name">{run.tool}</span>
	                                <div className="tool-run-actions">
	                                  {run.stdout_artifact_url && (
	                                    <a className="tool-run-link" href={api.downloadToolArtifact(selectedScan.scan_id, run.id, 'stdout')} title="Download stdout">
	                                      <Download size={12} aria-hidden="true" />stdout
	                                    </a>
	                                  )}
	                                  {run.stderr_artifact_url && (
	                                    <a className="tool-run-link" href={api.downloadToolArtifact(selectedScan.scan_id, run.id, 'stderr')} title="Download stderr">
	                                      <Download size={12} aria-hidden="true" />stderr
	                                    </a>
	                                  )}
	                                  <span className={`badge ${run.success ? 'badge-completed' : run.partial ? 'badge-running' : 'badge-failed'}`}>
	                                    {run.success ? 'complete' : run.partial ? 'partial evidence' : run.timed_out ? 'timed out' : `exit ${run.exit_code}`}
	                                  </span>
	                                </div>
	                              </div>
	                              <div className="tool-run-meta">
	                                {run.agent_type} · {run.phase || 'phase'} · {Math.round((run.duration || 0) * 10) / 10}s · stdout {run.stdout_size || 0}b · stderr {run.stderr_size || 0}b
	                              </div>
                              {run.command_preview && (
                                <pre className="tool-run-snippet" style={{ borderColor: 'rgba(34,211,238,0.18)' }}>
                                  {run.command_preview.slice(0, 900)}
                                </pre>
                              )}
                              {snippet && <pre className="tool-run-snippet">{snippet.slice(0, 900)}</pre>}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    </div>
                  </details>
                </div>
              )}
            </section>
  );
}
