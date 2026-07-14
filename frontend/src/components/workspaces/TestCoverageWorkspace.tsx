'use client';

import { ClipboardCheck, ShieldAlert, ShieldCheck, Target } from 'lucide-react';
import { MetricCard } from '@/components/ui/MetricCard';
import { StateView } from '@/components/ui/StateView';
import type { AssuranceCoverage, Scan } from '@/types';

interface Props { selectedScan?: Scan; assurance: AssuranceCoverage | null; }

export function TestCoverageWorkspace({ selectedScan, assurance }: Props) {
  return (
    <section>
      <div className="workspace-heading">
        <div className="workspace-heading-copy"><ClipboardCheck size={20} style={{ color: 'var(--accent)' }} aria-hidden="true" /><div><h2>Security Test Coverage</h2><p>OWASP WSTG coverage derived from persisted attack-surface, execution and proof evidence</p></div></div>
        {assurance && <span className="badge badge-informational">{assurance.catalog} · {assurance.catalog_version}</span>}
      </div>
      {!selectedScan ? <StateView variant="empty" icon={ClipboardCheck} title="No assessment selected" body="Select an assessment to inspect its OWASP testing coverage." />
        : !assurance ? <StateView variant="loading" title="Loading test coverage" body="Projecting persisted evidence onto OWASP WSTG domains." />
        : <div className="control-evidence-stack">
          <div className="evidence-disclaimer" role="note"><ShieldAlert size={16} aria-hidden="true" /><div><strong>Testing coverage—not compliance and not a pass</strong><span>{assurance.disclaimer}</span></div></div>
          <div className="control-summary-grid">
            <MetricCard icon={ShieldCheck} label="Tested domains" value={`${assurance.summary.tested}/${assurance.summary.total}`} sub="runner artifact captured" tone="emerald" />
            <MetricCard icon={Target} label="Observed only" value={assurance.summary.observed} sub="surface exists; test not executed" tone="cyan" />
            <MetricCard icon={ShieldAlert} label="Not tested" value={assurance.summary.not_tested} sub="explicit assessment gap" tone="amber" />
          </div>
          <div className="card-glass assurance-console">
            <div className="control-ledger-head"><div><h3>WSTG coverage heatmap</h3><p>{selectedScan.name} · {selectedScan.targets.join(', ')} · {assurance.summary.confirmed_proofs} confirmed behavior proofs</p></div><span className="badge badge-idle">claim: testing coverage only</span></div>
            <div className="assurance-heatmap">{assurance.categories.map(category => <article className={`assurance-cell ${category.status}`} key={category.category_id}><div className="assurance-cell-head"><code>{category.category_id}</code><span className={`coverage-signal ${category.status}`} /></div><strong>{category.title}</strong><p>{category.limitation}</p><div className="assurance-evidence">{category.executed_tools.map(tool => <span key={tool}>{tool}</span>)}{!category.executed_tools.length && category.observed_assets.map(asset => <span key={asset}>{asset}</span>)}</div></article>)}</div>
            <div className="assurance-frameworks">{assurance.frameworks.map(framework => <a href={framework.url} target="_blank" rel="noreferrer" key={framework.name}><span>{framework.name} {framework.version}</span><small>{framework.purpose}</small></a>)}</div>
          </div>
        </div>}
    </section>
  );
}
