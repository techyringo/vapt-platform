'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import {
  Activity,
  Bot,
  Bug,
  CheckCircle2,
  ChevronRight,
  CircleStop,
  ClipboardCheck,
  Download,
  FileText,
  LayoutDashboard,
  Moon,
  Play,
  Radar,
  RefreshCw,
  ScanSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Trash2,
  WifiOff,
  Wrench,
} from 'lucide-react';

import { useSSE } from '@/hooks/useSSE';
import { useToast } from '@/hooks/useToast';
import { api } from '@/lib/api';
import type { AgentDecision, AgentStatus, AssetGraph, AssuranceCoverage, AttackChainResult, DurableOperation, Finding, RuntimeLogFile, ScanCoverage, SSEEvent, Scan, ScanMode, ToolRun } from '@/types';
import { SEVERITIES } from '@/types';
import type { SeverityKey } from '@/types';
import type { WorkspaceTab } from '@/types/navigation';

// Layout
import { Header } from '@/components/layout/Header';
import { Sidebar } from '@/components/layout/Sidebar';
import { MobileTabBar } from '@/components/layout/MobileTabBar';

// UI primitives
import { CommandPalette, type CommandAction } from '@/components/ui/CommandPalette';
import { StateView } from '@/components/ui/StateView';
import { useTheme } from '@/context/ThemeContext';
import { MetricCard } from '@/components/ui/MetricCard';
import { ReportModal } from '@/components/ui/ReportModal';
import { ToastContainer } from '@/components/ui/Toast';
import { SkeletonDashboard } from '@/components/ui/Skeleton';

// Feature components
import { SeverityDonut, SEV_HEX } from '@/components/features/SeverityDonut';
import { SEV_BADGE_CLASS } from '@/components/features/FindingCard';
import { LiveTelemetry } from '@/components/features/LiveTelemetry';
import { LLMConfigPanel } from '@/components/features/LLMConfigPanel';
import { AppSecWorkspace } from '@/components/features/AppSecWorkspace';
import { DastWorkspace, LiveScanWorkspace, ReconIntelWorkspace } from '@/components/features/AssessmentWorkspaces';
import { WorkspaceErrorBoundary } from '@/components/ui/WorkspaceErrorBoundary';
import { FindingsWorkspace } from '@/components/workspaces/FindingsWorkspace';
import { TestCoverageWorkspace } from '@/components/workspaces/TestCoverageWorkspace';
import { OperationsWorkspace } from '@/components/workspaces/OperationsWorkspace';
import { AttackSurfaceWorkspace } from '@/components/workspaces/AttackSurfaceWorkspace';

/* ─── Types ─────────────────────────────────────────────── */
type SeverityFilter = SeverityKey | 'all';

/* ─── Constants ──────────────────────────────────────────── */
const FALLBACK_MODES: ScanMode[] = [
  {
    id: 'full_vapt',
    name: 'Full VAPT',
    description: 'Complete penetration test with exploitation and intelligent analysis.',
    agents: ['recon', 'enum', 'vuln_scanner', 'fuzzer', 'exploit', 'intel', 'reporter'],
    exploit: true, aggressive: true, focus: [],
  },
  {
    id: 'va_only',
    name: 'VA Only',
    description: 'Non-intrusive assessment: recon, crawling, service enum, template scanning.',
    agents: ['recon', 'enum', 'vuln_scanner', 'reporter'],
    exploit: false, aggressive: false, focus: [],
  },
];

const PHASE_ORDER = [
  'recon', 'enumeration', 'vuln_scanning', 'fuzzing',
  'exploitation', 'intelligence', 'reporting', 'completed',
] as const;

const ACTIVE_SCAN_STATES = new Set(['running', 'starting', 'pending', 'queued']);

const SEV_DOT_COLOR: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#22c55e', informational: '#06b6d4',
};

/* ─── Helpers ────────────────────────────────────────────── */
function formatPhase(phase?: string) {
  return (phase || 'standby').replace(/_/g, ' ');
}

function scanTime(scan: Scan) {
  const parsed = parseBackendTime(scan.start_time);
  return Number.isFinite(parsed) ? parsed : 0;
}

function parseBackendTime(value?: string) {
  if (!value) return Number.NaN;
  // Backend timestamps are UTC. Python's isoformat() may omit the trailing Z;
  // browsers otherwise interpret the value as local time (5.5h wrong in IST).
  const explicitZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
  return Date.parse(explicitZone ? value : `${value}Z`);
}

function orderScans(scanList: Scan[]) {
  return [...scanList].sort((a, b) => {
    const aInactive = ACTIVE_SCAN_STATES.has((a.status || '').toLowerCase()) ? 0 : 1;
    const bInactive = ACTIVE_SCAN_STATES.has((b.status || '').toLowerCase()) ? 0 : 1;
    if (aInactive !== bInactive) return aInactive - bInactive;
    const timeDelta = scanTime(b) - scanTime(a);
    if (timeDelta !== 0) return timeDelta;
    return (b.scan_id || '').localeCompare(a.scan_id || '');
  });
}

function statusBadgeClass(status?: string) {
  if (status === 'running')   return 'badge-running';
  if (status === 'completed') return 'badge-completed';
  if (status === 'failed' || status === 'cancelled') return 'badge-failed';
  return 'badge-idle';
}

function riskPosture(counts: Record<SeverityKey, number>) {
  const score = Math.min(100, counts.critical * 24 + counts.high * 13 + counts.medium * 6 + counts.low * 2 + counts.informational);
  if (score >= 70) return { score, label: 'Critical exposure', color: '#f43f5e' };
  if (score >= 38) return { score, label: 'High risk',         color: '#f97316' };
  if (score > 0)   return { score, label: 'Moderate risk',     color: '#22d3ee' };
  return              { score, label: 'No exposure',            color: '#22c55e' };
}

function formatElapsed(scan: Scan, now: number) {
  const started = parseBackendTime(scan.start_time);
  const seconds = scan.status === 'running' && Number.isFinite(started)
    ? Math.max(0, Math.floor((now - started) / 1000))
    : Math.max(0, Math.floor(scan.duration_seconds || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  return hours > 0
    ? `${hours}h ${String(minutes).padStart(2, '0')}m ${String(remainder).padStart(2, '0')}s`
    : `${minutes}m ${String(remainder).padStart(2, '0')}s`;
}

/* ═══════════════════════════════════════════════════════════
   MAIN DASHBOARD
═══════════════════════════════════════════════════════════ */
export default function Dashboard() {
  /* Core data */
  const [scans,          setScans]          = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [findings,       setFindings]       = useState<Finding[]>([]);
	  const [agentStatus,    setAgentStatus]    = useState<Record<string, AgentStatus>>({});
	  const [toolRuns,       setToolRuns]       = useState<ToolRun[]>([]);
	  const [operation,      setOperation]      = useState<DurableOperation | null>(null);
	  const [coverage,       setCoverage]       = useState<ScanCoverage | null>(null);
  const [assurance,       setAssurance]       = useState<AssuranceCoverage | null>(null);
  const [assetGraph,      setAssetGraph]      = useState<AssetGraph | null>(null);
  const [decisions,      setDecisions]      = useState<AgentDecision[]>([]);
  const [attackChains,   setAttackChains]   = useState<AttackChainResult | null>(null);
  const [modes,          setModes]          = useState<ScanMode[]>([]);
  const [toolsStatus,    setToolsStatus]    = useState<Record<string, any>>({});
  const [dockerInfo,     setDockerInfo]     = useState<any>(null);
  const [runtimeLogs,    setRuntimeLogs]    = useState<RuntimeLogFile[]>([]);
  const [apiHealthy,     setApiHealthy]     = useState<boolean | null>(null);
  const [clockNow,       setClockNow]       = useState(() => Date.now());

  /* UI state */
  const [activeTab,         setActiveTab]         = useState<WorkspaceTab>('dashboard');
  const [severityFilter,    setSeverityFilter]    = useState<SeverityFilter>('all');
  const [showQuarantined,   setShowQuarantined]   = useState(false);
  const [expandedFindings,  setExpandedFindings]  = useState<Set<string>>(new Set());
  const [loadingInitial,    setLoadingInitial]    = useState(true);
  const [loadingFindings,   setLoadingFindings]   = useState(false);
  const [showReportModal,   setShowReportModal]   = useState(false);
  const [refreshing,        setRefreshing]        = useState(false);
  const [starting,          setStarting]          = useState(false);

  /* Command palette */
  const [cmdkOpen, setCmdkOpen] = useState(false);
  const { toggleTheme } = useTheme();

  /* Launch form */
  const [targetInput, setTargetInput] = useState('');
  const [outOfScopeInput, setOutOfScopeInput] = useState('');
  const [scanMode,    setScanMode]    = useState('va_only');
  const [scanName,    setScanName]    = useState('');
  const [intensity, setIntensity] = useState<'safe' | 'standard' | 'lab'>('safe');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [labTargetConfirmed, setLabTargetConfirmed] = useState(false);

  const seenEventsRef    = useRef<Set<string>>(new Set());
  // Keep a ref to selectedScanId so callbacks always see the current value
  // without needing to re-create on every selection change.
  const selectedScanIdRef = useRef<string | null>(null);
  selectedScanIdRef.current = selectedScanId;

  const toast = useToast();

  /* Derived */
  const selectedScan = scans.find(s => s.scan_id === selectedScanId) || scans[0];
  const activeModes  = modes.length ? modes : FALLBACK_MODES;
  const selectedMode = activeModes.find(m => m.id === scanMode) || activeModes[0];

  /* ─── Finding dedup helper ─── */
  const _mergeFinding = useCallback((prev: Finding[], f: Finding | SSEEvent): Finding[] => {
    const candidate = f as unknown as Finding;
    const k = `${candidate.title}|${candidate.target_host}|${candidate.created_at}`;
    if (prev.some(e => `${e.title}|${e.target_host}|${e.created_at}` === k)) return prev;
    return [...prev, candidate];
  }, []);

  /* ─── Event absorption ─────────────────────────────────────────
     Handles BOTH SSE and polling paths.
     - Deduplicates by composite key so the same event never appears twice.
     - Updates findings state when the event belongs to the viewed scan.
     - Operational telemetry is owned by LiveTelemetry, outside this render tree.
  ─────────────────────────────────────────────────────────────── */
  const absorbEvent = useCallback((event: SSEEvent) => {
    const key = [
      event.timestamp || '',
      event.type,
      event.scan_id || '',
      event.title || event.message || event.phase || event.agent_type || event.status || '',
    ].join('|');
    if (seenEventsRef.current.has(key)) return false;
    seenEventsRef.current.add(key);
    if (seenEventsRef.current.size > 1500) {
      seenEventsRef.current = new Set(Array.from(seenEventsRef.current).slice(-1000));
    }

    // Update findings when the event belongs to the currently-viewed scan.
    // This makes the polling path (/api/events) a functional fallback for SSE.
    if (event.type === 'finding') {
      const forScan = event.scan_id || '';
      const viewing = selectedScanIdRef.current || '';
      if (!forScan || forScan === viewing) {
        setFindings(prev => _mergeFinding(prev, event));
      }
      // Update finding count on the scan in the list regardless.
      setScans(prev => prev.map(s =>
        s.scan_id === forScan
          ? { ...s, total_findings: (s.total_findings || 0) + 1 }
          : s,
      ));
    }

    return true;
  }, [_mergeFinding]);

  /* ─── SSE handler ─── */
  const handleEvent = useCallback((event: SSEEvent) => {
    if (event.type === 'finding') {
      absorbEvent(event);
      return;
    }
    if (event.type === 'agent_status') {
      const forScan = event.scan_id || '';
      const viewing = selectedScanIdRef.current || '';
      if (!forScan || forScan === viewing) {
        const name = event.agent_type || event.data?.agent_type;
        const data = event.data || event;
        if (name) setAgentStatus(prev => ({ ...prev, [name]: data as AgentStatus }));
      }
      absorbEvent(event);
      return;
    }
    if (event.type === 'log') { absorbEvent(event); return; }
    if (event.type === 'tool_log') {
      // The control stream excludes these server-side. This guard keeps raw
      // scanner lines out of the monolithic workspace if an older API sends one.
      return;
    }
    if (event.type === 'phase_change') {
      const phase = event.phase || event.data?.phase;
      setScans(prev => prev.map(s =>
        s.scan_id === event.scan_id ? { ...s, current_phase: phase || s.current_phase } : s,
      ));
      absorbEvent(event);
      return;
    }
    if (event.type === 'phase_complete' || event.type === 'surface_update') {
      if (event.scan_id && event.scan_id === selectedScanIdRef.current) {
        api.getAssetGraph(event.scan_id).then(setAssetGraph).catch(() => {});
        api.getToolRuns(event.scan_id).then(r => setToolRuns(r.tool_runs)).catch(() => {});
        api.getOperation(event.scan_id).then(setOperation).catch(() => {});
        api.getAssurance(event.scan_id).then(setAssurance).catch(() => {});
      }
      absorbEvent(event);
      return;
    }
    if (event.type === 'scan_started') {
      api.listScans()
        .then(list => {
          const ordered = orderScans(list);
          setScans(ordered);
          // Auto-switch to the new scan.
          setSelectedScanId(event.scan_id || ordered[0]?.scan_id || null);
        })
        .catch(() => {});
      absorbEvent(event);
      return;
    }
    if (event.type === 'scan_deleted') {
      const deletedId = event.scan_id;
      setScans(prev => prev.filter(scan => scan.scan_id !== deletedId));
      if (deletedId && deletedId === selectedScanIdRef.current) {
        setSelectedScanId(null);
        setFindings([]);
        setAgentStatus({});
        setToolRuns([]);
        setOperation(null);
        setAssurance(null);
        setAssetGraph(null);
      }
      absorbEvent(event);
      return;
    }
    if (event.type === 'scan_complete' || event.type === 'scan_failed') {
      // Refresh both list AND findings for the completed scan so the UI is consistent.
      api.listScans().then(list => setScans(orderScans(list))).catch(() => {});
      const completedId = event.scan_id;
      if (completedId && completedId === selectedScanIdRef.current) {
        api.getFindings(completedId)
          .then(r => setFindings(r.findings))
          .catch(() => {});
      }
      absorbEvent(event);
    }
  }, [absorbEvent]);

  const { connected } = useSSE(handleEvent, { channel: 'control' });

  /* ─── Data loading ─── */
  const refreshAll = useCallback(async () => {
    const [scanList, modeList, health, tools, logs] = await Promise.allSettled([
      api.listScans(),
      api.getModes(),
      api.getHealth(),
      api.getToolsStatus() as Promise<any>,
      api.listLogs(),
    ]);
    if (scanList.status === 'fulfilled') {
      const ordered = orderScans(scanList.value);
      setScans(ordered);
      setSelectedScanId(cur => {
        // If current selection is valid and still in the list, keep it.
        if (cur && ordered.some(s => s.scan_id === cur)) return cur;
        // Otherwise pick the first running scan, or most recent.
        return ordered[0]?.scan_id || null;
      });
    }
    if (modeList.status === 'fulfilled') setModes(modeList.value.modes);
    if (health.status === 'fulfilled') {
      setApiHealthy(true);
    } else {
      setApiHealthy(false);
    }
    if (tools.status === 'fulfilled') {
      setToolsStatus(tools.value.tools || {});
      setDockerInfo(tools.value.docker || null);
    }
    if (logs.status === 'fulfilled') setRuntimeLogs(logs.value.files || []);
  }, []);

  useEffect(() => {
    refreshAll()
      .catch(() => setApiHealthy(false))
      .finally(() => setLoadingInitial(false));
  }, [refreshAll]);

  useEffect(() => {
    if (!selectedScan?.scan_id) return;
    // Clear stale findings immediately so we don't flash wrong data while loading.
	    setFindings([]);
	    setAgentStatus({});
	    setToolRuns([]);
	    setOperation(null);
	    setCoverage(null);
	    setAssurance(null);
	    setAssetGraph(null);
	    setDecisions([]);
	    setAttackChains(null);
	    setLoadingFindings(true);
	    Promise.allSettled([
	      api.getFindings(selectedScan.scan_id),
	      api.getAgentStatus(selectedScan.scan_id),
	      api.getToolRuns(selectedScan.scan_id),
	      api.getOperation(selectedScan.scan_id),
	      api.getCoverage(selectedScan.scan_id),
	      api.getAssurance(selectedScan.scan_id),
	      api.getAssetGraph(selectedScan.scan_id),
	      api.getDecisions(selectedScan.scan_id),
	      api.getAttackChains(selectedScan.scan_id),
	    ]).then(([findingsRes, agentRes, toolRunRes, operationRes, coverageRes, controlRes, assetRes, decisionsRes, chainsRes]) => {
	      if (findingsRes.status === 'fulfilled') setFindings(findingsRes.value.findings);
	      if (agentRes.status === 'fulfilled')    setAgentStatus(agentRes.value.agents);
	      if (toolRunRes.status === 'fulfilled')  setToolRuns(toolRunRes.value.tool_runs);
	      if (operationRes.status === 'fulfilled') setOperation(operationRes.value);
	      if (coverageRes.status === 'fulfilled') setCoverage(coverageRes.value.coverage);
	      if (controlRes.status === 'fulfilled') setAssurance(controlRes.value);
	      if (assetRes.status === 'fulfilled') setAssetGraph(assetRes.value);
	      if (decisionsRes.status === 'fulfilled') setDecisions(decisionsRes.value.decisions);
	      if (chainsRes.status === 'fulfilled') setAttackChains(chainsRes.value);
	    }).finally(() => setLoadingFindings(false));
  }, [selectedScan?.scan_id]);

  useEffect(() => {
    if (!selectedScan?.scan_id) return;
    const loadEvents = () => {
      api.getEvents(selectedScan.scan_id, 300)
        .then(r => r.events.forEach(absorbEvent))
        .catch(() => {});
    };
    loadEvents();
    const iv = setInterval(
      loadEvents,
      connected ? 30000 : (selectedScan.status === 'running' ? 3500 : 10000),
    );
    return () => clearInterval(iv);
  }, [selectedScan?.scan_id, selectedScan?.status, connected, absorbEvent]);

	  useEffect(() => {
	    if (!selectedScan?.scan_id) return;
	    const loadToolRuns = () => {
	      Promise.allSettled([
	        api.getToolRuns(selectedScan.scan_id),
	        api.getOperation(selectedScan.scan_id),
	        api.getCoverage(selectedScan.scan_id),
	        api.getAssurance(selectedScan.scan_id),
	        api.getAssetGraph(selectedScan.scan_id),
	        api.getDecisions(selectedScan.scan_id),
	        api.getAttackChains(selectedScan.scan_id),
	      ]).then(([toolRunRes, operationRes, coverageRes, controlRes, assetRes, decisionsRes, chainsRes]) => {
	        if (toolRunRes.status === 'fulfilled') setToolRuns(toolRunRes.value.tool_runs);
	        if (operationRes.status === 'fulfilled') setOperation(operationRes.value);
	        if (coverageRes.status === 'fulfilled') setCoverage(coverageRes.value.coverage);
	        if (controlRes.status === 'fulfilled') setAssurance(controlRes.value);
	        if (assetRes.status === 'fulfilled') setAssetGraph(assetRes.value);
	        if (decisionsRes.status === 'fulfilled') setDecisions(decisionsRes.value.decisions);
	        if (chainsRes.status === 'fulfilled') setAttackChains(chainsRes.value);
	      })
	        .catch(() => {});
	    };
    loadToolRuns();
    const iv = setInterval(loadToolRuns, selectedScan.status === 'running' ? 7000 : 30000);
    return () => clearInterval(iv);
  }, [selectedScan?.scan_id, selectedScan?.status]);

  useEffect(() => {
    const iv = setInterval(() => refreshAll().catch(() => {}), 30000);
    return () => clearInterval(iv);
  }, [refreshAll]);

  useEffect(() => {
    if (selectedScan?.status !== 'running') return;
    const iv = setInterval(() => setClockNow(Date.now()), 1000);
    return () => clearInterval(iv);
  }, [selectedScan?.status]);

  /* ─── Actions ─── */
  const startScan = async () => {
    const targets = targetInput.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    const outOfScope = outOfScopeInput.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targets.length || !authorizationConfirmed || (intensity === 'lab' && !labTargetConfirmed)) return;
    setStarting(true);
    try {
      const result = await api.startScan(
        targets,
        scanMode,
        scanName || `Scan ${new Date().toLocaleDateString()}`,
        {
          out_of_scope: outOfScope,
          intensity,
          authorization_confirmed: authorizationConfirmed,
          lab_target_confirmed: intensity === 'lab' && labTargetConfirmed,
        },
      );
      setSelectedScanId(result.scan_id);
      setFindings([]);
      setAgentStatus({});
      setTargetInput('');
      setOutOfScopeInput('');
      setScanName('');
      setAuthorizationConfirmed(false);
      setLabTargetConfirmed(false);
      toast.success('Scan launched', `${targets.join(', ')} is now being assessed`);
      await refreshAll();
    } catch (e: any) {
      toast.error('Failed to start scan', e.message);
    } finally {
      setStarting(false);
    }
  };

  const stopScan = async () => {
    if (!selectedScan?.scan_id) return;
    try {
      await api.stopScan(selectedScan.scan_id);
      toast.warn('Scan stopped', selectedScan.name);
      await refreshAll();
    } catch (e: any) {
      toast.error('Failed to stop scan', e.message);
    }
  };

  const deleteScan = async (scan: Scan, event?: React.SyntheticEvent) => {
    event?.stopPropagation();
    if (!scan?.scan_id || scan.status === 'running') return;
    try {
      await api.deleteScan(scan.scan_id);
      toast.success('Scan deleted', scan.name || scan.scan_id);
      if (selectedScanId === scan.scan_id) {
        setSelectedScanId(null);
      }
      await refreshAll();
    } catch (e: any) {
      toast.error('Delete failed', e.message);
    }
  };

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refreshAll();
    } catch (e: any) {
      toast.error('Refresh failed', e.message);
    } finally {
      setTimeout(() => setRefreshing(false), 400);
    }
  }, [refreshAll, toast]);

  const handleFindingTriage = useCallback(async (finding: Finding, disposition: string, reason: string) => {
    if (!selectedScan?.scan_id || !finding.finding_id) return;
    try {
      const result = await api.triageFinding(
        selectedScan.scan_id, finding.finding_id, disposition, reason,
      );
      setFindings(previous => previous.map(item => (
        item.finding_id === finding.finding_id ? result.finding : item
      )));
      toast.success('Finding disposition recorded', disposition.replace(/_/g, ' '));
    } catch (error) {
      toast.error('Triage failed', error instanceof Error ? error.message : String(error));
      throw error;
    }
  }, [selectedScan?.scan_id, toast]);

  const toggleFinding = useCallback((key: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  /* ─── Derived values ─── */
  const severityCounts = useMemo<Record<SeverityKey, number>>(() => {
    const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    if (findings.length) {
      findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
      return counts;
    }
    // Only fall back to scan-list metadata when we're NOT actively loading.
    // This prevents "Medium 1 / 0 of 0 findings" flash during the fetch.
    if (selectedScan && !loadingFindings) {
      counts.critical      = selectedScan.critical_count || 0;
      counts.high          = selectedScan.high_count     || 0;
      counts.medium        = selectedScan.medium_count   || 0;
      counts.low           = selectedScan.low_count      || 0;
      counts.informational = selectedScan.info_count     || 0;
    }
    return counts;
  }, [findings, selectedScan, loadingFindings]);

  const sortedFindings = useMemo(() => {
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
    return [...findings].sort((a, b) => {
      const delta = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
      return delta !== 0 ? delta : (b.cvss_score || 0) - (a.cvss_score || 0);
    });
  }, [findings]);

  const filteredFindings = useMemo(
    () => {
      const bySeverity = severityFilter === 'all' ? sortedFindings : sortedFindings.filter(f => f.severity === severityFilter);
      return showQuarantined ? bySeverity : bySeverity.filter(f => !f.quarantined);
    },
    [severityFilter, sortedFindings, showQuarantined],
  );
  const quarantinedCount = useMemo(() => findings.filter(f => f.quarantined).length, [findings]);
  const verifiedFindings = useMemo(
    () => findings.filter(f => {
      const tags = new Set((f.tags || []).map(tag => tag.toLowerCase()));
      const replayProof = Boolean(f.request_proof && f.response_proof);
      const independentProof = tags.has('dast-proof') || tags.has('provider-verified') || tags.has('replay-proof');
      return f.status === 'confirmed' && !f.quarantined && (replayProof || independentProof);
    }),
    [findings],
  );
  const candidateFindings = Math.max(0, findings.length - verifiedFindings.length);
  const surfaceCount = assetGraph?.total_assets || 0;
  const mappedSurfaceAssets = useMemo(
    () => (assetGraph?.assets || []).filter(asset => ['domain', 'subdomain', 'service', 'technology', 'api_endpoint', 'url'].includes(asset.asset_type)).slice(0, 24),
    [assetGraph?.assets],
  );
  const assetLabelByKey = useMemo(
    () => new Map((assetGraph?.assets || []).map(asset => [asset.asset_key, asset.value])),
    [assetGraph?.assets],
  );

  const priorityFindings   = [...verifiedFindings, ...sortedFindings.filter(item => !verifiedFindings.includes(item))].slice(0, 8);
  const agentEntries       = useMemo(() => Object.entries(agentStatus), [agentStatus]);
  const partialToolRuns    = useMemo(() => toolRuns.filter(run => run.partial), [toolRuns]);
  const failedToolRuns     = useMemo(() => toolRuns.filter(run => !run.success && !run.partial), [toolRuns]);
  const totalFindings      = Object.values(severityCounts).reduce((s, v) => s + v, 0);
  const posture            = riskPosture(severityCounts);
  const targetCount        = useMemo(() => {
    const allTargets = new Set(scans.flatMap(s => s.targets || []));
    if (allTargets.size > 0) return allTargets.size;
    return targetInput.split(/[\n,]+/).map(t => t.trim()).filter(Boolean).length;
  }, [scans, targetInput]);
  const agentProgress      = agentEntries.length
    ? Math.round(agentEntries.reduce((s, [, a]) => s + (a.progress_pct || (a.status === 'completed' ? 100 : 0)), 0) / agentEntries.length)
    : 0;
  const activeScans   = scans.filter(s => s.status === 'running').length;
  const dockerReady   = Boolean(dockerInfo?.daemon_reachable);
  const capabilityCoverage = useMemo(() => {
    const labels: Record<string, string> = {
      recon: 'Discovery & attack surface', enumeration: 'Network & service mapping',
      vuln_scanning: 'Vulnerability validation', fuzzing: 'Web & API assessment',
      exploitation: 'Impact validation', intelligence: 'Intelligence & correlation',
      reporting: 'Evidence & reporting',
    };
    type CoverageItem = {
      name: string;
      displayName: string;
      state: 'ready' | 'on_demand' | 'blocked';
      reason: string;
      actionLabel: string;
    };
    type CoverageGroup = {
      label: string;
      total: number;
      ready: number;
      onDemand: number;
      blocked: number;
      items: CoverageItem[];
    };
    const groups: Record<string, CoverageGroup> = {};
    Object.entries(toolsStatus).forEach(([name, tool]: [string, any]) => {
      const phase = (tool.phases || [])[0] || 'extensions';
      const group = groups[phase] ||= {
        label: labels[phase] || 'Extension capabilities',
        total: 0,
        ready: 0,
        onDemand: 0,
        blocked: 0,
        items: [],
      };
      group.total += 1;
      const ready = tool.availability === 'ready' && ['docker', 'local', 'internal', 'api'].includes(tool.will_use);
      const onDemand = tool.availability === 'pullable';
      let state: CoverageItem['state'] = 'blocked';
      let reason = 'No approved local or container adapter is available.';
      let actionLabel = 'adapter not installed';
      if (ready) {
        state = 'ready';
        reason = `${tool.will_use} adapter is ready.`;
        actionLabel = 'ready';
        group.ready += 1;
      } else if (onDemand) {
        state = 'on_demand';
        reason = 'Approved image will be pulled only when evidence and policy select this capability.';
        actionLabel = 'available on demand';
        group.onDemand += 1;
      } else {
        group.blocked += 1;
        if (tool.availability === 'needs_api_key') {
          reason = 'An external provider credential is required; the platform cannot create this secret.';
          actionLabel = 'credential required';
        } else if (tool.availability === 'disabled_by_config') {
          reason = 'This capability is intentionally disabled by engagement policy.';
          actionLabel = 'policy disabled';
        }
      }
      group.items.push({
        name,
        displayName: tool.display_name || name,
        state,
        reason,
        actionLabel,
      });
    });
    Object.values(groups).forEach(group => group.items.sort((a, b) => a.displayName.localeCompare(b.displayName)));
    return Object.entries(groups).sort((a, b) => a[1].label.localeCompare(b[1].label));
  }, [toolsStatus]);
  const capabilityTotals = useMemo(() => capabilityCoverage.reduce(
    (totals, [, group]) => ({
      ready: totals.ready + group.ready,
      onDemand: totals.onDemand + group.onDemand,
      blocked: totals.blocked + group.blocked,
    }),
    { ready: 0, onDemand: 0, blocked: 0 },
  ), [capabilityCoverage]);

  const currentPhaseIndex = selectedScan ? PHASE_ORDER.findIndex(p => p === selectedScan.current_phase) : -1;

  /* ─── Render ────────────────────────────────────────────── */
  /* Global ⌘K / Ctrl+K to toggle the command palette */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setCmdkOpen(o => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const commandActions: CommandAction[] = [
    { id: 'nav-dashboard', group: 'Navigate', label: 'Command Center', sub: 'Authorised scopes and live execution', icon: LayoutDashboard, hint: ['1'], keywords: 'home overview scan dast', run: () => setActiveTab('dashboard') },
    { id: 'nav-live', group: 'Navigate', label: 'Live Scan', sub: 'Durable actions, tool outcomes and evidence', icon: Activity, hint: ['2'], keywords: 'live mission telemetry operation', run: () => setActiveTab('live') },
    { id: 'nav-recon', group: 'Navigate', label: 'Recon Intel', sub: 'Canonical attack surface inventory', icon: Radar, hint: ['3'], keywords: 'recon assets technology endpoints', run: () => setActiveTab('recon') },
    { id: 'nav-findings', group: 'Navigate', label: 'Findings', sub: 'Vulnerabilities', icon: ShieldAlert, hint: ['2'], keywords: 'vulns issues', run: () => setActiveTab('findings') },
    { id: 'nav-agents', group: 'Navigate', label: 'Attack Surface', sub: 'Canonical assets, paths and decisions', icon: Bot, hint: ['3'], keywords: 'paths decisions evidence surface', run: () => setActiveTab('agents') },
    { id: 'nav-dast', group: 'Navigate', label: 'DAST & API Validation', sub: 'Typed validators and WSTG evidence', icon: ScanSearch, keywords: 'dast api web testing validation proof', run: () => setActiveTab('dast') },
    { id: 'nav-govern', group: 'Navigate', label: 'Test Coverage', sub: 'OWASP WSTG evidence coverage', icon: ClipboardCheck, hint: ['4'], keywords: 'wstg asvs testing evidence audit', run: () => setActiveTab('govern') },
    { id: 'nav-tools', group: 'Administration', label: 'Operations', sub: 'Runner health and logs', icon: Wrench, hint: ['5'], keywords: 'status logs api keys', run: () => setActiveTab('tools') },
    {
      id: 'act-new-scan', group: 'Actions', label: 'New assessment', sub: 'Define an authorised scope', icon: Play, keywords: 'start run target',
      run: () => { setActiveTab('dashboard'); if (targetInput.trim()) startScan(); },
    },
    { id: 'act-refresh', group: 'Actions', label: 'Refresh data', icon: RefreshCw, hint: ['R'], keywords: 'reload sync', run: () => handleRefresh() },
    {
      id: 'act-report', group: 'Actions', label: 'Download report', sub: selectedScan ? undefined : 'Select a scan first', icon: FileText, keywords: 'export pdf html',
      run: () => { if (selectedScan) setShowReportModal(true); else toast.info('No scan selected', 'Pick a scan to export a report.'); },
    },
    { id: 'act-quarantine', group: 'Actions', label: 'Toggle quarantined findings', icon: ShieldAlert, keywords: 'hide show low evidence', run: () => { setActiveTab('findings'); setShowQuarantined(v => !v); } },
    { id: 'act-theme', group: 'Preferences', label: 'Toggle light / dark theme', icon: Moon, keywords: 'appearance dark light', run: () => toggleTheme() },
  ];

  return (
    <div className="app-shell">
      {/* Command palette */}
      <CommandPalette open={cmdkOpen} onClose={() => setCmdkOpen(false)} actions={commandActions} />

      {/* Toast notifications */}
      <ToastContainer toasts={toast.toasts} onDismiss={toast.dismiss} />

      {/* Report download modal */}
      {showReportModal && selectedScan && (
        <ReportModal
          scan={selectedScan}
          onClose={() => setShowReportModal(false)}
          onError={msg => toast.error('Download failed', msg)}
        />
      )}

      {/* Sidebar — desktop */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        scanCount={scans.length}
        findingCount={totalFindings}
        attackPathCount={attackChains?.summary.total || 0}
        connected={connected}
        apiHealthy={apiHealthy}
      />

      {/* Workspace */}
      <div className="workspace">
        {/* Header */}
        <Header
          apiHealthy={apiHealthy}
          connected={connected}
          targetCount={targetCount}
          refreshing={refreshing}
          onRefresh={handleRefresh}
          onOpenCommand={() => setCmdkOpen(true)}
        />

        {/* Mobile tab bar */}
        <MobileTabBar activeTab={activeTab} onTabChange={setActiveTab} />

        {/* Main content */}
        <main className="content-area">

          {/* Backend-unreachable banner — persistent while offline */}
          {apiHealthy === false && !loadingInitial && (
            <div className="offline-banner" role="alert">
              <WifiOff size={15} aria-hidden="true" style={{ flexShrink: 0 }} />
              <span>Backend unreachable — showing the last known data. Reconnecting automatically.</span>
              <button
                className="btn btn-secondary"
                onClick={handleRefresh}
                disabled={refreshing}
                style={{ marginLeft: 'auto', flexShrink: 0 }}
              >
                <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
                Retry
              </button>
            </div>
          )}

          <WorkspaceErrorBoundary workspace={activeTab}>

          {/* ── DASHBOARD TAB ─────────────────────────────── */}
          {activeTab === 'dashboard' && (
            loadingInitial ? <SkeletonDashboard /> : (
              <div className="dashboard-stack">

                {/* Mission banner */}
                <section className="mission-banner">
                  <div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                      <span className={`badge ${statusBadgeClass(selectedScan?.status)}`}>
                        {selectedScan?.status || 'standby'}
                      </span>
                      <span style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center' }}>
                        {selectedScan?.scan_id || 'no-scan-selected'}
                      </span>
                      {selectedScan?.current_phase && (
                        <span style={{
                          fontSize: 11, padding: '2px 8px', borderRadius: 6,
                          border: '1px solid var(--accent-border)',
                          background: 'var(--accent-dim)',
                          color: 'var(--accent)',
                        }}>
                          {formatPhase(selectedScan.current_phase)}
                        </span>
                      )}
                    </div>
                    <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {selectedScan?.name || 'Ready to launch assessment'}
                    </h2>
                    <p style={{ marginTop: 5, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, maxWidth: 700 }}>
                      {selectedScan
                        ? `${selectedScan.targets?.join(', ')} is under assessment. Verified surface evidence, test decisions and findings update in real time.`
                        : 'Define an authorised scope and launch an assessment. The workspace will show live application surfaces, validation progress and evidence-backed findings.'}
                    </p>
                  </div>

                  <div style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    gap: 4, padding: '10px 14px',
                    border: '1px solid rgba(255,255,255,0.07)',
                    borderRadius: 10, background: 'rgba(0,0,0,0.15)', minWidth: 100, textAlign: 'center',
                  }}>
                    <div className="section-label">Risk posture</div>
                    <div style={{
                      display: 'grid', placeItems: 'center',
                      width: 52, height: 52, borderRadius: '50%',
                      border: '1px solid rgba(255,255,255,0.1)',
                      background: 'rgba(0,0,0,0.18)',
                      fontFamily: 'var(--font-jetbrains), monospace',
                      fontSize: '1.1rem', fontWeight: 700,
                      color: posture.color, fontVariantNumeric: 'tabular-nums',
                    }}>
                      {posture.score}
                    </div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: posture.color }}>{posture.label}</div>
                  </div>
                </section>

                {/* KPI cards */}
                <section className="kpi-grid">
                  <MetricCard icon={Activity}      label="Active Assessments" value={activeScans} sub={`${scans.length} total`} tone="cyan" />
                  <MetricCard icon={ShieldCheck}   label="Behavior-verified" value={verifiedFindings.length} sub="replayable proof" tone="red" />
                  <MetricCard icon={Target}        label="Discovered Surface" value={surfaceCount} sub="durable evidence objects" tone="emerald" />
                  <MetricCard icon={Bug}           label="Candidate Leads" value={candidateFindings} sub="requires validation" tone="amber" />
                </section>

                {/* Workbench */}
                <section className="dashboard-workbench">
                  {/* Launch panel */}
                  <LaunchPanel
                    targetInput={targetInput}
                    setTargetInput={setTargetInput}
                    outOfScopeInput={outOfScopeInput}
                    setOutOfScopeInput={setOutOfScopeInput}
                    scanMode={scanMode}
                    setScanMode={setScanMode}
                    scanName={scanName}
                    setScanName={setScanName}
                    intensity={intensity}
                    setIntensity={setIntensity}
                    authorizationConfirmed={authorizationConfirmed}
                    setAuthorizationConfirmed={setAuthorizationConfirmed}
                    labTargetConfirmed={labTargetConfirmed}
                    setLabTargetConfirmed={setLabTargetConfirmed}
                    activeModes={activeModes}
                    selectedMode={selectedMode}
                    starting={starting}
                    onStart={startScan}
                    onRefresh={handleRefresh}
                    refreshing={refreshing}
                  />

                  {/* Right side operations */}
                  <div className="operations-grid">
                    {/* Engagement timeline + findings + agents */}
                    <div className="card-glass" style={{ padding: 16 }}>
                      {/* Header */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 14 }}>
                        <div>
                          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Engagement Timeline</h2>
                          <p style={{ marginTop: 3, fontSize: 12, color: 'var(--text-secondary)' }}>
                            {selectedScan ? `${selectedScan.targets?.join(', ')} — elapsed ${formatElapsed(selectedScan, clockNow)}` : 'No active engagement'}
                          </p>
                        </div>
                        {selectedScan && (
                          <div style={{ display: 'flex', gap: 8 }}>
                            {selectedScan.status === 'running' && (
                              <button onClick={stopScan} className="btn btn-danger">
                                <CircleStop size={14} />Stop
                              </button>
                            )}
                            <button onClick={() => setShowReportModal(true)} disabled={selectedScan.status !== 'completed'} title={selectedScan.status === 'completed' ? 'Download final report' : 'Available after all scan phases complete'} className="btn btn-secondary">
                              <Download size={14} />Report
                            </button>
                            {selectedScan.status !== 'running' && (
                              <button onClick={(event) => deleteScan(selectedScan, event)} className="btn btn-secondary" title="Delete scan">
                                <Trash2 size={14} />Delete
                              </button>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Severity overview */}
                      <div className="severity-overview">
                        <SeverityDonut counts={severityCounts} total={totalFindings} />
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(70px, 1fr))', gap: 8 }}>
                          {SEVERITIES.map(sev => (
                            <div
                              key={sev}
                              className="severity-card-mini"
                              style={{ borderColor: `${SEV_HEX[sev]}55`, background: `${SEV_HEX[sev]}0d` }}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
                                <span style={{ width: 7, height: 7, borderRadius: '50%', background: SEV_HEX[sev], flexShrink: 0, display: 'block' }} aria-hidden="true" />
                                <span style={{
                                  fontFamily: 'var(--font-jetbrains), monospace',
                                  fontSize: 18, fontWeight: 700,
                                  color: SEV_HEX[sev],
                                  fontVariantNumeric: 'tabular-nums',
                                }}>
                                  {severityCounts[sev]}
                                </span>
                              </div>
                              <div style={{ marginTop: 4, fontSize: 10, textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
                                {sev === 'informational' ? 'info' : sev}
                              </div>
                              <div style={{ marginTop: 6, height: 3, borderRadius: 2, background: 'rgba(0,0,0,0.25)', overflow: 'hidden' }}>
                                <div style={{
                                  height: '100%', borderRadius: 2, background: SEV_HEX[sev],
                                  width: `${totalFindings ? (severityCounts[sev] / totalFindings) * 100 : 0}%`,
                                  transition: 'width 400ms ease',
                                }} />
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Phase steps */}
                      <div className="phase-grid">
                        {PHASE_ORDER.map((phase, i) => {
                          const active = selectedScan?.current_phase === phase;
                          const done   = currentPhaseIndex > i || selectedScan?.status === 'completed';
                          return (
                            <div key={phase} className={`phase-step${active ? ' active' : done ? ' done' : ''}`}>
                              <span className="phase-num">
                                {done ? <CheckCircle2 size={11} aria-hidden="true" /> : i + 1}
                              </span>
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11 }}>
                                {formatPhase(phase)}
                              </span>
                            </div>
                          );
                        })}
                      </div>

                      {operation && (
                        <div className="durable-operation" aria-label="Durable operation status">
                          <div className="durable-operation-head">
                            <div>
                              <span className="section-label">Durable action ledger</span>
                              <p>
                                Results survive runner disconnects · replay cursor {operation.reconnect_cursor || '—'}
                              </p>
                            </div>
                            <div className="durable-operation-summary">
                              <span>{operation.summary.completed} completed</span>
                              {operation.summary.running > 0 && <span className="is-running">{operation.summary.running} running</span>}
                              {operation.summary.partial > 0 && <span className="is-partial">{operation.summary.partial} partial</span>}
                              {operation.summary.retrying > 0 && <span className="is-retrying">{operation.summary.retrying} retrying</span>}
                              {operation.summary.failed > 0 && <span className="is-failed">{operation.summary.failed} failed</span>}
                            </div>
                          </div>
                          {operation.actions.length === 0 ? (
                            <div className="durable-operation-empty">Capability actions appear when the first approved tool is queued.</div>
                          ) : (
                            <div className="durable-action-list">
                              {operation.actions.slice(-5).reverse().map(action => (
                                <div key={action.action_id} className="durable-action-row">
                                  <span className={`action-state action-state-${action.status}`} aria-hidden="true" />
                                  <div>
                                    <strong>{action.capability || action.tool}</strong>
                                    <span>{formatPhase(action.phase)} · {action.runner} · attempt {action.attempt}/{action.max_attempts}</span>
                                  </div>
                                  <span className={`badge ${action.status === 'completed' ? 'badge-completed' : action.status === 'running' ? 'badge-running' : action.status === 'failed' || action.status === 'timed_out' ? 'badge-failed' : 'badge-idle'}`}>
                                    {action.status.replaceAll('_', ' ')}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Scan list */}
                      <div style={{ maxHeight: 200, overflowY: 'auto', display: 'grid', gap: 6, marginBottom: 14 }}>
                        {scans.length === 0 ? (
                          <StateView variant="empty" compact icon={Shield} title="No scans yet" body="Launch your first scan from the panel on the left." />
                        ) : (
                          scans.map(scan => (
                            <div
                              key={scan.scan_id}
                              role="button"
                              tabIndex={0}
                              onClick={() => setSelectedScanId(scan.scan_id)}
                              onKeyDown={(event) => {
                                if (event.key === 'Enter' || event.key === ' ') setSelectedScanId(scan.scan_id);
                              }}
                              className={`scan-row${selectedScan?.scan_id === scan.scan_id ? ' selected' : ''}`}
                            >
                              <div style={{ minWidth: 0 }}>
                                <div style={{ fontSize: 13, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                                  {scan.name || scan.scan_id}
                                </div>
                                <div style={{ marginTop: 3, fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-jetbrains), monospace' }}>
                                  {scan.targets?.join(', ')} · {scan.mode}
                                </div>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                                <span className={`badge ${statusBadgeClass(scan.status)}`}>{scan.status}</span>
                                {scan.status !== 'running' && (
                                  <button
                                    type="button"
                                    tabIndex={0}
                                    onClick={(event) => deleteScan(scan, event)}
                                    className="icon-button"
                                    title="Delete scan"
                                  >
                                    <Trash2 size={13} aria-hidden="true" />
                                  </button>
                                )}
                                <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} aria-hidden="true" />
                              </div>
                            </div>
                          ))
                        )}
                      </div>

                      {/* Priority findings + live surface */}
                      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14, display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 280px', gap: 14 }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                            <span className="section-label">Priority Findings</span>
                            <button
                              onClick={() => setActiveTab('findings')}
                              style={{ fontSize: 11, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 500 }}
                            >
                              View all →
                            </button>
                          </div>
                          {priorityFindings.length === 0 ? (
                            <div className="quiet-empty">No findings for selected scan.</div>
                          ) : (
                            <div>
                              {priorityFindings.map((f, i) => (
                                <div key={`${f.title}-${f.target_host}-${i}`} className="finding-strip">
                                  <span className="sev-dot" style={{ background: SEV_DOT_COLOR[f.severity] || '#06b6d4' }} aria-hidden="true" />
                                  <div style={{ minWidth: 0, flex: 1 }}>
                                    <div style={{ fontSize: 12, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>{f.title}</div>
                                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-jetbrains), monospace', marginTop: 2 }}>
                                      {f.target_display || `${f.target_host}:${f.target_port}`} · {f.agent_source}
                                    </div>
                                  </div>
                                  <span className={`badge ${SEV_BADGE_CLASS[f.severity] || 'badge-informational'}`}>
                                    {f.severity === 'informational' ? 'info' : f.severity}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>

                        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 14 }}>
                          <span className="section-label" style={{ display: 'block', marginBottom: 10 }}>Live Attack Surface</span>
                          {!assetGraph || assetGraph.total_assets === 0 ? (
                            <div className="quiet-empty">Verified hosts, URLs, technologies and parameters appear after each phase.</div>
                          ) : (
                            <div style={{ display: 'grid', gap: 8 }}>
                              {Object.entries(assetGraph.summary).slice(0, 8).map(([type, count]) => (
                                <div key={type} className="agent-line">
                                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                                    <span style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                                      {type.replaceAll('_', ' ')}
                                    </span>
                                    <span className="badge badge-informational">{count}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                  </div>
                </section>
              </div>
            )
          )}

          {activeTab === 'findings' && (
            <FindingsWorkspace
              findings={findings}
              filteredFindings={filteredFindings}
              severityCounts={severityCounts}
              severityFilter={severityFilter}
              onSeverityFilter={setSeverityFilter}
              showQuarantined={showQuarantined}
              onShowQuarantined={setShowQuarantined}
              quarantinedCount={quarantinedCount}
              expandedFindings={expandedFindings}
              onToggleFinding={toggleFinding}
              loading={loadingFindings}
              apiHealthy={apiHealthy}
              selectedScan={selectedScan}
              refreshing={refreshing}
              onRefresh={handleRefresh}
              onReport={() => setShowReportModal(true)}
              onTriage={handleFindingTriage}
            />
          )}

          {/* ── ATTACK PATHS TAB ──────────────────────────── */}
          {activeTab === 'agents' && (
            <AttackSurfaceWorkspace
              selectedScan={selectedScan}
              loadingInitial={loadingInitial}
              agentEntries={agentEntries}
              agentProgress={agentProgress}
              assetGraph={assetGraph}
              mappedSurfaceAssets={mappedSurfaceAssets}
              assetLabelByKey={assetLabelByKey}
              decisions={decisions}
              attackChains={attackChains}
              coverage={coverage}
              toolRuns={toolRuns}
              partialToolRuns={partialToolRuns}
              failedToolRuns={failedToolRuns}
              onRefreshToolRuns={() => selectedScan?.scan_id && api.getToolRuns(selectedScan.scan_id).then(result => setToolRuns(result.tool_runs)).catch(() => {})}
            />
          )}

          {activeTab === 'govern' && (
            <TestCoverageWorkspace selectedScan={selectedScan} assurance={assurance} />
          )}

          {activeTab === 'tools' && (
            <OperationsWorkspace
              dockerReady={dockerReady}
              dockerInfo={dockerInfo}
              totals={capabilityTotals}
              runtimeLogs={runtimeLogs}
              coverage={capabilityCoverage}
              apiHealthy={apiHealthy}
              onRefreshLogs={() => api.listLogs().then(result => setRuntimeLogs(result.files || [])).catch(() => {})}
              onDeleteLog={(file) => {
                if (!window.confirm(`${file.name === 'vapt-runtime.log' ? 'Clear' : 'Delete'} ${file.name}?`)) return;
                api.deleteLog(file.name)
                  .then(() => api.listLogs())
                  .then(result => setRuntimeLogs(result.files || []))
                  .then(() => toast.success('Runtime log updated', file.name))
                  .catch((error: Error) => toast.error('Could not update runtime log', error.message));
              }}
              onRetry={handleRefresh}
            />
          )}

          {activeTab === 'live' && (
            <LiveScanWorkspace
              selectedScan={selectedScan}
              scans={scans}
              operation={operation}
              toolRuns={toolRuns}
              findings={findings}
              assetGraph={assetGraph}
              decisions={decisions}
              onSelectScan={setSelectedScanId}
              onStop={stopScan}
              onReport={() => setShowReportModal(true)}
            />
          )}

          {activeTab === 'recon' && (
            <ReconIntelWorkspace selectedScan={selectedScan} graph={assetGraph} toolRuns={toolRuns} />
          )}

          {activeTab === 'dast' && (
            <DastWorkspace
              selectedScan={selectedScan}
              assurance={assurance}
              findings={findings}
              toolRuns={toolRuns}
              decisions={decisions}
              onStartAssessment={() => { setScanMode('full_vapt'); setActiveTab('dashboard'); }}
            />
          )}

          {activeTab === 'appsec' && <AppSecWorkspace />}

          {/* ── CONFIG TAB ─────────────────────────────────── */}
          {activeTab === 'config' && (
            <LLMConfigPanel />
          )}

          </WorkspaceErrorBoundary>

        </main>
        <WorkspaceErrorBoundary workspace="live telemetry">
          <LiveTelemetry selectedScan={selectedScan} apiHealthy={apiHealthy} />
        </WorkspaceErrorBoundary>
      </div>
    </div>
  );
}

/* ─── LaunchPanel (inline — tightly coupled to page state) ─── */
interface LaunchPanelProps {
  targetInput: string;
  setTargetInput: (v: string) => void;
  outOfScopeInput: string;
  setOutOfScopeInput: (v: string) => void;
  scanMode: string;
  setScanMode: (v: string) => void;
  scanName: string;
  setScanName: (v: string) => void;
  intensity: 'safe' | 'standard' | 'lab';
  setIntensity: (v: 'safe' | 'standard' | 'lab') => void;
  authorizationConfirmed: boolean;
  setAuthorizationConfirmed: (v: boolean) => void;
  labTargetConfirmed: boolean;
  setLabTargetConfirmed: (v: boolean) => void;
  activeModes: ScanMode[];
  selectedMode: ScanMode;
  starting: boolean;
  onStart: () => void;
  onRefresh: () => void;
  refreshing: boolean;
}

function LaunchPanel({
  targetInput, setTargetInput,
  outOfScopeInput, setOutOfScopeInput,
  scanMode, setScanMode,
  scanName, setScanName,
  intensity, setIntensity,
  authorizationConfirmed, setAuthorizationConfirmed,
  labTargetConfirmed, setLabTargetConfirmed,
  activeModes, selectedMode,
  starting, onStart,
  onRefresh, refreshing,
}: LaunchPanelProps) {
  return (
    <div className="card-glass launch-panel" style={{ padding: 16 }}>
      {/* Title + exploit badge */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 4 }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>New Assessment</h2>
          <span style={{
            fontSize: 10, padding: '2px 8px', borderRadius: 6, fontWeight: 600,
            border: selectedMode.exploit ? '1px solid rgba(244,63,94,0.35)' : '1px solid rgba(34,197,94,0.35)',
            background: selectedMode.exploit ? 'rgba(244,63,94,0.09)' : 'rgba(34,197,94,0.09)',
            color: selectedMode.exploit ? 'var(--critical)' : 'var(--low)',
          }}>
            {selectedMode.exploit ? 'PROOF VALIDATION' : 'NON-INTRUSIVE'}
          </span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{selectedMode.description}</p>
      </div>

      <div style={{ display: 'grid', gap: 12 }}>
        <label>
          <div className="section-label" style={{ marginBottom: 6 }}>Authorised targets</div>
          <textarea
            value={targetInput}
            onChange={e => setTargetInput(e.target.value)}
            placeholder={"example.com, 10.0.0.1\n192.168.1.0/24"}
            rows={4}
            className="field"
            aria-label="Targets (comma or newline separated)"
            style={{ resize: 'none', minHeight: 90, fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12 }}
          />
        </label>

        <label>
          <div className="section-label" style={{ marginBottom: 6 }}>Out of scope</div>
          <textarea
            value={outOfScopeInput}
            onChange={e => setOutOfScopeInput(e.target.value)}
            placeholder={"demo.example.com, /admin\n10.0.0.20"}
            rows={3}
            className="field"
            aria-label="Out-of-scope hosts, IPs, CIDRs, or paths"
            style={{ resize: 'none', minHeight: 68, fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12 }}
          />
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4 }}>
            Use <span style={{ fontFamily: 'var(--font-jetbrains), monospace' }}>*.domain.tld</span> only when subdomains are authorised for active testing.
          </div>
        </label>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <label>
            <div className="section-label" style={{ marginBottom: 6 }}>Mode</div>
            <select value={scanMode} onChange={e => setScanMode(e.target.value)} className="field" style={{ height: 36 }}>
              {activeModes.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
            </select>
          </label>
          <label>
            <div className="section-label" style={{ marginBottom: 6 }}>Name</div>
            <input
              value={scanName}
              onChange={e => setScanName(e.target.value)}
              placeholder="Q3 external"
              className="field"
              style={{ height: 36 }}
              aria-label="Scan name"
            />
          </label>
        </div>

        <div className="assessment-policy-box">
          <div className="section-label">Execution policy</div>
          <div className="intensity-grid" role="group" aria-label="Assessment intensity">
            {([
              ['safe', 'Safe', '2 req/s · 3k requests'],
              ['standard', 'Standard', '5 req/s · 15k requests'],
              ['lab', 'Lab', '20 req/s · isolated targets only'],
            ] as const).map(([value, label, detail]) => (
              <button
                type="button"
                key={value}
                className={`intensity-option${intensity === value ? ' active' : ''}`}
                onClick={() => { setIntensity(value); if (value !== 'lab') setLabTargetConfirmed(false); }}
                aria-pressed={intensity === value}
              >
                <strong>{label}</strong><span>{detail}</span>
              </button>
            ))}
          </div>
          <label className="policy-confirmation">
            <input type="checkbox" checked={authorizationConfirmed} onChange={event => setAuthorizationConfirmed(event.target.checked)} />
            <span>I own these targets or have explicit written authorization to test them.</span>
          </label>
          {intensity === 'lab' && (
            <label className="policy-confirmation warning">
              <input type="checkbox" checked={labTargetConfirmed} onChange={event => setLabTargetConfirmed(event.target.checked)} />
              <span>Every target is an isolated lab such as Juice Shop; high-volume testing is permitted.</span>
            </label>
          )}
        </div>

        {/* Assessment workflow preview */}
        <div style={{
          borderRadius: 8, border: '1px solid var(--border)',
          background: 'rgba(0,0,0,0.12)', padding: '10px 12px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span className="section-label">Assessment workflow</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-jetbrains), monospace' }}>
              {selectedMode.agents.length} bounded stages
            </span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {selectedMode.agents.map((agent, i) => (
              <span key={agent} style={{
                fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10,
                padding: '3px 7px', borderRadius: 5,
                border: '1px solid var(--border)',
                background: i === 0 ? 'var(--accent-dim)' : 'var(--bg-elevated)',
                color: i === 0 ? 'var(--accent)' : 'var(--text-secondary)',
              }}>
                {agent}
              </span>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={onStart}
            disabled={starting || !targetInput.trim() || !authorizationConfirmed || (intensity === 'lab' && !labTargetConfirmed)}
            className="btn btn-primary"
            style={{ flex: 1 }}
          >
            {starting ? <RefreshCw size={15} className="animate-spin" aria-hidden="true" /> : <Play size={15} aria-hidden="true" />}
            {starting ? 'Starting…' : 'Start Assessment'}
          </button>
          <button onClick={onRefresh} disabled={refreshing} className="btn btn-icon" title="Refresh data" aria-label="Refresh data">
            <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  );
}
