'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import {
  Activity,
  Bot,
  Boxes,
  Bug,
  CheckCircle2,
  ChevronRight,
  CircleStop,
  Download,
  FileText,
  LayoutDashboard,
  Moon,
  Play,
  RefreshCw,
  Server,
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
import type { AgentDecision, AgentStatus, AssetGraph, AttackChainResult, Finding, RuntimeLogFile, ScanCoverage, SSEEvent, Scan, ScanMode, ToolRun } from '@/types';
import { SEVERITIES } from '@/types';
import type { SeverityKey } from '@/types';

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
import { SkeletonDashboard, SkeletonAgentCard, SkeletonFindingCard } from '@/components/ui/Skeleton';

// Feature components
import { SeverityDonut, SEV_HEX } from '@/components/features/SeverityDonut';
import { FindingCard, SEV_BADGE_CLASS } from '@/components/features/FindingCard';
import { AgentCard } from '@/components/features/AgentCard';
import { LiveFeed, type LogMessage } from '@/components/features/LiveFeed';
import { LLMConfigPanel } from '@/components/features/LLMConfigPanel';
import { AppSecWorkspace } from '@/components/features/AppSecWorkspace';

/* ─── Types ─────────────────────────────────────────────── */
type Tab = 'dashboard' | 'appsec' | 'findings' | 'agents' | 'tools' | 'config';
type SeverityFilter = SeverityKey | 'all';
const SEVERITY_FILTERS = ['all', ...SEVERITIES] as const;

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

function severityLabel(sev: SeverityFilter) {
  if (sev === 'all') return 'All';
  return sev === 'informational' ? 'Info' : sev.charAt(0).toUpperCase() + sev.slice(1);
}

function riskPosture(counts: Record<SeverityKey, number>) {
  const score = Math.min(100, counts.critical * 24 + counts.high * 13 + counts.medium * 6 + counts.low * 2 + counts.informational);
  if (score >= 70) return { score, label: 'Critical exposure', color: '#f43f5e' };
  if (score >= 38) return { score, label: 'High risk',         color: '#f97316' };
  if (score > 0)   return { score, label: 'Moderate risk',     color: '#22d3ee' };
  return              { score, label: 'No exposure',            color: '#22c55e' };
}

function formatAge(value?: string) {
  if (!value) return 'not started';
  const ms = Date.now() - parseBackendTime(value);
  if (!Number.isFinite(ms) || ms < 0) return 'just now';
  const min = Math.floor(ms / 60000);
  if (min < 1)  return 'just now';
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24)  return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
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

function eventLog(event: SSEEvent): LogMessage | null {
  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  if (event.type === 'ping') return null;
  if (event.type === 'finding') {
    return { msg: `${event.title || 'new issue'} on ${event.target_host || event.scan_id || 'target'}`, level: event.severity || 'info', time, source: 'finding', eventType: event.type };
  }
  if (event.type === 'agent_status') {
    const key    = event.agent_type || event.data?.agent_type || 'agent';
    const status = event.status     || event.data?.status     || 'updated';
    const count  = event.findings_count || event.data?.findings_count;
    return { msg: `${status}${count ? ` (${count} findings)` : ''}`, level: status === 'failed' ? 'error' : status === 'completed' ? 'success' : 'info', time, source: key, eventType: event.type };
  }
  if (event.type === 'log') {
    return { msg: event.message || event.data?.message || '', level: event.level || event.data?.level || 'info', time, source: event.agent || event.data?.agent || 'platform', phase: event.phase || event.data?.phase, eventType: event.type };
  }
  if (event.type === 'tool_log') {
    const tool = event.tool || event.data?.tool || 'tool';
    const line = event.line || event.data?.line || '';
    if (!line) return null;
    const stream = event.stream || event.data?.stream || 'stdout';
    const lower = String(line).toLowerCase();
    const level = /(?:fatal|exception|traceback|\berror\b|\bfailed\b)/.test(lower)
      ? 'error'
      : /(?:warn|timed?\s*out|rate.?limit|retry)/.test(lower)
        ? 'warn'
        : 'info';
    return { msg: line, level, time, source: tool, phase: event.phase || event.data?.phase, stream, eventType: event.type };
  }
  if (event.type === 'phase_change') {
    const phase = event.phase || event.data?.phase;
    return phase ? { msg: `Started ${formatPhase(phase)}`, level: 'info', time, source: 'orchestrator', phase, eventType: event.type } : null;
  }
  if (event.type === 'phase_complete' || event.type === 'surface_update') {
    const health = event.target_health?.status;
    const suffix = health ? ` · target ${health}` : '';
    return { msg: `${event.message || `${formatPhase(event.phase)} evidence persisted`}${suffix}`, level: health === 'unreachable' ? 'warn' : 'success', time };
  }
  if (event.type === 'scan_started') {
    const target = Array.isArray(event.targets) ? event.targets.join(', ') : event.scan_id;
    return { msg: `Scan started: ${target}`, level: 'success', time };
  }
  if (event.type === 'scan_deleted') return { msg: `Scan deleted: ${event.scan_id}`, level: 'warn', time };
  if (event.type === 'scan_complete') return { msg: 'Scan completed successfully', level: 'success', time };
  if (event.type === 'scan_failed')   return { msg: `Scan failed: ${event.error || 'unknown error'}`, level: 'error', time };
  return null;
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
	  const [coverage,       setCoverage]       = useState<ScanCoverage | null>(null);
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
  const [logMessages,       setLogMessages]       = useState<LogMessage[]>([]);
  const [activeTab,         setActiveTab]         = useState<Tab>('dashboard');
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

  const logRef           = useRef<HTMLDivElement>(null);
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
     - Updates logMessages for all event types.
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

    const log = eventLog(event);
    if (log?.msg) setLogMessages(prev => [...prev.slice(-299), log]);

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
      // Ephemeral live output — delivered once via SSE, bypass the dedup key
      // (which would collapse lines sharing a timestamp).
      const log = eventLog(event);
      if (log?.msg) setLogMessages(prev => [...prev.slice(-299), log]);
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

  const { connected } = useSSE(handleEvent);

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
	    setCoverage(null);
	    setAssetGraph(null);
	    setDecisions([]);
	    setAttackChains(null);
	    setLoadingFindings(true);
	    Promise.allSettled([
	      api.getFindings(selectedScan.scan_id),
	      api.getAgentStatus(selectedScan.scan_id),
	      api.getToolRuns(selectedScan.scan_id),
	      api.getCoverage(selectedScan.scan_id),
	      api.getAssetGraph(selectedScan.scan_id),
	      api.getDecisions(selectedScan.scan_id),
	      api.getAttackChains(selectedScan.scan_id),
	    ]).then(([findingsRes, agentRes, toolRunRes, coverageRes, assetRes, decisionsRes, chainsRes]) => {
	      if (findingsRes.status === 'fulfilled') setFindings(findingsRes.value.findings);
	      if (agentRes.status === 'fulfilled')    setAgentStatus(agentRes.value.agents);
	      if (toolRunRes.status === 'fulfilled')  setToolRuns(toolRunRes.value.tool_runs);
	      if (coverageRes.status === 'fulfilled') setCoverage(coverageRes.value.coverage);
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
	        api.getCoverage(selectedScan.scan_id),
	        api.getAssetGraph(selectedScan.scan_id),
	        api.getDecisions(selectedScan.scan_id),
	        api.getAttackChains(selectedScan.scan_id),
	      ]).then(([toolRunRes, coverageRes, assetRes, decisionsRes, chainsRes]) => {
	        if (toolRunRes.status === 'fulfilled') setToolRuns(toolRunRes.value.tool_runs);
	        if (coverageRes.status === 'fulfilled') setCoverage(coverageRes.value.coverage);
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
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logMessages]);

  useEffect(() => {
    const iv = setInterval(() => refreshAll().catch(() => {}), 30000);
    return () => clearInterval(iv);
  }, [refreshAll]);

  useEffect(() => {
    if (selectedScan?.status !== 'running') return;
    const iv = setInterval(() => setClockNow(Date.now()), 1000);
    return () => clearInterval(iv);
  }, [selectedScan?.status]);

  useEffect(() => {
    if (selectedScan?.status !== 'running') return;
    const iv = setInterval(() => {
      setLogMessages(prev => [...prev.slice(-299), {
        msg: `Still running: ${formatPhase(selectedScan.current_phase)} — ${selectedScan.targets?.join(', ') || 'target'}`,
        level: 'info',
        time: new Date().toLocaleTimeString(),
      }]);
    }, 15000);
    return () => clearInterval(iv);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedScan?.status, selectedScan?.current_phase, selectedScan?.targets?.join(',')]);

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
      setLogMessages([{ msg: `Scan queued for ${targets.join(', ')}`, level: 'success', time: new Date().toLocaleTimeString() }]);
      setTargetInput('');
      setOutOfScopeInput('');
      setScanName('');
      setAuthorizationConfirmed(false);
      setLabTargetConfirmed(false);
      toast.success('Scan launched', `${targets.join(', ')} is now being assessed`);
      await refreshAll();
    } catch (e: any) {
      toast.error('Failed to start scan', e.message);
      setLogMessages(prev => [...prev.slice(-199), { msg: `Failed to start: ${e.message}`, level: 'error', time: new Date().toLocaleTimeString() }]);
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
    () => findings.filter(f => f.status === 'confirmed' && !f.quarantined),
    [findings],
  );
  const candidateFindings = Math.max(0, findings.length - verifiedFindings.length);
  const surfaceCount = assetGraph?.total_assets || 0;

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
  const operationalTools = useMemo(() => (
    Object.fromEntries(
      Object.entries(toolsStatus).filter(([, tool]: [string, any]) => {
        const wu = tool.will_use as string;
        const availability = tool.availability as string || wu;
        return (
          wu === 'docker' ||
          wu === 'local' ||
          wu === 'internal' ||
          wu === 'api' ||
          availability === 'pullable'
        );
      }),
    )
  ), [toolsStatus]);
  const toolCounts    = useMemo(() => {
    const vals = Object.values(operationalTools);
    return {
      docker:   vals.filter((t: any) => t.will_use === 'docker').length,
      local:    vals.filter((t: any) => t.will_use === 'local').length,
      internal: vals.filter((t: any) => t.will_use === 'internal').length,
      api:      vals.filter((t: any) => t.will_use === 'api').length,
      pullable: vals.filter((t: any) => t.availability === 'pullable').length,
      total:    vals.length,
    };
  }, [operationalTools]);
  const capabilityCoverage = useMemo(() => {
    const labels: Record<string, string> = {
      recon: 'Discovery & attack surface', enumeration: 'Network & service mapping',
      vuln_scanning: 'Vulnerability validation', fuzzing: 'Web & API assessment',
      exploitation: 'Impact validation', intelligence: 'Intelligence & correlation',
      reporting: 'Evidence & reporting',
    };
    const groups: Record<string, { label: string; total: number; ready: number; gaps: number }> = {};
    Object.values(toolsStatus).forEach((tool: any) => {
      const phase = (tool.phases || [])[0] || 'extensions';
      const group = groups[phase] ||= { label: labels[phase] || 'Extension capabilities', total: 0, ready: 0, gaps: 0 };
      group.total += 1;
      const ready = tool.availability === 'ready' && ['docker', 'local', 'internal', 'api'].includes(tool.will_use);
      if (ready) group.ready += 1;
      else group.gaps += 1;
    });
    return Object.entries(groups).sort((a, b) => a[1].label.localeCompare(b[1].label));
  }, [toolsStatus]);

  const currentPhaseIndex = selectedScan ? PHASE_ORDER.findIndex(p => p === selectedScan.current_phase) : -1;

  const visibleLogs: LogMessage[] = logMessages.length ? logMessages : [
    { msg: connected ? 'SSE stream connected — awaiting events' : 'SSE stream connecting…',  level: connected ? 'success' : 'warn',  time: '—' },
    { msg: apiHealthy ? 'Backend API healthy' : apiHealthy === false ? 'Backend API unreachable — offline mode' : 'Checking backend API…', level: apiHealthy ? 'success' : apiHealthy === false ? 'error' : 'info', time: '—' },
    { msg: `${activeModes.length} scan mode(s) loaded`,                                      level: 'info',                           time: '—' },
    { msg: dockerReady ? 'Docker isolation layer ready' : 'Docker daemon not confirmed',     level: dockerReady ? 'success' : 'warn', time: '—' },
  ];

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
    { id: 'nav-dashboard', group: 'Navigate', label: 'Assessments', sub: 'Authorised scopes and live execution', icon: LayoutDashboard, hint: ['1'], keywords: 'home overview scan dast', run: () => setActiveTab('dashboard') },
    { id: 'nav-findings', group: 'Navigate', label: 'Findings', sub: 'Vulnerabilities', icon: ShieldAlert, hint: ['2'], keywords: 'vulns issues', run: () => setActiveTab('findings') },
    { id: 'nav-agents', group: 'Navigate', label: 'Attack Paths', sub: 'Evidence chains and decisions', icon: Bot, hint: ['3'], keywords: 'paths decisions evidence', run: () => setActiveTab('agents') },
    { id: 'nav-tools', group: 'Administration', label: 'Operations', sub: 'Runner health and logs', icon: Wrench, hint: ['4'], keywords: 'status logs api keys', run: () => setActiveTab('tools') },
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
                  <MetricCard icon={ShieldCheck}   label="Verified Findings" value={verifiedFindings.length} sub="report eligible" tone="red" />
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

                    {/* Live feed */}
                    <LiveFeed logs={visibleLogs} logRef={logRef} selectedScan={selectedScan} />
                  </div>
                </section>
              </div>
            )
          )}

          {/* ── FINDINGS TAB ──────────────────────────────── */}
          {activeTab === 'findings' && (
            <section>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <ShieldAlert size={20} style={{ color: 'var(--accent)', flexShrink: 0 }} aria-hidden="true" />
                  <div>
                    <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Findings</h2>
                    <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                      {filteredFindings.length} of {findings.length} findings
                    </p>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={handleRefresh} disabled={refreshing} className="btn btn-secondary">
                    <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
                    Refresh
                  </button>
                  {selectedScan && (
                    <button onClick={() => setShowReportModal(true)} disabled={selectedScan.status !== 'completed'} title={selectedScan.status === 'completed' ? 'Download final report' : 'Available after all scan phases complete'} className="btn btn-secondary">
                      <FileText size={14} aria-hidden="true" />Report
                    </button>
                  )}
                </div>
              </div>

              {/* Severity filter bar */}
              <div className="sev-filter-bar" style={{ marginBottom: 14 }} role="group" aria-label="Filter by severity">
                {SEVERITY_FILTERS.map(f => {
                  const count = f === 'all' ? findings.length : severityCounts[f as SeverityKey];
                  return (
                    <button
                      key={f}
                      onClick={() => setSeverityFilter(f)}
                      className={`sev-filter-btn${severityFilter === f ? ' active' : ''}`}
                      aria-pressed={severityFilter === f}
                    >
                      {f !== 'all' && (
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: SEV_DOT_COLOR[f] || '#06b6d4', display: 'inline-block', flexShrink: 0 }} aria-hidden="true" />
                      )}
                      {severityLabel(f)}
                      <span className="sev-filter-count">{count}</span>
                    </button>
                  );
                })}
                {quarantinedCount > 0 && (
                  <button
                    onClick={() => setShowQuarantined(v => !v)}
                    className={`sev-filter-btn${showQuarantined ? ' active' : ''}`}
                    aria-pressed={showQuarantined}
                    title="Low-evidence findings excluded from reports"
                    style={{ marginLeft: 'auto' }}
                  >
                    {showQuarantined ? 'Hiding' : 'Show'} quarantined
                    <span className="sev-filter-count">{quarantinedCount}</span>
                  </button>
                )}
              </div>

              {/* Finding list */}
              {loadingFindings ? (
                <div style={{ display: 'grid', gap: 8 }}>
                  {Array.from({ length: 5 }).map((_, i) => <SkeletonFindingCard key={i} />)}
                </div>
              ) : findings.length === 0 ? (
                apiHealthy === false ? (
                  <StateView variant="error" title="Couldn’t load findings" body="The backend is unreachable. Findings will appear once the connection is restored." onRetry={handleRefresh} />
                ) : (
                  <StateView variant="empty" icon={ShieldCheck} title="No findings loaded" body="Select a completed scan, or launch one — findings surface here in real time." />
                )
              ) : filteredFindings.length === 0 ? (
                <StateView
                  variant="no-results"
                  title="No matching findings"
                  body={`Nothing matches the "${severityLabel(severityFilter)}" filter${showQuarantined ? '' : ' — quarantined findings are hidden.'}`}
                  action={<button className="btn btn-secondary" onClick={() => { setSeverityFilter('all'); setShowQuarantined(true); }}>Clear filters</button>}
                />
              ) : (
                <div style={{ display: 'grid', gap: 8 }}>
                  {filteredFindings.map((f, i) => {
                    const key      = `${f.title}|${f.target_host}|${f.created_at || i}`;
                    const expanded = expandedFindings.has(key);
                    return (
                      <FindingCard
                        key={key}
                        finding={f}
                        expanded={expanded}
                        onToggle={() => toggleFinding(key)}
                      />
                    );
                  })}
                </div>
              )}
            </section>
          )}

          {/* ── ATTACK PATHS TAB ──────────────────────────── */}
          {activeTab === 'agents' && (
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
                          <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Adaptive Decision Ledger</h3>
                          <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                            Approved recommendations paired with observed execution outcomes
                          </p>
                        </div>
                        <span className="badge badge-informational">{decisions.length} entr{decisions.length === 1 ? 'y' : 'ies'}</span>
                      </div>
                      {decisions.length === 0 ? (
                        <div className="quiet-empty">Recommendations appear as each phase begins. They are recorded for review and are not silently executed.</div>
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
                                    ? (decision.executed_capabilities || []).map(item => `${item.tool}: ${item.outcome.replaceAll('_', ' ')}`).join(' · ') || 'No tool artifact captured'
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
                          Policy owns execution. AI ranks only eligible actions; every real run and recovery recommendation is written back here.
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

	                  <div className="card-glass" style={{ padding: 14 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12 }}>
                      <div>
                        <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Tool Runs</h3>
                        <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                          {toolRuns.length} captured · {partialToolRuns.length} partial · {failedToolRuns.length} failed
                        </p>
                      </div>
                      <button
                        onClick={() => selectedScan?.scan_id && api.getToolRuns(selectedScan.scan_id).then(r => setToolRuns(r.tool_runs)).catch(() => {})}
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
                </div>
              )}
            </section>
          )}

          {/* ── TOOLS TAB ─────────────────────────────────── */}
          {activeTab === 'tools' && (
            <section>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <Wrench size={20} style={{ color: 'var(--accent)' }} aria-hidden="true" />
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>Operations</h2>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
                    Administrative health for approved local, container and API runners
                  </p>
                </div>
              </div>

              {/* Metric cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0,1fr))', gap: 12, marginBottom: 16 }}>
                <MetricCard icon={Boxes}         label="Docker Ready"      value={dockerReady ? 'Ready' : 'Check'} sub={dockerInfo?.socket_available ? 'socket mounted' : 'socket missing'} tone={dockerReady ? 'emerald' : 'amber'} />
                <MetricCard icon={Server}        label="Ready Runtimes"    value={toolCounts.docker + toolCounts.local + toolCounts.internal + toolCounts.api} sub="behind capability adapters" tone="cyan" />
                <MetricCard icon={Download}      label="Needs Setup"       value={Object.values(toolsStatus).filter((t: any) => t.availability !== 'ready').length} sub="optional runner or credential" tone="amber" />
              </div>

              <div className="card-glass" style={{ padding: 14, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 10 }}>
                  <div>
                    <h3 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>Runtime Logs</h3>
                    <p style={{ marginTop: 2, fontSize: 11, color: 'var(--text-secondary)' }}>
                      {runtimeLogs.length} file{runtimeLogs.length === 1 ? '' : 's'} available
                    </p>
                  </div>
                  <button
                    onClick={() => api.listLogs().then(r => setRuntimeLogs(r.files || [])).catch(() => {})}
                    className="btn btn-secondary"
                  >
                    <RefreshCw size={14} aria-hidden="true" />Refresh
                  </button>
                </div>
                {runtimeLogs.length === 0 ? (
                  <div className="quiet-empty">Runtime log file appears after the rebuilt containers start.</div>
                ) : (
                  <div style={{ display: 'grid', gap: 8 }}>
                    {runtimeLogs.slice(0, 6).map(file => (
                      <a
                        key={file.name}
                        className="tool-row"
                        href={api.downloadLog(file.name)}
                        target="_blank"
                        rel="noreferrer"
                        style={{ textDecoration: 'none' }}
                      >
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12, color: 'var(--text-primary)' }}>{file.name}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                            {(file.size / 1024).toFixed(1)} KB · {formatAge(file.modified_at)}
                          </div>
                        </div>
                        <span className="badge badge-informational">download</span>
                      </a>
                    ))}
                  </div>
                )}
              </div>

              {/* Capability coverage — implementation tools stay behind adapters. */}
              {capabilityCoverage.length === 0 ? (
                apiHealthy === false ? (
                  <StateView variant="offline" title="Backend unreachable" body="Tool status will appear once the connection to the backend is restored." onRetry={handleRefresh} />
                ) : (
                  <StateView variant="empty" icon={Wrench} title="No tool data" body="No tools have reported status yet." />
                )
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 8 }}>
                  {capabilityCoverage.map(([phase, group]) => {
                    const complete = group.gaps === 0;
                    return (
                      <div key={phase} className="tool-row">
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                            {group.label}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {group.ready}/{group.total} execution adapters ready
                          </div>
                        </div>
                        <span className={`badge ${complete ? 'badge-completed' : 'badge-running'}`}>
                          {complete ? 'ready' : `${group.gaps} need${group.gaps === 1 ? 's' : ''} setup`}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          )}

          {activeTab === 'appsec' && <AppSecWorkspace />}

          {/* ── CONFIG TAB ─────────────────────────────────── */}
          {activeTab === 'config' && (
            <LLMConfigPanel />
          )}

        </main>
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
