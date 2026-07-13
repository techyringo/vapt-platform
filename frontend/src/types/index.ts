export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
export type SeverityKey = (typeof SEVERITIES)[number];

export interface Scan {
  scan_id: string;
  name: string;
  mode: string;
  status: string;
  current_phase: string;
  targets: string[];
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  start_time: string;
  duration_seconds: number;
  nvd_stats?: NVDStats;
  agent_status?: Record<string, AgentStatus>;
  findings?: Finding[];
  error?: string;
  end_time?: string;
}

export interface Finding {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cvss_score?: number;
  cvss_vector?: string;
  target_host: string;
  target_port: number;
  target_url: string;
  target_display?: string;
  evidence: string;
  request_proof?: string;
  remediation: string;
  references: string[];
  cve_ids: string[];
  cwe_ids: string[];
  tags: string[];
  confidence: string;
  status: string;
  agent_source: string;
  nvd_verified?: boolean;
  evidence_score?: number;
  evidence_grade?: string;
  validation_notes?: string[];
  quarantined?: boolean;
  llm_reasoning?: Record<string, unknown>;
  created_at: string;
}

export interface AgentStatus {
  agent_type: string;
  status: 'idle' | 'running' | 'completed' | 'failed' | 'skipped' | 'cancelled';
  findings_count: number;
  tools_run: string[];
  current_tool: string;
  progress_pct: number;
  error: string;
  started_at?: string;
  completed_at?: string;
}

export interface ToolRun {
  id: number;
  scan_id: string;
  agent_type: string;
  phase: string;
  tool: string;
  success: boolean;
  exit_code: number;
  duration: number;
  timed_out: boolean;
  command_preview?: string;
  stdout_snippet: string;
  stderr_snippet: string;
  stdout_size?: number;
  stderr_size?: number;
  stdout_sha256?: string;
  stderr_sha256?: string;
  stdout_artifact_url?: string;
  stderr_artifact_url?: string;
  created_at: string;
}

export interface APIKeyStatus {
  groups: Record<string, Array<{
    name: string;
    configured: boolean;
  }>>;
  summary: Record<string, {
    configured: number;
    total: number;
  }>;
  secrets_returned: boolean;
  credential_names_returned?: boolean;
  storage_location_returned?: boolean;
}

export interface RuntimeLogFile {
  name: string;
  size: number;
  modified_at: string;
  download_url: string;
}

export interface ScanMode {
  id: string;
  name: string;
  description: string;
  agents: string[];
  exploit: boolean;
  aggressive: boolean;
  focus: string[];
}

export interface NVDStats {
  total_lookups: number;
  verified: number;
  rejected: number;
  failed: number;
  cached: number;
}

export interface SSEEvent {
  type: 'scan_started' | 'phase_change' | 'finding' | 'agent_status' | 'log' | 'tool_log' | 'scan_complete' | 'scan_failed' | 'scan_deleted' | 'ping';
  scan_id: string;
  timestamp: string;
  [key: string]: any;
}

export interface AssetNode {
  asset_key: string;
  asset_type: string;
  value: string;
  source: string;
  confidence: string;
  metadata: Record<string, any>;
  first_seen: string;
  last_seen: string;
}

export interface AssetEdge {
  edge_key: string;
  source_key: string;
  target_key: string;
  relation: string;
  evidence: string;
  first_seen: string;
  last_seen: string;
}

export interface AssetGraph {
  scan_id: string;
  summary: Record<string, number>;
  total_assets: number;
  total_edges: number;
  assets: AssetNode[];
  edges: AssetEdge[];
}

export interface AttackSurfacePlanItem {
  capability: string;
  reason: string;
  phase: string;
  target_layer: string;
  categories: string[];
  candidate_tools: Array<{
    name: string;
    display_name: string;
    availability: string;
    will_use: string;
    aggressive: boolean;
  }>;
}

export interface AttackSurfacePlan {
  scan_id: string;
  asset_summary: Record<string, number>;
  planned_capabilities: AttackSurfacePlanItem[];
}

export interface AgentDecision {
  decision_id: string;
  phase: string;
  status: string;
  created_at: string;
  input_evidence: string[];
  selected: Array<{ tool: string; capability: string; reason: string; consumes: string[]; produces: string[] }>;
  hypotheses: string[];
  coverage_gaps: string[];
  model_trace: { used: boolean; provider: string; model: string; error: string };
}

export interface AttackChain {
  chain_id: string;
  name: string;
  target_host: string;
  status: 'verified' | 'hypothesis';
  confidence: string;
  impact: string;
  nodes: Array<{ evidence_ref: string; title: string; severity: string; role: string }>;
  edges: Array<{ source: string; target: string; relation: string; evidence_refs: string[] }>;
}

export interface AttackChainResult {
  scan_id: string;
  summary: { total: number; verified: number; hypotheses: number };
  chains: AttackChain[];
}

export interface CoverageCheck {
  id: string;
  label: string;
  phase: string;
  status: string;
  expected_tools: string[];
  tools_observed?: string[];
  successful_tools?: string[];
  notes?: string;
}

export interface ScanCoverage {
  version: string;
  summary: {
    total: number;
    completed: number;
    running: number;
    blind_spots: number;
  };
  checks: CoverageCheck[];
}

export interface LLMFallbackProvider {
  provider: string;
  model: string;
  base_url: string;
  api_key?: string;        // write-only (never returned)
  api_key_env?: string;
  verify_ssl?: boolean;
  max_rpm?: number;
  has_api_key?: boolean;   // read-only
}

export interface LLMConfig {
  provider: string;
  model: string;
  base_url: string;
  verify_ssl: boolean;
  api_key_env: string;
  has_api_key: boolean;
  analysis_model: string;
  report_model: string;
  review_model: string;
  temperature: number;
  max_tokens: number;
  max_rpm: number;
  fallback_providers: LLMFallbackProvider[];
  enabled: boolean | null;
  allow_fallbacks: boolean | null;
}

export interface LLMConfigInput {
  provider: string;
  model: string;
  base_url: string;
  verify_ssl: boolean;
  api_key: string;
  api_key_env: string;
  analysis_model: string;
  report_model: string;
  review_model: string;
  temperature: number;
  max_tokens: number;
  max_rpm: number;
  fallback_providers: LLMFallbackProvider[];
  enabled: boolean;
  allow_fallbacks: boolean;
}

export interface LLMTestInput {
  provider: string;
  model: string;
  base_url: string;
  verify_ssl: boolean;
  api_key: string;
  api_key_env: string;
}

export interface LLMProbe {
  reachable: boolean;
  inference_ready: boolean;
  latency_ms: number | null;
  models: string[];
  selected_model_present: boolean | null;
  error: string;
}
