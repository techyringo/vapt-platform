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
  finding_id: number;
  fingerprint?: string;
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
  response_proof?: string;
  poc_steps?: string[];
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
  triage_status?: 'untriaged' | 'true_positive' | 'false_positive' | 'accepted_risk' | 'duplicate' | 'resolved' | 'needs_review';
  triage_reason?: string;
  triage_actor?: string;
  triage_updated_at?: string;
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
  partial?: boolean;
  evidence_captured?: boolean;
  outcome?: 'completed' | 'partial' | 'timed_out' | 'resource_exhausted' | 'failed';
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

export interface DurableAction {
  action_id: string;
  scan_id: string;
  phase: string;
  capability: string;
  tool: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'retrying' | 'timed_out' | 'resource_exhausted' | 'failed';
  attempt: number;
  max_attempts: number;
  reason: string;
  runner: string;
  result: Record<string, any>;
  checkpoint: Record<string, any>;
  error: string;
  queued_at: string;
  started_at?: string;
  heartbeat_at?: string;
  completed_at?: string;
  updated_at: string;
}

export interface DurableOperation {
  operation_id: string;
  scan_id: string;
  status: string;
  current_phase: string;
  reconnect_cursor: number;
  summary: {
    total_actions: number;
    running: number;
    completed: number;
    partial: number;
    retrying: number;
    failed: number;
  };
  actions: DurableAction[];
  events: SSEEvent[];
  recovery: {
    durable_results: boolean;
    event_replay: boolean;
    operator_resume_required: boolean;
  };
}

export interface ControlEvidenceControl {
  control_id: string;
  title: string;
  family: string;
  status: 'evidenced' | 'not_evidenced';
  evidence_refs: string[];
  limitation: string;
  scope: string[];
}

export interface ControlEvidence {
  scan_id: string;
  catalog: string;
  catalog_version: string;
  claim: 'coverage_evidence_only';
  summary: {
    total: number;
    evidenced: number;
    not_evidenced: number;
    coverage_percent: number;
  };
  controls: ControlEvidenceControl[];
  disclaimer: string;
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
  type: 'scan_started' | 'phase_change' | 'phase_complete' | 'surface_update' | 'finding' | 'finding_triage' | 'agent_status' | 'agent_decision' | 'log' | 'tool_log' | 'scan_complete' | 'scan_failed' | 'scan_deleted' | 'ping';
  scan_id: string;
  timestamp: string;
  sequence?: number;
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
  raw_observations: number;
  raw_relationships: number;
  canonicalized: boolean;
  assets: AssetNode[];
  edges: AssetEdge[];
}

export interface AssuranceCategory {
  category_id: string;
  title: string;
  status: 'tested' | 'observed' | 'not_tested';
  executed_tools: string[];
  executed_validators: string[];
  observed_assets: string[];
  evidence_refs: string[];
  limitation: string;
}

export interface AssuranceCoverage {
  scan_id: string;
  catalog: string;
  catalog_version: string;
  claim: 'testing_coverage_only';
  scope: string[];
  summary: { total: number; tested: number; observed: number; not_tested: number; confirmed_proofs: number };
  categories: AssuranceCategory[];
  dynamic_validation?: {
    hypotheses_planned: number;
    hypotheses_scheduled: number;
    hypotheses_tested: number;
    proofs_confirmed: number;
    validator_summary: Record<string, Record<string, number>>;
    attempts: Array<{
      hypothesis_id: string;
      validator: string;
      vuln_type: string;
      url: string;
      parameter: string;
      source: string;
      status: 'confirmed' | 'not_confirmed' | 'skipped' | 'error';
      reason: string;
    }>;
  };
  frameworks: Array<{ name: string; version: string; purpose: string; url: string }>;
  disclaimer: string;
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
  policy?: { decision_authority?: string; model_role?: string };
  execution?: { mode: string; automatically_executed: boolean; note: string };
  decision_type?: 'adaptive_capability_plan' | 'execution_outcome';
  executed_capabilities?: Array<{
    tool: string;
    outcome: 'completed' | 'partial' | 'timed_out' | 'resource_exhausted' | 'failed';
    duration: number;
    evidence_captured: boolean;
    exit_code: number;
  }>;
  recovery_actions?: Array<{ tool: string; action: string }>;
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
  partial_tools?: string[];
  notes?: string;
}

export interface ScanCoverage {
  version: string;
  summary: {
    total: number;
    completed: number;
    running: number;
    partial?: number;
    blind_spots: number;
  };
  checks: CoverageCheck[];
}

export interface AppSecCoverageLane {
  status: 'planned' | 'running' | 'completed' | 'partial' | 'unavailable' | 'failed';
  tool: string;
  findings?: number;
  error?: string;
  verification?: 'active' | 'classification-only' | string;
  detectors?: Record<string, string>;
  languages?: Record<string, number>;
  manifests?: string[];
  rulepacks?: string[];
  files?: number;
  source_files?: number;
  scanned_files?: number;
  analysis_coverage_percent?: number;
  skipped_files?: number;
  scanner_errors?: number;
  duration_seconds?: number;
  limitation?: string;
  sbom?: {
    status: string;
    components?: number;
    format?: string;
    sha256?: string;
    size?: number;
    limitation?: string;
  };
}

export interface AppSecArtifact {
  id: number;
  assessment_id: string;
  kind: string;
  format: string;
  filename: string;
  sha256: string;
  size: number;
  created_at: string;
}

export interface AppSecFinding {
  id: number;
  fingerprint: string;
  source: string;
  category: 'sast' | 'sca' | 'iac' | 'secret' | string;
  rule_id: string;
  title: string;
  description: string;
  severity: SeverityKey;
  confidence: string;
  status: string;
  repository: string;
  path: string;
  start_line?: number;
  end_line?: number;
  package?: string;
  installed_version?: string;
  fixed_version?: string;
  cve_ids: string[];
  cwe_ids: string[];
  references: string[];
  evidence: string;
  remediation: string;
}

export interface AppSecAssessment {
  assessment_id: string;
  name: string;
  repository: string;
  ref: string;
  commit_sha: string;
  status: 'queued' | 'running' | 'partial' | 'completed' | 'failed';
  phase: string;
  progress: number;
  coverage: Record<string, AppSecCoverageLane>;
  summary: {
    total?: number;
    severities?: Partial<Record<SeverityKey, number>>;
    categories?: Record<string, number>;
    unavailable?: string[];
    baseline_assessment_id?: string;
    diff?: {
      new: number;
      unchanged: number;
      resolved: number;
      has_baseline: boolean;
      same_commit?: boolean;
      current_commit_sha?: string;
      baseline_commit_sha?: string;
      new_fingerprints?: string[];
      resolved_fingerprints?: string[];
    };
  };
  error?: string;
  artifacts?: AppSecArtifact[];
  created_at: string;
  updated_at: string;
  findings?: AppSecFinding[];
  tool_runs?: Array<Record<string, unknown>>;
}

export interface ReportStudioArtifact {
  id: number;
  report_id: string;
  kind: 'json' | 'markdown' | 'html' | 'pdf' | string;
  format: string;
  filename: string;
  sha256: string;
  size: number;
  created_at: string;
}

export interface ReportStudioFinding {
  fingerprint: string;
  title: string;
  description: string;
  severity: SeverityKey;
  cvss_score?: number | null;
  cvss_vector?: string;
  target: string;
  evidence: string;
  request_proof?: string;
  response_proof?: string;
  remediation: string;
  business_impact?: string;
  cve_ids: string[];
  cwe_ids: string[];
  references: string[];
  confidence: string;
  status: 'confirmed' | 'observed';
  source_file: string;
}

export interface ReportStudioJob {
  report_id: string;
  name: string;
  client_name: string;
  assessment_type: string;
  template_id: string;
  status: 'queued' | 'running' | 'partial' | 'completed' | 'failed';
  phase: string;
  progress: number;
  scope: string[];
  metadata: Record<string, string>;
  source_manifest: Array<{ filename: string; media_type: string; sha256: string; size: number }>;
  findings: ReportStudioFinding[];
  narrative: {
    executive_summary?: string;
    risk_statement?: string;
    key_recommendations?: string[];
    methodology_note?: string;
    llm_used?: boolean;
  };
  summary: {
    total_findings?: number;
    severities?: Partial<Record<SeverityKey, number>>;
    confirmed?: number;
    observed?: number;
    source_count?: number;
    source_bytes?: number;
    limitations?: string[];
  };
  artifacts?: ReportStudioArtifact[];
  error?: string;
  created_at: string;
  updated_at: string;
}

export interface ReportStudioTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
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
