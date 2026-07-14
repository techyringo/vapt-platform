const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '').replace(/\/$/, '');

function apiUrl(path: string): string {
  return `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
}

export async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(path), {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `API Error ${res.status}`);
  }
  return res.json();
}

export const api = {
  // Scans
  startScan: (targets: string[], mode: string, name: string, scopeConfig?: Record<string, unknown>) =>
    fetchAPI<{ scan_id: string; status: string }>('/api/scans/start', {
      method: 'POST',
      body: JSON.stringify({ targets, mode, name, scope_config: scopeConfig || undefined }),
    }),

  listScans: () =>
    fetchAPI<import('@/types').Scan[]>('/api/scans'),

  getScan: (id: string) =>
    fetchAPI<import('@/types').Scan>(`/api/scans/${id}`),

  stopScan: (id: string) =>
    fetchAPI<{ scan_id: string; status: string }>(`/api/scans/${id}/stop`, { method: 'POST' }),

  deleteScan: (id: string) =>
    fetchAPI<{ scan_id: string; status: string }>(`/api/scans/${id}`, { method: 'DELETE' }),

  getFindings: (id: string, filters?: { severity?: string; agent?: string; status?: string }) => {
    const params = new URLSearchParams();
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.agent) params.set('agent', filters.agent);
    if (filters?.status) params.set('status', filters.status);
    return fetchAPI<{ total: number; findings: import('@/types').Finding[] }>(`/api/scans/${id}/findings?${params}`);
  },

  getAssetGraph: (id: string, assetType?: string) => {
    const params = new URLSearchParams();
    if (assetType) params.set('asset_type', assetType);
    const query = params.toString();
    return fetchAPI<import('@/types').AssetGraph>(`/api/scans/${id}/assets${query ? `?${query}` : ''}`);
  },

  getAttackSurfacePlan: (id: string) =>
    fetchAPI<import('@/types').AttackSurfacePlan>(`/api/scans/${id}/attack-surface/plan`),

  getDecisions: (id: string, limit: number = 100) =>
    fetchAPI<{ scan_id: string; total: number; decisions: import('@/types').AgentDecision[] }>(`/api/scans/${id}/decisions?limit=${limit}`),

  getAttackChains: (id: string) =>
    fetchAPI<import('@/types').AttackChainResult>(`/api/scans/${id}/attack-chains`),

  getAgentStatus: (id: string) =>
    fetchAPI<{ scan_id: string; agents: Record<string, import('@/types').AgentStatus> }>(`/api/scans/${id}/agents`),

  getToolRuns: (id: string) =>
    fetchAPI<{ scan_id: string; total: number; tool_runs: import('@/types').ToolRun[] }>(`/api/scans/${id}/tool-runs`),

  getOperation: (id: string) =>
    fetchAPI<import('@/types').DurableOperation>(`/api/scans/${id}/operation`),

  getControlEvidence: (id: string) =>
    fetchAPI<import('@/types').ControlEvidence>(`/api/scans/${id}/control-evidence`),

  downloadToolArtifact: (scanId: string, runId: number, stream: 'stdout' | 'stderr' = 'stdout') =>
    apiUrl(`/api/scans/${scanId}/tool-runs/${runId}/artifact?stream=${stream}`),

  getCoverage: (id: string) =>
    fetchAPI<{ scan_id: string; coverage: import('@/types').ScanCoverage }>(`/api/scans/${id}/coverage`),

  getEvents: (id?: string, limit: number = 200) => {
    const params = new URLSearchParams();
    if (id) params.set('scan_id', id);
    params.set('limit', String(limit));
    return fetchAPI<{ events: import('@/types').SSEEvent[] }>(`/api/events?${params}`);
  },

  startAppSecAssessment: (repository: string, ref: string, name: string) =>
    fetchAPI<{ assessment_id: string; status: string }>('/api/appsec/assessments', {
      method: 'POST',
      body: JSON.stringify({ repository, ref, name }),
    }),

  listAppSecAssessments: () =>
    fetchAPI<{ assessments: import('@/types').AppSecAssessment[] }>('/api/appsec/assessments'),

  getAppSecAssessment: (id: string) =>
    fetchAPI<import('@/types').AppSecAssessment>(`/api/appsec/assessments/${id}`),

  downloadAppSecSarif: (id: string) =>
    apiUrl(`/api/appsec/assessments/${id}/sarif`),

  downloadAppSecArtifact: (id: string, kind: string) =>
    apiUrl(`/api/appsec/assessments/${id}/artifacts/${encodeURIComponent(kind)}`),

  downloadReport: (id: string, format: string = 'html') =>
    apiUrl(`/api/scans/${id}/report?format=${format}`),

  // Reference data
  getModes: () =>
    fetchAPI<{ modes: import('@/types').ScanMode[] }>('/api/modes'),

  getHealth: () => fetchAPI<{ status: string; version: string; nvd: any }>('/api/health'),

  getToolsStatus: () =>
    fetchAPI<{ docker: Record<string, any>; tools: Record<string, any>; api_keys?: import('@/types').APIKeyStatus }>('/api/tools/status'),

  getAPIKeysStatus: () =>
    fetchAPI<import('@/types').APIKeyStatus>('/api/system/api-keys'),

  listLogs: () =>
    fetchAPI<{ log_dir: string; files: import('@/types').RuntimeLogFile[] }>('/api/system/logs'),

  downloadLog: (name: string) =>
    apiUrl(`/api/system/logs/${encodeURIComponent(name)}/download`),

  deleteLog: (name: string) =>
    fetchAPI<{ name: string; action: 'cleared' | 'deleted' }>(`/api/system/logs/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    }),

  // LLM configuration (runtime, frontend-configurable — no hardcoded model)
  getLLMConfig: () =>
    fetchAPI<{ llm: import('@/types').LLMConfig }>('/api/config/llm'),

  saveLLMConfig: (cfg: import('@/types').LLMConfigInput) =>
    fetchAPI<{ llm: import('@/types').LLMConfig; probe: import('@/types').LLMProbe }>('/api/config/llm', {
      method: 'PUT',
      body: JSON.stringify(cfg),
    }),

  testLLM: (cfg: import('@/types').LLMTestInput) =>
    fetchAPI<{ probe: import('@/types').LLMProbe }>('/api/config/llm/test', {
      method: 'POST',
      body: JSON.stringify(cfg),
    }),
};
