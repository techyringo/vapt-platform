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
  startScan: (targets: string[], mode: string, name: string) =>
    fetchAPI<{ scan_id: string; status: string }>('/api/scans/start', {
      method: 'POST',
      body: JSON.stringify({ targets, mode, name }),
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

  getAgentStatus: (id: string) =>
    fetchAPI<{ scan_id: string; agents: Record<string, import('@/types').AgentStatus> }>(`/api/scans/${id}/agents`),

  getToolRuns: (id: string) =>
    fetchAPI<{ scan_id: string; total: number; tool_runs: import('@/types').ToolRun[] }>(`/api/scans/${id}/tool-runs`),

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
};
