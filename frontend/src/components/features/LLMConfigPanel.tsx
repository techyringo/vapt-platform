'use client';

import { useEffect, useState } from 'react';
import {
  ArrowDown, ArrowUp, Brain, CheckCircle2, Plus, RefreshCw, Save, Trash2, Wifi, WifiOff,
} from 'lucide-react';
import { api } from '@/lib/api';
import type { LLMConfig, LLMFallbackProvider, LLMProbe } from '@/types';
import { useToast } from '@/hooks/useToast';

const PROVIDERS = [
  'openai_compat', 'ollama', 'http_basic_chat', 'openai', 'groq', 'together', 'anthropic', 'gemini', 'azure',
];

interface Endpoint {
  provider: string;
  model: string;
  base_url: string;
  api_key: string;        // write-only; '' = keep stored
  api_key_env: string;
  verify_ssl: boolean;
  has_api_key: boolean;
}

function emptyEndpoint(provider = 'ollama'): Endpoint {
  return { provider, model: '', base_url: '', api_key: '', api_key_env: '', verify_ssl: true, has_api_key: false };
}

export function LLMConfigPanel() {
  const toast = useToast();
  const [endpoints, setEndpoints] = useState<Endpoint[]>([emptyEndpoint()]);
  const [analysisModel, setAnalysisModel] = useState('');
  const [reportModel, setReportModel] = useState('');
  const [reviewModel, setReviewModel] = useState('');
  const [temperature, setTemperature] = useState(0.3);
  const [maxTokens, setMaxTokens] = useState(4096);
  const [maxRpm, setMaxRpm] = useState(40);
  const [enabled, setEnabled] = useState(true);
  const [allowFallbacks, setAllowFallbacks] = useState(true);
  const [probes, setProbes] = useState<Record<number, LLMProbe | null>>({});
  const [testing, setTesting] = useState<Record<number, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const r = await api.getLLMConfig();
      const c: LLMConfig = r.llm;
      const primary: Endpoint = {
        provider: c.provider,
        model: c.model,
        base_url: c.base_url,
        api_key: '',
        api_key_env: c.api_key_env,
        verify_ssl: c.verify_ssl ?? true,
        has_api_key: c.has_api_key,
      };
      const rest: Endpoint[] = (c.fallback_providers || []).map((f: LLMFallbackProvider) => ({
        provider: f.provider,
        model: f.model,
        base_url: f.base_url,
        api_key: '',
        api_key_env: f.api_key_env || '',
        verify_ssl: f.verify_ssl ?? true,
        has_api_key: f.has_api_key ?? false,
      }));
      setEndpoints([primary, ...rest]);
      setAnalysisModel(c.analysis_model || c.model);
      setReportModel(c.report_model || c.model);
      setReviewModel(c.review_model || c.analysis_model || c.model);
      setTemperature(c.temperature ?? 0.3);
      setMaxTokens(c.max_tokens ?? 4096);
      setMaxRpm(c.max_rpm ?? 40);
      setEnabled(c.enabled ?? true);
      setAllowFallbacks(c.allow_fallbacks ?? true);
      setProbes({});
      setTesting({});
    } catch (e: any) {
      toast.error('Failed to load LLM config', e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  function update(i: number, patch: Partial<Endpoint>) {
    setEndpoints(prev => prev.map((ep, idx) => (idx === i ? { ...ep, ...patch } : ep)));
  }
  function add() {
    setEndpoints(prev => [...prev, emptyEndpoint('ollama')]);
  }
  function remove(i: number) {
    setEndpoints(prev => (prev.length > 1 ? prev.filter((_, idx) => idx !== i) : prev));
    setProbes(prev => {
      const next: Record<number, LLMProbe | null> = {};
      Object.entries(prev).forEach(([idx, v]) => {
        const n = Number(idx);
        if (n !== i) next[n > i ? n - 1 : n] = v;
      });
      return next;
    });
  }
  function move(i: number, dir: -1 | 1) {
    setEndpoints(prev => {
      const j = i + dir;
      if (j < 0 || j >= prev.length) return prev;
      const next = [...prev];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  }

  async function testOne(i: number) {
    const ep = endpoints[i];
    if (!ep) return;
    setTesting(prev => ({ ...prev, [i]: true }));
    setProbes(prev => ({ ...prev, [i]: null }));
    try {
      const r = await api.testLLM({
        provider: ep.provider, model: ep.model, base_url: ep.base_url,
        verify_ssl: ep.verify_ssl, api_key: ep.api_key, api_key_env: ep.api_key_env,
      });
      setProbes(prev => ({ ...prev, [i]: r.probe }));
      if (r.probe.inference_ready) {
        toast.success(`Endpoint ${i + 1} ready`, `Authenticated inference passed in ${r.probe.latency_ms ?? '—'} ms`);
      } else if (r.probe.reachable) {
        toast.error(`Endpoint ${i + 1} reachable but unusable`, r.probe.error || 'Inference test did not pass');
      } else {
        toast.error(`Endpoint ${i + 1} failed`, r.probe.error || 'unreachable');
      }
    } catch (e: any) {
      toast.error('Test failed', e.message);
    } finally {
      setTesting(prev => ({ ...prev, [i]: false }));
    }
  }

  async function save() {
    if (!endpoints.length) return;
    const primary = endpoints[0];
    setSaving(true);
    try {
      const r = await api.saveLLMConfig({
        provider: primary.provider,
        model: primary.model,
        base_url: primary.base_url,
        verify_ssl: primary.verify_ssl,
        api_key: primary.api_key,
        api_key_env: primary.api_key_env,
        analysis_model: analysisModel || primary.model,
        report_model: reportModel || primary.model,
        review_model: reviewModel || analysisModel || primary.model,
        temperature,
        max_tokens: maxTokens,
        max_rpm: maxRpm,
        fallback_providers: endpoints.slice(1).map(ep => ({
          provider: ep.provider, model: ep.model, base_url: ep.base_url,
          api_key: ep.api_key, api_key_env: ep.api_key_env, verify_ssl: ep.verify_ssl,
        })),
        enabled,
        allow_fallbacks: allowFallbacks,
      });
      // refresh stored-secret flags + clear write-only fields
      setEndpoints(prev => prev.map((ep, i) => {
        if (i === 0) return { ...ep, has_api_key: r.llm.has_api_key, api_key: '' };
        const f = r.llm.fallback_providers[i - 1];
        return { ...ep, has_api_key: f?.has_api_key ?? false, api_key: '' };
      }));
      setProbes({ 0: r.probe });
      if (r.probe.inference_ready) {
        toast.success('LLM endpoints saved', `${endpoints.length} source(s) · authenticated inference passed`);
      } else {
        toast.error('Settings saved, but inference failed', r.probe.error || `${primary.provider}:${primary.model || '—'} is not ready`);
      }
    } catch (e: any) {
      toast.error('Save failed', e.message);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <div className="card-glass" style={{ padding: 16, color: 'var(--text-secondary)' }}>Loading LLM config…</div>;
  }

  return (
    <section>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
        <Brain size={20} style={{ color: 'var(--accent)' }} aria-hidden="true" />
        <div>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>LLM Endpoints</h2>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            Stack multiple model sources — GPU vLLM, CPU Ollama, Mac /chat — each with its own URL &amp; auth. The chain falls through in order; the first source is primary.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', margin: '12px 0' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} /> Enabled
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={allowFallbacks} onChange={e => setAllowFallbacks(e.target.checked)} /> Allow fallback chain
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          temp
          <input className="field" style={{ height: 28, width: 56 }} type="number" step="0.1" min="0" max="2"
            value={temperature} onChange={e => setTemperature(parseFloat(e.target.value) || 0)} />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          max_tokens
          <input className="field" style={{ height: 28, width: 80 }} type="number" step="256" min="1"
            value={maxTokens} onChange={e => setMaxTokens(parseInt(e.target.value) || 1)} />
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          requests/min
          <input className="field" style={{ height: 28, width: 72 }} type="number" step="1" min="1"
            value={maxRpm} onChange={e => setMaxRpm(parseInt(e.target.value) || 1)} />
        </label>
      </div>

      <div style={{ display: 'grid', gap: 12 }}>
        {endpoints.map((ep, i) => {
          const isPrimary = i === 0;
          const probe = probes[i];
          const isTesting = testing[i];
          return (
            <div key={i} className="card-glass" style={{
              padding: 14,
              borderLeft: `3px solid ${isPrimary ? 'var(--accent)' : 'var(--border)'}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase',
                  color: isPrimary ? 'var(--accent)' : 'var(--text-muted)',
                }}>
                  {isPrimary ? '◆ Primary' : `Fallback ${i}`}
                </span>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button onClick={() => move(i, -1)} disabled={i === 0}
                    className="btn btn-secondary" style={{ padding: '5px 7px' }} title="Move up" aria-label="Move up">
                    <ArrowUp size={13} aria-hidden="true" />
                  </button>
                  <button onClick={() => move(i, 1)} disabled={i === endpoints.length - 1}
                    className="btn btn-secondary" style={{ padding: '5px 7px' }} title="Move down" aria-label="Move down">
                    <ArrowDown size={13} aria-hidden="true" />
                  </button>
                  <button onClick={() => remove(i)} disabled={endpoints.length <= 1}
                    className="btn btn-secondary" style={{ padding: '5px 7px', color: 'var(--critical)' }} title="Remove" aria-label="Remove endpoint">
                    <Trash2 size={13} aria-hidden="true" />
                  </button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <select className="field" style={{ height: 34 }} value={ep.provider} onChange={e => update(i, { provider: e.target.value })}>
                  {PROVIDERS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
                <input className="field" style={{ height: 34 }} value={ep.model}
                  onChange={e => update(i, { model: e.target.value })} placeholder="model (e.g. Qwen/Qwen2.5-32B-Instruct-AWQ)" />
              </div>

              <input className="field" style={{ height: 34, marginTop: 8 }} value={ep.base_url}
                onChange={e => update(i, { base_url: e.target.value })}
                placeholder="base URL — http://10.1.96.94:8000  or  https://your-ngrok.app" />

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 8 }}>
                <input className="field" style={{ height: 34 }} type="password" value={ep.api_key}
                  onChange={e => update(i, { api_key: e.target.value })}
                  placeholder={ep.has_api_key ? '•••• stored (blank = keep)' : 'api key / user:password (blank = none)'} />
                <input className="field" style={{ height: 34 }} value={ep.api_key_env}
                  onChange={e => update(i, { api_key_env: e.target.value })} placeholder="api_key_env (optional)" />
              </div>
              {ep.base_url.includes('integrate.api.nvidia.com') && ep.api_key_env === 'OPENAI_API_KEY' && !ep.api_key && (
                <div style={{ marginTop: 6, fontSize: 11, color: 'var(--medium)' }}>
                  NVIDIA endpoint is currently reading OPENAI_API_KEY. Re-enter the NVIDIA key above or change this to NVIDIA_API_KEY.
                </div>
              )}
              {ep.api_key_env && (
                <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted)' }}>
                  Credential source: environment variable <code>{ep.api_key_env}</code> when present; the stored key is fallback only. Recreate backend and worker containers after changing .env.
                </div>
              )}

              {isPrimary && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginTop: 8 }}>
                  <input className="field" style={{ height: 34 }} value={analysisModel}
                    onChange={e => setAnalysisModel(e.target.value)} placeholder="analysis model (triage)" />
                  <input className="field" style={{ height: 34 }} value={reportModel}
                    onChange={e => setReportModel(e.target.value)} placeholder="report model (reasoning)" />
                  <input className="field" style={{ height: 34 }} value={reviewModel}
                    onChange={e => setReviewModel(e.target.value)} placeholder="review model (independent)" />
                </div>
              )}

              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 10 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--text-muted)' }}>
                  <input type="checkbox" checked={ep.verify_ssl} onChange={e => update(i, { verify_ssl: e.target.checked })} /> verify TLS
                </label>
                <button onClick={() => testOne(i)} disabled={isTesting} className="btn btn-secondary" style={{ marginLeft: 'auto' }}>
                  {isTesting ? <RefreshCw size={13} className="animate-spin" aria-hidden="true" /> : <Wifi size={13} aria-hidden="true" />}
                  Test
                </button>
              </div>

              {probe && (
                <div style={{ marginTop: 10, fontSize: 11 }}>
                  {probe.inference_ready ? (
                    <span style={{ color: 'var(--low)' }}>
                      <CheckCircle2 size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: '-1px' }} aria-hidden="true" />
                      Inference ready · {probe.latency_ms ?? '—'} ms · {probe.models.length} model(s)
                      {ep.model && probe.selected_model_present === false && (
                        <span style={{ color: 'var(--medium)', marginLeft: 6 }}>· model NOT listed</span>
                      )}
                    </span>
                  ) : probe.reachable ? (
                    <span style={{ color: 'var(--critical)' }}>
                      <WifiOff size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: '-1px' }} aria-hidden="true" />
                      Reachable, but inference failed · {probe.error || 'authentication or model error'}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--critical)' }}>
                      <WifiOff size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: '-1px' }} aria-hidden="true" />
                      {probe.error || 'unreachable'}
                    </span>
                  )}
                  {probe.models.length > 0 && (
                    <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {probe.models.slice(0, 16).map(m => (
                        <span key={m} style={{
                          fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10, padding: '1px 6px',
                          border: '1px solid var(--border)', borderRadius: 3, color: 'var(--text-secondary)',
                        }}>{m}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
        <button onClick={add} className="btn btn-secondary">
          <Plus size={14} aria-hidden="true" /> Add endpoint
        </button>
        <button onClick={save} disabled={saving} className="btn btn-primary">
          <Save size={14} aria-hidden="true" /> {saving ? 'Saving…' : 'Save endpoints'}
        </button>
        <button onClick={load} className="btn btn-secondary">
          <RefreshCw size={14} aria-hidden="true" /> Reload
        </button>
      </div>
    </section>
  );
}
