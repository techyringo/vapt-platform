'use client';

import { useState } from 'react';
import { Download, FileCode2, FileJson, FileText, Globe, Loader2, X } from 'lucide-react';
import type { Scan } from '@/types';
import { api } from '@/lib/api';

interface Format {
  id: string;
  label: string;
  description: string;
  ext: string;
  icon: React.ElementType;
  available: boolean;
}

const FORMATS: Format[] = [
  {
    id: 'html',
    label: 'HTML Report',
    description: 'Full interactive report, shareable in any browser.',
    ext: 'html',
    icon: Globe,
    available: true,
  },
  {
    id: 'json',
    label: 'JSON Export',
    description: 'Machine-readable data for integrations and tooling.',
    ext: 'json',
    icon: FileJson,
    available: true,
  },
  {
    id: 'markdown',
    label: 'Markdown',
    description: 'Human-readable text for wikis and documentation.',
    ext: 'md',
    icon: FileCode2,
    available: true,
  },
  {
    id: 'pdf',
    label: 'PDF Report',
    description: 'Print-ready executive summary. (Coming soon)',
    ext: 'pdf',
    icon: FileText,
    available: false,
  },
];

interface ReportModalProps {
  scan: Scan;
  onClose: () => void;
  onError: (msg: string) => void;
}

export function ReportModal({ scan, onClose, onError }: ReportModalProps) {
  const [selected, setSelected] = useState<string>('html');
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    const fmt = FORMATS.find(f => f.id === selected);
    if (!fmt || !fmt.available) return;
    setDownloading(true);
    try {
      const url = api.downloadReport(scan.scan_id, fmt.id);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = `vapt-${scan.name || scan.scan_id}.${fmt.ext}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
      onClose();
    } catch (e: any) {
      onError(`Download failed: ${e.message}`);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div
      className="modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-modal-title"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="modal">
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              display: 'grid', placeItems: 'center',
              width: 32, height: 32, borderRadius: 8,
              background: 'var(--accent-dim)',
              border: '1px solid var(--accent-border)',
              color: 'var(--accent)',
            }}>
              <Download size={15} />
            </div>
            <div>
              <h2 id="report-modal-title" style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
                Download Report
              </h2>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                {scan.name || scan.scan_id}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="btn-icon btn"
            style={{ width: 30, height: 30, borderRadius: 6 }}
            aria-label="Close modal"
          >
            <X size={14} />
          </button>
        </div>

        <div className="modal-body">
          <div style={{ marginBottom: 8 }}>
            <div className="section-label" style={{ marginBottom: 10 }}>Select format</div>
            <div style={{ display: 'grid', gap: 6 }}>
              {FORMATS.map(fmt => {
                const FmtIcon = fmt.icon;
                const isSelected = selected === fmt.id;
                return (
                  <button
                    key={fmt.id}
                    disabled={!fmt.available}
                    onClick={() => fmt.available && setSelected(fmt.id)}
                    className={`report-format-option${isSelected ? ' selected' : ''}`}
                  >
                    <div style={{
                      display: 'grid', placeItems: 'center',
                      width: 34, height: 34, borderRadius: 8,
                      border: '1px solid var(--border)',
                      background: isSelected ? 'var(--accent-dim)' : 'var(--bg-elevated)',
                      color: isSelected ? 'var(--accent)' : 'var(--text-muted)',
                      flexShrink: 0,
                      transition: 'all 150ms ease',
                    }}>
                      <FmtIcon size={16} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0, textAlign: 'left' }}>
                      <div style={{
                        fontSize: 13, fontWeight: 600,
                        color: !fmt.available ? 'var(--text-muted)' : 'var(--text-primary)',
                      }}>
                        {fmt.label}
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 1 }}>
                        {fmt.description}
                      </div>
                    </div>
                    {!fmt.available && (
                      <span style={{
                        fontSize: 9, padding: '2px 6px', borderRadius: 4,
                        border: '1px solid var(--border)',
                        background: 'var(--bg-elevated)',
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase', letterSpacing: '0.08em',
                        fontWeight: 600, flexShrink: 0,
                      }}>
                        soon
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Scan summary */}
          <div style={{
            marginTop: 14, padding: '10px 12px', borderRadius: 8,
            border: '1px solid var(--border)',
            background: 'var(--bg-elevated)',
            display: 'grid', gap: 5, fontSize: 12,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Targets</span>
              <span style={{ fontFamily: 'var(--font-jetbrains), monospace', color: 'var(--text-primary)' }}>
                {scan.targets?.join(', ') || '—'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Total findings</span>
              <span style={{ fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}>
                {scan.total_findings || 0}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Status</span>
              <span style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{scan.status}</span>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-secondary" style={{ height: 34 }}>
            Cancel
          </button>
          <button
            onClick={handleDownload}
            disabled={downloading || !FORMATS.find(f => f.id === selected)?.available}
            className="btn btn-primary"
            style={{ height: 34 }}
          >
            {downloading ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
            {downloading ? 'Preparing…' : `Download ${FORMATS.find(f => f.id === selected)?.label}`}
          </button>
        </div>
      </div>
    </div>
  );
}
