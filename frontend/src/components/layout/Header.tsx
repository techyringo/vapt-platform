'use client';

import { Moon, Palette, RefreshCw, Shield, Sun, Wifi, WifiOff, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { COLOR_GRADES, useTheme, type ColorGrade } from '@/context/ThemeContext';

/* ─── Palette dropdown — shown only in light mode ─── */
function GradeMenu() {
  const { colorGrade, setColorGrade } = useTheme();
  const [open, setOpen]       = useState(false);
  const menuRef               = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const active = COLOR_GRADES.find(g => g.id === colorGrade)!;

  return (
    <div ref={menuRef} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="btn btn-icon"
        title="Accent colour"
        aria-label="Choose accent colour"
        aria-expanded={open}
        aria-haspopup="true"
        style={{ width: 32, height: 32, borderRadius: 7, gap: 4 }}
      >
        <span style={{
          width: 8, height: 8, borderRadius: '50%',
          background: active.accentHex, flexShrink: 0, display: 'block',
        }} aria-hidden="true" />
        <Palette size={11} aria-hidden="true" />
      </button>

      {open && (
        <div
          role="menu"
          style={{
            position: 'absolute', top: 'calc(100% + 6px)', right: 0,
            width: 172,
            border: '1px solid var(--border)',
            borderRadius: 10,
            background: 'var(--bg-card)',
            boxShadow: 'var(--shadow-modal)',
            padding: '6px',
            zIndex: 90,
            animation: 'expand-down 140ms ease',
          }}
        >
          <div style={{ padding: '4px 8px 6px', borderBottom: '1px solid var(--border)', marginBottom: 4 }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>
              Accent colour
            </span>
          </div>
          {COLOR_GRADES.map(g => (
            <button
              key={g.id}
              role="menuitemradio"
              aria-checked={colorGrade === g.id}
              onClick={() => { setColorGrade(g.id as ColorGrade); setOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                width: '100%', padding: '7px 8px', borderRadius: 6,
                background: colorGrade === g.id ? 'var(--accent-dim)' : 'transparent',
                border: colorGrade === g.id ? '1px solid var(--accent-border)' : '1px solid transparent',
                cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit',
                transition: 'background 120ms ease',
              }}
            >
              <span style={{
                width: 12, height: 12, borderRadius: '50%',
                background: g.accentHex, flexShrink: 0,
                boxShadow: colorGrade === g.id ? `0 0 0 2px ${g.accentHex}40` : 'none',
                transition: 'box-shadow 120ms ease',
              }} aria-hidden="true" />
              <span style={{
                fontSize: 12, fontWeight: colorGrade === g.id ? 600 : 400,
                color: colorGrade === g.id ? 'var(--accent)' : 'var(--text-secondary)',
              }}>
                {g.label}
              </span>
              {colorGrade === g.id && (
                <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--accent)', fontWeight: 700 }}>✓</span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ─── Header ────────────────────────────────────────────── */
interface HeaderProps {
  apiHealthy: boolean | null;
  connected: boolean;
  targetCount: number;
  refreshing: boolean;
  onRefresh: () => void;
}

export function Header({ apiHealthy, connected, targetCount, refreshing, onRefresh }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="app-header">
      {/* Brand */}
      <div className="header-brand">
        <div className="header-brand-icon" aria-hidden="true">
          <Shield size={16} />
        </div>
        <div style={{ minWidth: 0 }}>
          <h1 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em', lineHeight: 1.2 }}>
            VAPT <span style={{ color: 'var(--accent)' }}>Platform</span>
          </h1>
          <p style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 1, lineHeight: 1 }}>
            AI Pentest Console
          </p>
        </div>
      </div>

      {/* Controls right */}
      <div className="header-controls">
        {/* Status pills */}
        {targetCount > 0 && (
          <span className="status-pill cyan always-show" style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10 }}>
            {targetCount} {targetCount === 1 ? 'target' : 'targets'}
          </span>
        )}
        <span className={`status-pill ${apiHealthy ? 'green' : apiHealthy === false ? 'red' : 'amber'}`}>
          API {apiHealthy === null ? 'checking' : apiHealthy ? 'healthy' : 'offline'}
        </span>
        <span className={`status-pill ${connected ? 'green' : 'red'}`} style={{ gap: 5 }}>
          {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
          {connected ? 'Live' : 'Offline'}
        </span>

        {/* Divider */}
        <span style={{ width: 1, height: 18, background: 'var(--border)', margin: '0 2px' }} aria-hidden="true" />

        {/* Accent colour picker — only in light mode */}
        {theme === 'light' && <GradeMenu />}

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="btn btn-icon"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{ width: 32, height: 32, borderRadius: 7 }}
        >
          {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>

        {/* Refresh */}
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="btn btn-icon"
          title="Refresh data"
          aria-label="Refresh data"
          style={{ width: 32, height: 32, borderRadius: 7 }}
        >
          <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
        </button>

        {/* Version — subtle */}
        <span className="status-pill muted" style={{ fontFamily: 'var(--font-jetbrains), monospace', fontSize: 10 }}>
          v2.0.0
        </span>
      </div>
    </header>
  );
}
