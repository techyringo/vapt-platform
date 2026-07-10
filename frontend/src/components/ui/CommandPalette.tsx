'use client';

import type React from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, CornerDownLeft } from 'lucide-react';

export interface CommandAction {
  id: string;
  label: string;
  sub?: string;
  group: string;
  icon: React.ElementType;
  /** Short keyboard hint chips shown on the right, e.g. ['⌘', 'N']. */
  hint?: string[];
  /** Extra words to match against (aliases). */
  keywords?: string;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  actions: CommandAction[];
  placeholder?: string;
}

/**
 * Enterprise ⌘K command palette. Fully keyboard-driven (↑/↓ to move, ↵ to run,
 * Esc to close) with substring matching across label, sub, group and keywords.
 * Self-contained — the app supplies the action list.
 */
export function CommandPalette({ open, onClose, actions, placeholder = 'Search actions, scans, views…' }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Reset state whenever the palette opens; focus the input.
  useEffect(() => {
    if (open) {
      setQuery('');
      setActive(0);
      // Focus after the open animation frame so it lands reliably.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return actions;
    return actions.filter(a =>
      `${a.label} ${a.sub ?? ''} ${a.group} ${a.keywords ?? ''}`.toLowerCase().includes(q),
    );
  }, [query, actions]);

  // Clamp the active index whenever the result set changes.
  useEffect(() => { setActive(0); }, [query]);
  useEffect(() => {
    if (active >= filtered.length) setActive(Math.max(0, filtered.length - 1));
  }, [filtered.length, active]);

  // Keep the active row scrolled into view.
  useEffect(() => {
    if (!open) return;
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`);
    el?.scrollIntoView({ block: 'nearest' });
  }, [active, open]);

  if (!open) return null;

  const runAt = (idx: number) => {
    const action = filtered[idx];
    if (!action) return;
    onClose();
    // Defer so the palette unmounts before the action (e.g. a modal) opens.
    setTimeout(() => action.run(), 0);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(i => Math.min(i + 1, filtered.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(i => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); runAt(active); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };

  // Group the filtered results while preserving a flat index for keyboard nav.
  const groups: { name: string; items: { action: CommandAction; idx: number }[] }[] = [];
  filtered.forEach((action, idx) => {
    let g = groups.find(x => x.name === action.group);
    if (!g) { g = { name: action.group, items: [] }; groups.push(g); }
    g.items.push({ action, idx });
  });

  return (
    <div
      className="cmdk-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="cmdk-panel" onKeyDown={onKeyDown}>
        <div className="cmdk-input-row">
          <Search size={18} style={{ color: 'var(--text-muted)', flexShrink: 0 }} aria-hidden="true" />
          <input
            ref={inputRef}
            className="cmdk-input"
            placeholder={placeholder}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search actions"
            autoComplete="off"
            spellCheck={false}
          />
          <span className="kbd">esc</span>
        </div>

        <div className="cmdk-list" ref={listRef} role="listbox">
          {filtered.length === 0 ? (
            <div className="cmdk-empty">No matches for “{query}”.</div>
          ) : (
            groups.map(group => (
              <div key={group.name}>
                <div className="cmdk-group-label">{group.name}</div>
                {group.items.map(({ action, idx }) => {
                  const Icon = action.icon;
                  return (
                    <button
                      key={action.id}
                      data-idx={idx}
                      className={`cmdk-item${idx === active ? ' active' : ''}`}
                      role="option"
                      aria-selected={idx === active}
                      onMouseMove={() => setActive(idx)}
                      onClick={() => runAt(idx)}
                    >
                      <span className="cmdk-item-icon"><Icon size={14} aria-hidden="true" /></span>
                      <span className="cmdk-item-body">
                        <span className="cmdk-item-label">{action.label}</span>
                        {action.sub && <span className="cmdk-item-sub">{action.sub}</span>}
                      </span>
                      {action.hint && (
                        <span className="cmdk-item-hint">
                          {action.hint.map((h, i) => <span key={i} className="kbd">{h}</span>)}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="cmdk-footer">
          <span className="cmdk-footer-hint"><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
          <span className="cmdk-footer-hint"><span className="kbd"><CornerDownLeft size={10} /></span> select</span>
          <span className="cmdk-footer-hint" style={{ marginLeft: 'auto' }}>{filtered.length} result{filtered.length === 1 ? '' : 's'}</span>
        </div>
      </div>
    </div>
  );
}
