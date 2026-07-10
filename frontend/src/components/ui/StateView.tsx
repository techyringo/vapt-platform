'use client';

import type React from 'react';
import {
  Inbox, SearchX, AlertOctagon, WifiOff, ShieldOff, Loader2, RefreshCw,
} from 'lucide-react';

export type StateVariant = 'empty' | 'no-results' | 'error' | 'offline' | 'denied' | 'loading';
type Tone = 'muted' | 'critical' | 'warn' | 'accent';

interface VariantPreset {
  icon: React.ElementType;
  tone: Tone;
  title: string;
  body: string;
}

const PRESETS: Record<StateVariant, VariantPreset> = {
  empty: {
    icon: Inbox, tone: 'muted',
    title: 'Nothing here yet',
    body: 'Once data is available it will appear here.',
  },
  'no-results': {
    icon: SearchX, tone: 'muted',
    title: 'No matches',
    body: 'No items match the current filters. Try broadening or clearing them.',
  },
  error: {
    icon: AlertOctagon, tone: 'critical',
    title: 'Something went wrong',
    body: 'We could not load this data. This is usually temporary — try again.',
  },
  offline: {
    icon: WifiOff, tone: 'warn',
    title: 'Connection lost',
    body: 'The live connection to the backend dropped. Reconnecting automatically…',
  },
  denied: {
    icon: ShieldOff, tone: 'warn',
    title: 'Access restricted',
    body: 'You do not have permission to view this. Contact an administrator if you need access.',
  },
  loading: {
    icon: Loader2, tone: 'accent',
    title: 'Loading…',
    body: 'Fetching the latest data.',
  },
};

interface StateViewProps {
  variant: StateVariant;
  /** Override the preset title/body/icon/tone for this variant. */
  title?: string;
  body?: string;
  icon?: React.ElementType;
  tone?: Tone;
  /** Primary action node (e.g. a button). */
  action?: React.ReactNode;
  /** Convenience retry button; renders when provided. */
  onRetry?: () => void;
  retryLabel?: string;
  compact?: boolean;
}

/**
 * Canonical edge-case surface. Every list/panel/table should render one of
 * these instead of a blank area when it has no rows, hits an error, loses the
 * connection, or is access-restricted.
 */
export function StateView({
  variant, title, body, icon, tone, action, onRetry, retryLabel = 'Retry', compact,
}: StateViewProps) {
  const preset = PRESETS[variant];
  const Icon = icon ?? preset.icon;
  const resolvedTone = tone ?? preset.tone;
  const spinning = variant === 'loading';

  return (
    <div className="state-view" style={compact ? { padding: '24px 16px' } : undefined} role="status" aria-live="polite">
      <div className={`state-view-icon tone-${resolvedTone}`}>
        <Icon size={20} className={spinning ? 'animate-spin' : undefined} aria-hidden="true" />
      </div>
      <div className="state-view-title">{title ?? preset.title}</div>
      <div className="state-view-body">{body ?? preset.body}</div>
      {(action || onRetry) && (
        <div className="state-view-actions">
          {action}
          {onRetry && (
            <button className="btn btn-secondary" onClick={onRetry}>
              <RefreshCw size={14} aria-hidden="true" />
              {retryLabel}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
