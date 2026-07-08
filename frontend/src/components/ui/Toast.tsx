'use client';

import { Activity, AlertTriangle, CheckCircle2, X, XCircle } from 'lucide-react';
import type { Toast, ToastType } from '@/hooks/useToast';

function ToastIcon({ type }: { type: ToastType }) {
  const size = 15;
  if (type === 'success') return <CheckCircle2 size={size} style={{ color: 'var(--low)' }} />;
  if (type === 'error')   return <XCircle      size={size} style={{ color: 'var(--critical)' }} />;
  if (type === 'warn')    return <AlertTriangle size={size} style={{ color: 'var(--medium)' }} />;
  return <Activity size={size} style={{ color: 'var(--accent)' }} />;
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  return (
    <div
      className={`toast toast-${toast.type}`}
      role="alert"
      aria-live="polite"
      onClick={() => onDismiss(toast.id)}
    >
      <span className="toast-icon">
        <ToastIcon type={toast.type} />
      </span>
      <div className="toast-body">
        <div className="toast-title">{toast.title}</div>
        {toast.message && <div className="toast-msg">{toast.message}</div>}
      </div>
      <button
        className="toast-close"
        onClick={e => { e.stopPropagation(); onDismiss(toast.id); }}
        aria-label="Dismiss notification"
      >
        <X size={13} />
      </button>
    </div>
  );
}

export function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-container" role="region" aria-label="Notifications">
      {toasts.map(t => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}
