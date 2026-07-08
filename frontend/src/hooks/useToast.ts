import { useCallback, useState } from 'react';

export type ToastType = 'success' | 'error' | 'info' | 'warn';

export interface Toast {
  id: string;
  title: string;
  message?: string;
  type: ToastType;
}

let counter = 0;

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const push = useCallback((title: string, type: ToastType = 'info', message?: string) => {
    const id = `toast-${++counter}`;
    setToasts(prev => [...prev.slice(-4), { id, title, type, message }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4500);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const success = useCallback((title: string, message?: string) => push(title, 'success', message), [push]);
  const error   = useCallback((title: string, message?: string) => push(title, 'error', message),   [push]);
  const info    = useCallback((title: string, message?: string) => push(title, 'info', message),    [push]);
  const warn    = useCallback((title: string, message?: string) => push(title, 'warn', message),    [push]);

  return { toasts, push, dismiss, success, error, info, warn };
}
