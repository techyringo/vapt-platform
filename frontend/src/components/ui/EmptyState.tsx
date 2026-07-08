import type React from 'react';

interface EmptyStateProps {
  icon: React.ElementType;
  title: string;
  body: string;
  action?: React.ReactNode;
}

export function EmptyState({ icon: Icon, title, body, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <div>
        <div style={{
          display: 'inline-grid',
          placeItems: 'center',
          width: 44, height: 44,
          borderRadius: 12,
          border: '1px solid var(--border)',
          background: 'var(--bg-elevated)',
          marginBottom: 10,
          color: 'var(--text-muted)',
        }}>
          <Icon size={20} />
        </div>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</h3>
        <p style={{ marginTop: 6, fontSize: 12, color: 'var(--text-secondary)', maxWidth: 360, margin: '6px auto 0', lineHeight: 1.6 }}>
          {body}
        </p>
        {action && <div style={{ marginTop: 14 }}>{action}</div>}
      </div>
    </div>
  );
}
