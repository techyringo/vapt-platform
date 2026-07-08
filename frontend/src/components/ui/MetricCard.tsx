import type React from 'react';

type Tone = 'cyan' | 'red' | 'emerald' | 'amber';

interface MetricCardProps {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub: string;
  tone: Tone;
}

export function MetricCard({ icon: Icon, label, value, sub, tone }: MetricCardProps) {
  return (
    <div className={`metric-card metric-card-${tone}`}>
      <div className={`metric-icon metric-icon-${tone}`} aria-hidden="true">
        <Icon size={18} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div style={{
          fontSize: 10,
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          color: 'var(--text-muted)',
          fontWeight: 600,
        }}>
          {label}
        </div>
        <div style={{
          marginTop: 4,
          fontSize: 22,
          fontWeight: 700,
          fontVariantNumeric: 'tabular-nums',
          letterSpacing: '-0.02em',
          color: 'var(--text-primary)',
        }}>
          {value}
        </div>
        <div style={{
          fontSize: 11,
          color: 'var(--text-secondary)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          marginTop: 2,
        }}>
          {sub}
        </div>
      </div>
    </div>
  );
}
