import type React from 'react';

interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  borderRadius?: string | number;
  className?: string;
  style?: React.CSSProperties;
}

export function Skeleton({ width, height, borderRadius, className = '', style }: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width, height, borderRadius, ...style }}
      aria-hidden="true"
    />
  );
}

export function SkeletonMetricCard() {
  return (
    <div className="skeleton-card metric-card" style={{ minHeight: 86 }}>
      <Skeleton width={40} height={40} borderRadius={10} />
      <div style={{ flex: 1, display: 'grid', gap: 7 }}>
        <Skeleton height={10} width="55%" />
        <Skeleton height={22} width="40%" />
        <Skeleton height={10} width="70%" />
      </div>
    </div>
  );
}

export function SkeletonScanRow() {
  return (
    <div className="skeleton-card" style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ flex: 1, display: 'grid', gap: 6 }}>
        <Skeleton height={13} width="60%" />
        <Skeleton height={11} width="80%" />
      </div>
      <Skeleton height={20} width={60} borderRadius={6} />
    </div>
  );
}

export function SkeletonFindingCard() {
  return (
    <div className="skeleton-card" style={{ padding: '14px 16px', display: 'flex', gap: 12, alignItems: 'center' }}>
      <Skeleton width={7} height={7} borderRadius="50%" />
      <Skeleton width={48} height={20} borderRadius={6} />
      <div style={{ flex: 1, display: 'grid', gap: 6 }}>
        <Skeleton height={13} width="65%" />
        <Skeleton height={11} width="45%" />
      </div>
      <Skeleton width={18} height={18} borderRadius={4} />
    </div>
  );
}

export function SkeletonAgentCard() {
  return (
    <div className="skeleton-card" style={{ minHeight: 160 }}>
      <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
        <Skeleton width={34} height={34} borderRadius={8} />
        <div style={{ flex: 1, display: 'grid', gap: 6 }}>
          <Skeleton height={13} width="60%" />
          <Skeleton height={11} width="40%" />
        </div>
        <Skeleton width={56} height={20} borderRadius={6} />
      </div>
      <Skeleton height={5} borderRadius={4} style={{ marginBottom: 10 }} />
      <div style={{ display: 'flex', gap: 5 }}>
        {[40, 52, 44].map((w, i) => <Skeleton key={i} width={w} height={18} borderRadius={4} />)}
      </div>
    </div>
  );
}

export function SkeletonDashboard() {
  return (
    <div className="dashboard-stack">
      {/* Mission banner */}
      <div className="skeleton-card" style={{ padding: '14px 16px', minHeight: 88 }}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <Skeleton width={60} height={20} borderRadius={6} />
          <Skeleton width={120} height={20} borderRadius={6} />
        </div>
        <Skeleton height={16} width="45%" style={{ marginBottom: 8 }} />
        <Skeleton height={12} width="72%" />
      </div>

      {/* KPI grid */}
      <div className="kpi-grid">
        {Array.from({ length: 4 }).map((_, i) => <SkeletonMetricCard key={i} />)}
      </div>

      {/* Workbench */}
      <div className="dashboard-workbench">
        <div className="skeleton-card" style={{ minHeight: 400 }}>
          <Skeleton height={18} width="40%" style={{ marginBottom: 16 }} />
          <Skeleton height={90} style={{ marginBottom: 10 }} />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <Skeleton height={36} />
            <Skeleton height={36} />
          </div>
          <Skeleton height={80} style={{ marginBottom: 12 }} />
          <Skeleton height={36} />
        </div>
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="skeleton-card" style={{ minHeight: 300 }}>
            <Skeleton height={16} width="40%" style={{ marginBottom: 12 }} />
            <div style={{ display: 'grid', gap: 8 }}>
              {Array.from({ length: 4 }).map((_, i) => <SkeletonScanRow key={i} />)}
            </div>
          </div>
          <div className="skeleton-card" style={{ minHeight: 200 }}>
            <Skeleton height={14} width="30%" style={{ marginBottom: 10 }} />
            <Skeleton height={260} />
          </div>
        </div>
      </div>
    </div>
  );
}
