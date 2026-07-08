import type { SeverityKey } from '@/types';

const SEVERITIES: SeverityKey[] = ['critical', 'high', 'medium', 'low', 'informational'];

const SEV_HEX: Record<SeverityKey, string> = {
  critical:      '#f43f5e',
  high:          '#f97316',
  medium:        '#eab308',
  low:           '#22c55e',
  informational: '#06b6d4',
};

interface SeverityDonutProps {
  counts: Record<SeverityKey, number>;
  total: number;
}

export function SeverityDonut({ counts, total }: SeverityDonutProps) {
  const r  = 42;
  const sw = 13;
  const C  = 2 * Math.PI * r;

  let offset = 0;
  const segments = SEVERITIES.map(sev => {
    const val    = counts[sev] || 0;
    const length = total ? (val / total) * C : 0;
    const seg    = { sev, val, length, offset };
    offset += length;
    return seg;
  });

  const dominant = segments.reduce((best, s) => (s.val > best.val ? s : best), segments[0]);

  return (
    <div className="donut-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <div>
          <div className="section-label">Severity Mix</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 3 }}>
            {total ? `${dominant.sev === 'informational' ? 'info' : dominant.sev} leads` : 'No findings yet'}
          </div>
        </div>
        <span style={{
          fontFamily: 'var(--font-jetbrains), monospace', fontSize: 12,
          padding: '2px 8px', borderRadius: 5,
          border: '1px solid var(--border)',
          background: 'var(--bg-elevated)',
          color: 'var(--text-secondary)',
          fontVariantNumeric: 'tabular-nums',
        }}>
          {total}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* SVG donut */}
        <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
          <svg
            viewBox="0 0 112 112"
            style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}
            aria-hidden="true"
          >
            <circle cx="56" cy="56" r={r} fill="transparent" stroke="rgba(255,255,255,0.06)" strokeWidth={sw} />
            {segments.map(seg => seg.val > 0 && (
              <circle
                key={seg.sev}
                cx="56" cy="56" r={r}
                fill="transparent"
                stroke={SEV_HEX[seg.sev]}
                strokeWidth={sw}
                strokeDasharray={`${seg.length} ${C - seg.length}`}
                strokeDashoffset={-seg.offset}
                strokeLinecap="butt"
              />
            ))}
          </svg>
          <div style={{
            position: 'absolute', inset: 0,
            display: 'grid', placeItems: 'center', textAlign: 'center',
          }}>
            <div>
              <div style={{
                fontFamily: 'var(--font-jetbrains), monospace',
                fontSize: 22, fontWeight: 700,
                fontVariantNumeric: 'tabular-nums',
                color: 'var(--text-primary)',
              }}>
                {total}
              </div>
              <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-muted)' }}>total</div>
            </div>
          </div>
        </div>

        {/* Legend */}
        <div style={{ flex: 1, display: 'grid', gap: 6 }}>
          {SEVERITIES.map(sev => {
            const pct = total ? Math.round((counts[sev] / total) * 100) : 0;
            return (
              <div key={sev} style={{ display: 'grid', gridTemplateColumns: '8px minmax(0,1fr) 36px', alignItems: 'center', gap: 7, fontSize: 11 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_HEX[sev], display: 'block' }} aria-hidden="true" />
                <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textTransform: 'capitalize' }}>
                  {sev === 'informational' ? 'info' : sev}
                </span>
                <span style={{ textAlign: 'right', fontFamily: 'var(--font-jetbrains), monospace', color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
                  {pct}%
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export { SEV_HEX, SEVERITIES };
