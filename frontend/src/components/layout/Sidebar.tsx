'use client';

import type React from 'react';
import {
  Activity,
  ClipboardCheck,
  Code2,
  GitBranch,
  LayoutDashboard,
  Radar,
  ScanSearch,
  Settings,
  Shield,
  ShieldAlert,
  Wifi,
  WifiOff,
  Wrench,
} from 'lucide-react';
import type { WorkspaceTab } from '@/types/navigation';

interface SidebarItemProps {
  active: boolean;
  icon: React.ElementType;
  label: string;
  count?: number;
  onClick: () => void;
}

function SidebarItem({ active, icon: Icon, label, count, onClick }: SidebarItemProps) {
  return (
    <button
      onClick={onClick}
      className={`sidebar-item${active ? ' active' : ''}`}
      aria-current={active ? 'page' : undefined}
    >
      <Icon size={15} style={{ flexShrink: 0 }} aria-hidden="true" />
      <span className="sidebar-item-label">{label}</span>
      {typeof count === 'number' && count > 0 && (
        <span className="sidebar-item-count" aria-label={`${count} items`}>{count}</span>
      )}
    </button>
  );
}

interface SidebarProps {
  activeTab: WorkspaceTab;
  onTabChange: (tab: WorkspaceTab) => void;
  scanCount: number;
  findingCount: number;
  attackPathCount: number;
  connected: boolean;
  apiHealthy: boolean | null;
}

export function Sidebar({
  activeTab, onTabChange,
  scanCount, findingCount, attackPathCount,
  connected, apiHealthy,
}: SidebarProps) {
  return (
    <aside className="sidebar hidden lg:flex flex-col" aria-label="Navigation">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon" aria-hidden="true">
          <Shield size={14} />
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            VAPT <span style={{ color: 'var(--accent)' }}>Platform</span>
          </div>
          <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 1 }}>
            AI Pentest Console
          </div>
        </div>
      </div>

      {/* Nav items */}
      <nav className="sidebar-nav" aria-label="Main navigation">
        <div className="sidebar-section-label">Overview</div>
        <SidebarItem active={activeTab === 'dashboard'} icon={LayoutDashboard} label="Command Center" count={scanCount} onClick={() => onTabChange('dashboard')} />
        <div className="sidebar-section-label">Operations</div>
        <SidebarItem active={activeTab === 'live'}      icon={Activity}        label="Live Scan"                    onClick={() => onTabChange('live')} />
        <SidebarItem active={activeTab === 'recon'}     icon={Radar}           label="Recon Intel"                  onClick={() => onTabChange('recon')} />
        <div className="sidebar-section-label">Results</div>
        <SidebarItem active={activeTab === 'findings'}  icon={ShieldAlert}     label="Findings" count={findingCount}  onClick={() => onTabChange('findings')} />
        <SidebarItem active={activeTab === 'agents'}    icon={GitBranch}       label="Attack Surface" count={attackPathCount} onClick={() => onTabChange('agents')} />
        <div className="sidebar-section-label">Application Security</div>
        <SidebarItem active={activeTab === 'appsec'}    icon={Code2}           label="SAST & Supply Chain"           onClick={() => onTabChange('appsec')} />
        <SidebarItem active={activeTab === 'dast'}      icon={ScanSearch}      label="Adaptive DAST"                 onClick={() => onTabChange('dast')} />
        <SidebarItem active={activeTab === 'govern'}    icon={ClipboardCheck}  label="Test Coverage"              onClick={() => onTabChange('govern')} />
        <div className="sidebar-section-label">Administration</div>
        <SidebarItem active={activeTab === 'tools'}     icon={Wrench}          label="Operations"                    onClick={() => onTabChange('tools')} />
        <SidebarItem active={activeTab === 'config'}    icon={Settings}        label="Settings"                        onClick={() => onTabChange('config')} />
      </nav>

      {/* Footer — connection status */}
      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-muted)' }}>
          {connected
            ? <Wifi size={13} style={{ color: 'var(--low)' }} aria-label="Connected" />
            : <WifiOff size={13} style={{ color: 'var(--critical)' }} className="animate-pulse-dot" aria-label="Disconnected" />}
          <span>{connected ? 'SSE live' : 'SSE offline'}</span>
          <span
            role="status"
            aria-label={`API ${apiHealthy ? 'healthy' : apiHealthy === false ? 'offline' : 'checking'}`}
            style={{
              marginLeft: 'auto', width: 7, height: 7, borderRadius: '50%',
              background: apiHealthy ? 'var(--low)' : apiHealthy === false ? 'var(--critical)' : 'var(--medium)',
              display: 'inline-block',
            }}
            className={!apiHealthy ? 'animate-pulse-dot' : ''}
          />
        </div>
      </div>
    </aside>
  );
}
