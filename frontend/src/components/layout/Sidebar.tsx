'use client';

import type React from 'react';
import { Bot, LayoutDashboard, Settings, Shield, ShieldAlert, Wifi, WifiOff, Wrench } from 'lucide-react';

type Tab = 'dashboard' | 'findings' | 'agents' | 'tools' | 'config';

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
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  scanCount: number;
  findingCount: number;
  agentCount: number;
  toolCount: number;
  connected: boolean;
  apiHealthy: boolean | null;
}

export function Sidebar({
  activeTab, onTabChange,
  scanCount, findingCount, agentCount, toolCount,
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
        <SidebarItem active={activeTab === 'dashboard'} icon={LayoutDashboard} label="Dashboard" count={scanCount}     onClick={() => onTabChange('dashboard')} />
        <SidebarItem active={activeTab === 'findings'}  icon={ShieldAlert}     label="Findings"  count={findingCount}  onClick={() => onTabChange('findings')} />
        <SidebarItem active={activeTab === 'agents'}    icon={Bot}             label="Agents"    count={agentCount}    onClick={() => onTabChange('agents')} />
        <SidebarItem active={activeTab === 'tools'}     icon={Wrench}          label="Tools"     count={toolCount}     onClick={() => onTabChange('tools')} />
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
