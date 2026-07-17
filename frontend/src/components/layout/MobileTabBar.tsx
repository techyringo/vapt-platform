'use client';

import { Activity, Code2, FileText, LayoutDashboard, Radar, ShieldAlert } from 'lucide-react';
import type { WorkspaceTab } from '@/types/navigation';

const TABS = [
  { tab: 'dashboard' as WorkspaceTab, icon: LayoutDashboard, label: 'Command' },
  { tab: 'live'      as WorkspaceTab, icon: Activity,        label: 'Live' },
  { tab: 'recon'     as WorkspaceTab, icon: Radar,           label: 'Recon' },
  { tab: 'findings'  as WorkspaceTab, icon: ShieldAlert,     label: 'Findings' },
  { tab: 'appsec'    as WorkspaceTab, icon: Code2,           label: 'SAST' },
  { tab: 'reports'   as WorkspaceTab, icon: FileText,        label: 'Reports' },
] as const;

export function MobileTabBar({ activeTab, onTabChange }: { activeTab: WorkspaceTab; onTabChange: (tab: WorkspaceTab) => void }) {
  return (
    <nav className="mobile-tabs lg:hidden flex items-center" aria-label="Mobile navigation">
      {TABS.map(({ tab, icon: Icon, label }) => (
        <button
          key={tab}
          onClick={() => onTabChange(tab)}
          className={`mobile-tab-item${activeTab === tab ? ' active' : ''}`}
          aria-current={activeTab === tab ? 'page' : undefined}
        >
          <Icon size={18} aria-hidden="true" />
          <span>{label}</span>
        </button>
      ))}
    </nav>
  );
}
