'use client';

import { ClipboardCheck, Code2, GitBranch, LayoutDashboard, Settings, ShieldAlert } from 'lucide-react';

type Tab = 'dashboard' | 'appsec' | 'findings' | 'agents' | 'govern' | 'tools' | 'config';

const TABS = [
  { tab: 'dashboard' as Tab, icon: LayoutDashboard, label: 'Assess' },
  { tab: 'appsec'    as Tab, icon: Code2,          label: 'Code' },
  { tab: 'findings'  as Tab, icon: ShieldAlert,     label: 'Findings' },
  { tab: 'agents'    as Tab, icon: GitBranch,       label: 'Paths' },
  { tab: 'govern'    as Tab, icon: ClipboardCheck,  label: 'Evidence' },
  { tab: 'config'    as Tab, icon: Settings,        label: 'Admin' },
] as const;

export function MobileTabBar({ activeTab, onTabChange }: { activeTab: Tab; onTabChange: (tab: Tab) => void }) {
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
