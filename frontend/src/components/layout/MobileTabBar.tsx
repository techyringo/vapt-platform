'use client';

import { Bot, Code2, LayoutDashboard, Settings, ShieldAlert, Wrench } from 'lucide-react';

type Tab = 'dashboard' | 'appsec' | 'findings' | 'agents' | 'tools' | 'config';

const TABS = [
  { tab: 'dashboard' as Tab, icon: LayoutDashboard, label: 'Dash' },
  { tab: 'appsec'    as Tab, icon: Code2,          label: 'Code' },
  { tab: 'findings'  as Tab, icon: ShieldAlert,     label: 'Finds' },
  { tab: 'agents'    as Tab, icon: Bot,             label: 'Agents' },
  { tab: 'tools'     as Tab, icon: Wrench,          label: 'Exec' },
  { tab: 'config'    as Tab, icon: Settings,        label: 'Cfg' },
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
