import React from 'react';
import { Sidebar, NavTab } from './Sidebar';
import { Header } from './Header';

interface LayoutProps {
  children: React.ReactNode;
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  title: string;
  subtitle?: string;
  networkRiskScore?: number;
  loading?: boolean;
  onRefresh?: () => void;
}

export const Layout: React.FC<LayoutProps> = ({
  children,
  activeTab,
  onSelectTab,
  title,
  subtitle,
  networkRiskScore = 0,
  loading = false,
  onRefresh,
}) => {
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 antialiased">
      {/* Fixed Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={onSelectTab}
        networkRiskScore={networkRiskScore}
      />

      {/* Main Content Area */}
      <div className="flex flex-1 flex-col overflow-y-auto">
        <Header
          title={title}
          subtitle={subtitle}
          riskScore={networkRiskScore}
          loading={loading}
          onRefresh={onRefresh}
          onOpenAdvisor={() => onSelectTab('ai-advisor')}
        />

        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};
