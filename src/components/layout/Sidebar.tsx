import React from 'react';
import {
  Shield,
  LayoutDashboard,
  HardDrive,
  Radar,
  AlertTriangle,
  Activity,
  Bot,
  Terminal,
  ShieldAlert,
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'devices'
  | 'scanner'
  | 'findings'
  | 'telemetry'
  | 'honeypot'
  | 'ai-advisor';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  networkRiskScore?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  networkRiskScore = 0,
}) => {
  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Security Posture', icon: LayoutDashboard },
    { id: 'devices' as NavTab, label: 'Device Inventory', icon: HardDrive },
    { id: 'scanner' as NavTab, label: 'Defensive Scanner', icon: Radar },
    { id: 'findings' as NavTab, label: 'Security Findings', icon: AlertTriangle },
    { id: 'telemetry' as NavTab, label: 'Telemetry & Events', icon: Activity },
    { id: 'honeypot' as NavTab, label: 'Honeypot & Deception', icon: ShieldAlert },
    { id: 'ai-advisor' as NavTab, label: 'CipherX', icon: Bot },
  ];

  return (
    <aside className="w-64 shrink-0 flex flex-col justify-between border-r border-slate-800 bg-slate-950 px-4 py-5 select-none">
      <div>
        {/* Brand Logo */}
        <div className="flex items-center gap-3 px-2 mb-8">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">Cyber Home Shield</h1>
            <p className="text-[11px] font-medium text-cyan-400">Defensive Security Engine</p>
          </div>
        </div>

        {/* Navigation Menu */}
        <div className="space-y-1">
          <p className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Operations
          </p>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
                {item.id === 'honeypot' && (
                  <span className="ml-auto text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30">
                    DECOY
                  </span>
                )}
                {item.id === 'ai-advisor' && (
                  <span className="ml-auto text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
                    CIPHERX
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Footer Info */}
      <div className="mt-auto pt-4 border-t border-slate-900 space-y-3">
        <div className="rounded-lg bg-slate-900/90 p-3 border border-slate-800">
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="text-slate-400">Posture Score</span>
            <span className="font-bold text-white">{Math.round(networkRiskScore)} / 100</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                networkRiskScore > 75
                  ? 'bg-red-500'
                  : networkRiskScore > 50
                  ? 'bg-orange-500'
                  : networkRiskScore > 25
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, networkRiskScore))}%` }}
            />
          </div>
        </div>

        <div className="flex items-center gap-2 px-1 text-[11px] text-slate-400">
          <Terminal className="h-3.5 w-3.5 text-slate-400" />
          <span>RFC1918 Scope Guard Active</span>
        </div>
      </div>
    </aside>
  );
};
