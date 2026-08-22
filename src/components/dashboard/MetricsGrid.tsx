import React from 'react';
import { Card } from '../common/Card';
import { NetworkPostureResult } from '../../types';
import { HardDrive, AlertTriangle, ShieldAlert, Activity, Flame, CheckCircle } from 'lucide-react';

interface MetricsGridProps {
  posture: NetworkPostureResult | null;
}

export const MetricsGrid: React.FC<MetricsGridProps> = ({ posture }) => {
  if (!posture) return null;

  const cards = [
    {
      title: 'Total Devices',
      value: posture.total_devices,
      subtext: 'Observed assets in scope',
      icon: HardDrive,
      color: 'text-cyan-400',
      bg: 'bg-cyan-950/30',
      border: 'border-cyan-500/20',
    },
    {
      title: 'Vulnerable Devices',
      value: posture.vulnerable_devices,
      subtext: `${posture.total_devices > 0 ? Math.round((posture.vulnerable_devices / posture.total_devices) * 100) : 0}% of inventory`,
      icon: AlertTriangle,
      color: posture.vulnerable_devices > 0 ? 'text-amber-400' : 'text-emerald-400',
      bg: posture.vulnerable_devices > 0 ? 'bg-amber-950/30' : 'bg-emerald-950/30',
      border: posture.vulnerable_devices > 0 ? 'border-amber-500/20' : 'border-emerald-500/20',
    },
    {
      title: 'Critical Findings',
      value: posture.critical_findings,
      subtext: 'Immediate action required',
      icon: Flame,
      color: posture.critical_findings > 0 ? 'text-red-400' : 'text-slate-400',
      bg: posture.critical_findings > 0 ? 'bg-red-950/30' : 'bg-slate-900',
      border: posture.critical_findings > 0 ? 'border-red-500/30' : 'border-slate-800',
    },
    {
      title: 'High Severity Findings',
      value: posture.high_findings,
      subtext: 'Elevated risk priority',
      icon: ShieldAlert,
      color: posture.high_findings > 0 ? 'text-orange-400' : 'text-slate-400',
      bg: posture.high_findings > 0 ? 'bg-orange-950/30' : 'bg-slate-900',
      border: posture.high_findings > 0 ? 'border-orange-500/30' : 'border-slate-800',
    },
    {
      title: 'Active Anomalies',
      value: posture.active_anomalies,
      subtext: 'Traffic pattern deviations',
      icon: Activity,
      color: posture.active_anomalies > 0 ? 'text-emerald-400' : 'text-slate-400',
      bg: 'bg-slate-900',
      border: 'border-slate-800',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div
            key={i}
            className={`rounded-xl border ${c.border} ${c.bg} p-4 flex flex-col justify-between transition-all`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-slate-400">{c.title}</span>
              <Icon className={`h-4 w-4 ${c.color}`} />
            </div>
            <div>
              <div className="text-2xl font-bold tracking-tight text-white">{c.value}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{c.subtext}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
