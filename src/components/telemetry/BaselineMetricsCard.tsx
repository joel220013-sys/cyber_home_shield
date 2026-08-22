import React from 'react';
import { Card } from '../common/Card';
import { Activity, ShieldCheck, TrendingUp, AlertTriangle } from 'lucide-react';

export const BaselineMetricsCard: React.FC = () => {
  return (
    <Card
      title="Traffic Baseline Engine"
      subtitle="Statistical window monitoring for IoT exfiltration and abnormal bursts"
    >
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Baseline Sliding Window</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white">24 Hours</div>
          <p className="text-[11px] text-slate-400">Continuous rolling standard deviation calculation</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Threshold Trigger</span>
            <TrendingUp className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-white">&gt; 3.0 &sigma; (Sigma)</div>
          <p className="text-[11px] text-slate-400">Z-score anomaly threshold for packet bursts</p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Monitored Metrics</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-white">Ports & Rates</div>
          <p className="text-[11px] text-slate-400">Tracks new destination IPs, unusual ports, and volume</p>
        </div>
      </div>
    </Card>
  );
};
