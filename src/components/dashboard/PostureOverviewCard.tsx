import React from 'react';
import { Card } from '../common/Card';
import { RiskGauge } from '../common/RiskGauge';
import { NetworkPostureResult } from '../../types';
import { ShieldAlert, Activity, Eye, AlertOctagon } from 'lucide-react';

interface PostureOverviewCardProps {
  posture: NetworkPostureResult | null;
}

export const PostureOverviewCard: React.FC<PostureOverviewCardProps> = ({ posture }) => {
  if (!posture) {
    return (
      <Card title="Network Defensive Posture" subtitle="Real-time risk assessment">
        <p className="text-xs text-slate-400">No security data available.</p>
      </Card>
    );
  }

  const breakdown = posture.posture_breakdown || {};
  const exposureScore = breakdown.exposure?.score ?? 0;
  const vulnScore = breakdown.vulnerability?.score ?? 0;
  const anomalyScore = breakdown.anomaly?.score ?? 0;

  return (
    <Card
      title="Network Defensive Posture"
      subtitle={`Aggregated across ${posture.total_devices} authorized assets`}
      className="relative overflow-hidden"
    >
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Risk Gauge */}
        <div className="md:col-span-5 flex flex-col items-center justify-center p-2 border-b md:border-b-0 md:border-r border-slate-800">
          <RiskGauge score={posture.network_risk_score} size="lg" />
          <p className="mt-3 text-xs text-slate-400 text-center max-w-xs">
            Deterministic weighted risk calculated from exposed attack surface, active CVE findings, and telemetry anomalies.
          </p>
        </div>

        {/* Subscore Breakdown (40% Exposure, 40% Vuln, 20% Anomaly) */}
        <div className="md:col-span-7 space-y-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Score Breakdown & Weighting
          </div>

          {/* Exposure Subscore (40%) */}
          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800/80">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <div className="flex items-center gap-2">
                <Eye className="h-4 w-4 text-cyan-400" />
                <span className="font-semibold text-slate-200">Service Exposure</span>
                <span className="text-[10px] text-slate-400">(40% Weight)</span>
              </div>
              <span className="font-bold text-cyan-400">{Math.round(exposureScore)} / 100</span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-cyan-400 transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, exposureScore))}%` }}
              />
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Unencrypted protocols, reachable administration portals, and cleartext streams.
            </p>
          </div>

          {/* Vulnerability Subscore (40%) */}
          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800/80">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <div className="flex items-center gap-2">
                <AlertOctagon className="h-4 w-4 text-amber-400" />
                <span className="font-semibold text-slate-200">Vulnerabilities & Findings</span>
                <span className="text-[10px] text-slate-400">(40% Weight)</span>
              </div>
              <span className="font-bold text-amber-400">{Math.round(vulnScore)} / 100</span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-amber-400 transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, vulnScore))}%` }}
              />
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              {posture.critical_findings} Critical, {posture.high_findings} High security findings identified.
            </p>
          </div>

          {/* Anomaly Subscore (20%) */}
          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800/80">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-emerald-400" />
                <span className="font-semibold text-slate-200">Telemetry Baseline Anomaly</span>
                <span className="text-[10px] text-slate-400">(20% Weight)</span>
              </div>
              <span className="font-bold text-emerald-400">{Math.round(anomalyScore)} / 100</span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-emerald-400 transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, anomalyScore))}%` }}
              />
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              {posture.active_anomalies} active deviation(s) from established 24-hour traffic window.
            </p>
          </div>
        </div>
      </div>
    </Card>
  );
};
