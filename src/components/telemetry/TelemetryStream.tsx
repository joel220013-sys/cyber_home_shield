import React, { useState } from 'react';
import { Card } from '../common/Card';
import { NetworkEvent } from '../../types';
import { formatTimestamp } from '../../lib/utils';
import { Activity, AlertTriangle, ArrowRight, ShieldCheck, Zap } from 'lucide-react';

interface TelemetryStreamProps {
  events: NetworkEvent[];
  loading?: boolean;
  error?: string | null;
  onTriageEvent?: (event: NetworkEvent) => void;
}

export const TelemetryStream: React.FC<TelemetryStreamProps> = ({
  events,
  loading = false,
  error,
  onTriageEvent,
}) => {
  const [filterAnomalies, setFilterAnomalies] = useState<boolean>(false);

  const displayedEvents = filterAnomalies ? events.filter((e) => e.is_anomaly) : events;

  return (
    <Card
      title="Network Telemetry Event Stream"
      subtitle="Defensive connection telemetry and flow monitoring"
      action={
        <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
          <input
            type="checkbox"
            checked={filterAnomalies}
            onChange={(e) => setFilterAnomalies(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-900 text-cyan-500"
          />
          <span>Show Anomalies Only</span>
        </label>
      }
    >
      {loading ? (
        <div className="p-6 text-sm text-slate-400">Loading network telemetry...</div>
      ) : error ? (
        <div className="p-6 text-sm text-red-300">{error}</div>
      ) : events.length === 0 ? (
        <div className="p-6 text-sm text-slate-400">No network telemetry events recorded.</div>
      ) : (
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="border-b border-slate-800 bg-slate-950 text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
            <tr>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Flow Coordinates</th>
              <th className="px-4 py-3">Protocol / Port</th>
              <th className="px-4 py-3">Volume</th>
              <th className="px-4 py-3">Baseline Assessment</th>
              <th className="px-4 py-3 text-right">Triage</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/80">
            {displayedEvents.map((evt, i) => {
              const isAnom = evt.is_anomaly;

              return (
                <tr key={evt.id || i} className="hover:bg-slate-900/50 transition-colors">
                  <td className="px-4 py-3 text-slate-400 font-mono text-[11px]">
                    {formatTimestamp(evt.event_timestamp)}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    <div className="flex items-center gap-1.5 text-slate-200">
                      <span>{evt.source_ip}</span>
                      <ArrowRight className="h-3 w-3 text-slate-400" />
                      <span>{evt.destination_ip}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    <span className="font-semibold text-cyan-400">{evt.destination_port}</span>
                    <span className="text-slate-400">/{evt.protocol}</span>
                  </td>
                  <td className="px-4 py-3 text-[11px] text-slate-400">
                    {evt.bytes_transferred > 0
                      ? `${Math.round(evt.bytes_transferred / 1024)} KB`
                      : 'N/A'}
                  </td>
                  <td className="px-4 py-3">
                    {isAnom ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-bold">
                        <AlertTriangle className="h-3 w-3" />
                        ANOMALOUS ({evt.severity})
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-medium">
                        <ShieldCheck className="h-3 w-3" />
                        Normal Baseline
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {onTriageEvent && (
                      <button
                        onClick={() => onTriageEvent(evt)}
                        className="inline-flex items-center gap-1 rounded bg-slate-800 hover:bg-emerald-950/40 hover:text-emerald-300 border border-slate-700 px-2 py-1 text-[11px] font-medium text-slate-300 transition-colors"
                      >
                        <Zap className="h-3 w-3 text-emerald-400" />
                        <span>AI Triage</span>
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      )}
    </Card>
  );
};
