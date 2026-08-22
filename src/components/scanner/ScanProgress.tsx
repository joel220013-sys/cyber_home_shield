import React from 'react';
import { Card } from '../common/Card';
import { ScanJob } from '../../types';
import { StatusBadge } from '../common/Badge';
import { formatTimestamp } from '../../lib/utils';
import {
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Shield,
  Clock,
} from 'lucide-react';

interface ScanProgressProps {
  job: ScanJob | null;
  isScanning: boolean;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  job,
  isScanning,
}) => {
  if (!job) return null;

  const isCompleted = job.status === 'COMPLETED';
  const isFailed = job.status === 'FAILED';

  return (
    <Card
      title="Current Scan Status"
      subtitle={`Job ID: ${job.id.slice(0, 8)}...`}
      action={
        <StatusBadge
          status={job.status}
          variant={isCompleted ? 'online' : isFailed ? 'offline' : 'active'}
        />
      }
    >
      <div className="space-y-4">
        {/* Progress Bar / Indicator */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-300">
            <div className="flex items-center gap-2">
              {isScanning ? (
                <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
              ) : isCompleted ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-red-400" />
              )}

              <span className="font-semibold text-slate-200">
                {isScanning
                  ? 'Performing non-invasive defensive discovery...'
                  : isCompleted
                    ? 'Discovery execution completed successfully'
                    : 'Scan execution failed'}
              </span>
            </div>

            <span className="text-slate-400 font-mono text-[11px]">
              {job.target_subnet}
            </span>
          </div>

          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full transition-all duration-300 ${
                isCompleted
                  ? 'bg-emerald-500 w-full'
                  : isFailed
                    ? 'bg-red-500 w-full'
                    : 'bg-cyan-500 animate-pulse w-3/4'
              }`}
            />
          </div>
        </div>

        {/* Metrics Box */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800">
            <span className="text-[11px] text-slate-400">
              Devices Discovered
            </span>

            <div className="text-xl font-bold text-white mt-0.5">
              {job.devices_found}
            </div>
          </div>

          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800">
            <span className="text-[11px] text-slate-400">
              Port Checks
            </span>

            <div className="text-xl font-bold text-white mt-0.5">
              {job.ports_scanned}
            </div>
          </div>

          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800">
            <span className="text-[11px] text-slate-400">
              Strategy
            </span>

            <div className="text-xs font-semibold text-slate-200 mt-1">
              {job.scan_type}
            </div>
          </div>

          <div className="rounded-lg bg-slate-950/60 p-3 border border-slate-800">
            <span className="text-[11px] text-slate-400">
              Started At
            </span>

            <div className="text-[11px] text-slate-300 mt-1 font-mono">
              {formatTimestamp(job.started_at)}
            </div>
          </div>
        </div>

        {job.error_message && (
          <div className="rounded-lg bg-red-950/30 border border-red-500/30 p-3 text-xs text-red-300">
            <span className="font-semibold">Error:</span>{' '}
            {job.error_message}
          </div>
        )}
      </div>
    </Card>
  );
};