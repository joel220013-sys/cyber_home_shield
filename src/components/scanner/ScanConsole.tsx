import React, { useState } from 'react';
import { Card } from '../common/Card';
import { ScopeBanner } from '../common/ScopeBanner';
import { ScanType } from '../../types';
import { isPrivateSubnet } from '../../lib/utils';
import { Radar, Play, CheckCircle2, AlertCircle } from 'lucide-react';

interface ScanConsoleProps {
  onStartScan: (subnet: string, scanType: ScanType, dryRun: boolean) => Promise<any>;
  isScanning: boolean;
  error?: string | null;
}

export const ScanConsole: React.FC<ScanConsoleProps> = ({
  onStartScan,
  isScanning,
  error,
}) => {
  const [targetSubnet, setTargetSubnet] = useState<string>('192.168.1.0/24');
  const [scanType, setScanType] = useState<ScanType>('DISCOVERY');
  const [dryRun, setDryRun] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    if (!isPrivateSubnet(targetSubnet)) {
      setValidationError(
        'Invalid target scope: Cyber Home Shield only permits private RFC 1918 IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).'
      );
      return;
    }

    try {
      await onStartScan(targetSubnet, scanType, dryRun);
    } catch (err: any) {
      console.error('Scan error:', err);
    }
  };

  return (
    <Card title="Defensive Network Scanner" subtitle="Authorized local subnet asset discovery">
      <div className="space-y-4">
        <ScopeBanner />

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Target Subnet Input */}
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">
                Target Subnet Scope (RFC 1918 Private IPv4)
              </label>
              <input
                type="text"
                value={targetSubnet}
                onChange={(e) => {
                  setTargetSubnet(e.target.value);
                  setValidationError(null);
                }}
                disabled={isScanning}
                placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/24"
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder-slate-400 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <div className="flex items-center gap-2 text-[11px] text-slate-400">
                <span>Presets:</span>
                <button
                  type="button"
                  onClick={() => setTargetSubnet('192.168.1.0/24')}
                  className="text-cyan-400 hover:underline"
                >
                  192.168.1.0/24
                </button>
                <span>•</span>
                <button
                  type="button"
                  onClick={() => setTargetSubnet('10.0.0.0/24')}
                  className="text-cyan-400 hover:underline"
                >
                  10.0.0.0/24
                </button>
                <span>•</span>
                <button
                  type="button"
                  onClick={() => setTargetSubnet('172.16.0.0/24')}
                  className="text-cyan-400 hover:underline"
                >
                  172.16.0.0/24
                </button>
              </div>
            </div>

            {/* Scan Type Selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Scan Strategy</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value as ScanType)}
                disabled={isScanning}
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none cursor-pointer"
              >
                <option value="DISCOVERY">ARP & ICMP Asset Discovery</option>
                <option value="PORT_PROFILE">Service & Port Profiling</option>
                <option value="FULL">Comprehensive Defensive Audit</option>
              </select>
            </div>
          </div>

          {/* Dry Run Toggle & Action Button */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-2 border-t border-slate-800/80">
            <label className="flex items-center gap-2.5 cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
                disabled={isScanning}
                className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
              />
              <div>
                <span className="font-semibold text-slate-200">Dry-Run Simulation Mode</span>
                <span className="block text-[11px] text-slate-400">
                  Performs zero socket probes; simulates discovery safely
                </span>
              </div>
            </label>

            <button
              type="submit"
              disabled={isScanning}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 px-5 py-2.5 text-xs font-bold text-white transition-colors shadow-md shadow-cyan-600/20 disabled:cursor-not-allowed"
            >
              <Radar className={`h-4 w-4 ${isScanning ? 'animate-spin text-cyan-200' : ''}`} />
              <span>{isScanning ? 'Scan In Progress...' : 'Start Defensive Scan'}</span>
            </button>
          </div>
        </form>

        {/* Validation or API Errors */}
        {(validationError || error) && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
            <span>{validationError || error}</span>
          </div>
        )}
      </div>
    </Card>
  );
};
