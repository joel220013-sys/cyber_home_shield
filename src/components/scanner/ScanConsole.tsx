import React, { useState, useEffect } from 'react';
import { Card } from '../common/Card';
import { ScopeBanner } from '../common/ScopeBanner';
import { ScanType } from '../../types';
import { isPrivateSubnet } from '../../lib/utils';
import { useAuth } from '../../context/AuthContext';
import { Radar, ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';

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
  const { user, updateProfile } = useAuth();

  const [targetSubnet, setTargetSubnet] = useState<string>(
    user?.authorized_network_scope || '192.168.1.0/24'
  );
  const [scanType, setScanType] = useState<ScanType>('DISCOVERY');
  const [dryRun, setDryRun] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isUpdatingScope, setIsUpdatingScope] = useState<boolean>(false);

  // Synchronize targetSubnet when the authenticated user profile loads
  useEffect(() => {
    if (user?.authorized_network_scope) {
      // If user hasn't typed a custom subnet or is on the default fallback, sync to user's authorized scope
      if (targetSubnet === '192.168.1.0/24' || !targetSubnet) {
        setTargetSubnet(user.authorized_network_scope);
      }
    }
  }, [user?.authorized_network_scope]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    const cleanTarget = targetSubnet.trim();

    if (!isPrivateSubnet(cleanTarget)) {
      setValidationError(
        'Invalid target scope: Cyber Home Shield only permits private RFC 1918 IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).'
      );
      return;
    }

    try {
      await onStartScan(cleanTarget, scanType, dryRun);
    } catch (err: any) {
      console.error('Scan error:', err);
    }
  };

  const isScopeError =
    (error && error.toLowerCase().includes('authorized network scope')) ||
    (validationError && validationError.toLowerCase().includes('authorized network scope'));

  const handleAuthorizeAndScan = async () => {
    const cleanTarget = targetSubnet.trim();
    if (!isPrivateSubnet(cleanTarget)) {
      setValidationError(
        'Target must be a valid RFC 1918 private subnet (e.g. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).'
      );
      return;
    }

    try {
      setIsUpdatingScope(true);
      setValidationError(null);
      await updateProfile({ authorized_network_scope: cleanTarget });
      await onStartScan(cleanTarget, scanType, dryRun);
    } catch (err: any) {
      setValidationError(err?.message || 'Failed to update authorized network scope');
    } finally {
      setIsUpdatingScope(false);
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
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-300">
                  Target Subnet Scope (RFC 1918 Private IPv4)
                </label>
                {user?.authorized_network_scope && (
                  <span className="text-[11px] text-slate-400">
                    Authorized: <span className="font-mono text-cyan-400 font-semibold">{user.authorized_network_scope}</span>
                  </span>
                )}
              </div>
              <input
                type="text"
                value={targetSubnet}
                onChange={(e) => {
                  setTargetSubnet(e.target.value);
                  setValidationError(null);
                }}
                disabled={isScanning || isUpdatingScope}
                placeholder="e.g. 10.47.148.0/24 or 192.168.1.0/24"
                className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder-slate-400 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                <span>Presets:</span>
                {user?.authorized_network_scope && (
                  <button
                    type="button"
                    onClick={() => {
                      setTargetSubnet(user.authorized_network_scope);
                      setValidationError(null);
                    }}
                    className="inline-flex items-center gap-1 rounded bg-cyan-950/70 border border-cyan-500/40 px-2 py-0.5 text-cyan-300 hover:bg-cyan-900/60 transition-colors font-mono"
                    title="Click to set your authorized network scope"
                  >
                    <ShieldCheck className="h-3 w-3 text-cyan-400" />
                    My Scope: {user.authorized_network_scope}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setTargetSubnet('192.168.1.0/24');
                    setValidationError(null);
                  }}
                  className="text-cyan-400 hover:underline"
                >
                  192.168.1.0/24
                </button>
                <span>•</span>
                <button
                  type="button"
                  onClick={() => {
                    setTargetSubnet('10.0.0.0/24');
                    setValidationError(null);
                  }}
                  className="text-cyan-400 hover:underline"
                >
                  10.0.0.0/24
                </button>
                <span>•</span>
                <button
                  type="button"
                  onClick={() => {
                    setTargetSubnet('172.16.0.0/24');
                    setValidationError(null);
                  }}
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
                disabled={isScanning || isUpdatingScope}
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
                disabled={isScanning || isUpdatingScope}
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
              disabled={isScanning || isUpdatingScope}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 px-5 py-2.5 text-xs font-bold text-white transition-colors shadow-md shadow-cyan-600/20 disabled:cursor-not-allowed"
            >
              <Radar className={`h-4 w-4 ${isScanning ? 'animate-spin text-cyan-200' : ''}`} />
              <span>
                {isUpdatingScope
                  ? 'Updating Scope...'
                  : isScanning
                  ? 'Scan In Progress...'
                  : 'Start Defensive Scan'}
              </span>
            </button>
          </div>
        </form>

        {/* Validation or API Errors with Actionable Remediation */}
        {(validationError || error) && (
          <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-3.5 text-xs text-red-300 space-y-2.5">
            <div className="flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 text-red-400 mt-0.5" />
              <div className="flex-1 space-y-1">
                <p className="font-medium text-red-200">{validationError || error}</p>
                {isScopeError && (
                  <p className="text-[11px] text-slate-400">
                    Your account is registered to scan{' '}
                    <code className="text-cyan-300 font-mono font-semibold">
                      {user?.authorized_network_scope || 'its authorized subnet'}
                    </code>
                    . To scan <code className="text-amber-300 font-mono font-semibold">{targetSubnet}</code>, click the button below to update your scope and scan automatically.
                  </p>
                )}
              </div>
            </div>

            {isScopeError && (
              <div className="flex flex-wrap items-center gap-2 pl-6 pt-1">
                {user?.authorized_network_scope && (
                  <button
                    type="button"
                    onClick={() => {
                      setTargetSubnet(user.authorized_network_scope);
                      setValidationError(null);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-md bg-cyan-950/80 border border-cyan-500/40 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-900 transition-colors"
                  >
                    <RefreshCw className="h-3 w-3 text-cyan-400" />
                    Switch to {user.authorized_network_scope}
                  </button>
                )}
                {isPrivateSubnet(targetSubnet) && (
                  <button
                    type="button"
                    disabled={isUpdatingScope || isScanning}
                    onClick={handleAuthorizeAndScan}
                    className="inline-flex items-center gap-1.5 rounded-md bg-red-600/30 border border-red-500/50 px-3.5 py-1.5 text-xs font-semibold text-red-100 hover:bg-red-600/50 transition-colors disabled:opacity-50"
                  >
                    <ShieldCheck className="h-3.5 w-3.5 text-red-300" />
                    {isUpdatingScope ? 'Updating Scope...' : `Authorize & Scan ${targetSubnet}`}
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
};
