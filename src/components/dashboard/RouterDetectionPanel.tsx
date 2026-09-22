import React, { useState, useEffect } from 'react';
import {
  CheckCircle,
  Loader2,
  Router,
  ShieldAlert,
  Wifi,
  Activity,
  Layers,
  AlertTriangle,
  ArrowRight,
} from 'lucide-react';
import { Card } from '../common/Card';
import { networkService } from '../../services/networkService';
import { NetworkDiscoveryResponse, RouterDetectionResponse, RouterHealthResponse } from '../../types';
import { useAuth } from '../../context/AuthContext';

/** Return a Tailwind colour class for the hop count. */
function hopColour(hops: number | null): string {
  if (hops === null) return 'text-slate-500';
  if (hops <= 1) return 'text-emerald-300';
  if (hops <= 2) return 'text-amber-300';
  return 'text-red-300';
}

/** Return a Tailwind colour class for the security classification. */
function classColour(cls: string): string {
  if (cls === 'SUSPICIOUS') return 'text-red-300';
  if (cls === 'KNOWN') return 'text-emerald-300';
  return 'text-amber-300';
}

interface RouterDetectionPanelProps {
  onDiscovered?: () => void;
}

export const RouterDetectionPanel: React.FC<RouterDetectionPanelProps> = ({ onDiscovered }) => {
  const { user, updateProfile } = useAuth();
  const [detection, setDetection] = useState<RouterDetectionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [health, setHealth] = useState<RouterHealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState(false);
  const [discovery, setDiscovery] = useState<NetworkDiscoveryResponse | null>(null);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [discoveryError, setDiscoveryError] = useState(false);
  const [isAuthorizing, setIsAuthorizing] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSuccess, setAuthSuccess] = useState<string | null>(null);

  const detectRouter = async () => {
    setLoading(true);
    setError(false);
    try {
      setDetection(await networkService.detectRouter());
    } catch {
      setDetection(null);
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    detectRouter();
  }, []);

  const checkRouter = async () => {
    setHealthLoading(true);
    setHealthError(false);
    try {
      setHealth(await networkService.checkRouterHealth());
    } catch {
      setHealth(null);
      setHealthError(true);
    } finally {
      setHealthLoading(false);
    }
  };

  const isDetected = detection?.status === 'detected';
  const detectedNetwork = detection?.network_cidr;
  const userScope = user?.authorized_network_scope;
  const isScopeMismatch = Boolean(
    isDetected &&
    detectedNetwork &&
    userScope &&
    detectedNetwork !== userScope
  );

  const handleAuthorizeAndDiscover = async () => {
    if (!detectedNetwork) return;
    setIsAuthorizing(true);
    setAuthError(null);
    setAuthSuccess(null);
    try {
      await updateProfile({ authorized_network_scope: detectedNetwork });
      setAuthSuccess(`Authorized defensive scope switched to ${detectedNetwork}`);

      // Immediately run discovery on the freshly authorized network!
      setDiscoveryLoading(true);
      setDiscoveryError(false);
      try {
        const res = await networkService.discoverDevices();
        setDiscovery(res);
        onDiscovered?.();
      } catch {
        setDiscovery(null);
        setDiscoveryError(true);
      } finally {
        setDiscoveryLoading(false);
      }
    } catch (err: any) {
      setAuthError(err?.message || 'Failed to update authorized network scope');
    } finally {
      setIsAuthorizing(false);
    }
  };

  const discoverDevices = async () => {
    // If scope mismatch, seamlessly update profile to the detected network
    // before discovering so scanning is not blocked by stale scope
    if (isScopeMismatch && detectedNetwork) {
      await handleAuthorizeAndDiscover();
      return;
    }

    setDiscoveryLoading(true);
    setDiscoveryError(false);
    try {
      const res = await networkService.discoverDevices();
      setDiscovery(res);
      onDiscovered?.();
    } catch {
      setDiscovery(null);
      setDiscoveryError(true);
    } finally {
      setDiscoveryLoading(false);
    }
  };

  return (
    <Card
      title="Security Posture & Local Discovery"
      subtitle="Read-only identity and posture evidence from the Cyber Home Shield backend machine"
      action={
        <div className="flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={detectRouter}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-semibold text-white transition-colors hover:bg-cyan-500 disabled:cursor-wait disabled:opacity-60"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Router className="h-4 w-4" />}
            {loading ? 'Detecting network...' : 'Detect My Router'}
          </button>
          <button
            type="button"
            onClick={discoverDevices}
            disabled={discoveryLoading || isAuthorizing}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-200 transition-colors hover:bg-cyan-900/40 disabled:cursor-wait disabled:opacity-60"
          >
            {discoveryLoading || isAuthorizing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Wifi className="h-4 w-4" />
            )}
            {isAuthorizing
              ? 'Authorizing scope...'
              : discoveryLoading
              ? 'Scanning network...'
              : 'Discover Devices'}
          </button>
          <button
            type="button"
            onClick={checkRouter}
            disabled={healthLoading}
            className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-3 py-2 text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-900/40 disabled:cursor-wait disabled:opacity-60"
          >
            {healthLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle className="h-4 w-4" />}
            {healthLoading ? 'Checking...' : 'Check Router'}
          </button>
        </div>
      }
    >
      {!detection && !loading && !error && (
        <div className="flex items-center gap-3 py-3 text-sm text-slate-400">
          <Router className="h-5 w-5 text-slate-500" />
          Router not detected
        </div>
      )}

      {loading && <p className="py-3 text-sm text-cyan-300">Detecting network...</p>}

      {(error || detection?.status === 'unavailable') && !loading && (
        <div className="flex items-center gap-3 py-3 text-sm text-amber-300">
          <ShieldAlert className="h-5 w-5" />
          Unable to detect local network information.
        </div>
      )}

      {isDetected && !loading && (
        <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <div><span className="text-slate-500">Router/Gateway</span><p className="font-mono text-slate-100">{detection.gateway_ip}</p></div>
          <div><span className="text-slate-500">Local IP</span><p className="font-mono text-slate-100">{detection.local_ip}</p></div>
          <div><span className="text-slate-500">Network</span><p className="font-mono text-slate-100">{detection.network_cidr}</p></div>
          <div><span className="text-slate-500">Interface</span><p className="text-slate-100">{detection.interface}</p></div>
          <div className="col-span-2 flex items-center gap-2 text-emerald-300">
            <CheckCircle className="h-4 w-4" /> Status: Connected ({detection.connection_type})
          </div>
        </div>
      )}

      {/* ── Network Scope Mismatch Warning & 1-Click Authorize ── */}
      {isScopeMismatch && (
        <div className="mt-4 rounded-xl border border-amber-500/40 bg-amber-950/30 p-4 shadow-lg shadow-amber-950/20">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 rounded-lg bg-amber-500/10 p-2 text-amber-400 border border-amber-500/20 shrink-0">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-bold text-amber-200">Network Scope Mismatch</h4>
                  <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[10px] font-semibold text-amber-300 uppercase tracking-wide">
                    Protection Active
                  </span>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-amber-300/80">
                  Your physical machine is on <span className="font-mono font-bold text-white bg-slate-900/60 px-1.5 py-0.5 rounded">{detectedNetwork}</span>, but your account is authorized for <span className="font-mono font-bold text-amber-200 bg-slate-900/60 px-1.5 py-0.5 rounded">{userScope}</span>.
                  Discovery was locked to prevent unauthorized cross-subnet scanning.
                </p>
                {authError && <p className="mt-1.5 text-xs text-rose-400 font-semibold">{authError}</p>}
                {authSuccess && <p className="mt-1.5 text-xs text-emerald-400 font-semibold">{authSuccess}</p>}
              </div>
            </div>

            <button
              type="button"
              onClick={handleAuthorizeAndDiscover}
              disabled={isAuthorizing || discoveryLoading}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-amber-500 to-cyan-500 px-4 py-2.5 text-xs font-bold text-slate-950 shadow-md shadow-cyan-950/50 hover:from-amber-400 hover:to-cyan-400 disabled:cursor-wait disabled:opacity-60 transition-all shrink-0"
            >
              {isAuthorizing ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin text-slate-950" />
                  <span>Authorizing...</span>
                </>
              ) : (
                <>
                  <CheckCircle className="h-4 w-4 text-slate-950" />
                  <span>Authorize & Discover {detectedNetwork}</span>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-950" />
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {healthError && !healthLoading && (
        <p className="mt-4 border-t border-slate-800 pt-3 text-sm text-amber-300">Router Unavailable</p>
      )}

      {health && !healthLoading && (
        <div className="mt-4 border-t border-slate-800 pt-3 text-sm">
          {health.status === 'reachable' ? (
            <div className="space-y-1 text-emerald-300">
              <p className="font-semibold">Router Reachable</p>
              <p className="text-slate-300">Gateway: <span className="font-mono text-slate-100">{health.gateway_ip}</span></p>
              <p className="text-slate-300">Latency: <span className="font-mono text-slate-100">{health.latency_ms} ms</span></p>
            </div>
          ) : (
            <div className="space-y-1 text-amber-300">
              <p className="font-semibold">Router Unavailable</p>
              {health.gateway_ip && <p className="text-slate-300">Gateway: <span className="font-mono text-slate-100">{health.gateway_ip}</span></p>}
            </div>
          )}
        </div>
      )}

      {/* ── Discovery scanning indicator ── */}
      {(discoveryLoading || isAuthorizing) && (
        <div className="mt-4 border-t border-slate-800 pt-4">
          <div className="flex items-center gap-2 text-sm text-cyan-300">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>
              {isAuthorizing
                ? `Authorizing subnet ${detectedNetwork}...`
                : 'Running ARP + Nmap scan — this may take up to 30 s…'}
            </span>
          </div>
        </div>
      )}

      {/* ── Discovery results ── */}
      {discovery && !discoveryLoading && !isAuthorizing && (
        <div className="mt-4 border-t border-slate-800 pt-4 text-sm">

          {/* Header row: status + stats badges */}
          <div className="mb-3 flex flex-wrap items-center gap-3">
            <span className={`font-semibold ${discovery.status === 'completed' ? 'text-cyan-200' : 'text-amber-300'}`}>
              {discovery.status === 'completed' ? '✓ Scan Completed' : 'Discovery unavailable'}
            </span>

            {/* Device count badge */}
            <span className="inline-flex items-center gap-1 rounded-full bg-cyan-900/50 px-2.5 py-0.5 text-xs font-semibold text-cyan-200 ring-1 ring-cyan-700/50">
              <Wifi className="h-3 w-3" />
              {discovery.total_devices ?? discovery.devices.length} device{(discovery.total_devices ?? discovery.devices.length) !== 1 ? 's' : ''} found
            </span>

            {/* Scan method badge */}
            {discovery.scan_method && (
              <span className="inline-flex items-center gap-1 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-400 ring-1 ring-slate-700">
                <Activity className="h-3 w-3" />
                {discovery.scan_method}
              </span>
            )}

            {/* Network badge */}
            {discovery.network && (
              <span className="inline-flex items-center gap-1 rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-400 ring-1 ring-slate-700">
                <Layers className="h-3 w-3" />
                {discovery.network}
              </span>
            )}
          </div>

          {discovery.devices.length === 0 ? (
            <div className="space-y-2 py-2">
              <p className="text-slate-400">
                {discovery.message ||
                  (discovery.status === 'unavailable' && isScopeMismatch
                    ? `Discovery was halted because detected subnet ${discovery.network || detectedNetwork} is outside your registered scope (${userScope}).`
                    : 'No devices found on this subnet.')}
              </p>
              {isScopeMismatch && (
                <div className="flex items-center gap-3 pt-1">
                  <span className="text-xs text-amber-300">
                    Click the button above or{' '}
                    <button
                      type="button"
                      onClick={handleAuthorizeAndDiscover}
                      disabled={isAuthorizing || discoveryLoading}
                      className="underline font-bold text-cyan-300 hover:text-cyan-200 disabled:opacity-50"
                    >
                      click here to authorize {detectedNetwork}
                    </button>{' '}
                    and scan all local devices.
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/60 text-slate-500">
                  <tr>
                    <th className="px-3 py-2">IP Address</th>
                    <th className="px-3 py-2">MAC Address</th>
                    <th className="px-3 py-2">Hostname / Vendor</th>
                    <th className="px-3 py-2">Hops</th>
                    <th className="px-3 py-2">OS Guess</th>
                    <th className="px-3 py-2">Role</th>
                    <th className="px-3 py-2">Posture</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {discovery.devices.map((device) => (
                    <tr key={device.ip} className="align-top transition-colors hover:bg-slate-800/30">

                      {/* IP */}
                      <td className="px-3 py-2.5">
                        <span className="font-mono text-slate-100">{device.ip}</span>
                        <div className="mt-0.5 text-[10px] text-slate-500">{device.status}</div>
                      </td>

                      {/* MAC */}
                      <td className="px-3 py-2.5">
                        <span className="font-mono">{device.mac ?? '—'}</span>
                        {device.mac_type !== 'unknown' && (
                          <div className="mt-0.5 text-[10px] text-slate-500">{device.mac_type}</div>
                        )}
                      </td>

                      {/* Hostname / Vendor */}
                      <td className="px-3 py-2.5">
                        <span>{device.hostname ?? <span className="italic text-slate-500">unresolved</span>}</span>
                        {device.vendor && (
                          <div className="mt-0.5 text-[10px] text-slate-500">{device.vendor}</div>
                        )}
                      </td>

                      {/* Hops */}
                      <td className="px-3 py-2.5">
                        {device.hop_count !== null && device.hop_count !== undefined ? (
                          <div className="flex flex-col">
                            <span className={`font-bold ${hopColour(device.hop_count)}`}>
                              {device.hop_count} hop{device.hop_count !== 1 ? 's' : ''}
                            </span>
                            {device.ttl !== null && device.ttl !== undefined && (
                              <span className="text-[10px] text-slate-500">TTL {device.ttl}</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      {/* OS Guess */}
                      <td className="px-3 py-2.5">
                        {device.os_guess
                          ? <span className="text-slate-300">{device.os_guess}</span>
                          : <span className="text-slate-600">—</span>
                        }
                      </td>

                      {/* Role */}
                      <td className="px-3 py-2.5 text-slate-400">{device.device_role}</td>

                      {/* Posture */}
                      <td className="px-3 py-2.5">
                        <span className={`font-semibold ${classColour(device.identity_classification)}`}>
                          {device.identity_classification}
                        </span>
                        <div className="mt-0.5 text-[10px] text-slate-500">{device.reason}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {discoveryError && !discoveryLoading && !isAuthorizing && (
        <p className="mt-4 border-t border-slate-800 pt-3 text-sm text-amber-300">
          Error discovering devices — check that the backend is running.
        </p>
      )}
    </Card>
  );
};
