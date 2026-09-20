import React, { useState } from 'react';
import { CheckCircle, Loader2, Router, ShieldAlert, Wifi, Activity, Layers } from 'lucide-react';
import { Card } from '../common/Card';
import { networkService } from '../../services/networkService';
import { NetworkDiscoveryResponse, RouterDetectionResponse, RouterHealthResponse } from '../../types';

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
  const [detection, setDetection] = useState<RouterDetectionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [health, setHealth] = useState<RouterHealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState(false);
  const [discovery, setDiscovery] = useState<NetworkDiscoveryResponse | null>(null);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [discoveryError, setDiscoveryError] = useState(false);

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

  const discoverDevices = async () => {
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
            disabled={discoveryLoading}
            className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-200 transition-colors hover:bg-cyan-900/40 disabled:cursor-wait disabled:opacity-60"
          >
            {discoveryLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wifi className="h-4 w-4" />}
            {discoveryLoading ? 'Scanning network...' : 'Discover Devices'}
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
      {discoveryLoading && (
        <div className="mt-4 border-t border-slate-800 pt-4">
          <div className="flex items-center gap-2 text-sm text-cyan-300">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Running ARP + Nmap scan — this may take up to 30 s…</span>
          </div>
        </div>
      )}

      {/* ── Discovery results ── */}
      {discovery && !discoveryLoading && (
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
            <p className="text-slate-500">No devices found on this subnet.</p>
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

      {discoveryError && !discoveryLoading && (
        <p className="mt-4 border-t border-slate-800 pt-3 text-sm text-amber-300">
          Error discovering devices — check that the backend is running.
        </p>
      )}
    </Card>
  );
};
