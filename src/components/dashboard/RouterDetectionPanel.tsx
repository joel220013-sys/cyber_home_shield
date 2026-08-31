import React, { useState } from 'react';
import { CheckCircle, Loader2, Router, ShieldAlert } from 'lucide-react';
import { Card } from '../common/Card';
import { networkService } from '../../services/networkService';
import { NetworkDiscoveryResponse, RouterDetectionResponse, RouterHealthResponse } from '../../types';

export const RouterDetectionPanel: React.FC = () => {
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
      setDiscovery(await networkService.discoverDevices());
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
            {discoveryLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Router className="h-4 w-4" />}
            {discoveryLoading ? 'Discovering...' : 'Discover Devices'}
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

      {discovery && !discoveryLoading && (
        <div className="mt-4 border-t border-slate-800 pt-3 text-sm">
          <p className="font-semibold text-cyan-200">
            {discovery.status === 'completed' ? 'Completed' : 'Discovery unavailable'}
          </p>
          {discovery.network && <p className="mt-1 text-slate-300">Network: <span className="font-mono text-slate-100">{discovery.network}</span></p>}
          <p className="text-slate-300">Devices found: <span className="font-mono text-slate-100">{discovery.devices.length}</span></p>
          {discovery.devices.length === 0 ? (
            <p className="mt-2 text-slate-500">No devices found</p>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-500"><tr><th className="pb-2 pr-3">IP</th><th className="pb-2 pr-3">Hostname / Vendor</th><th className="pb-2 pr-3">Role</th><th className="pb-2 pr-3">Security posture</th><th className="pb-2">Evidence</th></tr></thead>
                <tbody className="text-slate-300">{discovery.devices.map((device) => <tr key={device.ip} className="border-t border-slate-800 align-top"><td className="py-2 pr-3 font-mono">{device.ip}<div className="text-[10px] text-slate-500">{device.mac ?? 'MAC unavailable'} · {device.mac_type}</div></td><td className="py-2 pr-3">{device.hostname ?? 'Hostname unresolved'}<div className="text-[10px] text-slate-500">{device.vendor ?? (device.mac_type === 'locally_administered' ? 'Vendor unavailable because MAC is locally administered' : 'Vendor lookup returned no manufacturer')}</div></td><td className="py-2 pr-3">{device.device_role}</td><td className="py-2 pr-3"><span className={device.identity_classification === 'SUSPICIOUS' ? 'text-red-300' : device.identity_classification === 'KNOWN' ? 'text-emerald-300' : 'text-amber-300'}>{device.identity_classification}</span><div className="text-[10px] text-slate-500">{device.reason}</div></td><td className="py-2 text-[10px] text-slate-400">{device.posture_evidence.length ? device.posture_evidence.map((item, index) => <div key={`${item.source}-${index}`}>{item.category}: {item.detail}</div>) : device.evidence_state}</td></tr>)}</tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {discoveryError && !discoveryLoading && <p className="mt-4 border-t border-slate-800 pt-3 text-sm text-amber-300">Error discovering devices</p>}
    </Card>
  );
};
