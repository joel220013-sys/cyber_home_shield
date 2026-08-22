import React from 'react';
import { Device } from '../../types';
import { StatusBadge } from '../common/Badge';
import { getRiskLevel, formatTimestamp } from '../../lib/utils';
import {
  Shield,
  HardDrive,
  Router,
  Camera,
  Tv,
  Printer,
  Laptop,
  Server,
  Cpu,
  ChevronRight,
} from 'lucide-react';

interface DeviceTableProps {
  devices: Device[];
  onSelectDevice: (device: Device) => void;
}

export const DeviceTable: React.FC<DeviceTableProps> = ({ devices, onSelectDevice }) => {
  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'ROUTER':
      case 'GATEWAY':
        return Router;
      case 'IP_CAMERA':
        return Camera;
      case 'SMART_TV':
        return Tv;
      case 'PRINTER':
        return Printer;
      case 'NAS':
      case 'SERVER':
        return Server;
      case 'LAPTOP':
      case 'WORKSTATION':
        return Laptop;
      case 'IOT':
      default:
        return Cpu;
    }
  };

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/60">
      <table className="w-full text-left text-xs text-slate-300">
        <thead className="border-b border-slate-800 bg-slate-950/80 text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
          <tr>
            <th className="px-4 py-3">Device Identity</th>
            <th className="px-4 py-3">IP & MAC Address</th>
            <th className="px-4 py-3">Observed Ports</th>
            <th className="px-4 py-3">Risk Posture</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">Last Seen</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/80">
          {devices.map((device) => {
            const Icon = getDeviceIcon(device.device_type);
            const score = Math.round(device.risk_score ?? 0);
            const risk = getRiskLevel(score);
            const portCount = device.ports?.length ?? 0;

            return (
              <tr
                key={device.id}
                onClick={() => onSelectDevice(device)}
                className="hover:bg-slate-800/50 transition-colors cursor-pointer group"
              >
                {/* Identity */}
                <td className="px-4 py-3.5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800 text-slate-300 group-hover:bg-cyan-500/20 group-hover:text-cyan-400 transition-colors">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-slate-100">{device.hostname || 'Unknown Host'}</div>
                      <div className="text-[11px] text-slate-400">{device.vendor || device.device_type}</div>
                    </div>
                  </div>
                </td>

                {/* Network Coordinates */}
                <td className="px-4 py-3.5 font-mono text-xs">
                  <div className="text-slate-200">{device.ip_address}</div>
                  <div className="text-[10px] text-slate-400">{device.mac_address || 'N/A'}</div>
                </td>

                {/* Open Ports */}
                <td className="px-4 py-3.5">
                  <div className="flex flex-wrap gap-1">
                    {portCount > 0 ? (
                      device.ports?.slice(0, 3).map((p, i) => (
                        <span
                          key={i}
                          className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300 border border-slate-700"
                        >
                          {p.port_number}/{p.service_name || p.protocol.toLowerCase()}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-400 text-[11px]">0 open ports</span>
                    )}
                    {portCount > 3 && (
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                        +{portCount - 3}
                      </span>
                    )}
                  </div>
                </td>

                {/* Risk Score */}
                <td className="px-4 py-3.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`inline-flex items-center justify-center h-6 px-2 rounded font-bold text-xs border ${risk.badgeBg} ${risk.badgeBorder} ${risk.badgeText}`}
                    >
                      {score}
                    </span>
                    <span className="text-[10px] uppercase font-semibold text-slate-400">
                      {risk.label.replace(' RISK', '')}
                    </span>
                  </div>
                </td>

                {/* Status */}
                <td className="px-4 py-3.5">
                  <StatusBadge
                    status={device.is_online ? 'Online' : 'Offline'}
                    variant={device.is_online ? 'online' : 'offline'}
                  />
                </td>

                {/* Last Seen */}
                <td className="px-4 py-3.5 text-slate-400 text-[11px]">
                  {formatTimestamp(device.last_seen)}
                </td>

                {/* Action arrow */}
                <td className="px-4 py-3.5 text-right">
                  <span className="inline-flex items-center justify-center text-slate-400 group-hover:text-cyan-400 transition-colors">
                    <ChevronRight className="h-4 w-4" />
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
