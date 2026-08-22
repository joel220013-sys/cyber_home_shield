import React from 'react';
import { Card } from '../common/Card';
import { Device } from '../../types';
import { HardDrive, ShieldCheck, ChevronRight } from 'lucide-react';

interface DiscoveredAssetsListProps {
  devices: Device[];
  onSelectDevice?: (device: Device) => void;
}

export const DiscoveredAssetsList: React.FC<DiscoveredAssetsListProps> = ({
  devices,
  onSelectDevice,
}) => {
  return (
    <Card
      title="Discovered Network Assets"
      subtitle={`${devices.length} endpoints located on authorized subnet`}
    >
      {devices.length === 0 ? (
        <div className="text-center py-8 text-xs text-slate-400">
          No assets discovered in recent scans. Start a defensive scan to populate inventory.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {devices.map((d) => (
            <div
              key={d.id}
              onClick={() => onSelectDevice && onSelectDevice(d)}
              className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/50 hover:border-slate-700 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-900 border border-slate-800 text-cyan-400">
                  <HardDrive className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-xs font-bold text-slate-100">{d.hostname || d.ip_address}</div>
                  <div className="text-[11px] text-slate-400 font-mono">{d.ip_address} • {d.vendor || d.device_type}</div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
                  {d.ports?.length || 0} ports
                </span>
                <ChevronRight className="h-4 w-4 text-slate-400" />
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
};
