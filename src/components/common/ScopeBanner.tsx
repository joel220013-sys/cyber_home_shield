import React from 'react';
import { ShieldCheck, Lock } from 'lucide-react';

export const ScopeBanner: React.FC = () => {
  return (
    <div className="flex items-center justify-between rounded-lg border border-cyan-500/20 bg-cyan-950/20 px-4 py-2.5 text-xs text-cyan-200">
      <div className="flex items-center gap-2.5">
        <ShieldCheck className="h-4 w-4 text-cyan-400 shrink-0" />
        <div>
          <span className="font-semibold text-cyan-100">Authorized Defensive Network Scope Only:</span>{' '}
          <span className="text-cyan-300">
            Operations strictly restricted to private RFC 1918 IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
          </span>
        </div>
      </div>
      <div className="hidden sm:flex items-center gap-1.5 rounded bg-cyan-900/40 px-2 py-1 text-[11px] font-medium text-cyan-300">
        <Lock className="h-3 w-3" />
        <span>Ethical Baseline</span>
      </div>
    </div>
  );
};
