import React from 'react';
import { ShieldAlert, ShieldCheck, Inbox } from 'lucide-react';

interface EmptyStateProps {
  title?: string;
  message?: string;
  icon?: 'empty' | 'shield' | 'check';
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = 'No security data available',
  message = 'Run a network discovery scan to populate device profiles and assess risk posture.',
  icon = 'empty',
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center rounded-xl border border-dashed border-slate-800 bg-slate-900/40">
      <div className="mb-3 rounded-full bg-slate-800/80 p-3 text-slate-400">
        {icon === 'shield' ? (
          <ShieldAlert className="h-6 w-6 text-cyan-400" />
        ) : icon === 'check' ? (
          <ShieldCheck className="h-6 w-6 text-emerald-400" />
        ) : (
          <Inbox className="h-6 w-6 text-slate-400" />
        )}
      </div>
      <h4 className="text-sm font-semibold text-slate-200">{title}</h4>
      <p className="mt-1 max-w-sm text-xs text-slate-400 leading-relaxed">{message}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};
