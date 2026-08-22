import React from 'react';
import { Severity, BaselineStatus } from '../../types';
import { getSeverityTokens } from '../../lib/utils';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const tokens = getSeverityTokens(severity);
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border ${tokens.border} ${tokens.bg} ${tokens.text} ${sizeClasses}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tokens.dot}`} />
      {tokens.label}
    </span>
  );
};

interface StatusBadgeProps {
  status: string;
  variant?: 'online' | 'offline' | 'active' | 'warning' | 'neutral';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, variant = 'neutral' }) => {
  let styles = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (variant === 'online' || status.toLowerCase() === 'completed') {
    styles = 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30';
    dotColor = 'bg-emerald-400';
  } else if (variant === 'offline' || status.toLowerCase() === 'failed') {
    styles = 'bg-red-950/40 text-red-300 border-red-500/30';
    dotColor = 'bg-red-400';
  } else if (variant === 'active' || status.toLowerCase() === 'running') {
    styles = 'bg-cyan-950/40 text-cyan-300 border-cyan-500/30';
    dotColor = 'bg-cyan-400 animate-pulse';
  } else if (variant === 'warning') {
    styles = 'bg-amber-950/40 text-amber-300 border-amber-500/30';
    dotColor = 'bg-amber-400';
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${styles}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
      {status}
    </span>
  );
};
