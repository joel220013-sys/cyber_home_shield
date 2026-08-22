import React from 'react';
import { Card } from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import { SecurityFinding } from '../../types';
import { AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';
import { formatTimestamp } from '../../lib/utils';

interface RecentFindingsFeedProps {
  findings: SecurityFinding[];
  onSelectFinding?: (finding: SecurityFinding) => void;
  onViewAll?: () => void;
}

export const RecentFindingsFeed: React.FC<RecentFindingsFeedProps> = ({
  findings,
  onSelectFinding,
  onViewAll,
}) => {
  const topFindings = findings.slice(0, 4);

  return (
    <Card
      title="High-Priority Security Findings"
      subtitle="Actionable defensive recommendations"
      action={
        onViewAll ? (
          <button
            onClick={onViewAll}
            className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
          >
            <span>View All ({findings.length})</span>
            <ArrowRight className="h-3 w-3" />
          </button>
        ) : null
      }
    >
      {topFindings.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-6 text-center">
          <ShieldCheck className="h-8 w-8 text-emerald-400 mb-2" />
          <span className="text-xs font-semibold text-slate-200">No Critical Findings</span>
          <p className="text-[11px] text-slate-400 mt-0.5">Your monitored assets have no severe exposures.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {topFindings.map((f) => (
            <div
              key={f.id}
              onClick={() => onSelectFinding && onSelectFinding(f)}
              className="flex items-start justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer"
            >
              <div className="space-y-1 pr-4">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <span className="text-xs font-semibold text-slate-100 line-clamp-1">{f.title}</span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                  {f.description}
                </p>
                <div className="flex items-center gap-3 text-[10px] text-slate-400">
                  <span>Category: {f.category}</span>
                  <span>•</span>
                  <span>{formatTimestamp(f.created_at)}</span>
                </div>
              </div>
              <ArrowRight className="h-4 w-4 text-slate-400 shrink-0 mt-2" />
            </div>
          ))}
        </div>
      )}
    </Card>
  );
};
