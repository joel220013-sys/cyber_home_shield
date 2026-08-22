import React, { useState } from 'react';
import { Card } from '../common/Card';
import { SeverityBadge } from '../common/Badge';
import { SecurityFinding, Severity } from '../../types';
import { formatTimestamp } from '../../lib/utils';
import {
  AlertTriangle,
  Search,
  Filter,
  Bot,
  CheckCircle,
  ExternalLink,
  ShieldCheck,
} from 'lucide-react';

interface FindingsViewProps {
  findings: SecurityFinding[];
  onTriageFinding?: (finding: SecurityFinding) => void;
  onOpenAdvisorChat?: (message: string) => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onTriageFinding,
  onOpenAdvisorChat,
}) => {
  const [search, setSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const filtered = findings.filter((f) => {
    const matchesSearch =
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.category.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search security findings & CVEs..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900 pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-400 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900 text-slate-200">All Severities</option>
              <option value="CRITICAL" className="bg-slate-900 text-slate-200">Critical</option>
              <option value="HIGH" className="bg-slate-900 text-slate-200">High</option>
              <option value="MEDIUM" className="bg-slate-900 text-slate-200">Medium</option>
              <option value="LOW" className="bg-slate-900 text-slate-200">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings List */}
      {filtered.length === 0 ? (
        <Card>
          <div className="py-12 text-center">
            <ShieldCheck className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
            <h4 className="text-sm font-semibold text-slate-200">No matching security findings</h4>
            <p className="text-xs text-slate-400 mt-1">No vulnerabilities match your filter criteria.</p>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filtered.map((finding) => (
            <div
              key={finding.id}
              className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={finding.severity} />
                  <h4 className="text-sm font-bold text-slate-100">{finding.title}</h4>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-slate-400">
                  <span className="font-mono">{finding.category}</span>
                  <span>•</span>
                  <span>{formatTimestamp(finding.created_at)}</span>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

              {finding.remediation_steps && (
                <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3 text-xs space-y-1">
                  <span className="font-semibold text-cyan-400">Remediation Guide:</span>
                  <p className="text-slate-300 leading-relaxed">{finding.remediation_steps}</p>
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <div className="text-[11px] text-slate-400">
                  Status:{' '}
                  <span className="font-semibold text-slate-300 uppercase">
                    {finding.status || 'ACTIVE'}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {onTriageFinding && (
                    <button
                      onClick={() => onTriageFinding(finding)}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-950/30 hover:bg-emerald-900/40 px-3 py-1.5 text-xs font-medium text-emerald-300 transition-colors"
                    >
                      <Bot className="h-3.5 w-3.5 text-emerald-400" />
                      <span>CipherX Triage</span>
                    </button>
                  )}

                  {onOpenAdvisorChat && (
                    <button
                      onClick={() => onOpenAdvisorChat(`Explain how to remediate finding: "${finding.title}"`)}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors"
                    >
                      <span>Ask Advisor</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
