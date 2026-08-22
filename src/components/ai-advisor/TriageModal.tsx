import React, { useState, useEffect, useRef } from 'react';
import { NetworkEvent, SecurityFinding, AIThreatAnalysis, Severity } from '../../types';
import { aiService } from '../../services/aiService';
import { SeverityBadge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { X, Bot, ShieldCheck, Zap, AlertTriangle, CheckCircle } from 'lucide-react';

interface TriageModalProps {
  event?: NetworkEvent | null;
  finding?: SecurityFinding | null;
  onClose: () => void;
}

export const TriageModal: React.FC<TriageModalProps> = ({ event, finding, onClose }) => {
  const [analysis, setAnalysis] = useState<AIThreatAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const triageRequestKeyRef = useRef<string | null>(null);

  useEffect(() => {
    const triageRequestKey = `${event?.id ?? ''}:${finding?.id ?? ''}`;
    if (triageRequestKeyRef.current === triageRequestKey) return;
    triageRequestKeyRef.current = triageRequestKey;

    const runTriage = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await aiService.triageEvent({
          event_data: event ? (event as any) : undefined,
          finding_data: finding ? (finding as any) : undefined,
        });
        setAnalysis(res.analysis);
      } catch (err: any) {
        setError(err.message || 'Failed to triage with CipherX');
      } finally {
        setLoading(false);
      }
    };

    if (event || finding) {
      runTriage();
    }
  }, [event, finding]);

  if (!event && !finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="w-full max-w-xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-6 py-4">
          <div className="flex items-center gap-2.5 font-bold text-slate-100 text-sm">
            <Bot className="h-5 w-5 text-emerald-400" />
            <span>CipherX Telemetry Triage</span>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          {/* Target Summary */}
          <div className="rounded-lg bg-slate-950 p-3 border border-slate-800 text-xs">
            <div className="font-semibold text-slate-300 mb-1">
              Target Diagnostic Target:
            </div>
            {event ? (
              <div className="font-mono text-slate-400 text-[11px]">
                {event.source_ip} &rarr; {event.destination_ip}:{event.destination_port} ({event.protocol})
              </div>
            ) : finding ? (
              <div className="text-slate-200 font-semibold">{finding.title}</div>
            ) : null}
          </div>

          {loading ? (
            <LoadingSpinner message="CipherX is analyzing telemetry facts..." />
          ) : error ? (
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4 text-xs text-red-300">
              <AlertTriangle className="h-4 w-4 text-red-400 mb-1" />
              <span>{error}</span>
            </div>
          ) : analysis ? (
            <div className="space-y-4 text-xs">
              {/* Threat Level & Confidence */}
              <div className="flex items-center justify-between rounded-lg bg-slate-950 p-3 border border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Assessed Threat Level:</span>
                  <SeverityBadge severity={analysis.threat_level} size="sm" />
                </div>
                <div className="text-[11px] text-slate-400">
                  Confidence: <span className="font-bold text-white">{Math.round(analysis.confidence)}%</span>
                </div>
              </div>

              {/* Summary Narrative */}
              <div className="rounded-lg bg-slate-950/70 p-3.5 border border-slate-800 space-y-1">
                <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px]">
                  Analysis Summary
                </span>
                <p className="text-slate-300 leading-relaxed">{analysis.summary}</p>
              </div>

              {/* Recommended Actions */}
              {analysis.recommended_actions?.length > 0 && (
                <div className="space-y-2">
                  <span className="font-semibold text-emerald-300 uppercase tracking-wider text-[10px]">
                    Defensive Actions
                  </span>
                  <div className="space-y-1.5">
                    {analysis.recommended_actions.map((act, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 rounded bg-slate-950/50 p-2 border border-slate-800/80 text-slate-300"
                      >
                        <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </div>

        {/* Modal Footer */}
        <div className="flex justify-end border-t border-slate-800 bg-slate-950 px-6 py-3">
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 hover:bg-slate-700 px-4 py-2 text-xs font-semibold text-white transition-colors"
          >
            Close Triage
          </button>
        </div>
      </div>
    </div>
  );
};
