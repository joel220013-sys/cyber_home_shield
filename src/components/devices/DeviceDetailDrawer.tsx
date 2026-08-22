import React, { useEffect, useState } from 'react';
import {
  Device,
  DeviceRiskResult,
  DeviceRiskExplanation,
  HardeningGuideResponse,
} from '../../types';
import { riskService } from '../../services/riskService';
import { aiService } from '../../services/aiService';
import { RiskGauge } from '../common/RiskGauge';
import { SeverityBadge, StatusBadge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';
import { formatTimestamp } from '../../lib/utils';
import {
  X,
  Shield,
  Bot,
  Lock,
  CheckCircle,
  Zap,
} from 'lucide-react';

interface DeviceDetailDrawerProps {
  device: Device | null;
  onClose: () => void;
  onOpenAdvisorChat?: (initialMessage: string) => void;
}

export const DeviceDetailDrawer: React.FC<DeviceDetailDrawerProps> = ({
  device,
  onClose,
  onOpenAdvisorChat,
}) => {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'findings' | 'ai-explain' | 'hardening'
  >('overview');

  const [riskDetails, setRiskDetails] =
    useState<DeviceRiskResult | null>(null);

  const [loadingRisk, setLoadingRisk] =
    useState<boolean>(false);

  const [aiExplanation, setAiExplanation] =
    useState<DeviceRiskExplanation | null>(null);

  const [loadingAi, setLoadingAi] =
    useState<boolean>(false);

  const [hardeningGuide, setHardeningGuide] =
    useState<HardeningGuideResponse | null>(null);

  const [loadingHardening, setLoadingHardening] =
    useState<boolean>(false);

  // ========================================================================
  // FETCH DEVICE RISK
  // ========================================================================

  useEffect(() => {
    if (!device) return;

    setActiveTab('overview');
    setRiskDetails(null);
    setAiExplanation(null);
    setHardeningGuide(null);

    const fetchRisk = async () => {
      setLoadingRisk(true);

      try {
        const res = await riskService.getDeviceRisk(device.id);
        setRiskDetails(res);
      } catch (err) {
        console.warn(
          'Could not fetch device risk from API:',
          err
        );
      } finally {
        setLoadingRisk(false);
      }
    };

    fetchRisk();
  }, [device]);

  // ========================================================================
  // NEMOTRON DEVICE RISK EXPLANATION
  // ========================================================================

  const loadAiExplanation = async () => {
    if (!device || aiExplanation) return;

    setLoadingAi(true);

    try {
      const res = await aiService.explainDeviceRisk(device.id);
      setAiExplanation(res);
    } catch (err) {
      console.error(
        'Failed to get AI risk explanation:',
        err
      );
    } finally {
      setLoadingAi(false);
    }
  };

  // ========================================================================
  // HARDENING GUIDE
  // ========================================================================

  const loadHardeningGuide = async () => {
    if (!device || hardeningGuide) return;

    setLoadingHardening(true);

    try {
      const openPortNums =
        device.ports?.map((p) => p.port_number) || [];

      const res =
        await aiService.generateHardeningGuide({
          target_type: device.device_type,
          observed_services: openPortNums,
          context: {
            hostname: device.hostname,
            vendor: device.vendor,
            ip_address: device.ip_address,
          },
        });

      setHardeningGuide(res);
    } catch (err) {
      console.error(
        'Failed to get hardening guide:',
        err
      );
    } finally {
      setLoadingHardening(false);
    }
  };

  // ========================================================================
  // NO DEVICE
  // ========================================================================

  if (!device) return null;

  // ========================================================================
  // RISK VALUES
  // ========================================================================

  const score =
    riskDetails?.overall_score ??
    device.risk_score ??
    0;

  const exposureScore =
    riskDetails?.exposure_subscore ?? 0;

  const vulnerabilityScore =
    riskDetails?.vulnerability_subscore ?? 0;

  const anomalyScore =
    riskDetails?.anomaly_subscore ?? 0;

  const findings =
    riskDetails?.findings ??
    device.findings ??
    [];

  // ========================================================================
  // RENDER
  // ========================================================================

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden">

        {/* ================================================================
            HEADER
        ================================================================ */}

        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-6 py-4">
          <div className="flex items-center gap-3">

            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Shield className="h-5 w-5" />
            </div>

            <div>
              <h3 className="text-sm font-bold text-white">
                {device.hostname || 'Device Profile'}
              </h3>

              <p className="text-xs text-slate-400 font-mono">
                {device.ip_address} •{' '}
                {device.vendor || device.device_type}
              </p>
            </div>

          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
            aria-label="Close device details"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* ================================================================
            TAB NAVIGATION
        ================================================================ */}

        <div className="flex border-b border-slate-800 bg-slate-950/50 px-6 text-xs font-semibold text-slate-400 overflow-x-auto">

          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 px-3 border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            Overview & Exposure
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`py-3 px-3 border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'findings'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            Findings ({findings.length})
          </button>

          <button
            onClick={() => {
              setActiveTab('ai-explain');
              loadAiExplanation();
            }}
            className={`py-3 px-3 border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
              activeTab === 'ai-explain'
                ? 'border-emerald-400 text-emerald-300'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            <Bot className="h-3.5 w-3.5" />
            <span>CipherX Analysis</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('hardening');
              loadHardeningGuide();
            }}
            className={`py-3 px-3 border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
              activeTab === 'hardening'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent hover:text-slate-200'
            }`}
          >
            <Lock className="h-3.5 w-3.5" />
            <span>Hardening Guide</span>
          </button>

        </div>

        {/* ================================================================
            BODY
        ================================================================ */}

        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* ==============================================================
              TAB 1 — OVERVIEW
          ============================================================== */}

          {activeTab === 'overview' && (
            <div className="space-y-6">

              {/* ========================================================
                  RISK SCORE CARD
              ======================================================== */}

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">

                <div className="flex items-center justify-between gap-6">

                  <div className="space-y-2">

                    <div className="text-xs font-semibold text-slate-400">
                      DETERMINISTIC RISK SCORE
                    </div>

                    <div className="text-xs text-slate-400 max-w-xs">
                      Weighted security posture calculated from
                      exposure, vulnerabilities and telemetry anomalies.
                    </div>

                    <div className="text-[10px] text-slate-500">
                      Exposure 40% • Vulnerability 40% • Anomaly 20%
                    </div>

                  </div>

                  <div className="shrink-0">
                    {loadingRisk ? (
                      <LoadingSpinner message="Calculating risk..." />
                    ) : (
                      <RiskGauge
                        score={score}
                        size="md"
                      />
                    )}
                  </div>

                </div>

                {/* SUBSCORES */}

                {riskDetails && (
                  <div className="grid grid-cols-3 gap-2 mt-5">

                    {/* EXPOSURE */}

                    <div className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-3 text-center">

                      <div className="text-[10px] uppercase tracking-wider text-slate-500">
                        Exposure
                      </div>

                      <div className="text-lg font-bold text-amber-400 mt-1">
                        {exposureScore.toFixed(1)}
                      </div>

                      <div className="text-[9px] text-slate-500">
                        Weight: 40%
                      </div>

                      <div className="text-[9px] text-slate-600 mt-1">
                        Contribution:{' '}
                        {(exposureScore * 0.4).toFixed(2)}
                      </div>

                    </div>

                    {/* VULNERABILITY */}

                    <div className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-3 text-center">

                      <div className="text-[10px] uppercase tracking-wider text-slate-500">
                        Vulnerability
                      </div>

                      <div className="text-lg font-bold text-orange-400 mt-1">
                        {vulnerabilityScore.toFixed(2)}
                      </div>

                      <div className="text-[9px] text-slate-500">
                        Weight: 40%
                      </div>

                      <div className="text-[9px] text-slate-600 mt-1">
                        Contribution:{' '}
                        {(vulnerabilityScore * 0.4).toFixed(2)}
                      </div>

                    </div>

                    {/* ANOMALY */}

                    <div className="rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-3 text-center">

                      <div className="text-[10px] uppercase tracking-wider text-slate-500">
                        Anomaly
                      </div>

                      <div className="text-lg font-bold text-red-400 mt-1">
                        {anomalyScore.toFixed(1)}
                      </div>

                      <div className="text-[9px] text-slate-500">
                        Weight: 20%
                      </div>

                      <div className="text-[9px] text-slate-600 mt-1">
                        Contribution:{' '}
                        {(anomalyScore * 0.2).toFixed(2)}
                      </div>

                    </div>

                  </div>
                )}

              </div>

              {/* ========================================================
                  ENDPOINT IDENTITY
              ======================================================== */}

              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-3">

                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Endpoint Identity
                </h4>

                <div className="grid grid-cols-2 gap-3 text-xs">

                  <div>
                    <span className="text-slate-400">
                      IP Address:
                    </span>

                    <p className="font-mono text-slate-200 font-semibold">
                      {device.ip_address}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400">
                      MAC Address:
                    </span>

                    <p className="font-mono text-slate-200">
                      {device.mac_address || 'N/A'}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400">
                      Device Type:
                    </span>

                    <p className="text-slate-200 font-medium">
                      {device.device_type}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400">
                      Vendor:
                    </span>

                    <p className="text-slate-200">
                      {device.vendor || 'Generic'}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400">
                      Status:
                    </span>

                    <div className="mt-0.5">
                      <StatusBadge
                        status={
                          device.is_online
                            ? 'Online'
                            : 'Offline'
                        }
                        variant={
                          device.is_online
                            ? 'online'
                            : 'offline'
                        }
                      />
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-400">
                      First Observed:
                    </span>

                    <p className="text-slate-200">
                      {formatTimestamp(device.first_seen)}
                    </p>
                  </div>

                </div>
              </div>

              {/* ========================================================
                  PORTS
              ======================================================== */}

              <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-3">

                <div className="flex items-center justify-between">

                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Observed Ports & Services (
                    {device.ports?.length || 0}
                    )
                  </h4>

                  <span className="text-[11px] text-slate-400">
                    Defensive port profiling
                  </span>

                </div>

                {!device.ports ||
                device.ports.length === 0 ? (
                  <p className="text-xs text-slate-400">
                    No open ports discovered.
                  </p>
                ) : (
                  <div className="space-y-2">

                    {device.ports.map((p, i) => (
                      <div
                        key={`${p.port_number}-${p.protocol}-${i}`}
                        className="flex items-center justify-between rounded-lg border border-slate-800/80 bg-slate-900/80 px-3 py-2 text-xs"
                      >

                        <div className="flex items-center gap-2 font-mono">

                          <span className="font-bold text-cyan-400">
                            {p.port_number}
                          </span>

                          <span className="text-slate-400">
                            / {p.protocol}
                          </span>

                          <span className="text-slate-200 font-medium capitalize">
                            {p.service_name || 'Generic'}
                          </span>

                        </div>

                        {p.port_number === 80 ||
                        p.port_number === 554 ||
                        p.port_number === 445 ? (
                          <span className="rounded bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-[10px] font-semibold text-amber-400">
                            Exposed Service
                          </span>
                        ) : (
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-400">
                            Active
                          </span>
                        )}

                      </div>
                    ))}

                  </div>
                )}

              </div>

            </div>
          )}

          {/* ==============================================================
              TAB 2 — FINDINGS
          ============================================================== */}

          {activeTab === 'findings' && (
            <div className="space-y-4">

              {findings.length === 0 ? (

                <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-8 text-center text-xs text-slate-400">

                  <CheckCircle className="h-6 w-6 text-emerald-400 mx-auto mb-2" />

                  No security findings currently recorded
                  for this device.

                </div>

              ) : (

                findings.map((f, i) => (
                  <div
                    key={i}
                    className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-2.5"
                  >

                    <div className="flex items-center justify-between">

                      <SeverityBadge
                        severity={f.severity}
                        size="sm"
                      />

                      <span className="text-[11px] text-slate-400">
                        Category: {f.category}
                      </span>

                    </div>

                    <h5 className="text-xs font-bold text-slate-100">
                      {f.title}
                    </h5>

                    <p className="text-xs text-slate-400 leading-relaxed">
                      {f.description}
                    </p>

                    {f.remediation_steps && (
                      <div className="rounded-lg bg-slate-900 p-2.5 border border-slate-800 text-xs">

                        <span className="font-semibold text-cyan-400">
                          Remediation:
                        </span>{' '}

                        <span className="text-slate-300">
                          {f.remediation_steps}
                        </span>

                      </div>
                    )}

                  </div>
                ))

              )}

            </div>
          )}

          {/* ==============================================================
              TAB 3 — NEMOTRON
          ============================================================== */}

          {activeTab === 'ai-explain' && (
            <div className="space-y-4">

              {loadingAi ? (

                <LoadingSpinner message="Consulting CipherX..." />

              ) : aiExplanation ? (

                <div className="space-y-4 text-xs">

                  {/* AI SUMMARY */}

                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 space-y-2">

                    <div className="flex items-center justify-between">

                      <div className="flex items-center gap-2 font-bold text-emerald-300">

                        <Bot className="h-4 w-4" />

                        <span>
                          CipherX Narrative Assessment
                        </span>

                      </div>

                      <span className="text-[10px] rounded bg-emerald-900/60 px-2 py-0.5 text-emerald-300 font-semibold">
                        Score:{' '}
                        {aiExplanation.deterministic_risk_score}
                        /100
                      </span>

                    </div>

                    <p className="text-slate-300 leading-relaxed">
                      {aiExplanation.likely_security_implications}
                    </p>

                  </div>

                  {/* OBSERVED FACTS */}

                  {aiExplanation.key_observations?.length > 0 && (
                    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-2">

                      <h5 className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
                        Observed Facts
                      </h5>

                      <ul className="list-disc list-inside space-y-1 text-slate-300">

                        {aiExplanation.key_observations.map(
                          (obs, i) => (
                            <li key={i}>{obs}</li>
                          )
                        )}

                      </ul>

                    </div>
                  )}

                  {/* DEFENSIVE PRIORITIES */}

                  {aiExplanation.defensive_priorities?.length > 0 && (
                    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-2">

                      <h5 className="font-semibold text-cyan-400 uppercase tracking-wider text-[11px]">
                        Defensive Priorities
                      </h5>

                      <div className="space-y-1.5">

                        {aiExplanation.defensive_priorities.map(
                          (dp, i) => (
                            <div
                              key={i}
                              className="flex items-center gap-2 text-slate-200"
                            >

                              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 shrink-0" />

                              <span>{dp}</span>

                            </div>
                          )
                        )}

                      </div>

                    </div>
                  )}

                  {/* OPEN ADVISOR CHAT */}

                  {onOpenAdvisorChat && (
                    <button
                      onClick={() =>
                        onOpenAdvisorChat(
                          `Explain risk and isolation steps for device ${
                            device.hostname ||
                            device.ip_address
                          }`
                        )
                      }
                      className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 py-2.5 font-semibold text-white transition-colors"
                    >

                      <Zap className="h-4 w-4" />

                      <span>
                        Chat with CipherX about this Device
                      </span>

                    </button>
                  )}

                </div>

              ) : (

                <button
                  onClick={loadAiExplanation}
                  className="w-full py-3 rounded-lg border border-emerald-500/30 bg-emerald-950/30 text-emerald-300 font-semibold text-xs hover:bg-emerald-900/40 transition-colors"
                >
                  Generate CipherX Risk Analysis
                </button>

              )}

            </div>
          )}

          {/* ==============================================================
              TAB 4 — HARDENING
          ============================================================== */}

          {activeTab === 'hardening' && (
            <div className="space-y-4">

              {loadingHardening ? (

                <LoadingSpinner message="Synthesizing defensive hardening playbook..." />

              ) : hardeningGuide ? (

                <div className="space-y-4 text-xs">

                  {/* ISOLATION STRATEGY */}

                  <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-4 space-y-1.5">

                    <div className="font-bold text-cyan-300 flex items-center gap-2">

                      <Lock className="h-4 w-4" />

                      <span>
                        Target Architecture:{' '}
                        {hardeningGuide.target_type}
                      </span>

                    </div>

                    <p className="text-slate-300 leading-relaxed">
                      {hardeningGuide.summary}
                    </p>

                  </div>

                  {/* HARDENING RECOMMENDATIONS */}

                  <div className="space-y-2.5">

                    {hardeningGuide.hardening_items?.map(
                      (rec, i) => (
                        <div
                          key={i}
                          className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 space-y-1.5"
                        >

                          <div className="flex items-center justify-between">

                            <span className="font-bold text-slate-100">
                              {rec.action}
                            </span>

                            <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 font-mono">
                              {rec.priority}
                            </span>

                          </div>

                          <p className="text-slate-400 text-[11px] leading-relaxed">
                            {rec.reason}
                          </p>

                          {rec.safe_steps?.length > 0 && (
                            <ul className="list-disc list-inside text-slate-400 text-[11px] space-y-0.5">
                              {rec.safe_steps.map((step, stepIndex) => (
                                <li key={stepIndex}>{step}</li>
                              ))}
                            </ul>
                          )}

                          {rec.verification_guidance && (
                            <p className="text-slate-500 text-[11px] leading-relaxed">
                              Verify: {rec.verification_guidance}
                            </p>
                          )}

                        </div>
                      )
                    )}

                  </div>

                </div>

              ) : (

                <button
                  onClick={loadHardeningGuide}
                  className="w-full py-3 rounded-lg border border-cyan-500/30 bg-cyan-950/30 text-cyan-300 font-semibold text-xs hover:bg-cyan-900/40 transition-colors"
                >
                  Generate Step-by-Step Hardening Playbook
                </button>

              )}

            </div>
          )}

        </div>
      </div>
    </div>
  );
};