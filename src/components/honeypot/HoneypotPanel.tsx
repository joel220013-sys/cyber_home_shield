/**
 * Honeypot & Deception Subsystem Panel (Phase 8)
 * Real-time trap monitoring, safe probe simulations, and NVIDIA Nemotron threat analysis.
 */

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Play,
  Square,
  RefreshCw,
  Sparkles,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Cpu,
  Layers,
  Terminal,
  Search,
  Filter,
  Eye,
  X,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { honeypotService } from '../../services/honeypotService';
import {
  HoneypotStatusResponse,
  HoneypotEvent,
  HoneypotAnalysisResponse,
  Severity,
} from '../../types';
import { SeverityBadge } from '../common/Badge';
import { LoadingSpinner } from '../common/LoadingSpinner';

interface HoneypotPanelProps {
  onOpenAdvisorWithPrompt?: (prompt: string) => void;
}

export const HoneypotPanel: React.FC<HoneypotPanelProps> = ({ onOpenAdvisorWithPrompt }) => {
  const [status, setStatus] = useState<HoneypotStatusResponse | null>(null);
  const [events, setEvents] = useState<HoneypotEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Simulation state
  const [simTrapType, setSimTrapType] = useState<string>('http_iot_gateway');
  const [simSourceIp, setSimSourceIp] = useState<string>('192.168.1.188');
  const [simInteractionType, setSimInteractionType] = useState<string>('login_attempt');
  const [simEndpoint, setSimEndpoint] = useState<string>('/login');
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simMessage, setSimMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // AI Analysis Modal State
  const [analyzingEventId, setAnalyzingEventId] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<HoneypotAnalysisResponse | null>(null);
  const [selectedEventForAnalysis, setSelectedEventForAnalysis] = useState<HoneypotEvent | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState<boolean>(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [statusRes, eventsRes] = await Promise.all([
        honeypotService.getStatus(),
        honeypotService.getEvents({ limit: 100 }),
      ]);
      setStatus(statusRes);
      setEvents(eventsRes);
    } catch (err) {
      console.error('Failed to load honeypot telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleToggleRunning = async () => {
    if (!status) return;
    try {
      setActionLoading(true);
      if (status.running) {
        await honeypotService.stop();
      } else {
        await honeypotService.start('127.0.0.1');
      }
      await fetchData();
    } catch (err: any) {
      alert(`Action failed: ${err.message || err}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleSimulateProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSimulating(true);
      setSimMessage(null);
      const created = await honeypotService.simulateProbe({
        trap_type: simTrapType,
        source_ip: simSourceIp,
        interaction_type: simInteractionType,
        endpoint: simEndpoint,
      });
      setSimMessage({
        type: 'success',
        text: `Simulated probe captured: ${created.interaction_type} on port ${created.destination_port}`,
      });
      await fetchData();
    } catch (err: any) {
      setSimMessage({
        type: 'error',
        text: `Simulation failed: ${err.message || err}`,
      });
    } finally {
      setSimulating(false);
    }
  };

  const handleOpenAnalysis = async (event: HoneypotEvent) => {
    setSelectedEventForAnalysis(event);
    setAnalyzingEventId(event.id);
    setAnalysisResult(null);
    setAnalysisLoading(true);

    try {
      const result = await honeypotService.analyzeIncident(event.id);
      setAnalysisResult(result);
    } catch (err) {
      console.error('AI Analysis failed', err);
    } finally {
      setAnalysisLoading(false);
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (filterSeverity !== 'ALL' && ev.severity !== filterSeverity) return false;
    if (filterType !== 'ALL' && ev.interaction_type !== filterType) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        ev.source_ip.toLowerCase().includes(q) ||
        ev.honeypot_id.toLowerCase().includes(q) ||
        ev.interaction_type.toLowerCase().includes(q) ||
        (ev.endpoint && ev.endpoint.toLowerCase().includes(q)) ||
        ev.payload_sample.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* 1. Subsystem Header & Status Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 shadow-sm backdrop-blur-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30 text-amber-400">
              <ShieldAlert className="h-6 w-6" />
              {status?.running && (
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                </span>
              )}
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-lg font-bold text-white tracking-wide">
                  Isolated Honeypot & Deception Subsystem
                </h2>
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${
                    status?.running
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}
                >
                  {status?.running ? 'ACTIVE LISTENING' : 'OFFLINE'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                Deploys decoy network traps to absorb unauthorized lateral scanning, log probe telemetry safely,
                and generate early-warning defensive alerts without risking real host or device compromise.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 self-start md:self-auto">
            <button
              onClick={fetchData}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
              title="Refresh telemetry"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>

            <button
              onClick={handleToggleRunning}
              disabled={actionLoading}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold shadow-sm transition ${
                status?.running
                  ? 'bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20'
              }`}
            >
              {status?.running ? (
                <>
                  <Square className="h-3.5 w-3.5 fill-current" />
                  <span>Deactivate Traps</span>
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>Activate Traps</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Isolation Guarantee Badges */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="flex items-center gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
            <Lock className="h-4 w-4 text-cyan-400 shrink-0" />
            <div>
              <span className="text-slate-400 block text-[10px]">Bind Interface</span>
              <span className="font-mono font-medium text-slate-200">{status?.bind_host || '127.0.0.1'} (Loopback)</span>
            </div>
          </div>
          <div className="flex items-center gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div>
              <span className="text-slate-400 block text-[10px]">Pivot Protection</span>
              <span className="font-medium text-slate-200">Strict Sandbox Isolation</span>
            </div>
          </div>
          <div className="flex items-center gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
            <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
            <div>
              <span className="text-slate-400 block text-[10px]">Credential Handling</span>
              <span className="font-medium text-slate-200">Zero Storage / Auto-Redact</span>
            </div>
          </div>
          <div className="flex items-center gap-2 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
            <Sparkles className="h-4 w-4 text-purple-400 shrink-0" />
            <div>
              <span className="text-slate-400 block text-[10px]">AI Security Advisor</span>
              <span className="font-medium text-purple-300">CipherX</span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Deception Trap Services Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <span>Active Decoy Services</span>
          </h3>
          <span className="text-xs text-slate-400">
            {status?.services.filter((s) => s.running).length ?? 0} of {status?.services.length ?? 3} traps running
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {(status?.services || []).map((service) => (
            <div
              key={service.type}
              className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 relative overflow-hidden flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-white">{service.name}</span>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                      service.running
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {service.running ? 'LISTENING' : 'IDLE'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mb-3">{service.description}</p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-300">
                  <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[11px] text-cyan-400">
                    {service.protocol}
                  </span>
                  <span>Port {service.port}</span>
                </div>
                <div className="text-slate-400">
                  <span className="text-white font-bold">{service.interactions_count}</span> interactions
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Probe Simulation Testing Console */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Safe Probe Injection & Simulation</h3>
          </div>
          <span className="text-xs text-slate-400">Deterministic defensive test harness</span>
        </div>

        <form onSubmit={handleSimulateProbe} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 items-end">
          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Target Trap</label>
            <select
              value={simTrapType}
              onChange={(e) => {
                const val = e.target.value;
                setSimTrapType(val);
                if (val === 'http_iot_gateway') {
                  setSimInteractionType('login_attempt');
                  setSimEndpoint('/login');
                } else if (val === 'fake_ssh') {
                  setSimInteractionType('ssh_connection');
                  setSimEndpoint('ssh');
                } else {
                  setSimInteractionType('camera_access');
                  setSimEndpoint('/snapshot');
                }
              }}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="http_iot_gateway">IoT Gateway (8088/HTTP)</option>
              <option value="fake_ssh">SSH Decoy (2222/TCP)</option>
              <option value="fake_camera">IP Camera (8554/RTSP)</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Simulated Source IP</label>
            <input
              type="text"
              value={simSourceIp}
              onChange={(e) => setSimSourceIp(e.target.value)}
              placeholder="192.168.1.188"
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Interaction Type</label>
            <input
              type="text"
              value={simInteractionType}
              onChange={(e) => setSimInteractionType(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Endpoint / Target</label>
            <input
              type="text"
              value={simEndpoint}
              onChange={(e) => setSimEndpoint(e.target.value)}
              className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <button
              type="submit"
              disabled={simulating}
              className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs py-2 px-3 transition shadow-sm"
            >
              <Radio className={`h-3.5 w-3.5 ${simulating ? 'animate-spin' : ''}`} />
              <span>{simulating ? 'Injecting...' : 'Inject Test Probe'}</span>
            </button>
          </div>
        </form>

        {simMessage && (
          <div
            className={`mt-3 p-2.5 rounded-lg text-xs flex items-center justify-between ${
              simMessage.type === 'success'
                ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30'
                : 'bg-red-500/10 text-red-300 border border-red-500/30'
            }`}
          >
            <span>{simMessage.text}</span>
            <button onClick={() => setSimMessage(null)} className="text-slate-400 hover:text-white">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {/* 4. Intercepted Telemetry & Incident Log */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-amber-400" />
            <h3 className="text-sm font-bold text-white">Intercepted Deception Telemetry</h3>
            <span className="ml-2 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-800 text-slate-300">
              {filteredEvents.length} events
            </span>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search IP, endpoint, payload..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-slate-950 border border-slate-800 text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="py-1.5 px-2.5 text-xs rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>

            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="py-1.5 px-2.5 text-xs rounded-lg bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Actions</option>
              <option value="login_attempt">Login Attempt</option>
              <option value="admin_endpoint_access">Admin Access</option>
              <option value="ssh_connection">SSH Probe</option>
              <option value="camera_access">Camera Probe</option>
              <option value="http_request">HTTP Request</option>
            </select>
          </div>
        </div>

        {/* Events Table */}
        {loading ? (
          <div className="py-16 text-center">
            <LoadingSpinner size="md" />
            <p className="text-xs text-slate-400 mt-2">Loading honeypot events...</p>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            <ShieldAlert className="h-8 w-8 text-slate-400 mx-auto mb-2 opacity-40" />
            <p>No honeypot interactions match the selected filters.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Trap ID</th>
                  <th className="py-3 px-4">Source IP</th>
                  <th className="py-3 px-4">Port</th>
                  <th className="py-3 px-4">Interaction</th>
                  <th className="py-3 px-4">Endpoint / Details</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(ev.event_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-2.5 px-4 font-sans text-slate-200">{ev.honeypot_id}</td>
                    <td className="py-2.5 px-4 text-cyan-400 font-bold">{ev.source_ip}</td>
                    <td className="py-2.5 px-4 text-slate-300">{ev.destination_port}</td>
                    <td className="py-2.5 px-4 font-sans text-slate-300">{ev.interaction_type}</td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate" title={ev.payload_sample}>
                      <span className="text-slate-200">{ev.endpoint || '/'}</span>{' '}
                      {ev.payload_sample && <span className="text-slate-400 text-[11px]">({ev.payload_sample})</span>}
                    </td>
                    <td className="py-2.5 px-4">
                      <SeverityBadge severity={ev.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleOpenAnalysis(ev)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[11px] font-sans font-medium transition"
                      >
                        <Sparkles className="h-3 w-3 text-purple-400" />
                        <span>AI Advisor</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 5. NVIDIA Nemotron AI Incident Analysis Modal */}
      {selectedEventForAnalysis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl rounded-xl border border-purple-500/30 bg-slate-900 shadow-2xl p-6 overflow-hidden">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-400">
                  <Sparkles className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white">CipherX Threat Analysis</h3>
                    <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[10px] border border-purple-500/30">
                      nemotron-3-8b
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Defensive narrative analysis for honeypot probe event from{' '}
                    <span className="font-mono text-cyan-400">{selectedEventForAnalysis.source_ip}</span>
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedEventForAnalysis(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="py-4 space-y-4 max-h-[70vh] overflow-y-auto">
              {/* Event Metadata Snapshot */}
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div>
                  <span className="text-slate-400 text-[10px] block">Source IP</span>
                  <span className="text-cyan-400 font-bold">{selectedEventForAnalysis.source_ip}</span>
                </div>
                <div>
                  <span className="text-slate-400 text-[10px] block">Target Port</span>
                  <span className="text-white">{selectedEventForAnalysis.destination_port}</span>
                </div>
                <div>
                  <span className="text-slate-400 text-[10px] block">Trap Type</span>
                  <span className="text-amber-400">{selectedEventForAnalysis.honeypot_id}</span>
                </div>
                <div>
                  <span className="text-slate-400 text-[10px] block">Severity</span>
                  <SeverityBadge severity={selectedEventForAnalysis.severity} size="sm" />
                </div>
              </div>

              {analysisLoading ? (
                <div className="py-12 text-center">
                  <LoadingSpinner size="lg" />
                  <p className="text-xs text-slate-400 mt-3 font-medium">
                    Consulting CipherX...
                  </p>
                </div>
              ) : analysisResult ? (
                <div className="space-y-4 text-xs">
                  {/* Pattern & Summary */}
                  <div className="bg-purple-950/30 border border-purple-500/30 rounded-lg p-3.5">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[11px] font-bold text-purple-300 uppercase tracking-wide">
                        Detected Attack Pattern
                      </span>
                      <span className="text-[11px] font-semibold text-emerald-400">
                        {analysisResult.confidence}% Confidence
                      </span>
                    </div>
                    <p className="text-sm font-semibold text-white mb-2">{analysisResult.pattern_detected}</p>
                    <p className="text-slate-300 leading-relaxed">{analysisResult.summary}</p>
                  </div>

                  {/* Defensive Implications */}
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                      <span>Defensive Implications</span>
                    </h4>
                    <ul className="space-y-1.5 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                      {analysisResult.defensive_implications.map((imp, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-slate-300">
                          <span className="text-amber-400 font-bold">•</span>
                          <span>{imp}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Recommended Actions */}
                  <div>
                    <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      <span>Recommended Defensive Actions</span>
                    </h4>
                    <ul className="space-y-2">
                      {analysisResult.recommended_actions.map((act, idx) => (
                        <li
                          key={idx}
                          className="flex items-start gap-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200"
                        >
                          <ChevronRight className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{act}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="py-8 text-center text-slate-400 text-xs">
                  Analysis currently unavailable.
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[11px] text-slate-400">
                    Model: {analysisResult?.model_used || 'CipherX'}
              </span>
              <div className="flex items-center gap-2">
                {onOpenAdvisorWithPrompt && selectedEventForAnalysis && (
                  <button
                    onClick={() => {
                      const prompt = `Can you explain the defensive mitigation strategy for a honeypot incident from IP ${selectedEventForAnalysis.source_ip} targeting port ${selectedEventForAnalysis.destination_port}?`;
                      setSelectedEventForAnalysis(null);
                      onOpenAdvisorWithPrompt(prompt);
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs transition"
                  >
                    <span>Discuss in CipherX Chat</span>
                    <ExternalLink className="h-3 w-3" />
                  </button>
                )}
                <button
                  onClick={() => setSelectedEventForAnalysis(null)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
