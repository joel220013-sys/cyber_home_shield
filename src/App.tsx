/**
 * Cyber Home Shield - Defensive Security Operations Dashboard
 * Frontend Architecture: React 18 + TypeScript + Tailwind CSS + Lucide + Recharts
 */

import React, { useState } from 'react';
import { Layout } from './components/layout/Layout';
import { NavTab } from './components/layout/Sidebar';
import { PostureOverviewCard } from './components/dashboard/PostureOverviewCard';
import { MetricsGrid } from './components/dashboard/MetricsGrid';
import { RiskDistributionChart } from './components/dashboard/RiskDistributionChart';
import { SeverityBreakdownChart } from './components/dashboard/SeverityBreakdownChart';
import { RecentFindingsFeed } from './components/dashboard/RecentFindingsFeed';
import { RouterDetectionPanel } from './components/dashboard/RouterDetectionPanel';
import { DeviceTable } from './components/devices/DeviceTable';
import { DeviceFilters } from './components/devices/DeviceFilters';
import { DeviceDetailDrawer } from './components/devices/DeviceDetailDrawer';
import { ScanConsole } from './components/scanner/ScanConsole';
import { ScanProgress } from './components/scanner/ScanProgress';
import { DiscoveredAssetsList } from './components/scanner/DiscoveredAssetsList';
import { FindingsView } from './components/findings/FindingsView';
import { TelemetryStream } from './components/telemetry/TelemetryStream';
import { BaselineMetricsCard } from './components/telemetry/BaselineMetricsCard';
import { HoneypotPanel } from './components/honeypot/HoneypotPanel';
import { NemotronChat } from './components/ai-advisor/NemotronChat';
import { TriageModal } from './components/ai-advisor/TriageModal';
import { ScopeBanner } from './components/common/ScopeBanner';
import { LoadingSpinner } from './components/common/LoadingSpinner';
import { AuthModal } from './components/auth/AuthModal';
import { AuthProvider } from './context/AuthContext';

import { useNetworkPosture } from './hooks/useNetworkPosture';
import { useDevices } from './hooks/useDevices';
import { useFindings } from './hooks/useFindings';
import { useScanner } from './hooks/useScanner';
import { useTelemetry } from './hooks/useTelemetry';
import { Device, SecurityFinding, NetworkEvent } from './types';

function DashboardContent() {
  const [activeTab, setActiveTab] = useState<NavTab>('dashboard');

  // Core data hooks
  const { posture, loading: loadingPosture, error: postureError, refresh: refreshPosture } = useNetworkPosture();
  const {
    devices,
    filteredDevices,
    loading: loadingDevices,
    searchQuery,
    setSearchQuery,
    typeFilter,
    setTypeFilter,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    refresh: refreshDevices,
    discoverInventory,
  } = useDevices();
  const {
    findings,
    loading: loadingFindings,
    error: findingsError,
    refresh: refreshFindings,
  } = useFindings();

  const { activeJob, isScanning, error: scanError, startScan } = useScanner();
  const { events, loading: loadingTelemetry, error: telemetryError } = useTelemetry();

  // Modals & Drawers state
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [triageTarget, setTriageTarget] = useState<{ event?: NetworkEvent; finding?: SecurityFinding } | null>(null);
  const [initialAdvisorPrompt, setInitialAdvisorPrompt] = useState<string | undefined>(undefined);

  const handleRefreshAll = () => {
    refreshPosture();
    refreshDevices();
    refreshFindings();
  };

  const handleOpenAdvisorWithPrompt = (prompt: string) => {
    setInitialAdvisorPrompt(prompt);
    setActiveTab('ai-advisor');
  };

  const getPageHeader = () => {
    switch (activeTab) {
      case 'dashboard':
        return {
          title: 'Defensive Security Posture',
          subtitle: 'Real-time aggregated risk assessment, exposure levels, and posture metrics',
        };
      case 'devices':
        return {
          title: 'Authorized Device Inventory',
          subtitle: 'Discovered network endpoints, fingerprint profiles, and deterministic risk scores',
        };
      case 'scanner':
        return {
          title: 'Defensive Network Scanner',
          subtitle: 'Targeted RFC 1918 discovery probes, port profiling, and active service mapping',
        };
      case 'findings':
        return {
          title: 'Security Vulnerabilities & Findings',
          subtitle: 'Identified configuration weaknesses, open risks, and actionable remediations',
        };
      case 'telemetry':
        return {
          title: 'Connection Telemetry & Baseline Flow',
          subtitle: '24-hour statistical anomaly monitoring and connection audit trail',
        };
      case 'honeypot':
        return {
          title: 'Isolated Honeypot & Deception Subsystem',
          subtitle: 'Loopback decoy traps, automated threat telemetry capture, and CipherX investigation',
        };
      case 'ai-advisor':
        return {
          title: 'CipherX',
          subtitle: 'Contextual threat intelligence, security narrative analysis, and hardening playbooks',
        };
    }
  };

  const headerInfo = getPageHeader();
  const networkRiskScore = posture?.network_risk_score ?? 0;

  return (
    <Layout
      activeTab={activeTab}
      onSelectTab={(tab) => {
        setActiveTab(tab);
        if (tab !== 'ai-advisor') setInitialAdvisorPrompt(undefined);
      }}
      title={headerInfo.title}
      subtitle={headerInfo.subtitle}
      networkRiskScore={networkRiskScore}
      loading={loadingPosture || loadingDevices}
      onRefresh={handleRefreshAll}
    >
      {/* TAB 1: POSTURE DASHBOARD */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <ScopeBanner />

          <RouterDetectionPanel />

          {loadingPosture && !posture ? (
            <LoadingSpinner message="Evaluating network defensive posture..." />
          ) : (
            <>
              {/* Primary Posture Card */}
              <PostureOverviewCard posture={posture} />

              {/* 5-Metric Quick Bar */}
              <MetricsGrid posture={posture} />

              {/* Visual Charts Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-7">
                  <RiskDistributionChart posture={posture} devices={devices} />
                </div>
                <div className="lg:col-span-5">
                  <SeverityBreakdownChart posture={posture} />
                </div>
              </div>

              {/* Recent Findings Feed */}
              <RecentFindingsFeed
                findings={[]}
                onSelectFinding={(f) => setTriageTarget({ finding: f })}
                onViewAll={() => setActiveTab('findings')}
              />
            </>
          )}
        </div>
      )}

      {/* TAB 2: DEVICE INVENTORY */}
      {activeTab === 'devices' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <ScopeBanner />

          <DeviceFilters
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            typeFilter={typeFilter}
            onTypeChange={setTypeFilter}
            sortBy={sortBy}
            onSortByChange={setSortBy}
            sortOrder={sortOrder}
            onToggleSortOrder={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
          />

          <div className="flex justify-end">
            <button
              type="button"
              onClick={discoverInventory}
              disabled={loadingDevices}
              className="rounded-lg border border-cyan-500/40 bg-cyan-950/30 px-3 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-900/40 disabled:opacity-60"
            >
              {loadingDevices ? 'Refreshing inventory…' : 'Refresh authorized inventory'}
            </button>
          </div>

          {loadingDevices && devices.length === 0 ? (
            <LoadingSpinner message="Scanning local device cache..." />
          ) : (
            <DeviceTable
              devices={filteredDevices}
              onSelectDevice={(d) => setSelectedDevice(d)}
            />
          )}
        </div>
      )}

      {/* TAB 3: DEFENSIVE SCANNER */}
      {activeTab === 'scanner' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <ScanConsole
            onStartScan={async (subnet, scanType, dryRun) => {
              await startScan(subnet, scanType, dryRun);
            }}
            isScanning={isScanning}
            error={scanError}
          />

          {activeJob && <ScanProgress job={activeJob} isScanning={isScanning} />}

          <DiscoveredAssetsList
            devices={devices}
            onSelectDevice={(d) => setSelectedDevice(d)}
          />
        </div>
      )}

      {/* TAB 4: SECURITY FINDINGS */}
      {activeTab === 'findings' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <ScopeBanner />
          {loadingFindings ? (
            <LoadingSpinner message="Loading security findings..." />
          ) : findingsError ? (
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4 text-sm text-red-300">
              {findingsError}
            </div>
          ) : (
            <FindingsView
              findings={findings}
              onTriageFinding={(f) => setTriageTarget({ finding: f })}
              onOpenAdvisorChat={(msg) => handleOpenAdvisorWithPrompt(msg)}
            />
          )}
        </div>
      )}

      {/* TAB 5: TELEMETRY & EVENTS */}
      {activeTab === 'telemetry' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <BaselineMetricsCard />
          <TelemetryStream
            events={events}
            loading={loadingTelemetry}
            error={telemetryError}
            onTriageEvent={(e) => setTriageTarget({ event: e })}
          />
        </div>
      )}

      {/* TAB 6: HONEYPOT & DECEPTION */}
      {activeTab === 'honeypot' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <HoneypotPanel onOpenAdvisorWithPrompt={handleOpenAdvisorWithPrompt} />
        </div>
      )}

      {/* TAB 7: NEMOTRON AI ADVISOR */}
      {activeTab === 'ai-advisor' && (
        <div className="space-y-6 animate-in fade-in duration-300">
          <NemotronChat initialPrompt={initialAdvisorPrompt} />
        </div>
      )}

      {/* Device Details Slide-out Drawer */}
      {selectedDevice && (
        <DeviceDetailDrawer
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
          onOpenAdvisorChat={(msg) => {
            setSelectedDevice(null);
            handleOpenAdvisorWithPrompt(msg);
          }}
        />
      )}

      {/* Telemetry / Finding Triage Modal */}
      {triageTarget && (
        <TriageModal
          event={triageTarget.event}
          finding={triageTarget.finding}
          onClose={() => setTriageTarget(null)}
        />
      )}

      {/* Auth Modal */}
      <AuthModal />
    </Layout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
}
