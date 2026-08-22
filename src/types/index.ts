/**
 * Cyber Home Shield TypeScript Type Definitions
 * Mirrors FastAPI / Pydantic Backend Data Contracts
 */

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type DeviceType =
  | 'ROUTER'
  | 'GATEWAY'
  | 'SWITCH'
  | 'ACCESS_POINT'
  | 'WORKSTATION'
  | 'LAPTOP'
  | 'SERVER'
  | 'NAS'
  | 'IOT'
  | 'SMART_TV'
  | 'IP_CAMERA'
  | 'PRINTER'
  | 'MOBILE'
  | 'UNKNOWN';

export type ScanType = 'DISCOVERY' | 'QUICK' | 'FULL' | 'PORT_PROFILE';

export type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'UNKNOWN';

export type FindingStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'SUPPRESSED' | 'FALSE_POSITIVE';

export type BaselineStatus =
  | 'normal'
  | 'elevated'
  | 'anomalous'
  | 'severe_anomaly'
  | 'insufficient_data';

export type FindingCategory =
  | 'EXPOSURE'
  | 'CONFIGURATION'
  | 'SERVICE'
  | 'ANOMALY'
  | 'AUTHENTICATION'
  | 'OTHER';

export interface User {
  id: string;
  email: string;
  full_name: string;
  authorized_network_scope: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
}

export interface UserRegisterRequest {
  email: string;
  password: string;
  full_name?: string;
  authorized_network_scope?: string;
}

export interface UserLoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface FindingEvidence {
  source: string;
  port?: number | null;
  protocol?: string | null;
  reason: string;
  raw_data?: string | null;
  timestamp: string;
}

export interface EvaluatedFinding {
  finding_id?: string | null;
  device_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  evidence: Record<string, any>;
  remediation_steps: string;
  cve_id: string;
}

export interface OpenPort {
  id?: string;
  device_id: string;
  port_number: number;
  protocol: string;
  service_name?: string;
  banner?: string | null;
  state?: string;
  created_at?: string;
  updated_at?: string;
}

export interface NetworkEvent {
  id: string;
  device_id?: string | null;
  event_timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  bytes_transferred: number;
  is_anomaly: boolean;
  anomaly_reason: string;
  severity: Severity;
  created_at: string;
  updated_at: string;
}

export interface SecurityFinding {
  id: string;
  device_id: string;
  scan_job_id?: string | null;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  evidence: Record<string, any>;
  remediation_steps?: string | null;
  cve_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Device {
  id: string;
  ip_address: string;
  mac_address?: string | null;
  hostname?: string | null;
  vendor?: string | null;
  device_type: DeviceType;
  os_fingerprint?: string | null;
  is_online: boolean;
  first_seen: string;
  last_seen: string;
  ports?: OpenPort[];
  findings?: SecurityFinding[];
  events?: NetworkEvent[];
  risk_score?: number;
}

export interface ScanJob {
  id: string;
  target_subnet: string;
  scan_type: ScanType;
  status: ScanStatus;
  devices_found: number;
  ports_scanned: number;
  started_at: string;
  completed_at?: string | null;
  summary_findings: Record<string, any>;
  error_message?: string;
}

export interface ExposureResult {
  exposure_score: number;
  open_ports_count: number;
  risky_services_count: number;
  service_exposures: Array<Record<string, any>>;
  reasons: string[];
}

export interface AnomalyBaseline {
  baseline_window_seconds: number;
  event_count: number;
  known_destination_ports: number[];
  known_protocols: string[];
  average_event_rate: number;
  current_event_rate: number;
  deviation: number;
  status: BaselineStatus;
  reasons: string[];
}

export interface AnomalyResult {
  anomaly_score: number;
  status: BaselineStatus;
  anomalies_detected: Array<Record<string, any>>;
  events_analyzed: number;
  baseline: AnomalyBaseline;
}

export interface VulnerabilityResult {
  vulnerability_score: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  reasons: string[];
}

export interface ScoreContribution {
  weight: number;
  score: number;
  weighted_contribution: number;
}

export interface DeviceRiskResult {
  device_id: string;
  overall_score: number;
  exposure_subscore: number;
  vulnerability_subscore: number;
  anomaly_subscore: number;
  critical_findings_count: number;
  high_findings_count: number;
  open_risky_ports_count: number;
  score_breakdown: {
    exposure?: ScoreContribution;
    vulnerability?: ScoreContribution;
    anomaly?: ScoreContribution;
    [key: string]: any;
  };
  summary_notes: string;
  findings: EvaluatedFinding[];
  evaluated_at: string;
}

export interface NetworkPostureResult {
  network_risk_score: number;
  total_devices: number;
  vulnerable_devices: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  active_anomalies: number;
  device_scores: Record<string, number>;
  posture_breakdown: Record<string, any>;
  last_evaluated_at: string;
}

// AI Advisor Types (NVIDIA Nemotron)
export interface AIThreatAnalysis {
  threat_level: Severity;
  confidence: number;
  summary: string;
  observed_facts: string[];
  recommended_actions: string[];
  defensive_priority: 'IMMEDIATE' | 'HIGH' | 'SCHEDULED' | 'INFORMATIONAL';
}

export interface AITriageRequest {
  event_data?: Record<string, any>;
  finding_data?: Record<string, any>;
}

export interface AITriageResponse {
  analysis: AIThreatAnalysis;
  ai_available: boolean;
}

export interface AIChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: string;
  confidence?: number;
  evidence_citations?: string[];
  defensive_priorities?: string[];
  suggested_followups?: string[];
  model_name?: string;
  ai_available?: boolean;
}

export interface AIChatRequest {
  message: string;
  history?: Array<{ role: string; content: string }>;
  context_device_id?: string;
}

export interface AIChatResponse {
  reply?: string | null;
  suggested_followups?: string[];
  ai_available: boolean;
  model_name?: string;
  evidence_citations?: string[];
  defensive_priorities?: string[];
  confidence?: number;
}

export interface DeviceRiskExplanation {
  device_id: string;
  deterministic_risk_score: number;
  key_observations: string[];
  risk_factors_explained: Array<{
    factor: string;
    description: string;
    impact: 'HIGH' | 'MEDIUM' | 'LOW';
  }>;
  likely_security_implications: string;
  defensive_priorities: string[];
  ai_available: boolean;
}

export interface FindingExplanation {
  finding_id: string;
  title: string;
  severity: Severity;
  risk_explanation: string;
  why_it_matters: string;
  step_by_step_remediation: string[];
  verification_steps: string[];
  ai_available: boolean;
}

export interface HardeningGuideRequest {
  target_type: string;
  observed_services?: number[];
  context?: Record<string, any>;
}

export interface HardeningGuideResponse {
  target_type: string;
  hardening_items: Array<{
    priority: string;
    action: string;
    reason: string;
    safe_steps: string[];
    verification_guidance: string;
  }>;
  summary: string;
  ai_available: boolean;
}

// Honeypot & Deception Subsystem Types (Phase 8)
export interface HoneypotTrapService {
  name: string;
  type: string;
  port: number;
  protocol: string;
  description: string;
  running: boolean;
  interactions_count: number;
}

export interface HoneypotStatusResponse {
  enabled: boolean;
  running: boolean;
  bind_host: string;
  services: HoneypotTrapService[];
  total_captured_events: number;
  high_severity_events: number;
  last_interaction_timestamp?: string | null;
}

export interface HoneypotEvent {
  id: string;
  user_id?: string | null;
  event_timestamp: string;
  honeypot_id: string;
  source_ip: string;
  source_port: number;
  destination_port: number;
  protocol: Protocol;
  interaction_type: string;
  endpoint?: string;
  user_agent?: string;
  payload_sample: string;
  metadata_fields: Record<string, any>;
  severity: Severity;
  created_at: string;
}

export interface HoneypotAnalysisResponse {
  event_id: string;
  summary: string;
  pattern_detected: string;
  severity: Severity;
  defensive_implications: string[];
  recommended_actions: string[];
  confidence: number;
  model_used: string;
}

export interface HoneypotSimulateRequest {
  trap_type: string;
  source_ip?: string;
  interaction_type?: string;
  endpoint?: string;
}

export interface HoneypotStartRequest {
  bind_host?: string;
}

export interface HoneypotStartResponse {
  status: string;
  running: boolean;
  bind_host: string;
  active_services: string[];
  message: string;
}

export interface HoneypotStopResponse {
  status: string;
  running: boolean;
  message: string;
}
