import { apiRequest } from './api';
import {
  AITriageRequest,
  AITriageResponse,
  AIChatRequest,
  AIChatResponse,
  DeviceRiskExplanation,
  FindingExplanation,
  HardeningGuideRequest,
  HardeningGuideResponse,
} from '../types';

export const aiService = {
  /**
   * Send defensive cybersecurity message to NVIDIA Nemotron
   */
  async chatAdvisory(payload: AIChatRequest): Promise<AIChatResponse> {
    return await apiRequest<AIChatResponse>('/api/v1/ai/chat', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Defensive AI triage on telemetry or finding
   */
  async triageEvent(payload: AITriageRequest): Promise<AITriageResponse> {
    return await apiRequest<AITriageResponse>('/api/v1/ai/triage', {
      method: 'POST',
      body: JSON.stringify(payload),
    }, 25000);
  },

  /**
   * Generate narrative risk explanation for device
   */
  async explainDeviceRisk(deviceId: string): Promise<DeviceRiskExplanation> {
    return await apiRequest<DeviceRiskExplanation>(`/api/v1/ai/explain-device/${deviceId}`, {
      method: 'POST',
    });
  },

  /**
   * Explain security finding with remediation steps
   */
  async explainFinding(findingId: string): Promise<FindingExplanation> {
    return await apiRequest<FindingExplanation>(`/api/v1/ai/explain-finding/${findingId}`, {
      method: 'POST',
    });
  },

  /**
   * Generate actionable hardening guide
   */
  async generateHardeningGuide(payload: HardeningGuideRequest): Promise<HardeningGuideResponse> {
    return await apiRequest<HardeningGuideResponse>('/api/v1/ai/hardening-guide', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },
};
