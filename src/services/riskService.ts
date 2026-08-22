import { apiRequest } from './api';
import { NetworkPostureResult, DeviceRiskResult } from '../types';

export const riskService = {
  /**
   * Fetch aggregated network defensive security posture
   */
  async getNetworkPosture(): Promise<NetworkPostureResult> {
    return await apiRequest<NetworkPostureResult>('/api/v1/risk/posture');
  },

  /**
   * Fetch deterministic risk breakdown for a single device
   */
  async getDeviceRisk(deviceId: string): Promise<DeviceRiskResult> {
    return await apiRequest<DeviceRiskResult>(`/api/v1/risk/devices/${deviceId}`);
  },
};
