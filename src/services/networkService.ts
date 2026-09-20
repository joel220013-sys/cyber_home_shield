import { apiRequest } from './api';
import { NetworkDiscoveryResponse, RouterDetectionResponse, RouterHealthResponse } from '../types';

export const NETWORK_DISCOVERY_TIMEOUT_MS = 60000;

export const networkService = {
  async detectRouter(): Promise<RouterDetectionResponse> {
    return await apiRequest<RouterDetectionResponse>('/api/v1/network/router');
  },

  async checkRouterHealth(): Promise<RouterHealthResponse> {
    return await apiRequest<RouterHealthResponse>('/api/v1/network/router/health');
  },

  async discoverDevices(): Promise<NetworkDiscoveryResponse> {
    return await apiRequest<NetworkDiscoveryResponse>('/api/v1/network/devices/discover', {
      method: 'POST',
      body: JSON.stringify({}),
    }, NETWORK_DISCOVERY_TIMEOUT_MS);
  },
};