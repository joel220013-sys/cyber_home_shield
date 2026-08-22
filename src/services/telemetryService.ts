import { apiRequest } from './api';
import { NetworkEvent } from '../types';

export const telemetryService = {
  async getEvents(limit: number = 100): Promise<NetworkEvent[]> {
    return await apiRequest<NetworkEvent[]>(`/api/v1/telemetry/events?limit=${limit}`);
  },
};