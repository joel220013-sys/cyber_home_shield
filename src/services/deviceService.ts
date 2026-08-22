import { apiRequest } from './api';
import { Device } from '../types';

export const deviceService = {
  /**
  * Retrieve the devices persisted by the backend discovery service.
   */
  async getDevices(): Promise<Device[]> {
    return await apiRequest<Device[]>('/api/v1/devices');
  },

  /**
   * Retrieve a specific device by ID
   */
  async getDeviceById(id: string): Promise<Device | null> {
    return await apiRequest<Device>(`/api/v1/devices/${id}`);
  },
};
