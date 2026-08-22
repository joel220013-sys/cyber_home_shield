import { apiRequest } from './api';
import { ScanJob, ScanType } from '../types';

export interface CreateScanPayload {
  target_subnet: string;
  scan_type?: ScanType;
  dry_run?: boolean;
  ports?: number[];
}

export const scanService = {
  /**
   * Start a defensive discovery scan on an authorized RFC1918 subnet
   */
  async createScan(payload: CreateScanPayload): Promise<ScanJob> {
    return await apiRequest<ScanJob>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Query status of an existing scan job
   */
  async getScan(scanId: string): Promise<ScanJob> {
    return await apiRequest<ScanJob>(`/api/v1/scans/${scanId}`);
  },
};
