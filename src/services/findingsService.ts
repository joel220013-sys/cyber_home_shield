import { apiRequest } from './api';
import { SecurityFinding } from '../types';

export const findingsService = {
  async getFindings(): Promise<SecurityFinding[]> {
    return await apiRequest<SecurityFinding[]>('/api/v1/findings');
  },
};