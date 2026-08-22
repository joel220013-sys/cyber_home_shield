/**
 * Authentication and Profile API Service
 * Handles user registration, login, token management, and profile synchronization.
 */

import { apiRequest, setAuthToken } from './api';
import { TokenResponse, User, UserLoginRequest, UserRegisterRequest } from '../types';

export const authService = {
  /**
   * Register a new security administrator account
   */
  async register(data: UserRegisterRequest): Promise<TokenResponse> {
    const response = await apiRequest<TokenResponse>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (response.access_token) {
      setAuthToken(response.access_token);
    }
    return response;
  },

  /**
   * Authenticate with email & password
   */
  async login(data: UserLoginRequest): Promise<TokenResponse> {
    const response = await apiRequest<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (response.access_token) {
      setAuthToken(response.access_token);
    }
    return response;
  },

  /**
   * Invalidate authentication session
   */
  async logout(): Promise<void> {
    try {
      await apiRequest<{ message: string }>('/api/v1/auth/logout', {
        method: 'POST',
      });
    } catch {
      // ignore network errors on logout
    } finally {
      setAuthToken(null);
    }
  },

  /**
   * Fetch current authenticated user profile
   */
  async getMe(): Promise<User> {
    return apiRequest<User>('/api/v1/auth/me', {
      method: 'GET',
    });
  },

  /**
   * Update profile name or authorized defensive subnet
   */
  async updateMe(data: { full_name?: string; authorized_network_scope?: string }): Promise<User> {
    return apiRequest<User>('/api/v1/auth/me', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },
};
