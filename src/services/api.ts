/// <reference types="vite/client" />
/**
 * Centralized API Client for Cyber Home Shield
 * Communicates strictly with the FastAPI Backend (VITE_API_BASE_URL)
 */

export const DEFAULT_TUNNEL_URL = 'https://andrews-luis-sas-dollars.trycloudflare.com';

export function getApiBaseUrl(): string {
  // When running remotely on Vercel or mobile browser, route through Cloudflare Tunnel
  if (
    typeof window !== 'undefined' &&
    window.location.hostname !== 'localhost' &&
    window.location.hostname !== '127.0.0.1'
  ) {
    // Clear any stale localStorage URLs from past dead sessions
    const saved = localStorage.getItem('chs_backend_url');
    if (saved && saved !== DEFAULT_TUNNEL_URL && saved.includes('trycloudflare.com')) {
      localStorage.removeItem('chs_backend_url');
    }
    const envUrl = (import.meta as any).env?.VITE_API_BASE_URL;
    if (envUrl && envUrl.trim()) {
      return envUrl.trim().replace(/\/$/, '');
    }
    return DEFAULT_TUNNEL_URL;
  }
  return 'http://127.0.0.1:8000';
}

export function setApiBaseUrl(url: string): void {
  if (typeof window !== 'undefined') {
    if (url && url.trim()) {
      localStorage.setItem('chs_backend_url', url.trim().replace(/\/$/, ''));
    } else {
      localStorage.removeItem('chs_backend_url');
    }
  }
}

export const API_BASE_URL = getApiBaseUrl();

let authToken: string | null = null;

export function getAuthToken(): string | null {
  if (authToken) return authToken;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      return window.sessionStorage.getItem('chs_auth_token');
    }
  } catch {
    // ignore
  }
  return null;
}

export function setAuthToken(token: string | null): void {
  authToken = token;
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      if (token) {
        window.sessionStorage.setItem('chs_auth_token', token);
      } else {
        window.sessionStorage.removeItem('chs_auth_token');
      }
    }
  } catch {
    // ignore
  }
}

export class ApiError extends Error {
  public status: number;
  public details?: any;

  constructor(message: string, status: number = 500, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

/**
 * Execute an HTTP request to the FastAPI backend with timeout and auth header injection
 */
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  timeoutMs: number = 15000
): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = new Headers(options.headers || {});
    if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
      headers.set('Content-Type', 'application/json');
    }
    headers.set('Accept', 'application/json');

    const token = getAuthToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const response = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let errorBody: any = null;
      try {
        errorBody = await response.json();
      } catch {
        try {
          errorBody = await response.text();
        } catch {
          errorBody = null;
        }
      }

      let errorMessage = `HTTP ${response.status} ${response.statusText}`;
      if (errorBody) {
        if (typeof errorBody === 'string') {
          errorMessage = errorBody;
        } else if (typeof errorBody.detail === 'string') {
          errorMessage = errorBody.detail;
        } else if (Array.isArray(errorBody.detail)) {
          errorMessage = errorBody.detail
            .map((errItem: any) =>
              typeof errItem === 'object' && errItem !== null
                ? errItem.msg || errItem.message || JSON.stringify(errItem)
                : String(errItem)
            )
            .join('; ');
        } else if (errorBody.message) {
          errorMessage = errorBody.message;
        }
      }

      throw new ApiError(errorMessage, response.status, errorBody);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return await response.json();
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new ApiError('Request timed out. Please check if your backend and tunnel are reachable.', 408);
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      'Unable to connect to the Cyber Home Shield backend. Please verify your Cloudflare Tunnel is running on your PC.',
      0,
      err
    );
  }
}
