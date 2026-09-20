/// <reference types="vite/client" />
/**
 * Centralized API Client for Cyber Home Shield
 * Communicates strictly with the FastAPI Backend (VITE_API_BASE_URL)
 */

export const API_BASE_URL =
  (import.meta as any).env?.VITE_API_BASE_URL ||
  (typeof window !== 'undefined' && window.location.port === '3000'
    ? 'http://127.0.0.1:8000'
    : 'http://127.0.0.1:8000');

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
  timeoutMs: number = 10000
): Promise<T> {
  const url = `${API_BASE_URL.replace(/\/$/, '')}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

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
        errorBody = await response.text();
      }

      let detailMsg: string;
      if (typeof errorBody === 'object' && errorBody !== null) {
        if (Array.isArray(errorBody.detail)) {
          detailMsg = errorBody.detail
            .map((item: any) => (typeof item === 'object' && item?.msg ? item.msg : String(item)))
            .join('; ');
        } else if (typeof errorBody.detail === 'string') {
          detailMsg = errorBody.detail;
        } else if (typeof errorBody.message === 'string') {
          detailMsg = errorBody.message;
        } else {
          detailMsg = JSON.stringify(errorBody);
        }
      } else {
        detailMsg = String(errorBody);
      }

      throw new ApiError(
        detailMsg || `HTTP ${response.status}: ${response.statusText}`,
        response.status,
        errorBody
      );
    }

    if (response.status === 204) {
      return {} as T;
    }

    return (await response.json()) as T;
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new ApiError(`Request timed out after ${timeoutMs}ms`, 408);
    }
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(
      error.message || 'Unable to connect to Cyber Home Shield backend',
      0,
      error
    );
  }
}
