/// <reference types="vite/client" />
/**
 * Centralized API Client for Cyber Home Shield
 * Communicates strictly with the FastAPI Backend (VITE_API_BASE_URL)
 * Features auto-failover, Cloudflare Tunnel detection, and zero-config remote sync.
 */

export const DEFAULT_TUNNEL_URL = 'https://twice-translated-gui-welding.trycloudflare.com';
export const FALLBACK_TUNNEL_URL = 'https://chs-security-engine.loca.lt';
export const GITHUB_RAW_CONFIG_URL =
  'https://raw.githubusercontent.com/joel220013-sys/cyber_home_shield/main/active_tunnel.json';

let currentWorkingUrl: string | null = null;
let resolutionPromise: Promise<string> | null = null;

function isRemoteHost(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.location.hostname !== 'localhost' &&
    window.location.hostname !== '127.0.0.1'
  );
}

/**
 * Fast health check to verify if a candidate backend/tunnel is responding.
 */
async function checkHealth(candidateUrl: string, timeoutMs: number = 3500): Promise<boolean> {
  if (!candidateUrl) return false;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`${candidateUrl.replace(/\/$/, '')}/api/v1/health`, {
      method: 'GET',
      headers: {
        'Bypass-Tunnel-Reminder': 'true',
        'bypass-tunnel-reminder': 'true',
        Accept: 'application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(tid);
    if (res.ok) {
      const data = await res.json().catch(() => null);
      return !!(data && (data.status === 'ok' || data.service));
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Dynamically resolves the fastest, healthy backend tunnel without manual user intervention.
 */
export async function resolveWorkingBackendUrl(forceRefresh: boolean = false): Promise<string> {
  if (!isRemoteHost()) {
    return 'http://127.0.0.1:8000';
  }

  // Check explicit environment override first if provided
  const envUrl = (import.meta as any).env?.VITE_API_BASE_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, '');
  }

  if (currentWorkingUrl && !forceRefresh) {
    return currentWorkingUrl;
  }

  if (resolutionPromise && !forceRefresh) {
    return resolutionPromise;
  }

  resolutionPromise = (async () => {
    try {
      // 1. If we have a cached working URL, verify if it's still alive
      const cached =
        typeof window !== 'undefined'
          ? window.sessionStorage?.getItem('chs_working_backend_url')
          : null;
      if (cached && (await checkHealth(cached, 2500))) {
        currentWorkingUrl = cached;
        return cached;
      }

      // 2. Test primary Cloudflare Tunnel
      if (await checkHealth(DEFAULT_TUNNEL_URL, 3000)) {
        currentWorkingUrl = DEFAULT_TUNNEL_URL;
        if (typeof window !== 'undefined') {
          window.sessionStorage?.setItem('chs_working_backend_url', DEFAULT_TUNNEL_URL);
        }
        return DEFAULT_TUNNEL_URL;
      }

      // 3. Dynamically discover freshest tunnel published by PC on GitHub
      try {
        const ghRes = await fetch(`${GITHUB_RAW_CONFIG_URL}?_t=${Date.now()}`, {
          cache: 'no-store',
          headers: { Accept: 'application/json' },
        });
        if (ghRes.ok) {
          const cfg = await ghRes.json();
          if (cfg?.tunnel_url && cfg.tunnel_url !== DEFAULT_TUNNEL_URL) {
            if (await checkHealth(cfg.tunnel_url, 3000)) {
              currentWorkingUrl = cfg.tunnel_url;
              if (typeof window !== 'undefined') {
                window.sessionStorage?.setItem('chs_working_backend_url', cfg.tunnel_url);
              }
              return cfg.tunnel_url;
            }
          }
        }
      } catch {
        // Continue to fallback
      }

      // 4. Test persistent static fallback tunnel (localtunnel)
      if (await checkHealth(FALLBACK_TUNNEL_URL, 3500)) {
        currentWorkingUrl = FALLBACK_TUNNEL_URL;
        if (typeof window !== 'undefined') {
          window.sessionStorage?.setItem('chs_working_backend_url', FALLBACK_TUNNEL_URL);
        }
        return FALLBACK_TUNNEL_URL;
      }

      // Default to primary Cloudflare tunnel if all probes timed out
      currentWorkingUrl = DEFAULT_TUNNEL_URL;
      return DEFAULT_TUNNEL_URL;
    } finally {
      resolutionPromise = null;
    }
  })();

  return resolutionPromise;
}

export function getApiBaseUrl(): string {
  if (!isRemoteHost()) {
    return 'http://127.0.0.1:8000';
  }
  const envUrl = (import.meta as any).env?.VITE_API_BASE_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, '');
  }
  return currentWorkingUrl || DEFAULT_TUNNEL_URL;
}

export function setApiBaseUrl(url: string): void {
  if (typeof window !== 'undefined') {
    if (url && url.trim()) {
      currentWorkingUrl = url.trim().replace(/\/$/, '');
      window.sessionStorage?.setItem('chs_working_backend_url', currentWorkingUrl);
    } else {
      currentWorkingUrl = null;
      window.sessionStorage?.removeItem('chs_working_backend_url');
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
 * Execute an HTTP request to the FastAPI backend with timeout, auto-failover, and auth header injection
 */
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  timeoutMs: number = 18000
): Promise<T> {
  let baseUrl = await resolveWorkingBackendUrl();
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;

  const sendRequest = async (targetBase: string): Promise<Response> => {
    const url = `${targetBase}${normalizedEndpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const headers = new Headers(options.headers || {});
      if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
        headers.set('Content-Type', 'application/json');
      }
      headers.set('Accept', 'application/json');
      headers.set('Bypass-Tunnel-Reminder', 'true');
      headers.set('bypass-tunnel-reminder', 'true');

      const token = getAuthToken();
      if (token && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`);
      }

      const res = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return res;
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }
  };

  let response: Response;
  try {
    response = await sendRequest(baseUrl);
    // If Cloudflare returns a tunnel down status (530 Argo Tunnel error or 502/504 gateway timeout)
    if (response.status === 530 || response.status === 502 || response.status === 504) {
      throw new Error(`Tunnel status ${response.status}`);
    }
  } catch (initialErr: any) {
    // Trigger auto-failover to locate active tunnel
    try {
      const refreshedBase = await resolveWorkingBackendUrl(true);
      if (refreshedBase && refreshedBase !== baseUrl) {
        baseUrl = refreshedBase;
        response = await sendRequest(baseUrl);
      } else {
        throw initialErr;
      }
    } catch {
      if (initialErr.name === 'AbortError') {
        throw new ApiError('Request timed out. Please check if your backend and tunnel are reachable.', 408);
      }
      throw new ApiError(
        'Unable to connect to the Cyber Home Shield backend. Please verify your Cloudflare Tunnel is running on your PC.',
        0,
        initialErr
      );
    }
  }

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
}
