// SentinelTrace Frontend — Axios API Client

import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';

const isBrowser = typeof window !== 'undefined';
const hostname = isBrowser ? window.location.hostname : '';
const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1';
const isLanIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) && !isLoopback;

const RENDER_BACKEND_URL = 'https://sentineltrace-e9td.onrender.com/api/v1';

let rawBaseUrl =
  (import.meta as any).env?.VITE_API_BASE_URL ||
  (import.meta as any).env?.VITE_API_URL ||
  '';

if (!rawBaseUrl) {
  if (isLoopback) {
    rawBaseUrl = 'http://localhost:8000/api/v1';
  } else if (isLanIp) {
    // When accessing from mobile on local Wi-Fi, target host machine backend at the same IP
    rawBaseUrl = `http://${hostname}:8000/api/v1`;
  } else {
    // Deployed production or cloud environments (e.g., Vercel)
    rawBaseUrl = RENDER_BACKEND_URL;
  }
} else if (isBrowser && !isLoopback && (rawBaseUrl.includes('localhost') || rawBaseUrl.includes('127.0.0.1'))) {
  // If env var was defaulted to localhost but running on mobile or deployed domain
  if (isLanIp) {
    rawBaseUrl = `http://${hostname}:8000/api/v1`;
  } else {
    rawBaseUrl = RENDER_BACKEND_URL;
  }
}

export const BASE_URL = rawBaseUrl.replace(/\/+$/, '');


export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 60000, // 60s to accommodate Render cold start on free tier
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Required for HttpOnly refresh token cookie
});

// ── Auth Token Store ──────────────────────────────────────────────────────────
let accessToken: string | null = null;
try {
  const storedAuth = typeof window !== 'undefined' ? localStorage.getItem('sentineltrace-auth') : null;
  if (storedAuth) {
    const parsed = JSON.parse(storedAuth);
    if (parsed?.state?.accessToken) {
      accessToken = parsed.state.accessToken;
    }
  }
} catch {
  // Ignore parsing errors
}

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

// ── Request Interceptor: attach access token ──────────────────────────────────
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (accessToken && config.headers) {
    config.headers['Authorization'] = `Bearer ${accessToken}`;
  }
  // When sending FormData, delete Content-Type so browser sets correct boundary
  if (config.data instanceof FormData && config.headers) {
    delete config.headers['Content-Type'];
  }
  return config;
});

// ── Response Interceptor: auto-refresh on 401 ─────────────────────────────────
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}> = [];

function processQueue(error: Error | null, token: string | null = null) {
  failedQueue.forEach((prom) => {
    if (error) prom.reject(error);
    else prom.resolve(token!);
  });
  failedQueue = [];
}

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Skip refresh for auth endpoints to avoid infinite loops
    const isAuthEndpoint = originalRequest.url?.includes('/auth/');
    if (error.response?.status === 401 && !originalRequest._retry && !isAuthEndpoint) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            originalRequest.headers['Authorization'] = `Bearer ${token}`;
            return apiClient(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await apiClient.post<{ access_token: string; session_expires_in?: number }>('/auth/refresh');
        setAccessToken(data.access_token);
        processQueue(null, data.access_token);
        originalRequest.headers['Authorization'] = `Bearer ${data.access_token}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError as Error, null);
        setAccessToken(null);
        try {
          localStorage.removeItem('sentineltrace-auth');
        } catch {
          // Ignore
        }
        // Redirect to login with reason
        if (typeof window !== 'undefined') {
          window.location.href = '/login?reason=session_expired';
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await apiClient.get('/health');
    return res.data?.status === 'healthy';
  } catch (err) {
    return false;
  }
}

export default apiClient;
