// SentinelTrace Frontend — Utility Functions

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { SeverityLevel, ThreatCategory, AnalysisStatus } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ── Severity helpers ──────────────────────────────────────────────────────────
export function getSeverityClass(severity?: SeverityLevel | null): string {
  switch (severity) {
    case 'CRITICAL': return 'severity-critical';
    case 'HIGH': return 'severity-high';
    case 'MEDIUM': return 'severity-medium';
    case 'LOW': return 'severity-low';
    case 'INFO': return 'severity-info';
    default: return 'text-[hsl(var(--foreground-subtle))] border border-[hsl(var(--border))]';
  }
}

export function getSeverityColor(severity?: SeverityLevel | null): string {
  switch (severity) {
    case 'CRITICAL': return 'hsl(var(--critical))';
    case 'HIGH': return 'hsl(var(--high))';
    case 'MEDIUM': return 'hsl(var(--medium))';
    case 'LOW': return 'hsl(var(--low))';
    case 'INFO': return 'hsl(var(--info))';
    default: return 'hsl(var(--foreground-muted))';
  }
}

export function getSeverityWeight(severity?: SeverityLevel | null): number {
  switch (severity) {
    case 'CRITICAL': return 5;
    case 'HIGH': return 4;
    case 'MEDIUM': return 3;
    case 'LOW': return 2;
    case 'INFO': return 1;
    default: return 0;
  }
}

// ── Status helpers ────────────────────────────────────────────────────────────
export function getStatusClass(status: AnalysisStatus): string {
  switch (status) {
    case 'PENDING': return 'status-pending';
    case 'PROCESSING': return 'status-processing';
    case 'COMPLETE': return 'status-complete';
    case 'FAILED': return 'status-failed';
    case 'QUARANTINED': return 'status-quarantined';
    default: return '';
  }
}

// ── Threat Category Labels ────────────────────────────────────────────────────
export const THREAT_CATEGORY_LABELS: Record<ThreatCategory, string> = {
  PHISHING: 'Phishing',
  SPEAR_PHISHING: 'Spear Phishing',
  BEC: 'Business Email Compromise',
  MALWARE: 'Malware',
  SPAM: 'Spam',
  RANSOMWARE: 'Ransomware',
  CREDENTIAL_HARVEST: 'Credential Harvesting',
  SOCIAL_ENGINEERING: 'Social Engineering',
  UNKNOWN: 'Unknown',
  BENIGN: 'Benign',
};

// ── Formatting ────────────────────────────────────────────────────────────────
export function formatFileSize(bytes?: number): string {
  if (!bytes) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(iso?: string): string {
  if (!iso) return '—';
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(iso));
}

export function formatRelativeTime(iso?: string): string {
  if (!iso) return '—';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMin / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(iso);
}

export function truncateHash(hash?: string, chars = 16): string {
  if (!hash) return '—';
  if (hash.length <= chars) return hash;
  return `${hash.slice(0, chars / 2)}…${hash.slice(-(chars / 2))}`;
}

export function truncate(str?: string, max = 50): string {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

// ── IOC type label ────────────────────────────────────────────────────────────
export function getIOCTypeLabel(iocType: string): string {
  const labels: Record<string, string> = {
    IP_ADDRESS: 'IP',
    DOMAIN: 'Domain',
    URL: 'URL',
    EMAIL: 'Email',
    FILE_HASH_MD5: 'MD5',
    FILE_HASH_SHA256: 'SHA-256',
    FILE_HASH_SHA1: 'SHA-1',
    HEADER: 'Header',
    USER_AGENT: 'User-Agent',
    BITCOIN_ADDRESS: 'BTC',
    CVE: 'CVE',
    OTHER: 'Other',
  };
  return labels[iocType] || iocType;
}

/**
 * Safely extracts a user-friendly displayable string from any error object,
 * hiding internal server/backend technical details from end-users.
 */
export function extractErrorMessage(err: unknown, defaultMessage = 'An unexpected error occurred. Please try again.'): string {
  if (!err) return defaultMessage;

  if (typeof err === 'string') {
    if (err.includes('Network Error') || err.includes('ERR_NETWORK') || err.includes('Failed to fetch')) {
      return 'Network connection issue. Please check your internet connection or try again in a moment.';
    }
    if (err.includes('timeout') || err.includes('exceed') || err.includes('ECONNABORTED')) {
      return 'Request timed out. Please try again.';
    }
    return err;
  }

  const anyErr = err as any;

  // 1. Network connectivity / server unreachable
  if (
    anyErr?.code === 'ERR_NETWORK' ||
    anyErr?.message === 'Network Error' ||
    anyErr?.message === 'Failed to fetch' ||
    (anyErr?.name === 'TypeError' && anyErr?.message?.includes('fetch'))
  ) {
    return 'Network connection issue. Please check your internet connection or try again in a moment.';
  }

  // 2. Request timeout / long waiting
  if (
    anyErr?.code === 'ECONNABORTED' ||
    anyErr?.message?.toLowerCase().includes('timeout') ||
    anyErr?.message?.toLowerCase().includes('exceed')
  ) {
    return 'Request timed out. Please try again.';
  }

  // 3. HTTP status-based user-friendly messages
  const status = anyErr?.response?.status;
  if (status === 500 || status === 502 || status === 503 || status === 504) {
    return 'Service temporarily unavailable. Please try again in a moment.';
  }

  // 4. FastAPI Pydantic detail field
  const detail = anyErr?.response?.data?.detail ?? anyErr?.detail;
  if (typeof detail === 'string') {
    if (detail.includes('Internal Server Error') || detail.includes('Traceback')) {
      return 'Service temporarily unavailable. Please try again in a moment.';
    }
    return detail;
  }

  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item?.msg) {
          const loc = Array.isArray(item.loc) ? item.loc.slice(1).join('.') : '';
          return loc ? `${loc}: ${item.msg}` : item.msg;
        }
        return JSON.stringify(item);
      })
      .join('; ');
  }

  if (detail && typeof detail === 'object') {
    return detail.msg || detail.message || defaultMessage;
  }

  if (anyErr?.message && typeof anyErr.message === 'string') {
    const msg = anyErr.message;
    if (msg.includes('Network Error') || msg.includes('Failed to fetch')) {
      return 'Network connection issue. Please check your internet connection or try again in a moment.';
    }
    if (msg.includes('timeout') || msg.includes('exceed')) {
      return 'Request timed out. Please try again.';
    }
    if (!msg.startsWith('{') && !msg.startsWith('<') && !msg.includes('Traceback')) {
      return msg;
    }
  }

  return defaultMessage;
}


