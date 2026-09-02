// SentinelTrace Frontend — TanStack Query API Hooks

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  AnalysisTriggerResponse,
  CampaignGraphResponse,
  EmailAnalysisDetail,
  EmailAnalysisSummary,
  EnrichmentResponse,
  GeoLocationResponse,
  PaginatedResponse,
  TokenResponse,
  User,
} from '@/types';
import apiClient from '../lib/api';

// ── Query Keys ────────────────────────────────────────────────────────────────
export const queryKeys = {
  me: ['me'] as const,
  analyses: (params?: Record<string, unknown>) => ['analyses', params] as const,
  analysis: (id: string) => ['analysis', id] as const,
  campaignGraph: (params?: Record<string, unknown>) => ['campaignGraph', params] as const,
  enrichment: (indicator: string, type: string) => ['enrichment', indicator, type] as const,
  geolocation: (ip: string) => ['geolocation', ip] as const,
};

// ── Auth ──────────────────────────────────────────────────────────────────────
export function useMe() {
  return useQuery({
    queryKey: queryKeys.me,
    queryFn: () => apiClient.get<User>('/auth/me').then((r) => r.data),
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; password: string }) =>
      apiClient.post<TokenResponse>('/auth/login', data).then((r) => r.data),
    onSuccess: (data) => {
      qc.setQueryData(queryKeys.me, data.user);
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiClient.post('/auth/logout'),
    onSuccess: () => {
      qc.clear();
    },
  });
}

export function useGoogleOAuthURL() {
  return useQuery({
    queryKey: ['googleOAuthUrl'],
    queryFn: () =>
      apiClient.get<{ authorization_url: string; state: string }>('/auth/google').then((r) => r.data),
    enabled: false,
  });
}

// ── Email Analyses ────────────────────────────────────────────────────────────

export interface AnalysisFilters {
  page?: number;
  page_size?: number;
  status?: string;
  severity?: string;
  threat_category?: string;
  search?: string;
  [key: string]: unknown;
}

export function useAnalyses(filters: AnalysisFilters = {}) {
  return useQuery({
    queryKey: queryKeys.analyses(filters),
    queryFn: () =>
      apiClient
        .get<PaginatedResponse<EmailAnalysisSummary>>('/emails/', { params: filters })
        .then((r) => r.data),
    staleTime: 30 * 1000,
  });
}

export function useAnalysis(id: string) {
  return useQuery({
    queryKey: queryKeys.analysis(id),
    queryFn: () => apiClient.get<EmailAnalysisDetail>(`/emails/${id}`).then((r) => r.data),
    enabled: !!id,
  });
}

export function useUploadEmail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ file, notes, priority }: { file: File; notes?: string; priority?: string }) => {
      const fd = new FormData();
      fd.append('file', file);
      if (notes) fd.append('notes', notes);
      if (priority) fd.append('priority', priority);
      return apiClient
        .post<AnalysisTriggerResponse>('/emails/upload', fd, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
        .then((r) => r.data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analyses'] });
    },
  });
}

export function useDeleteAnalysis() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiClient.delete(`/emails/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analyses'] });
    },
  });
}

// ── Threat Intel ──────────────────────────────────────────────────────────────

export function useEnrichIndicator(indicator: string, type: string, enabled = false) {
  return useQuery({
    queryKey: queryKeys.enrichment(indicator, type),
    queryFn: () =>
      apiClient
        .post<EnrichmentResponse>('/intel/enrich', { indicator, indicator_type: type })
        .then((r) => r.data),
    enabled: enabled && !!indicator,
  });
}

export function useGeolocate(ip: string, enabled = false) {
  return useQuery({
    queryKey: queryKeys.geolocation(ip),
    queryFn: () =>
      apiClient
        .post<GeoLocationResponse>('/geo/locate', { ip_address: ip })
        .then((r) => r.data),
    enabled: enabled && !!ip,
  });
}

// ── Campaign Graph ────────────────────────────────────────────────────────────

export function useCampaignGraph(params: { analysis_id?: string; campaign_id?: string; depth?: number }) {
  return useQuery({
    queryKey: queryKeys.campaignGraph(params),
    queryFn: () =>
      apiClient.get<CampaignGraphResponse>('/graph/campaign', { params }).then((r) => r.data),
    enabled: !!(params.analysis_id || params.campaign_id),
  });
}
