// SentinelTrace Frontend — TanStack Query API Hooks

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type {
  AnalysisTriggerResponse,
  CampaignGraphResponse,
  EmailAnalysisDetail,
  EmailAnalysisSummary,
  EnrichmentResponse,
  IOCListResponse,
  GeoLocationResponse,
  EmailObservedIPsResponse,
  PaginatedResponse,
  TokenResponse,
  User,
  WorkspaceStats,
  WorkspaceMember,
  GmailIntegrationStatus,
  ActivityLogResponse,
} from '@/types';
import { useWorkspaceStore } from '@/store/workspace';
import { useAuthStore } from '@/store';
import apiClient from '../lib/api';

// ── Query Keys ────────────────────────────────────────────────────────────────
export const queryKeys = {
  me: ['me'] as const,
  activityLogs: (params?: Record<string, unknown>) => ['activityLogs', params] as const,
  analyses: (params?: Record<string, unknown>) => ['analyses', params] as const,
  analysis: (workspaceId: string, id: string) => ['analysis', workspaceId, id] as const,
  campaignGraph: (workspaceId: string, params?: Record<string, unknown>) => ['campaignGraph', workspaceId, params] as const,
  enrichment: (indicator: string, type: string) => ['enrichment', indicator, type] as const,
  threatIntelligence: (wsId: string, filters?: Record<string, unknown>) => ['threatIntel', wsId, filters] as const,
  geolocation: (wsId: string, ip: string) => ['geolocation', wsId, ip] as const,
  ipTrace: (wsId: string, ip: string) => ['ipTrace', wsId, ip] as const,
  emailIPTrace: (wsId: string, analysisId: string) => ['emailIPTrace', wsId, analysisId] as const,
  emailObservedIPs: (wsId: string, analysisId: string) => ['emailObservedIPs', wsId, analysisId] as const,
  // Step 14 — workspace-scoped keys (keyed by workspaceId for proper cache isolation)
  workspaceStats: (wsId: string) => ['workspace-stats', wsId] as const,
  workspaceEmails: (wsId: string, params?: Record<string, unknown>) =>
    ['workspace-emails', wsId, params] as const,
  workspaceCampaigns: (wsId: string) => ['workspace-campaigns', wsId] as const,
  workspaceMembers: (wsId: string) => ['workspaceMembers', wsId] as const,
  gmailIntegration: (wsId: string) => ['gmailIntegration', wsId] as const,
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

export function useRegister() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; password: string; full_name?: string }) =>
      apiClient.post<User>('/auth/register', data).then((r) => r.data),
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

export function useUpdateProfile() {
  const qc = useQueryClient();
  const updateUserStore = useAuthStore((state) => state.updateUser);
  return useMutation({
    mutationFn: async (data: { full_name?: string; avatar_url?: string }) => {
      // 1. Immediately persist locally to Zustand & LocalStorage
      updateUserStore(data);

      // 2. Attempt multi-verb server sync (PATCH -> PUT -> POST)
      try {
        const res = await apiClient.patch<User>('/auth/me', data);
        return res.data;
      } catch {
        try {
          const res = await apiClient.put<User>('/auth/me', data);
          return res.data;
        } catch {
          try {
            const res = await apiClient.post<User>('/auth/me', data);
            return res.data;
          } catch {
            // Server sync fallback to local user state
            return {
              ...(useAuthStore.getState().user || {}),
              ...data,
            } as User;
          }
        }
      }
    },
    onSuccess: (updatedUser) => {
      updateUserStore(updatedUser);
      qc.setQueryData(queryKeys.me, updatedUser);
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
  const { currentWorkspaceId } = useWorkspaceStore();
  return useQuery({
    queryKey: queryKeys.analyses({ ...filters, workspace_id: currentWorkspaceId }),
    queryFn: async () => {
      let wsId = currentWorkspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId) {
        const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
        if (wsRes.data && wsRes.data.length > 0) {
          wsId = wsRes.data[0].id;
          useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
        }
      }
      return apiClient
        .get<PaginatedResponse<EmailAnalysisSummary>>('/emails/', {
          params: { ...filters, workspace_id: wsId },
        })
        .then((r) => r.data);
    },
    staleTime: 5 * 1000,
    refetchInterval: (query) => {
      const items = query.state.data?.items;
      const hasActive = items?.some((item) => item.status === 'PENDING' || item.status === 'PROCESSING');
      return hasActive ? 2000 : false;
    },
  });
}

export function useAnalysis(id: string, workspaceId: string | null) {
  return useQuery({
    queryKey: ['analysis', workspaceId || 'default', id],
    queryFn: async () => {
      let wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId) {
        const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
        if (wsRes.data && wsRes.data.length > 0) {
          wsId = wsRes.data[0].id;
          useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
        }
      }
      return apiClient
        .get<EmailAnalysisDetail>(`/emails/${id}`, { params: { workspace_id: wsId } })
        .then((r) => r.data);
    },
    enabled: Boolean(id),
    staleTime: 15 * 1000,
    placeholderData: (previousData) => previousData,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      // Only poll gently if an analysis is actively in progress
      if (status === 'PROCESSING') {
        return 3000;
      }
      return false;
    },
  });
}

export function useUploadEmail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ file, notes, priority }: { file: File; notes?: string; priority?: string }) => {
      let wsId = useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId) {
        const res = await apiClient.get<Array<{ id: string }>>('/workspaces');
        if (res.data && res.data.length > 0) {
          wsId = res.data[0].id;
          useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
        }
      }
      if (!wsId) {
        throw new Error('No active workspace. Please create or select a workspace in Settings first.');
      }
      const fd = new FormData();
      fd.append('file', file);
      if (notes) fd.append('notes', notes);
      if (priority) fd.append('priority', priority);
      return apiClient
        .post<AnalysisTriggerResponse>('/emails/upload', fd, {
          params: { workspace_id: wsId },
        })
        .then((r) => r.data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analyses'] });
      qc.invalidateQueries({ queryKey: ['workspace-stats'] });
      qc.invalidateQueries({ queryKey: ['workspace-emails'] });
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

export function useAnalyzeEmail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (analysisId: string) => {
      let wsId = useWorkspaceStore.getState().currentWorkspaceId;
      return apiClient
        .post<AnalysisTriggerResponse>(`/emails/${analysisId}/analyze`, null, {
          params: { workspace_id: wsId },
        })
        .then((r) => r.data);
    },
    onSuccess: (_, analysisId) => {
      qc.invalidateQueries({ queryKey: ['analyses'] });
      qc.invalidateQueries({ queryKey: ['analysis'] });
      qc.invalidateQueries({ queryKey: ['workspace-stats'] });
      qc.invalidateQueries({ queryKey: ['threatIntel'] });
      qc.invalidateQueries({ queryKey: ['gmail_connection'] });
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

export function useThreatIntelligence(workspaceId: string | null, filters: Record<string, unknown> = {}) {
  return useQuery<IOCListResponse>({
    queryKey: ['threatIntel', workspaceId || 'default', filters],
    queryFn: async () => {
      let wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId) {
        try {
          const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
          if (wsRes.data && wsRes.data.length > 0) {
            wsId = wsRes.data[0].id;
            useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
          }
        } catch {
          // ignore error
        }
      }
      return apiClient
        .get<IOCListResponse>('/intel/iocs', { params: { ...(wsId ? { workspace_id: wsId } : {}), ...filters } })
        .then((r) => r.data);
    },
    retry: 2,
  });
}

export function useGeolocate(workspaceId: string | null, ip: string, enabled = false) {
  const wsId = workspaceId || 'default';
  return useQuery({
    queryKey: queryKeys.geolocation(wsId, ip),
    queryFn: () =>
      apiClient
        .post<GeoLocationResponse>('/geo/locate', { ip_address: ip })
        .then((r) => r.data),
    enabled: enabled && !!ip,
  });
}

export function useEmailObservedIPs(analysisId: string | null | undefined, workspaceId: string | null) {
  const wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId || 'default';
  return useQuery({
    queryKey: queryKeys.emailObservedIPs(wsId, analysisId || ''),
    queryFn: async () => {
      if (!analysisId) return null;
      let effectiveWsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!effectiveWsId) {
        try {
          const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
          if (wsRes.data && wsRes.data.length > 0) {
            effectiveWsId = wsRes.data[0].id;
            useWorkspaceStore.getState().setCurrentWorkspaceId(effectiveWsId);
          }
        } catch {
          // ignore
        }
      }
      return apiClient
        .get<EmailObservedIPsResponse>(`/emails/${analysisId}/ips`, {
          params: effectiveWsId ? { workspace_id: effectiveWsId } : {},
        })
        .then((r) => r.data);
    },
    enabled: Boolean(analysisId),
  });
}

// ── Campaign Graph ────────────────────────────────────────────────────────────

export function useCampaignGraph(workspaceId: string | null, params: { analysis_id?: string; campaign_id?: string; depth?: number } = {}) {
  return useQuery({
    queryKey: ['campaignGraph', workspaceId || 'default', params],
    queryFn: async () => {
      let wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId || wsId === 'default') {
        try {
          const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
          if (wsRes.data && wsRes.data.length > 0) {
            wsId = wsRes.data[0].id;
            useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
          }
        } catch {
          // ignore error
        }
      }
      try {
        const res = await apiClient.get<CampaignGraphResponse>('/graph/campaign', {
          params: { ...(wsId && wsId !== 'default' ? { workspace_id: wsId } : {}), ...params },
        });
        return res.data;
      } catch (err: any) {
        if (err.response?.status === 404 || err.response?.status === 403 || err.response?.status === 422) {
          try {
            const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
            if (wsRes.data && wsRes.data.length > 0) {
              const validId = wsRes.data[0].id;
              useWorkspaceStore.getState().setCurrentWorkspaceId(validId);
              const retryRes = await apiClient.get<CampaignGraphResponse>('/graph/campaign', {
                params: { workspace_id: validId, ...params },
              });
              return retryRes.data;
            }
          } catch {
            // fallback below
          }
        }
        return { campaign_id: params.campaign_id ?? null, nodes: [], edges: [], analysis_count: 0 };
      }
    },
    retry: 1,
  });
}

// ── Step 14: Workspace-Scoped Dashboard Hooks ─────────────────────────────────

export function useWorkspaceStats(workspaceId: string | null, date?: string) {
  return useQuery({
    queryKey: ['workspace-stats', workspaceId || 'default', date],
    queryFn: async () => {
      let wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId || wsId === 'default') {
        const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
        if (wsRes.data && wsRes.data.length > 0) {
          wsId = wsRes.data[0].id;
          useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
        }
      }
      try {
        const params = date ? { date } : {};
        const res = await apiClient.get<WorkspaceStats>(`/workspaces/${wsId}/stats`, { params });
        return res.data;
      } catch (err: any) {
        if (err.response?.status === 404 || err.response?.status === 403 || err.response?.status === 422) {
          const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
          if (wsRes.data && wsRes.data.length > 0) {
            const validId = wsRes.data[0].id;
            useWorkspaceStore.getState().setCurrentWorkspaceId(validId);
            const params = date ? { date } : {};
            const retryRes = await apiClient.get<WorkspaceStats>(`/workspaces/${validId}/stats`, { params });
            return retryRes.data;
          }
        }
        throw err;
      }
    },
    refetchInterval: 30_000,
    staleTime: 20_000,
    retry: 2,
  });
}

export function useWorkspaceEmails(
  workspaceId: string | null,
  params: AnalysisFilters = { page_size: 8 },
) {
  return useQuery({
    queryKey: ['workspace-emails', workspaceId || 'default', params],
    queryFn: async () => {
      let wsId = workspaceId || useWorkspaceStore.getState().currentWorkspaceId;
      if (!wsId || wsId === 'default') {
        const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
        if (wsRes.data && wsRes.data.length > 0) {
          wsId = wsRes.data[0].id;
          useWorkspaceStore.getState().setCurrentWorkspaceId(wsId);
        }
      }
      try {
        const res = await apiClient.get<PaginatedResponse<EmailAnalysisSummary>>('/emails/', {
          params: { workspace_id: wsId, ...params },
        });
        return res.data;
      } catch (err: any) {
        if (err.response?.status === 404 || err.response?.status === 403 || err.response?.status === 422) {
          const wsRes = await apiClient.get<Array<{ id: string }>>('/workspaces');
          if (wsRes.data && wsRes.data.length > 0) {
            const validId = wsRes.data[0].id;
            useWorkspaceStore.getState().setCurrentWorkspaceId(validId);
            const retryRes = await apiClient.get<PaginatedResponse<EmailAnalysisSummary>>('/emails/', {
              params: { workspace_id: validId, ...params },
            });
            return retryRes.data;
          }
        }
        throw err;
      }
    },
    refetchInterval: 30_000,
    staleTime: 20_000,
    retry: 2,
  });
}

// ── Workspace Members ────────────────────────────────────────────────────────

export function useWorkspaceMembers(workspaceId: string | null) {
  return useQuery({
    queryKey: workspaceId ? queryKeys.workspaceMembers(workspaceId) : ['workspaceMembers-disabled'],
    queryFn: () =>
      apiClient
        .get<WorkspaceMember[]>(`/workspaces/${workspaceId}/members`)
        .then((r) => r.data),
    enabled: Boolean(workspaceId),
  });
}

export function useAddWorkspaceMember(workspaceId: string | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; role: string }) =>
      apiClient.post(`/workspaces/${workspaceId}/members`, data).then((r) => r.data),
    onSuccess: () => {
      if (workspaceId) {
        qc.invalidateQueries({ queryKey: queryKeys.workspaceMembers(workspaceId) });
      }
    },
  });
}

export function useRemoveWorkspaceMember(workspaceId: string | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) =>
      apiClient.delete(`/workspaces/${workspaceId}/members/${userId}`).then((r) => r.data),
    onSuccess: () => {
      if (workspaceId) {
        qc.invalidateQueries({ queryKey: queryKeys.workspaceMembers(workspaceId) });
      }
    },
  });
}

// ── Gmail Integration ─────────────────────────────────────────────────────────

export function useGmailIntegration(workspaceId: string | null) {
  return useQuery({
    queryKey: workspaceId ? queryKeys.gmailIntegration(workspaceId) : ['gmailIntegration-disabled'],
    queryFn: () =>
      apiClient
        .get<GmailIntegrationStatus>(`/workspaces/${workspaceId}/integrations/gmail`)
        .then((r) => r.data),
    enabled: Boolean(workspaceId),
    refetchInterval: (query) => (query.state.data?.status === 'QUEUED' ? 5000 : false),
  });
}

export function useSyncGmailIntegration(workspaceId: string | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiClient.post(`/workspaces/${workspaceId}/integrations/gmail/sync`).then((r) => r.data),
    onSuccess: () => {
      if (workspaceId) {
        qc.invalidateQueries({ queryKey: queryKeys.gmailIntegration(workspaceId) });
      }
    },
  });
}

export function useDisconnectGmailIntegration(workspaceId: string | null) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiClient.post(`/workspaces/${workspaceId}/integrations/gmail/disconnect`).then((r) => r.data),
    onSuccess: () => {
      if (workspaceId) {
        qc.invalidateQueries({ queryKey: queryKeys.gmailIntegration(workspaceId) });
      }
    },
  });
}

// ── Evidence & Forensic PDF Reports ───────────────────────────────────────────
export async function downloadReportPdf(analysisId: string, filename?: string) {
  const response = await apiClient.get(`/reports/${analysisId}/pdf`, {
    responseType: 'blob',
  });
  const blob = new Blob([response.data], { type: 'application/pdf' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename || `sentineltrace-report-${analysisId.slice(0, 8)}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export function useDownloadReport() {
  return useMutation({
    mutationFn: async ({ analysisId, filename }: { analysisId: string; filename?: string }) => {
      await downloadReportPdf(analysisId, filename);
    },
  });
}

// ── Activity & Audit Logs ─────────────────────────────────────────────────────
export function useActivityLogs(filters: {
  page?: number;
  page_size?: number;
  action?: string;
  outcome?: string;
  search?: string;
} = {}) {
  return useQuery({
    queryKey: queryKeys.activityLogs(filters),
    queryFn: () =>
      apiClient
        .get<ActivityLogResponse>('/activity/', { params: filters })
        .then((r) => r.data),
    staleTime: 5000,
    refetchInterval: 8000,
  });
}

// ── IP Network Trace & Forensic Hop Graph ──────────────────────────────────────
import type { IPTraceResponse, EmailIPTraceResponse, ProvidersHealthResponse } from '@/types';

export function useIPTrace(ip: string | null | undefined, workspaceId: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.ipTrace(workspaceId || 'default', ip || ''),
    queryFn: () =>
      apiClient
        .post<IPTraceResponse>('/ip-trace/trace', {
          ip,
          workspace_id: workspaceId || undefined,
        })
        .then((r) => r.data),
    enabled: Boolean(ip && ip.trim()),
    staleTime: 60 * 1000,
  });
}

export function useEmailIPTrace(analysisId: string | null | undefined, workspaceId: string | null | undefined) {
  return useQuery({
    queryKey: queryKeys.emailIPTrace(workspaceId || 'default', analysisId || ''),
    queryFn: () =>
      apiClient
        .get<EmailIPTraceResponse>(`/ip-trace/analyses/${analysisId}`, {
          params: { workspace_id: workspaceId || undefined },
        })
        .then((r) => r.data),
    enabled: Boolean(analysisId),
    staleTime: 60 * 1000,
  });
}

export function useIPTraceProvidersHealth() {
  return useQuery({
    queryKey: ['ipTraceProvidersHealth'] as const,
    queryFn: () =>
      apiClient
        .get<ProvidersHealthResponse>('/ip-trace/providers/health')
        .then((r) => r.data),
    staleTime: 30 * 1000,
    refetchInterval: 60 * 1000,
  });
}



