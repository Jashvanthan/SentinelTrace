import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';

export interface GmailConnection {
  id: string;
  email_address: string;
  status: 'ACTIVE' | 'ERROR' | 'DISCONNECTED' | 'NOT_CONNECTED' | 'QUEUED';
  monitoring_enabled: boolean;
  analysis_mode: 'AUTO' | 'MANUAL';
  last_sync_at: string | null;
  error_message: string | null;
  emails_fetched: number;
  emails_analyzed: number;
  workspace_id?: string;
}

export interface GmailConfigUpdatePayload {
  monitoring_enabled?: boolean;
  analysis_mode?: 'AUTO' | 'MANUAL';
}

export const integrationsApi = {
  getGmailConnection: async (workspaceId: string): Promise<GmailConnection | null> => {
    try {
      const { data } = await api.get(`/workspaces/${workspaceId}/integrations/gmail`);
      return data;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      throw e;
    }
  },

  updateGmailConfig: async (workspaceId: string, payload: GmailConfigUpdatePayload): Promise<GmailConnection> => {
    const { data } = await api.patch(`/workspaces/${workspaceId}/integrations/gmail/config`, payload);
    return data;
  },
  
  syncGmail: async (workspaceId: string) => {
    const { data } = await api.post(`/workspaces/${workspaceId}/integrations/gmail/sync`);
    return data;
  },

  disconnectGmail: async (workspaceId: string) => {
    const { data } = await api.post(`/workspaces/${workspaceId}/integrations/gmail/disconnect`);
    return data;
  },

  getConnectUrl: async (workspaceId: string): Promise<string> => {
    const { data } = await api.get(`/workspaces/${workspaceId}/integrations/gmail/connect`);
    return data.authorization_url;
  }
};

export function useGmailConnection(workspaceId: string | null) {
  return useQuery({
    queryKey: ['gmail_connection', workspaceId],
    queryFn: () => integrationsApi.getGmailConnection(workspaceId!),
    enabled: !!workspaceId,
  });
}

export function useUpdateGmailConfig(workspaceId: string | null) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: GmailConfigUpdatePayload) =>
      integrationsApi.updateGmailConfig(workspaceId!, payload),
    onSuccess: (updatedData) => {
      queryClient.setQueryData(['gmail_connection', workspaceId], updatedData);
      queryClient.invalidateQueries({ queryKey: ['gmail_connection', workspaceId] });
      queryClient.invalidateQueries({ queryKey: ['workspace-stats', workspaceId] });
    },
  });
}

export function useSyncGmail(workspaceId: string | null) {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: () => integrationsApi.syncGmail(workspaceId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gmail_connection', workspaceId] });
      queryClient.invalidateQueries({ queryKey: ['analyses'] });
      queryClient.invalidateQueries({ queryKey: ['workspace-stats'] });
      queryClient.invalidateQueries({ queryKey: ['threat-summary'] });
      queryClient.invalidateQueries({ queryKey: ['iocs'] });
    }
  });
}

