import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';

export interface GmailConnection {
  id: string;
  email_address: string;
  status: 'ACTIVE' | 'ERROR' | 'DISCONNECTED';
  last_sync_at: string | null;
  error_message: string | null;
}

export const integrationsApi = {
  getGmailConnection: async (workspaceId: string): Promise<GmailConnection | null> => {
    try {
      const { data } = await api.get(`/api/v1/workspaces/${workspaceId}/integrations/gmail`);
      return data;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      throw e;
    }
  },
  
  syncGmail: async (workspaceId: string) => {
    const { data } = await api.post(`/api/v1/workspaces/${workspaceId}/integrations/gmail/sync`);
    return data;
  }
};

export function useGmailConnection(workspaceId: string | null) {
  return useQuery({
    queryKey: ['gmail_connection', workspaceId],
    queryFn: () => integrationsApi.getGmailConnection(workspaceId!),
    enabled: !!workspaceId,
  });
}

export function useSyncGmail(workspaceId: string | null) {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: () => integrationsApi.syncGmail(workspaceId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gmail_connection', workspaceId] });
    }
  });
}
