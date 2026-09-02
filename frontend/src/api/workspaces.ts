import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/lib/api';

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  role: 'owner' | 'admin' | 'analyst' | 'viewer';
}

export const workspacesApi = {
  listWorkspaces: async (): Promise<Workspace[]> => {
    const { data } = await api.get('/api/v1/workspaces');
    return data;
  },
  
  createWorkspace: async (name: string): Promise<Workspace> => {
    const { data } = await api.post('/api/v1/workspaces', { name });
    return data;
  }
};

export function useWorkspaces() {
  return useQuery({
    queryKey: ['workspaces'],
    queryFn: workspacesApi.listWorkspaces,
  });
}
