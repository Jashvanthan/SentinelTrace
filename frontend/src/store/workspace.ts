import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { Workspace } from '@/api/workspaces';

interface WorkspaceState {
  currentWorkspaceId: string | null;
  setCurrentWorkspaceId: (id: string | null) => void;
  clearWorkspace: () => void;
}

export const useWorkspaceStore = create<WorkspaceState>()(
  persist(
    (set) => ({
      currentWorkspaceId: null,
      setCurrentWorkspaceId: (id) => set({ currentWorkspaceId: id }),
      clearWorkspace: () => set({ currentWorkspaceId: null }),
    }),
    {
      name: 'sentineltrace-workspace',
      // Persisting the workspace ID is safe and improves UX, 
      // but authorization is strictly enforced by the backend using this ID.
    }
  )
);
