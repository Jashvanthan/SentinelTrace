// SentinelTrace Frontend — Zustand Auth Store

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User } from '@/types';
import { setAccessToken } from '@/lib/api';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  accessToken: string | null;

  setAuth: (user: User, token: string) => void;
  clearAuth: () => void;
  updateUser: (user: Partial<User>) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      accessToken: null,

      setAuth: (user, token) => {
        setAccessToken(token);
        set({ user, isAuthenticated: true, accessToken: token });
      },

      clearAuth: () => {
        setAccessToken(null);
        set({ user: null, isAuthenticated: false, accessToken: null });
      },

      updateUser: (partial) =>
        set((state) => ({
          user: state.user ? { ...state.user, ...partial } : null,
        })),
    }),
    {
      name: 'sentineltrace-auth',
      // Only persist user, not token (token lives in memory)
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
      onRehydrateStorage: () => (state) => {
        // On page reload, access token is gone — clear auth to force re-login via refresh cookie
        if (state) {
          state.accessToken = null;
          setAccessToken(null);
        }
      },
    }
  )
);

// ── UI Store ──────────────────────────────────────────────────────────────────

interface UIState {
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  toggleSidebar: () => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
}));

// ── Notifications Store ───────────────────────────────────────────────────────

export type NotificationType = 'success' | 'error' | 'warning' | 'info';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  description?: string;
  duration?: number;
}

interface NotificationState {
  notifications: Notification[];
  addNotification: (n: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
}

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],
  addNotification: (n) => {
    const id = crypto.randomUUID();
    set((state) => ({
      notifications: [...state.notifications, { ...n, id }],
    }));
    // Auto-dismiss after duration
    if (n.duration !== 0) {
      setTimeout(() => {
        set((state) => ({
          notifications: state.notifications.filter((notif) => notif.id !== id),
        }));
      }, n.duration ?? 5000);
    }
  },
  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
}));

export * from './workspace';
