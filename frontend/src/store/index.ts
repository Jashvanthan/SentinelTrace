// SentinelTrace Frontend — Zustand Auth Store

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User } from '@/types';
import { setAccessToken } from '@/lib/api';

const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  accessToken: string | null;
  sessionExpiresAt: number | null; // Unix timestamp (ms) when 24h session expires

  setAuth: (user: User, token: string, sessionExpiresInSeconds?: number) => void;
  clearAuth: () => void;
  updateUser: (user: Partial<User>) => void;
  isSessionExpired: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      accessToken: null,
      sessionExpiresAt: null,

      setAuth: (user, token, sessionExpiresInSeconds) => {
        setAccessToken(token);
        const expiresAt = sessionExpiresInSeconds
          ? Date.now() + sessionExpiresInSeconds * 1000
          : Date.now() + TWENTY_FOUR_HOURS_MS;
        set({
          user,
          isAuthenticated: true,
          accessToken: token,
          sessionExpiresAt: expiresAt,
        });
      },

      clearAuth: () => {
        setAccessToken(null);
        set({
          user: null,
          isAuthenticated: false,
          accessToken: null,
          sessionExpiresAt: null,
        });
      },

      updateUser: (partial) =>
        set((state) => ({
          user: state.user ? { ...state.user, ...partial } : null,
        })),

      isSessionExpired: () => {
        const state = get();
        if (!state.isAuthenticated) return false;
        if (!state.sessionExpiresAt) return false;
        return Date.now() >= state.sessionExpiresAt;
      },
    }),
    {
      name: 'sentineltrace-auth',
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
        accessToken: state.accessToken,
        sessionExpiresAt: state.sessionExpiresAt,
      }),
      onRehydrateStorage: () => (state) => {
        if (!state) return;
        // Automatically purge session if 24 hours have elapsed
        if (state.sessionExpiresAt && Date.now() >= state.sessionExpiresAt) {
          state.clearAuth();
          return;
        }
        if (state.accessToken) {
          setAccessToken(state.accessToken);
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
