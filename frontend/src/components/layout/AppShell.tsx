// SentinelTrace Frontend — App Shell (Sidebar Layout)

import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  BarChart3, FileSearch, Globe, LayoutDashboard,
  LogOut, Mail, Menu, Network, Settings, Shield, ShieldAlert,
  User, Activity, FileText, Wifi, WifiOff, ChevronLeft, ChevronRight, Plug
} from 'lucide-react';
import { useAuthStore, useUIStore } from '@/store';
import { useLogout } from '@/api/hooks';
import { checkHealth } from '@/lib/api';
import { cn } from '@/utils';
import { useWorkspaces } from '@/api/workspaces';
import { useWorkspaceStore } from '@/store';

interface NavItem {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { label: 'Email Analysis', path: '/emails', icon: Mail },
  { label: 'Threat Intel', path: '/intel', icon: ShieldAlert },
  { label: 'Forensics', path: '/forensics', icon: FileSearch },
  { label: 'Campaign Graph', path: '/graph', icon: Network },
  { label: 'Geolocation', path: '/geo', icon: Globe },
  { label: 'Reports', path: '/reports', icon: FileText },
  { label: 'Activity Log', path: '/activity', icon: Activity },
];

const ADMIN_ITEMS: NavItem[] = [
  { label: 'Integrations', path: '/integrations', icon: Plug },
  { label: 'Settings', path: '/settings', icon: Settings },
];

export function AppShell() {
  const { user } = useAuthStore();
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const navigate = useNavigate();
  const logout = useLogout();
  const [isBackendConnected, setIsBackendConnected] = useState<boolean | null>(null);

  useEffect(() => {
    checkHealth().then(setIsBackendConnected);
  }, []);

  const handleLogout = async () => {
    await logout.mutateAsync();
    useAuthStore.getState().clearAuth();
    useWorkspaceStore.getState().clearWorkspace();
    navigate('/login');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[hsl(var(--background))]">
      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside
        className={cn(
          'flex flex-col border-r border-[hsl(var(--border))] bg-[hsl(var(--surface-1))]',
          'transition-all duration-300 ease-in-out flex-shrink-0',
          sidebarOpen ? 'w-60' : 'w-16',
          'relative'
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4 border-b border-[hsl(var(--border))]">
          <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-[hsl(var(--accent))] flex items-center justify-center">
            <Shield className="w-5 h-5 text-[hsl(var(--accent-foreground))]" />
          </div>
          {sidebarOpen && (
            <span className="font-bold text-[hsl(var(--foreground))] text-sm tracking-tight">
              SentinelTrace
            </span>
          )}
        </div>

        {/* Diagnostic Indicator */}
        {sidebarOpen && isBackendConnected !== null && (
          <div className="px-4 py-2 border-b border-[hsl(var(--border))] flex items-center justify-between text-xs">
            <span className="text-[hsl(var(--foreground-muted))]">Backend</span>
            {isBackendConnected ? (
              <span className="flex items-center gap-1.5 text-[hsl(var(--success))] font-medium">
                <Wifi className="w-3 h-3" />
                Online
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-[hsl(var(--critical))] font-medium">
                <WifiOff className="w-3 h-3" />
                Offline
              </span>
            )}
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 space-y-1 px-2">
          {NAV_ITEMS.map((item) => (
            <SidebarNavItem key={item.path} item={item} collapsed={!sidebarOpen} />
          ))}

          {user?.role === 'ADMIN' && (
            <>
              <div className={cn('px-2 py-2 mt-4', sidebarOpen && 'border-t border-[hsl(var(--border))]')}>
                {sidebarOpen && (
                  <span className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider px-2">
                    Admin
                  </span>
                )}
              </div>
              {ADMIN_ITEMS.map((item) => (
                <SidebarNavItem key={item.path} item={item} collapsed={!sidebarOpen} />
              ))}
            </>
          )}
        </nav>

        {/* User Profile + Logout */}
        <div className="border-t border-[hsl(var(--border))] p-3">
          <div className={cn('flex items-center gap-3', !sidebarOpen && 'justify-center')}>
            <div className="w-8 h-8 rounded-full bg-[hsl(var(--accent-subtle))] flex items-center justify-center flex-shrink-0">
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt={user.full_name} className="w-8 h-8 rounded-full object-cover" />
              ) : (
                <User className="w-4 h-4 text-[hsl(var(--accent))]" />
              )}
            </div>
            {sidebarOpen && (
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate">{user?.full_name}</p>
                <p className="text-xs text-[hsl(var(--foreground-subtle))] truncate">{user?.role}</p>
              </div>
            )}
            {sidebarOpen && (
              <button
                onClick={handleLogout}
                className="p-1.5 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--critical))] transition-colors"
                title="Logout"
              >
                <LogOut className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Collapse Toggle */}
        <button
          onClick={toggleSidebar}
          className="absolute -right-3 top-1/2 -translate-y-1/2 w-6 h-6 rounded-full
                     bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                     flex items-center justify-center hover:bg-[hsl(var(--surface-3))]
                     text-[hsl(var(--foreground-muted))] transition-colors z-10"
        >
          {sidebarOpen ? <ChevronLeft className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </button>
      </aside>

      {/* ── Main Content ─────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Bar */}
        <header className="flex items-center justify-between px-6 py-3 border-b border-[hsl(var(--border))] bg-[hsl(var(--surface-1))] flex-shrink-0">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              <button
                onClick={toggleSidebar}
                className="p-1.5 rounded hover:bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] md:hidden"
              >
                <Menu className="w-5 h-5" />
              </button>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[hsl(var(--low))] animate-pulse" />
                <span className="text-xs text-[hsl(var(--foreground-muted))]">System Online</span>
              </div>
            </div>
            
            {/* Workspace Selector */}
            <WorkspaceSelector />
            
          </div>
          <div className="flex items-center gap-3">
            <BarChart3 className="w-4 h-4 text-[hsl(var(--foreground-muted))]" />
            <span className="text-xs text-[hsl(var(--foreground-subtle))]">
              {new Date().toLocaleTimeString()}
            </span>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6 scrollable">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function SidebarNavItem({
  item,
  collapsed,
}: {
  item: NavItem;
  collapsed: boolean;
}) {
  const Icon = item.icon;
  return (
    <NavLink
      to={item.path}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-3 px-3 py-2 rounded-[var(--radius-sm)] text-sm',
          'transition-all duration-150 group',
          isActive
            ? 'bg-[hsl(var(--accent-subtle))] text-[hsl(var(--accent))] font-medium'
            : 'text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] hover:text-[hsl(var(--foreground))]',
          collapsed && 'justify-center px-2'
        )
      }
    >
      <Icon className={cn('w-4 h-4 flex-shrink-0', collapsed && 'w-5 h-5')} />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && item.badge !== undefined && (
        <span className="ml-auto text-xs bg-[hsl(var(--critical))] text-white rounded-full px-1.5 py-0.5 min-w-[20px] text-center">
          {item.badge}
        </span>
      )}
    </NavLink>
  );
}

function WorkspaceSelector() {
  const { data: workspaces, isLoading } = useWorkspaces();
  const { currentWorkspaceId, setCurrentWorkspaceId } = useWorkspaceStore();

  useEffect(() => {
    // Auto-select first workspace if none is selected and data is available
    if (!currentWorkspaceId && workspaces && workspaces.length > 0) {
      setCurrentWorkspaceId(workspaces[0].id);
    }
  }, [workspaces, currentWorkspaceId, setCurrentWorkspaceId]);

  if (isLoading) {
    return <div className="text-xs text-[hsl(var(--foreground-muted))] animate-pulse">Loading workspace...</div>;
  }

  if (!workspaces || workspaces.length === 0) {
    return <div className="text-xs text-[hsl(var(--warning))]">No workspace</div>;
  }

  const currentWs = workspaces.find(w => w.id === currentWorkspaceId) || workspaces[0];

  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-[hsl(var(--foreground-subtle))]">Workspace:</span>
      <select
        value={currentWorkspaceId || ''}
        onChange={(e) => setCurrentWorkspaceId(e.target.value)}
        className="bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded px-2 py-1 text-[hsl(var(--foreground))] outline-none focus:border-[hsl(var(--accent))] transition-colors"
      >
        {workspaces.map(ws => (
          <option key={ws.id} value={ws.id}>
            {ws.name} ({ws.role})
          </option>
        ))}
      </select>
    </div>
  );
}
