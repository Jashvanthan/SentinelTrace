// SentinelTrace Frontend — App Shell (Sidebar Layout matching SOC Reference UI)

import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  BarChart3, FileSearch, Globe, LayoutDashboard,
  LogOut, Mail, Menu, Network, Settings, Shield, ShieldAlert,
  User, Activity, FileText, Wifi, WifiOff, ChevronLeft, ChevronRight, Plug,
  Plus, Search, HelpCircle, FolderKanban, Layers
} from 'lucide-react';
import { useAuthStore, useUIStore } from '@/store';
import { useLogout } from '@/api/hooks';
import { checkHealth } from '@/lib/api';
import { cn } from '@/utils';
import { useWorkspaces } from '@/api/workspaces';
import { useWorkspaceStore } from '@/store';
import { useRealtimeEvents } from '@/api/realtime';

interface NavItem {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { label: 'Investigate', path: '/investigate', icon: Search },
  { label: 'Threat Intel', path: '/intel', icon: ShieldAlert },
  { label: 'Evidence', path: '/evidence', icon: FileSearch },
  { label: 'Campaigns', path: '/campaigns', icon: Network },
  { label: 'Reports', path: '/reports', icon: FileText },
];

const UTILITY_ITEMS: NavItem[] = [
  { label: 'Geolocation', path: '/geo', icon: Globe },
  { label: 'Activity Log', path: '/activity', icon: Activity },
  { label: 'Integrations', path: '/integrations', icon: Plug },
  { label: 'Settings', path: '/settings', icon: Settings },
];

export function AppShell() {
  const { user } = useAuthStore();
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const navigate = useNavigate();
  const logout = useLogout();
  const { currentWorkspaceId } = useWorkspaceStore();
  const { connectionState } = useRealtimeEvents(currentWorkspaceId);
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
    <div className="flex h-screen overflow-hidden bg-[#090d16] text-[#f1f5f9]">
      {/* ── LEFT SIDEBAR ────────────────────────────────────────────────── */}
      <aside
        className={cn(
          'flex flex-col border-r border-[#232e42] bg-[#090d16]',
          'transition-all duration-200 ease-in-out flex-shrink-0 z-20',
          sidebarOpen ? 'w-60' : 'w-16',
          'relative'
        )}
      >
        {/* Logo Section */}
        <div className="flex items-center gap-2 px-3 py-3 border-b border-[#232e42] overflow-hidden">
          <div className="flex-shrink-0">
            <img
              src="/sentineltrace-logo.jpg"
              alt="SentinelTrace"
              className={cn(
                'object-contain rounded transition-all duration-200',
                sidebarOpen ? 'h-9 w-auto' : 'h-8 w-8 rounded-md object-cover'
              )}
            />
          </div>
          {sidebarOpen && (
            <div className="flex flex-col min-w-0">
              <span className="font-bold text-white text-sm tracking-tight leading-none">
                SentinelTrace
              </span>
              <span className="text-[10px] uppercase font-medium tracking-wider text-[#64748b] mt-1 font-mono">
                CYBERSECURITY PLATFORM
              </span>
            </div>
          )}
        </div>

        {/* Primary Action Button: + New Investigation */}
        <div className="p-3 border-b border-[#232e42]">
          <button
            onClick={() => navigate('/investigate')}
            className={cn(
              'w-full flex items-center justify-center gap-2 py-2 px-3 rounded',
              'bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold tracking-wide',
              'transition-colors shadow-sm cursor-pointer',
              !sidebarOpen && 'px-0'
            )}
            title="New Investigation"
          >
            <Plus className="w-4 h-4 flex-shrink-0" />
            {sidebarOpen && <span>New Investigation</span>}
          </button>
        </div>

        {/* Navigation List */}
        <nav className="flex-1 overflow-y-auto py-3 space-y-0.5 px-2">
          {NAV_ITEMS.map((item) => (
            <SidebarNavItem key={item.path} item={item} collapsed={!sidebarOpen} />
          ))}

          <div className="my-2 border-t border-[#232e42]" />

          {UTILITY_ITEMS.map((item) => (
            <SidebarNavItem key={item.path} item={item} collapsed={!sidebarOpen} />
          ))}
        </nav>

        {/* Bottom Actions: Help Center & Log Out */}
        <div className="border-t border-[#232e42] p-2 space-y-1">
          <button
            onClick={() => navigate('/settings')}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2 rounded text-xs text-[#94a3b8] hover:bg-[#121824] hover:text-white transition-colors cursor-pointer',
              !sidebarOpen && 'justify-center px-0'
            )}
            title="Help Center"
          >
            <HelpCircle className="w-4 h-4 flex-shrink-0" />
            {sidebarOpen && <span>Help Center</span>}
          </button>

          <button
            onClick={handleLogout}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2 rounded text-xs text-[#94a3b8] hover:bg-red-950/40 hover:text-red-400 transition-colors cursor-pointer',
              !sidebarOpen && 'justify-center px-0'
            )}
            title="Log Out"
          >
            <LogOut className="w-4 h-4 flex-shrink-0" />
            {sidebarOpen && <span>Log Out</span>}
          </button>
        </div>

        {/* Collapse Toggle */}
        <button
          onClick={toggleSidebar}
          className="absolute -right-3 top-12 w-6 h-6 rounded-full
                     bg-[#121824] border border-[#232e42]
                     flex items-center justify-center hover:bg-[#161c2b]
                     text-[#94a3b8] hover:text-white transition-colors z-30 cursor-pointer"
        >
          {sidebarOpen ? <ChevronLeft className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </button>
      </aside>

      {/* ── MAIN CONTENT AREA ─────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#090d16]">
        {/* Top Header Bar */}
        <header className="flex items-center justify-between px-6 py-2.5 border-b border-[#232e42] bg-[#0d121d] flex-shrink-0">
          {/* Global Search Bar */}
          <div className="flex items-center gap-4 flex-1 max-w-md">
            <div className="relative w-full">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
              <input
                type="text"
                placeholder="Search IPs, Hashes, Cases..."
                className="w-full bg-[#121824] border border-[#232e42] rounded px-3 py-1.5 pl-9 text-xs text-white placeholder-[#64748b] outline-none focus:border-[#3b82f6] font-mono transition-colors"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && e.currentTarget.value.trim()) {
                    navigate(`/intel?q=${encodeURIComponent(e.currentTarget.value.trim())}`);
                  }
                }}
              />
            </div>
          </div>

          {/* Right Header Status & User Controls */}
          <div className="flex items-center gap-4">
            <WorkspaceSelector />

            <div className="h-4 w-px bg-[#232e42]" />

            <div className="flex items-center gap-2">
              {connectionState === 'CONNECTED' ? (
                <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
              ) : (
                <span className="w-2 h-2 rounded-full bg-[#f97316]" />
              )}
              <span className="text-xs font-mono text-[#94a3b8]">
                {connectionState === 'CONNECTED' ? 'LIVE SOC FEED' : 'RECONNECTING'}
              </span>
            </div>

            <div className="h-4 w-px bg-[#232e42]" />

            <div className="flex items-center gap-2 text-xs font-mono text-[#94a3b8]">
              {user?.avatar_url ? (
                <img
                  src={user.avatar_url}
                  alt="Profile"
                  className="w-5 h-5 rounded-full object-cover border border-[#3b82f6]"
                />
              ) : (
                <User className="w-3.5 h-3.5" />
              )}
              <span>{user?.full_name || 'Analyst'}</span>
            </div>
          </div>
        </header>

        {/* Dynamic Page View */}
        <main className="flex-1 overflow-y-auto p-6 scrollable bg-[#090d16]">
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
          'flex items-center gap-3 px-3 py-2 text-xs font-medium rounded transition-all duration-150 relative group',
          isActive
            ? 'bg-[#1b2434] text-white font-semibold border-l-2 border-[#3b82f6]'
            : 'text-[#94a3b8] hover:bg-[#121824] hover:text-white',
          collapsed && 'justify-center px-2'
        )
      }
    >
      <Icon className={cn('w-4 h-4 flex-shrink-0', collapsed && 'w-5 h-5')} />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && item.badge !== undefined && (
        <span className="ml-auto text-[10px] bg-red-950/80 text-red-400 border border-red-800/40 rounded px-1.5 py-0.2 font-mono">
          {item.badge}
        </span>
      )}
    </NavLink>
  );
}

function WorkspaceSelector() {
  const { data: workspaces, isLoading } = useWorkspaces();
  const { currentWorkspaceId, setCurrentWorkspaceId } = useWorkspaceStore();

  const activeWs = workspaces?.find((w) => w.id === currentWorkspaceId) || workspaces?.[0];

  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <span className="text-[#64748b]">WS:</span>
      <select
        value={currentWorkspaceId || ''}
        onChange={(e) => setCurrentWorkspaceId(e.target.value)}
        className="bg-[#121824] border border-[#232e42] rounded px-2.5 py-1 text-xs text-white focus:outline-none focus:border-[#3b82f6] cursor-pointer"
      >
        {workspaces?.map((w) => (
          <option key={w.id} value={w.id}>
            {w.name}
          </option>
        ))}
      </select>
    </div>
  );
}
