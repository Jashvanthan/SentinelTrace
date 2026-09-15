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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const logout = useLogout();
  const { currentWorkspaceId } = useWorkspaceStore();
  const { connectionState } = useRealtimeEvents(currentWorkspaceId);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean | null>(null);

  useEffect(() => {
    checkHealth().then(setIsBackendConnected);
  }, []);

  // Close mobile drawer on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout.mutateAsync();
    useAuthStore.getState().clearAuth();
    useWorkspaceStore.getState().clearWorkspace();
    navigate('/login');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#090d16] text-[#f1f5f9]">
      {/* ── MOBILE DRAWER BACKDROP ─────────────────────────────────────────── */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-xs z-40 md:hidden transition-opacity"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* ── MOBILE DRAWER NAVIGATION (Slide-in on small screens) ───────────── */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-64 bg-[#090d16] border-r border-[#232e42] shadow-2xl flex flex-col md:hidden',
          'transition-transform duration-200 ease-in-out',
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Mobile Header in Drawer */}
        <div className="flex items-center justify-between px-4 h-16 border-b border-[#232e42] bg-[#0d121d]">
          <div className="flex items-center gap-2.5">
            <img
              src="/sentineltrace-logo.jpg"
              alt="SentinelTrace"
              className="h-8 w-8 rounded object-cover border border-[#232e42]"
            />
            <div className="flex flex-col min-w-0">
              <span className="font-bold text-white text-2xl tracking-tight leading-none">
                SentinelTrace
              </span>
              <span className="text-[9px] uppercase font-medium tracking-wider text-[#64748b] mt-1 font-mono">
                CYBERSECURITY PLATFORM
              </span>
            </div>
          </div>
          <button
            onClick={() => setMobileMenuOpen(false)}
            className="p-1.5 rounded text-[#94a3b8] hover:text-white hover:bg-[#121824] border border-transparent hover:border-[#232e42] transition-colors cursor-pointer"
            title="Close menu"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
        </div>

        {/* Mobile Primary Action: + New Investigation */}
        <div className="p-3 border-b border-[#232e42]">
          <button
            onClick={() => {
              setMobileMenuOpen(false);
              navigate('/investigate');
            }}
            className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold tracking-wide transition-colors shadow-sm cursor-pointer"
          >
            <Plus className="w-4 h-4 flex-shrink-0" />
            <span>New Investigation</span>
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 overflow-y-auto py-3 space-y-0.5 px-2">
          {NAV_ITEMS.map((item) => (
            <SidebarNavItem
              key={item.path}
              item={item}
              collapsed={false}
              onNavigate={() => setMobileMenuOpen(false)}
            />
          ))}

          <div className="my-2 border-t border-[#232e42]" />

          {UTILITY_ITEMS.map((item) => (
            <SidebarNavItem
              key={item.path}
              item={item}
              collapsed={false}
              onNavigate={() => setMobileMenuOpen(false)}
            />
          ))}
        </nav>

        {/* Drawer Bottom Actions */}
        <div className="border-t border-[#232e42] p-2 space-y-1">
          <button
            onClick={() => {
              setMobileMenuOpen(false);
              navigate('/help');
            }}
            className={cn(
              "w-full flex items-center gap-3 px-3 py-2 rounded text-xs transition-colors cursor-pointer",
              location.pathname === '/help'
                ? "bg-[#1b2434] text-white font-semibold border-l-2 border-[#3b82f6]"
                : "text-[#94a3b8] hover:bg-[#121824] hover:text-white"
            )}
          >
            <HelpCircle className="w-4 h-4 flex-shrink-0 text-[#3b82f6]" />
            <span>Help Center</span>
          </button>

          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-2 rounded text-xs text-[#94a3b8] hover:bg-red-950/40 hover:text-red-400 transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4 flex-shrink-0" />
            <span>Log Out</span>
          </button>
        </div>
      </aside>

      {/* ── DESKTOP LEFT SIDEBAR ─────────────────────────────────────────── */}
      <aside
        className={cn(
          'hidden md:flex flex-col border-r border-[#232e42] bg-[#090d16]',
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
              <span className="font-bold text-white text-2xl tracking-tight leading-none">
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
            onClick={() => navigate('/help')}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2 rounded text-xs transition-colors cursor-pointer',
              location.pathname === '/help'
                ? 'bg-[#1b2434] text-white font-semibold border-l-2 border-[#3b82f6]'
                : 'text-[#94a3b8] hover:bg-[#121824] hover:text-white',
              !sidebarOpen && 'justify-center px-0'
            )}
            title="Help Center & User Guidelines"
          >
            <HelpCircle className="w-4 h-4 flex-shrink-0 text-[#3b82f6]" />
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
        {/* Top Header Bar — Increased Mobile Height (h-24 / 96px) for touch ergonomics */}
        <header className="flex items-center justify-between px-3.5 sm:px-4 md:px-6 h-24 md:h-14 border-b border-[#232e42] bg-[#0d121d] flex-shrink-0 gap-2.5">
          {/* Mobile Hamburger + Branding */}
          <div className="flex items-center gap-2.5 md:hidden">
            <button
              onClick={() => setMobileMenuOpen(true)}
              className="p-2 rounded-lg bg-[#121824] border border-[#232e42] text-[#94a3b8] hover:text-white hover:bg-[#1f2a3e] active:scale-95 transition-all shadow-xs cursor-pointer"
              title="Open navigation drawer"
            >
              <Menu className="w-5 h-5 text-white" />
            </button>
            <img
              src="/sentineltrace-logo.jpg"
              alt="SentinelTrace"
              className="h-8 w-8 rounded object-cover border border-[#232e42] shadow-xs"
            />
            <div className="flex flex-col min-w-0">
              <span className="font-bold text-white text-2xl tracking-tight leading-none">
                SentinelTrace
              </span>
              <span className="text-[8px] uppercase font-semibold tracking-wider text-[#3b82f6] font-mono mt-0.5">
                SOC PLATFORM
              </span>
            </div>
          </div>

          {/* Global Search Bar (hidden on small mobile screens, visible from sm up) */}
          <div className="hidden sm:flex items-center gap-4 flex-1 max-w-md">
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
          <div className="flex items-center gap-2 sm:gap-3 md:gap-4 ml-auto">
            <div className="hidden md:block">
              <WorkspaceSelector />
            </div>

            <div className="hidden md:block h-4 w-px bg-[#232e42]" />

            <div className="hidden sm:flex items-center gap-2">
              {connectionState === 'CONNECTED' ? (
                <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
              ) : (
                <span className="w-2 h-2 rounded-full bg-[#f97316]" />
              )}
              <span className="text-[11px] font-mono text-[#94a3b8] whitespace-nowrap">
                {connectionState === 'CONNECTED' ? 'LIVE SOC FEED' : 'RECONNECTING'}
              </span>
            </div>

            <div className="h-4 w-px bg-[#232e42]" />

            <button
              onClick={() => navigate('/settings')}
              className="flex items-center gap-1.5 sm:gap-2 text-xs font-mono text-[#94a3b8] hover:text-white px-1.5 sm:px-2 py-1 rounded-md hover:bg-[#121824] border border-transparent hover:border-[#232e42] transition-all cursor-pointer group"
              title="Account & Profile Settings"
            >
              {user?.avatar_url ? (
                <img
                  src={user.avatar_url}
                  alt="Profile"
                  className="w-7 h-7 sm:w-6 sm:h-6 rounded-full object-cover border border-[#3b82f6] group-hover:border-[#60a5fa] shadow-xs transition-colors"
                />
              ) : (
                <div className="w-7 h-7 sm:w-6 sm:h-6 rounded-full bg-[#121824] border border-[#232e42] group-hover:border-[#3b82f6] flex items-center justify-center text-slate-300 group-hover:text-white transition-colors">
                  <User className="w-4 h-4 sm:w-3.5 sm:h-3.5" />
                </div>
              )}
              <span className="hidden sm:inline truncate max-w-[120px] font-medium group-hover:text-white transition-colors">
                {user?.full_name || 'Analyst'}
              </span>
            </button>
          </div>
        </header>

        {/* Dynamic Page View */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-4 md:p-6 scrollable bg-[#090d16] overflow-x-hidden">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function SidebarNavItem({
  item,
  collapsed,
  onNavigate,
}: {
  item: NavItem;
  collapsed: boolean;
  onNavigate?: () => void;
}) {
  const Icon = item.icon;
  return (
    <NavLink
      to={item.path}
      onClick={onNavigate}
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

  useEffect(() => {
    if (workspaces && workspaces.length > 0) {
      const exists = workspaces.some((w) => w.id === currentWorkspaceId);
      if (!currentWorkspaceId || !exists) {
        setCurrentWorkspaceId(workspaces[0].id);
      }
    }
  }, [workspaces, currentWorkspaceId, setCurrentWorkspaceId]);

  const selectedId = currentWorkspaceId || workspaces?.[0]?.id || '';

  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <span className="text-[#64748b]">WS:</span>
      <select
        value={selectedId}
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
