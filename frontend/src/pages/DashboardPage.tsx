// SentinelTrace Frontend — Dashboard Page (SOC Reference UI)

import { useMemo, useEffect } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  Clock,
  Mail,
  Network,
  Shield,
  ShieldAlert,
  Target,
  TrendingUp,
  Calendar,
  ChevronRight
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useWorkspaceStats } from '@/api/hooks';
import { useWorkspaceStore } from '@/store';
import { useWorkspaces } from '@/api/workspaces';
import { StatCard } from '@/components/dashboard/StatCard';
import { StatusBadge } from '@/components/threats/SeverityBadge';
import { formatRelativeTime } from '@/utils';

export function DashboardPage() {
  const { currentWorkspaceId, setCurrentWorkspaceId } = useWorkspaceStore();
  const { data: workspaces } = useWorkspaces();

  useEffect(() => {
    if (workspaces && workspaces.length > 0) {
      const isValid = workspaces.some((w) => w.id === currentWorkspaceId);
      if (!currentWorkspaceId || !isValid) {
        setCurrentWorkspaceId(workspaces[0].id);
      }
    }
  }, [workspaces, currentWorkspaceId, setCurrentWorkspaceId]);

  const currentWorkspace = useMemo(
    () => workspaces?.find((w) => w.id === currentWorkspaceId) || workspaces?.[0],
    [workspaces, currentWorkspaceId],
  );

  const activeWorkspaceId = currentWorkspace?.id || currentWorkspaceId;

  const {
    data: stats,
    isLoading,
    isError,
    dataUpdatedAt,
  } = useWorkspaceStats(activeWorkspaceId);

  if (!currentWorkspaceId) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <Shield className="w-10 h-10 text-[hsl(var(--foreground-subtle))]" />
        <p className="text-sm text-[hsl(var(--foreground-muted))] font-mono">
          Select a workspace to view the security overview.
        </p>
      </div>
    );
  }

  // Calculate risk distribution percentages from actual stats
  const totalScanned = stats?.total_emails_scanned ?? 0;
  const criticalCount = stats?.recent_emails?.filter((e) => e.severity === 'CRITICAL').length || 0;
  const highCount = stats?.recent_emails?.filter((e) => e.severity === 'HIGH').length || 0;
  const mediumCount = stats?.recent_emails?.filter((e) => e.severity === 'MEDIUM').length || 0;
  const lowCount = stats?.recent_emails?.filter((e) => e.severity === 'INFO' || e.severity === 'LOW').length || 0;
  const totalRecent = criticalCount + highCount + mediumCount + lowCount;

  const critPct = totalRecent > 0 ? Math.round((criticalCount / totalRecent) * 100) : 0;
  const highPct = totalRecent > 0 ? Math.round((highCount / totalRecent) * 100) : 0;
  const medPct = totalRecent > 0 ? Math.round((mediumCount / totalRecent) * 100) : 0;
  const lowPct = totalRecent > 0 ? Math.max(0, 100 - critPct - highPct - medPct) : 0;

  return (
    <div className="space-y-6">
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Security Overview
          </h1>
          <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
            Real-time threat monitoring and active investigations.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/emails"
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#3b82f6] hover:bg-[#2563eb] text-white text-xs font-mono font-medium rounded transition-colors"
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Analyze Email</span>
          </Link>
          <div className="flex items-center gap-2 bg-[#121824] border border-[#232e42] rounded px-3 py-1.5 text-xs text-[hsl(var(--foreground-muted))] font-mono">
            <Calendar className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))]" />
            <span>Last 24 Hours</span>
          </div>
        </div>
      </div>

      {/* Error State */}
      {isError && !isLoading && (
        <div className="flex items-center gap-3 p-3 rounded bg-red-950/40 border border-red-800/40 text-xs text-red-400 font-mono">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>Could not sync real-time workspace metrics. Retrying connection...</span>
        </div>
      )}

      {/* ── Top Metric Cards ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="EMAILS ANALYZED"
          value={isLoading ? undefined : (stats?.total_emails_scanned ?? 0).toLocaleString()}
          icon={Mail}
          variant="default"
          isLoading={isLoading}
        />
        <StatCard
          title="THREATS DETECTED"
          value={isLoading ? undefined : (stats?.threats_detected ?? 0).toLocaleString()}
          icon={ShieldAlert}
          variant={stats?.threats_detected ? 'high' : 'default'}
          isLoading={isLoading}
        />
        <StatCard
          title="CRITICAL CASES"
          value={isLoading ? undefined : (criticalCount > 0 ? criticalCount : stats?.active_campaigns ?? 0)}
          badgeText={criticalCount > 0 ? 'Requires Action' : undefined}
          icon={AlertTriangle}
          variant={criticalCount > 0 ? 'critical' : 'default'}
          isLoading={isLoading}
        />
        <StatCard
          title="AVG RISK SCORE"
          value={
            isLoading
              ? undefined
              : stats?.average_threat_score !== null && stats?.average_threat_score !== undefined
              ? `${Math.round(stats.average_threat_score)} /100`
              : '0 /100'
          }
          icon={TrendingUp}
          variant={
            stats?.average_threat_score && stats.average_threat_score >= 70
              ? 'critical'
              : stats?.average_threat_score && stats.average_threat_score >= 40
              ? 'medium'
              : 'default'
          }
          isLoading={isLoading}
        />
      </div>

      {/* ── Lower Section Grid: Risk Distribution + Active Investigations ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Card */}
        <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide">
              Risk Distribution
            </h2>

            <div className="mt-6 space-y-4 font-mono text-xs">
              <div className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-red-400 font-bold">CRITICAL</span>
                  <span className="text-[hsl(var(--foreground-muted))]">{critPct}%</span>
                </div>
                <div className="h-2 w-full bg-[#182030] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full transition-all duration-300"
                    style={{ width: `${critPct}%` }}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-orange-400 font-bold">HIGH</span>
                  <span className="text-[hsl(var(--foreground-muted))]">{highPct}%</span>
                </div>
                <div className="h-2 w-full bg-[#182030] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full transition-all duration-300"
                    style={{ width: `${highPct}%` }}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-blue-400 font-bold">MEDIUM</span>
                  <span className="text-[hsl(var(--foreground-muted))]">{medPct}%</span>
                </div>
                <div className="h-2 w-full bg-[#182030] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-blue-500 rounded-full transition-all duration-300"
                    style={{ width: `${medPct}%` }}
                  />
                </div>
              </div>

              <div className="space-y-1">
                <div className="flex justify-between text-[11px]">
                  <span className="text-slate-400 font-bold">LOW</span>
                  <span className="text-[hsl(var(--foreground-muted))]">{lowPct}%</span>
                </div>
                <div className="h-2 w-full bg-[#182030] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-slate-500 rounded-full transition-all duration-300"
                    style={{ width: `${lowPct}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Active Investigations Table */}
        <div className="lg:col-span-2 bg-[#121824] border border-[#232e42] rounded-md p-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#1f2a3e]">
            <h2 className="text-sm font-semibold text-white tracking-wide">
              Active Investigations
            </h2>
            <Link
              to="/emails"
              aria-label="View all email analyses"
              className="text-xs text-[#3b82f6] hover:underline font-mono flex items-center gap-1"
            >
              <span>View all email analyses</span>
              <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="overflow-x-auto mt-3">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#1f2a3e] text-[10px] uppercase font-mono text-[hsl(var(--foreground-subtle))] tracking-wider">
                  <th className="py-2.5 px-3">CASE ID</th>
                  <th className="py-2.5 px-3">SUBJECT / ENTITY</th>
                  <th className="py-2.5 px-3">RISK SCORE</th>
                  <th className="py-2.5 px-3">STATUS</th>
                  <th className="py-2.5 px-3 text-right">TIMESTAMP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182030] text-xs font-mono">
                {isLoading ? (
                  Array.from({ length: 4 }).map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      <td className="py-3 px-3"><div className="h-4 w-24 bg-[#182030] rounded" /></td>
                      <td className="py-3 px-3"><div className="h-4 w-40 bg-[#182030] rounded" /></td>
                      <td className="py-3 px-3"><div className="h-4 w-12 bg-[#182030] rounded" /></td>
                      <td className="py-3 px-3"><div className="h-4 w-20 bg-[#182030] rounded" /></td>
                      <td className="py-3 px-3 text-right"><div className="h-4 w-16 bg-[#182030] rounded ml-auto" /></td>
                    </tr>
                  ))
                ) : stats?.recent_emails && stats.recent_emails.length > 0 ? (
                  stats.recent_emails.slice(0, 5).map((email, idx) => {
                    const score = Math.round(email.threat_score ?? 50);
                    const dotColor = score >= 75 ? 'bg-red-500' : score >= 50 ? 'bg-orange-500' : score >= 25 ? 'bg-blue-500' : 'bg-slate-400';
                    const caseId = `#ST-2026-${(1000 + idx).toString().padStart(4, '0')}`;
                    return (
                      <tr key={email.id} className="hover:bg-[#161c2b] transition-colors cursor-pointer" onClick={() => window.location.href = `/emails/${email.id}`}>
                        <td className="py-3 px-3 text-white font-bold">{caseId}</td>
                        <td className="py-3 px-3 text-[hsl(var(--foreground))] truncate max-w-[200px]">
                          {email.subject || email.sender_email || 'Email Forensic Trace'}
                        </td>
                        <td className="py-3 px-3">
                          <div className="flex items-center gap-1.5 font-bold">
                            <span>{score}</span>
                            <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                          </div>
                        </td>
                        <td className="py-3 px-3">
                          <StatusBadge status={email.status || 'INVESTIGATING'} />
                        </td>
                        <td className="py-3 px-3 text-right text-[hsl(var(--foreground-muted))]">
                          {formatRelativeTime(email.created_at)}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-[hsl(var(--foreground-muted))] font-mono text-xs">
                      No active investigations found in this workspace.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

