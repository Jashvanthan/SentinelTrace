// SentinelTrace Frontend — Activity & Audit Log Page

import { useState, useMemo } from 'react';
import {
  Activity, Search, Filter, RefreshCw, Download, CheckCircle2,
  XCircle, AlertOctagon, Users, Shield, Key, Mail, Brain,
  FileDown, Network, ChevronDown, ChevronRight, Copy, Check,
  Laptop, Globe, ExternalLink
} from 'lucide-react';
import { useActivityLogs } from '@/api/hooks';
import { formatDate } from '@/utils';
import type { ActivityLogItem } from '@/types';

export function ActivityLogPage() {
  const [search, setSearch] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { data, isLoading, refetch, isRefetching } = useActivityLogs({
    page: 1,
    page_size: 100,
    search: search ? search : undefined,
    outcome: outcomeFilter !== 'ALL' ? outcomeFilter : undefined,
    action: actionFilter !== 'ALL' ? actionFilter : undefined,
  });

  const logs = data?.items || [];
  const summary = data?.summary || {
    total_events: 0,
    success_count: 0,
    failure_count: 0,
    unique_users_count: 0,
    top_actions: {},
  };

  const handleCopyDetails = (id: string, details: unknown) => {
    navigator.clipboard.writeText(JSON.stringify(details, null, 2));
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(logs, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentineltrace-audit-logs-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const getActionIcon = (action: string) => {
    const act = action.toUpperCase();
    if (act.includes('LOGIN') || act.includes('AUTH') || act.includes('USER')) {
      return <Key className="w-4 h-4 text-emerald-400" />;
    }
    if (act.includes('EMAIL') || act.includes('UPLOAD')) {
      return <Mail className="w-4 h-4 text-sky-400" />;
    }
    if (act.includes('REPORT')) {
      return <FileDown className="w-4 h-4 text-purple-400" />;
    }
    if (act.includes('CAMPAIGN') || act.includes('GRAPH')) {
      return <Network className="w-4 h-4 text-indigo-400" />;
    }
    if (act.includes('INTEL') || act.includes('IOC')) {
      return <Brain className="w-4 h-4 text-amber-400" />;
    }
    return <Activity className="w-4 h-4 text-blue-400" />;
  };

  const formatActionName = (action: string) => {
    return action
      .replace(/_/g, ' ')
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[hsl(var(--accent-subtle))] border border-[hsl(var(--accent)/0.3)]">
              <Activity className="w-5 h-5 text-[hsl(var(--accent))]" />
            </div>
            <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">
              Security & Activity Log
            </h1>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Live Audit Stream
            </div>
          </div>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            Immutable SOC audit trail, operator access records, forensic pipeline lifecycle, and security events.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isLoading || isRefetching}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))] transition-colors cursor-pointer disabled:opacity-50"
            title="Refresh logs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleExportJson}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md bg-[hsl(var(--accent-subtle))] hover:bg-[hsl(var(--accent)/0.2)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)] transition-colors cursor-pointer disabled:opacity-50"
            title="Export audit records to JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Zero-Secret Logging & Compliance Notice */}
      <div className="card-surface p-3.5 border-l-4 border-l-[hsl(var(--accent))] bg-[hsl(var(--surface-1))] flex items-start gap-3 text-xs">
        <Shield className="w-4 h-4 text-[hsl(var(--accent))] shrink-0 mt-0.5" />
        <p className="text-[hsl(var(--foreground-muted))] leading-relaxed">
          <strong className="text-[hsl(var(--foreground))]">Zero-Secret Audit Policy:</strong> Event records capture operational actions, tenant identities, resource references, and outcome states. Sensitive credentials, passwords, JWTs, OAuth tokens, API keys, and internal model deliberations are strictly excluded and never persisted.
        </p>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card-surface p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]">
            <Shield className="w-5 h-5 text-[hsl(var(--accent))]" />
          </div>
          <div>
            <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
              Total Audited Events
            </p>
            <p className="text-2xl font-bold text-[hsl(var(--foreground))] mt-0.5">
              {summary.total_events}
            </p>
          </div>
        </div>

        <div className="card-surface p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
              Successful Actions
            </p>
            <p className="text-2xl font-bold text-emerald-400 mt-0.5">
              {summary.success_count}
            </p>
          </div>
        </div>

        <div className="card-surface p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20">
            <AlertOctagon className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
              Errors / Denials
            </p>
            <p className="text-2xl font-bold text-rose-400 mt-0.5">
              {summary.failure_count}
            </p>
          </div>
        </div>

        <div className="card-surface p-4 flex items-center gap-4">
          <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Users className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
              Distinct Operators
            </p>
            <p className="text-2xl font-bold text-purple-400 mt-0.5">
              {summary.unique_users_count}
            </p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card-surface p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--foreground-subtle))]" />
          <input
            type="text"
            placeholder="Search action, actor, IP, or resource..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-sm rounded-md bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:outline-none focus:border-[hsl(var(--accent))]"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))]" />
            <span className="text-xs text-[hsl(var(--foreground-subtle))]">Outcome:</span>
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              className="text-xs rounded-md bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-[hsl(var(--foreground))] px-2.5 py-1.5 focus:outline-none focus:border-[hsl(var(--accent))]"
            >
              <option value="ALL">All Outcomes</option>
              <option value="SUCCESS">Success</option>
              <option value="FAILURE">Failure</option>
              <option value="DENIED">Denied</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-[hsl(var(--foreground-subtle))]">Category:</span>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="text-xs rounded-md bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-[hsl(var(--foreground))] px-2.5 py-1.5 focus:outline-none focus:border-[hsl(var(--accent))]"
            >
              <option value="ALL">All Event Types</option>
              <option value="LOGIN">Authentication</option>
              <option value="EMAIL">Email Forensics</option>
              <option value="REPORT">Evidence Reports</option>
              <option value="CAMPAIGN">Campaign Correlation</option>
            </select>
          </div>
        </div>
      </div>

      {/* Activity Log Feed / Table */}
      <div className="card-surface overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center">
            <div className="w-8 h-8 border-2 border-[hsl(var(--accent))] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-sm text-[hsl(var(--foreground-muted))]">Streaming activity logs...</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center">
            <Activity className="w-10 h-10 text-[hsl(var(--foreground-subtle))] mx-auto mb-3 opacity-40" />
            <h3 className="text-base font-semibold text-[hsl(var(--foreground))]">No Activity Logs Found</h3>
            <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1 max-w-sm mx-auto">
              No audit events matched your search or filter parameters.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-[hsl(var(--border))]">
            {logs.map((log) => {
              const isExpanded = expandedLogId === log.id;
              const hasDetails = Boolean(log.details && Object.keys(log.details).length > 0) || Boolean(log.error_message);
              const isSuccess = log.outcome.toUpperCase() === 'SUCCESS';

              return (
                <div
                  key={log.id}
                  className="p-4 hover:bg-[hsl(var(--surface-2)/0.4)] transition-colors"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    {/* Event Type & Action */}
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div className="p-2 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex-shrink-0 mt-0.5">
                        {getActionIcon(log.action)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-[hsl(var(--foreground))] truncate">
                            {formatActionName(log.action)}
                          </span>
                          <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] border border-[hsl(var(--border))]">
                            {log.action}
                          </span>
                          {log.resource_type && (
                            <span className="text-xs text-[hsl(var(--accent))] bg-[hsl(var(--accent-subtle))] px-2 py-0.5 rounded border border-[hsl(var(--accent)/0.2)]">
                              {log.resource_type}
                            </span>
                          )}
                        </div>

                        {/* Actor & Source Telemetry */}
                        <div className="flex items-center gap-3 mt-1.5 text-xs text-[hsl(var(--foreground-muted))] flex-wrap">
                          <span className="flex items-center gap-1">
                            <span className="font-medium text-[hsl(var(--foreground))]">
                              {log.user_name || log.user_email || 'Automated System'}
                            </span>
                            {log.user_email && (
                              <span className="text-[hsl(var(--foreground-subtle))] font-mono">
                                ({log.user_email})
                              </span>
                            )}
                          </span>
                          {log.ip_address && (
                            <span className="flex items-center gap-1 font-mono text-[hsl(var(--foreground-subtle))]">
                              <Globe className="w-3 h-3" />
                              {log.ip_address}
                            </span>
                          )}
                          {log.resource_id && (
                            <span className="font-mono text-[11px] text-[hsl(var(--foreground-subtle))] truncate max-w-[180px]">
                              target: {log.resource_id.slice(0, 12)}...
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Timestamp & Outcome & Details toggle */}
                    <div className="flex items-center gap-3 flex-shrink-0 justify-between md:justify-end">
                      <span className="text-xs text-[hsl(var(--foreground-muted))] font-mono whitespace-nowrap">
                        {formatDate(log.created_at)}
                      </span>

                      <span
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                          isSuccess
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        }`}
                      >
                        {isSuccess ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {log.outcome}
                      </span>

                      {hasDetails && (
                        <button
                          onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                          className="inline-flex items-center gap-1 text-xs text-[hsl(var(--accent))] hover:underline cursor-pointer"
                        >
                          {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          {isExpanded ? 'Hide' : 'Details'}
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Expandable JSON Details Drawer */}
                  {isExpanded && hasDetails && (
                    <div className="mt-3.5 pt-3 border-t border-[hsl(var(--border))] bg-[hsl(var(--surface-2)/0.5)] rounded-lg p-3.5">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
                          Telemetry & Forensic Details
                        </span>
                        <button
                          onClick={() => handleCopyDetails(log.id, log.details || { error: log.error_message })}
                          className="inline-flex items-center gap-1 text-xs text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))] transition-colors"
                        >
                          {copiedId === log.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy JSON</span>
                            </>
                          )}
                        </button>
                      </div>

                      {log.error_message && (
                        <div className="mb-2 p-2.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs font-mono">
                          <strong>Error:</strong> {log.error_message}
                        </div>
                      )}

                      {log.details && (
                        <pre className="text-xs font-mono text-[hsl(var(--foreground))] bg-[hsl(var(--surface-3))] p-3 rounded overflow-x-auto max-h-60 border border-[hsl(var(--border))]">
                          {JSON.stringify(log.details, null, 2)}
                        </pre>
                      )}

                      {log.user_agent && (
                        <div className="mt-2 text-[11px] font-mono text-[hsl(var(--foreground-subtle))] truncate">
                          User-Agent: {log.user_agent}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
