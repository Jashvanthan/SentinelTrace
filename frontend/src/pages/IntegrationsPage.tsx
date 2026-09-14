import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useWorkspaceStore } from '@/store';
import { useWorkspaces } from '@/api/workspaces';
import { useGmailConnection, useSyncGmail, useUpdateGmailConfig, integrationsApi } from '@/api/integrations';
import {
  Mail, CheckCircle2, AlertCircle, RefreshCw, Plus, Loader2,
  Shield, Zap, Radio, Power, Eye, Unlink
} from 'lucide-react';
import { cn } from '@/utils';

export function IntegrationsPage() {
  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: workspaces } = useWorkspaces();
  const currentWorkspace = workspaces?.find((w: any) => w.id === currentWorkspaceId);

  const [searchParams] = useSearchParams();
  const [isConnecting, setIsConnecting] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  const statusParam = searchParams.get('status');
  const errorParam = searchParams.get('error');

  const { data: connection, isLoading } = useGmailConnection(currentWorkspaceId);
  const syncMutation = useSyncGmail(currentWorkspaceId);
  const updateConfigMutation = useUpdateGmailConfig(currentWorkspaceId);

  if (!currentWorkspaceId) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-[hsl(var(--foreground-muted))]">Please select a workspace to view integrations.</p>
      </div>
    );
  }

  const handleConnect = async () => {
    if (!currentWorkspaceId) return;
    try {
      setIsConnecting(true);
      setActionError(null);
      const authUrl = await integrationsApi.getConnectUrl(currentWorkspaceId);
      if (authUrl) {
        window.location.href = authUrl;
      }
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to initiate Gmail OAuth. Please check your workspace permissions.');
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!currentWorkspaceId) return;
    if (!window.confirm('Are you sure you want to disconnect Gmail? This will revoke access tokens.')) return;
    try {
      setIsDisconnecting(true);
      setActionError(null);
      await integrationsApi.disconnectGmail(currentWorkspaceId);
      window.location.reload();
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to disconnect Gmail.');
      setIsDisconnecting(false);
    }
  };

  const handleToggleMonitoring = async () => {
    if (!connection || updateConfigMutation.isPending) return;
    const nextState = !connection.monitoring_enabled;
    try {
      await updateConfigMutation.mutateAsync({
        monitoring_enabled: nextState,
      });
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to update monitoring status.');
    }
  };

  const handleModeChange = async (mode: 'AUTO' | 'MANUAL') => {
    if (!connection || updateConfigMutation.isPending || connection.analysis_mode === mode) return;
    try {
      await updateConfigMutation.mutateAsync({
        analysis_mode: mode,
      });
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to update analysis mode.');
    }
  };

  const handleSyncNow = async () => {
    try {
      setSyncFeedback(null);
      setActionError(null);
      await syncMutation.mutateAsync();
      setSyncFeedback('Synchronization queued. Fetching messages according to configured mode.');
      setTimeout(() => setSyncFeedback(null), 5000);
    } catch (err: any) {
      setActionError(err.response?.data?.detail || 'Failed to trigger synchronization.');
    }
  };

  const isConnected = connection && connection.status === 'ACTIVE';

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-3xl font-bold text-[hsl(var(--foreground))]">Integrations & Connectors</h1>
        <p className="mt-2 text-sm text-[hsl(var(--foreground-muted))]">
          Configure mail server integrations, monitoring behavior, and threat analysis modes.
        </p>
      </div>

      {statusParam === 'connected' && (
        <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
          <span>Gmail integration successfully connected and active.</span>
        </div>
      )}

      {syncFeedback && (
        <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 text-sm flex items-center gap-3">
          <RefreshCw className="w-5 h-5 flex-shrink-0 animate-spin" />
          <span>{syncFeedback}</span>
        </div>
      )}

      {(errorParam || actionError) && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-3">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <span>{actionError || `OAuth connection error: ${errorParam}. Please verify your permissions and try again.`}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Gmail Configuration Card */}
        <div className="lg:col-span-2 rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--surface))] p-6 space-y-6">
          <div className="flex items-start justify-between pb-4 border-b border-[hsl(var(--border-subtle))]">
            <div className="flex items-center gap-3.5">
              <div className="p-3 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-xl">
                <Mail className="w-7 h-7 text-red-500" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-[hsl(var(--foreground))] flex items-center gap-2">
                  Google Workspace (Gmail)
                  {isConnected ? (
                    <span className="flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 rounded-full">
                      <CheckCircle2 className="w-3 h-3" />
                      Connected
                    </span>
                  ) : (
                    <span className="text-[11px] font-semibold text-[hsl(var(--foreground-muted))] bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] px-2 py-0.5 rounded-full">
                      Not Connected
                    </span>
                  )}
                </h3>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
                  Tenant-isolated OAuth 2.0 connection with AES-256 encrypted credential storage.
                </p>
              </div>
            </div>

            {isConnected && (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleToggleMonitoring}
                  disabled={updateConfigMutation.isPending}
                  className={cn(
                    "px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors border cursor-pointer",
                    connection.monitoring_enabled
                      ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 hover:bg-emerald-500/25"
                      : "bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700"
                  )}
                  title="Toggle background monitoring without disconnecting"
                >
                  <Power className="w-3.5 h-3.5" />
                  Monitoring: {connection.monitoring_enabled ? 'ON' : 'OFF'}
                </button>
              </div>
            )}
          </div>

          {isLoading ? (
            <div className="h-40 bg-[hsl(var(--surface-2))] rounded-lg animate-pulse" />
          ) : isConnected ? (
            <div className="space-y-6">
              {/* Telemetry & Connection Details Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[hsl(var(--surface-2))] p-4 rounded-lg border border-[hsl(var(--border-subtle))] text-xs font-mono">
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase tracking-wider text-[10px]">Connected Account</span>
                  <span className="font-semibold text-[hsl(var(--foreground))] truncate block mt-1" title={connection.email_address}>
                    {connection.email_address}
                  </span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase tracking-wider text-[10px]">Workspace</span>
                  <span className="font-semibold text-[hsl(var(--foreground))] truncate block mt-1">
                    {currentWorkspace?.name || 'Current'}
                  </span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase tracking-wider text-[10px]">Emails Fetched</span>
                  <span className="font-semibold text-blue-400 block mt-1 text-sm">
                    {connection.emails_fetched ?? 0}
                  </span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase tracking-wider text-[10px]">Emails Analyzed</span>
                  <span className="font-semibold text-emerald-400 block mt-1 text-sm">
                    {connection.emails_analyzed ?? 0}
                  </span>
                </div>
              </div>

              {/* Analysis Mode Selector */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-bold text-[hsl(var(--foreground))] uppercase tracking-wider font-mono">
                    Gmail Analysis Mode
                  </label>
                  <span className="text-[11px] text-[hsl(var(--foreground-subtle))] font-mono">
                    Controls automated vs on-demand processing
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {/* Mode A: Auto */}
                  <button
                    type="button"
                    onClick={() => handleModeChange('AUTO')}
                    disabled={updateConfigMutation.isPending}
                    className={cn(
                      "p-4 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between",
                      connection.analysis_mode === 'AUTO'
                        ? "bg-blue-950/40 border-blue-500/50 shadow-lg shadow-blue-950/50"
                        : "bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:border-[hsl(var(--border-subtle))] opacity-75 hover:opacity-100"
                    )}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="flex items-center gap-2 font-bold text-sm text-[hsl(var(--foreground))]">
                          <Zap className={cn("w-4 h-4", connection.analysis_mode === 'AUTO' ? "text-blue-400" : "text-[hsl(var(--foreground-muted))]")} />
                          Automatically Analyze New Emails
                        </span>
                        {connection.analysis_mode === 'AUTO' && (
                          <span className="text-[10px] uppercase font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40 px-2 py-0.5 rounded">Active</span>
                        )}
                      </div>
                      <p className="text-xs text-[hsl(var(--foreground-muted))] leading-relaxed">
                        Fetch emails and immediately run the complete threat analysis pipeline (AI/LLM + Threat Intel + Risk Fusion).
                      </p>
                    </div>
                  </button>

                  {/* Mode B: Manual */}
                  <button
                    type="button"
                    onClick={() => handleModeChange('MANUAL')}
                    disabled={updateConfigMutation.isPending}
                    className={cn(
                      "p-4 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between",
                      connection.analysis_mode === 'MANUAL'
                        ? "bg-amber-950/40 border-amber-500/50 shadow-lg shadow-amber-950/50"
                        : "bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:border-[hsl(var(--border-subtle))] opacity-75 hover:opacity-100"
                    )}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="flex items-center gap-2 font-bold text-sm text-[hsl(var(--foreground))]">
                          <Eye className={cn("w-4 h-4", connection.analysis_mode === 'MANUAL' ? "text-amber-400" : "text-[hsl(var(--foreground-muted))]")} />
                          Fetch Emails for Manual Analysis
                        </span>
                        {connection.analysis_mode === 'MANUAL' && (
                          <span className="text-[10px] uppercase font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 px-2 py-0.5 rounded">Active</span>
                        )}
                      </div>
                      <p className="text-xs text-[hsl(var(--foreground-muted))] leading-relaxed">
                        Fetch and store emails as unanalyzed items. You select which specific emails to analyze on demand.
                      </p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Action Buttons Toolbar */}
              <div className="pt-4 border-t border-[hsl(var(--border-subtle))] flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs text-[hsl(var(--foreground-subtle))] font-mono">
                  {connection.last_sync_at ? (
                    <span>Last synchronized: {new Date(connection.last_sync_at).toLocaleString()}</span>
                  ) : (
                    <span>Never synchronized</span>
                  )}
                </div>

                <div className="flex items-center gap-2.5">
                  <button
                    onClick={handleSyncNow}
                    disabled={syncMutation.isPending}
                    className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors disabled:opacity-50 cursor-pointer shadow-sm"
                  >
                    <RefreshCw className={cn("w-3.5 h-3.5", syncMutation.isPending && "animate-spin")} />
                    {syncMutation.isPending ? 'Synchronizing...' : 'Sync Now'}
                  </button>

                  <button
                    onClick={handleConnect}
                    disabled={isConnecting}
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-[hsl(var(--foreground))] bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {isConnecting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Reconnect'}
                  </button>

                  <button
                    onClick={handleDisconnect}
                    disabled={isDisconnecting}
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-red-400 bg-red-950/30 hover:bg-red-950/60 border border-red-800/40 rounded-md transition-colors disabled:opacity-50 cursor-pointer"
                    title="Revoke and remove connection"
                  >
                    <Unlink className="w-3.5 h-3.5" />
                    Disconnect
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center space-y-4">
              <p className="text-sm text-[hsl(var(--foreground-muted))] max-w-md mx-auto">
                Connect your organization's Google Workspace account to enable automated continuous monitoring or manual forensic review.
              </p>
              <button
                onClick={handleConnect}
                disabled={isConnecting}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-white bg-red-600 hover:bg-red-500 rounded-lg transition-colors disabled:opacity-50 cursor-pointer shadow-lg shadow-red-950/40"
              >
                {isConnecting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                {isConnecting ? 'Connecting OAuth...' : 'Connect Gmail Account'}
              </button>
            </div>
          )}
        </div>

        {/* Side Info & Security Posture Card */}
        <div className="space-y-4">
          <div className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--surface))] p-5 space-y-3">
            <h4 className="text-xs font-bold text-[hsl(var(--foreground))] uppercase tracking-wider font-mono flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              Security Architecture
            </h4>
            <ul className="text-xs text-[hsl(var(--foreground-subtle))] space-y-2 leading-relaxed">
              <li className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>Zero Cross-Tenant Leakage:</strong> Emails and analyses are strictly isolated to workspace <code>{currentWorkspace?.slug || 'workspace'}</code>.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>Encrypted Tokens:</strong> Refresh and access tokens are secured at rest using Fernet symmetric encryption.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span><strong>Idempotent Sync:</strong> Deduplication protects against redundant Celery pipeline jobs.</span>
              </li>
            </ul>
          </div>

          <div className="rounded-xl border border-[hsl(var(--border-subtle))] border-dashed bg-[hsl(var(--background))] p-5 flex flex-col items-center justify-center opacity-60 text-center">
            <div className="w-10 h-10 rounded-full bg-[hsl(var(--surface))] flex items-center justify-center mb-2">
              <span className="text-lg">🏢</span>
            </div>
            <h3 className="text-xs font-bold text-[hsl(var(--foreground-muted))] uppercase">Microsoft 365 Connector</h3>
            <p className="text-[11px] text-[hsl(var(--foreground-subtle))] mt-1">Enterprise Exchange & Graph Ingestion (Coming Soon)</p>
          </div>
        </div>
      </div>
    </div>
  );
}

