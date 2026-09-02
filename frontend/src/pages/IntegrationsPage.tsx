import React from 'react';
import { useWorkspaceStore } from '@/store';
import { useGmailConnection, useSyncGmail } from '@/api/integrations';
import { Mail, CheckCircle2, AlertCircle, RefreshCw, Plus } from 'lucide-react';
import api from '@/lib/api'; // using for the baseURL

export function IntegrationsPage() {
  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: connection, isLoading } = useGmailConnection(currentWorkspaceId);
  const syncMutation = useSyncGmail(currentWorkspaceId);

  if (!currentWorkspaceId) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-[hsl(var(--foreground-muted))]">Please select a workspace to view integrations.</p>
      </div>
    );
  }

  const handleConnect = () => {
    // Navigate to the connect endpoint which redirects to Google
    window.location.href = `/api/v1/workspaces/${currentWorkspaceId}/integrations/gmail/connect`;
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div>
        <h1 className="text-3xl font-bold text-[hsl(var(--foreground))]">Integrations</h1>
        <p className="mt-2 text-sm text-[hsl(var(--foreground-muted))]">
          Connect external services and data sources to your workspace.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Gmail Card */}
        <div className="rounded-xl border border-[hsl(var(--border-subtle))] bg-[hsl(var(--surface))] p-6 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-[hsl(var(--accent))] to-transparent opacity-0 group-hover:opacity-5 transition-opacity duration-500" />
          
          <div className="flex items-start justify-between mb-4 relative z-10">
            <div className="p-3 bg-[hsl(var(--background))] rounded-lg">
              <Mail className="w-6 h-6 text-red-500" />
            </div>
            {connection?.status === 'ACTIVE' && (
              <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-500 bg-emerald-500/10 px-2.5 py-1 rounded-full">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Connected
              </span>
            )}
            {connection?.status === 'ERROR' && (
              <span className="flex items-center gap-1.5 text-xs font-medium text-red-500 bg-red-500/10 px-2.5 py-1 rounded-full">
                <AlertCircle className="w-3.5 h-3.5" />
                Error
              </span>
            )}
          </div>

          <h3 className="text-lg font-semibold text-[hsl(var(--foreground))] relative z-10">Google Workspace (Gmail)</h3>
          <p className="mt-1 text-sm text-[hsl(var(--foreground-muted))] mb-6 relative z-10">
            Ingest and analyze suspicious emails directly from user mailboxes.
          </p>

          <div className="relative z-10">
            {isLoading ? (
              <div className="h-9 w-full bg-[hsl(var(--background))] rounded-md animate-pulse" />
            ) : connection ? (
              <div className="space-y-4">
                <div className="text-sm">
                  <span className="text-[hsl(var(--foreground-muted))]">Connected as: </span>
                  <span className="font-medium text-[hsl(var(--foreground))]">{connection.email_address}</span>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={() => syncMutation.mutate()}
                    disabled={syncMutation.isPending}
                    className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] bg-[hsl(var(--background))] hover:bg-[hsl(var(--border-subtle))] border border-[hsl(var(--border-subtle))] rounded-md transition-colors disabled:opacity-50"
                  >
                    <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                    {syncMutation.isPending ? 'Syncing...' : 'Sync Now'}
                  </button>
                  <button
                    onClick={handleConnect}
                    className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:text-red-400 bg-[hsl(var(--background))] hover:bg-red-500/10 border border-[hsl(var(--border-subtle))] hover:border-red-500/30 rounded-md transition-colors"
                  >
                    Reconnect
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={handleConnect}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-[hsl(var(--background))] bg-[hsl(var(--foreground))] hover:bg-[hsl(var(--foreground-subtle))] rounded-md transition-colors"
              >
                <Plus className="w-4 h-4" />
                Connect Gmail
              </button>
            )}
          </div>
        </div>
        
        {/* Placeholder for future integrations */}
        <div className="rounded-xl border border-[hsl(var(--border-subtle))] border-dashed bg-[hsl(var(--background))] p-6 flex flex-col items-center justify-center opacity-50">
          <div className="w-12 h-12 rounded-full bg-[hsl(var(--surface))] flex items-center justify-center mb-4">
            <span className="text-xl">🏢</span>
          </div>
          <h3 className="text-sm font-medium text-[hsl(var(--foreground-muted))]">Microsoft 365</h3>
          <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">Coming Soon</p>
        </div>
      </div>
    </div>
  );
}
