import React, { useState } from 'react';
import { useMe, useUpdateProfile, useWorkspaceMembers, useAddWorkspaceMember, useRemoveWorkspaceMember, useGmailIntegration, useSyncGmailIntegration, useDisconnectGmailIntegration } from '@/api/hooks';
import { useAuthStore } from '@/store';
import { useWorkspaceStore } from '@/store/workspace';
import { useWorkspaces } from '@/api/workspaces';
import { Shield, User, Users, Mail, AlertTriangle, Loader2, CheckCircle, XCircle, Trash2, Plus, ExternalLink, Upload, CreditCard, Sparkles, Check, AlertCircle, Info, X } from 'lucide-react';
import { cn, extractErrorMessage } from '@/utils';
import { integrationsApi, useGmailConnection, useSyncGmail, useUpdateGmailConfig } from '@/api/integrations';

type TabId = 'general' | 'members' | 'integrations' | 'billing';

interface PopNotification {
  type: 'success' | 'error' | 'info';
  text: string;
}

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('general');
  const [popMessage, setPopMessage] = useState<PopNotification | null>(null);

  const handleShowPop = (msg: PopNotification) => {
    setPopMessage(msg);
    setTimeout(() => {
      setPopMessage((current) => (current?.text === msg.text ? null : current));
    }, 4000);
  };

  return (
    <div className="space-y-6 flex flex-col h-full lg:h-[calc(100vh-8rem)] relative">
      {/* Floating Pop Notification Toast */}
      {popMessage && (
        <div className={cn(
          "fixed top-6 right-6 z-50 p-4 rounded-lg border shadow-xl flex items-center gap-3 font-mono text-xs animate-in fade-in slide-in-from-top-4 duration-200 max-w-md",
          popMessage.type === 'success' ? "bg-emerald-950/95 text-emerald-300 border-emerald-500/40 shadow-emerald-950/60" :
          popMessage.type === 'error' ? "bg-red-950/95 text-red-300 border-red-500/40 shadow-red-950/60" :
          "bg-blue-950/95 text-blue-300 border-blue-500/40 shadow-blue-950/60"
        )}>
          {popMessage.type === 'success' && <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />}
          {popMessage.type === 'error' && <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />}
          {popMessage.type === 'info' && <Info className="w-4 h-4 text-blue-400 shrink-0" />}
          <span className="font-semibold leading-relaxed">{popMessage.text}</span>
          <button onClick={() => setPopMessage(null)} className="ml-auto p-1 hover:opacity-70 text-slate-400 cursor-pointer shrink-0">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      <div>
        <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Settings</h1>
        <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
          Manage your account, workspace members, integrations, and subscription billing.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6 flex-1 min-h-0">
        {/* Sidebar Nav */}
        <div className="w-full lg:w-64 flex-shrink-0">
          <nav className="flex lg:flex-col gap-2 overflow-x-auto lg:overflow-visible pb-2 lg:pb-0">
            <TabButton id="general" active={activeTab} onClick={setActiveTab} icon={User} label="General" />
            <TabButton id="members" active={activeTab} onClick={setActiveTab} icon={Users} label="Members" />
            <TabButton id="integrations" active={activeTab} onClick={setActiveTab} icon={Mail} label="Integrations" />
            <TabButton id="billing" active={activeTab} onClick={setActiveTab} icon={CreditCard} label="Billing & Subscription" />
          </nav>
        </div>

        {/* Content Area */}
        <div className="flex-1 card-surface border border-[hsl(var(--border))] rounded-lg overflow-y-auto">
          {activeTab === 'general' && <GeneralSettings onShowPop={handleShowPop} />}
          {activeTab === 'members' && <MembersSettings onShowPop={handleShowPop} />}
          {activeTab === 'integrations' && <IntegrationsSettings onShowPop={handleShowPop} />}
          {activeTab === 'billing' && <BillingSettings />}
        </div>
      </div>
    </div>
  );
}

// ── Shared UI ─────────────────────────────────────────────────────────────────

function TabButton({ id, active, onClick, icon: Icon, label }: { id: TabId; active: TabId; onClick: (id: TabId) => void; icon: any; label: string }) {
  const isActive = active === id;
  return (
    <button
      onClick={() => onClick(id)}
      className={cn(
        "flex items-center gap-3 px-4 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap",
        isActive
          ? "bg-[hsl(var(--accent)/0.1)] text-[hsl(var(--accent))]"
          : "text-[hsl(var(--foreground-subtle))] hover:bg-[hsl(var(--surface-3))] hover:text-[hsl(var(--foreground))]"
      )}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}

// ── General Settings ──────────────────────────────────────────────────────────

function GeneralSettings({ onShowPop }: { onShowPop: (msg: PopNotification) => void }) {
  const storeUser = useAuthStore((state) => state.user);
  const updateUser = useAuthStore((state) => state.updateUser);
  const updateProfileMutation = useUpdateProfile();
  const { data: apiUser, isLoading } = useMe();
  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: workspaces } = useWorkspaces();
  const currentWorkspace = workspaces?.find((w: any) => w.id === currentWorkspaceId);

  const currentUser = storeUser || apiUser;

  const [fullName, setFullName] = useState(currentUser?.full_name || 'Jashvanthan Ashok');
  const [avatarUrl, setAvatarUrl] = useState(currentUser?.avatar_url || '');
  const [isSaved, setIsSaved] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  React.useEffect(() => {
    if (currentUser) {
      if (currentUser.full_name) setFullName(currentUser.full_name);
      if (currentUser.avatar_url !== undefined) setAvatarUrl(currentUser.avatar_url || '');
    }
  }, [currentUser]);

  const handlePhotoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      onShowPop({ type: 'error', text: 'Selected image file exceeds 5MB limit. Please choose a smaller photo.' });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        const rawDataUrl = reader.result;
        const img = new Image();
        img.onload = () => {
          try {
            const canvas = document.createElement('canvas');
            const MAX_SIZE = 256;
            let width = img.width || MAX_SIZE;
            let height = img.height || MAX_SIZE;

            if (width > height) {
              if (width > MAX_SIZE) {
                height = Math.round(height * (MAX_SIZE / width));
                width = MAX_SIZE;
              }
            } else {
              if (height > MAX_SIZE) {
                width = Math.round(width * (MAX_SIZE / height));
                height = MAX_SIZE;
              }
            }
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx?.drawImage(img, 0, 0, width, height);
            const compressed = canvas.toDataURL('image/jpeg', 0.85);
            setAvatarUrl(compressed);
            onShowPop({ type: 'info', text: 'Photo selected! Click "Save Profile Information" to save changes.' });
          } catch {
            setAvatarUrl(rawDataUrl);
            onShowPop({ type: 'info', text: 'Photo selected! Click "Save Profile Information" to save changes.' });
          }
        };
        img.onerror = () => {
          setAvatarUrl(rawDataUrl);
          onShowPop({ type: 'info', text: 'Photo selected! Click "Save Profile Information" to save changes.' });
        };
        img.src = rawDataUrl;
      }
    };
    reader.readAsDataURL(file);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const updatedUser = await updateProfileMutation.mutateAsync({
        full_name: fullName,
        avatar_url: avatarUrl,
      });
      updateUser(updatedUser);
      setIsSaved(true);
      onShowPop({ type: 'success', text: 'Profile information & photo saved successfully!' });
      setTimeout(() => setIsSaved(false), 3000);
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      let msg = 'Failed to save profile information. Please try again.';
      if (typeof detail === 'string') {
        msg = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        msg = detail[0]?.msg || detail[0]?.message || msg;
      }
      onShowPop({ type: 'error', text: msg });
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading && !currentUser) return <LoadingState />;

  return (
    <div className="p-6 space-y-8 max-w-2xl">
      <section>
        <h2 className="text-lg font-semibold text-white mb-4 border-b border-[#232e42] pb-2">
          Profile Information
        </h2>

        <form onSubmit={handleSave} className="space-y-6">
          {/* Avatar Photo Section */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-[#94a3b8] uppercase tracking-wider font-mono">
              Profile Photo
            </label>
            <div className="flex items-center gap-5 bg-[#090d16] border border-[#232e42] rounded p-4">
              <div className="relative w-16 h-16 rounded-full overflow-hidden border-2 border-[#3b82f6] bg-[#161c2b] flex items-center justify-center shrink-0">
                {avatarUrl ? (
                  <img src={avatarUrl} alt="Avatar" className="w-full h-full object-cover" />
                ) : (
                  <span className="text-xl font-bold text-white font-mono">
                    {fullName ? fullName.slice(0, 2).toUpperCase() : 'JA'}
                  </span>
                )}
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <label className="px-3 py-1.5 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded cursor-pointer transition-colors inline-flex items-center gap-1.5 font-mono">
                    <Upload className="w-3.5 h-3.5" />
                    <span>Upload New Photo</span>
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handlePhotoUpload}
                      className="hidden"
                    />
                  </label>

                  {avatarUrl && (
                    <button
                      type="button"
                      onClick={() => {
                        setAvatarUrl('');
                        onShowPop({ type: 'info', text: 'Photo removed. Click "Save Profile Information" to apply changes.' });
                      }}
                      className="px-3 py-1.5 bg-[#121824] hover:bg-red-950/40 text-red-400 border border-[#232e42] hover:border-red-800/60 text-xs font-semibold rounded transition-colors font-mono cursor-pointer"
                    >
                      Remove Photo
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-[#64748b] font-mono">
                  Supports PNG, JPG, or GIF. Stored in your analyst profile.
                </p>
              </div>
            </div>
          </div>

          {/* Full Name Input */}
          <div className="space-y-1">
            <label htmlFor="fullNameInput" className="block text-xs font-semibold text-[#94a3b8] uppercase tracking-wider font-mono">
              Full Name
            </label>
            <input
              id="fullNameInput"
              type="text"
              required
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-3 py-2 bg-[#090d16] border border-[#232e42] rounded text-sm text-white focus:outline-none focus:border-[#3b82f6] font-mono"
            />
          </div>

          {/* Email Address Read-only */}
          <div className="space-y-1">
            <label className="block text-xs font-semibold text-[#94a3b8] uppercase tracking-wider font-mono">
              Email Address
            </label>
            <div className="px-3 py-2 bg-[#090d16] border border-[#232e42] rounded text-sm text-[#94a3b8] font-mono flex items-center justify-between">
              <span>{currentUser?.email || 'jashvan467@gmail.com'}</span>
              <span className="text-[10px] text-[#64748b] uppercase font-mono">● Primary SSO</span>
            </div>
          </div>

          {/* Save Button & Alert Status */}
          <div className="flex items-center gap-4 pt-2">
            <button
              type="submit"
              disabled={isSaving}
              className="px-5 py-2 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded transition-colors font-mono cursor-pointer flex items-center gap-2 disabled:opacity-50"
            >
              {isSaving ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Save Profile Information</span>
                </>
              )}
            </button>

            {isSaved && (
              <span className="text-xs text-[#22c55e] font-mono flex items-center gap-1.5">
                <CheckCircle className="w-4 h-4 text-[#22c55e]" />
                Profile saved successfully!
              </span>
            )}
          </div>
        </form>
      </section>

      {/* Active Workspace */}
      <section className="pt-4 border-t border-[#232e42]">
        <h2 className="text-lg font-semibold text-white mb-4 border-b border-[#232e42] pb-2">
          Active Workspace
        </h2>
        {currentWorkspace ? (
          <div className="space-y-4 max-w-md">
            <DetailRow label="Workspace Name" value={currentWorkspace.name} />
            <DetailRow
              label="Workspace Role"
              value={
                <span className="uppercase text-[#3b82f6] font-semibold font-mono">
                  {currentWorkspace.role}
                </span>
              }
            />
          </div>
        ) : (
          <p className="text-xs text-[#94a3b8] font-mono">No active workspace selected.</p>
        )}
      </section>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs font-medium text-[#64748b] uppercase tracking-wider mb-1 font-mono">{label}</label>
      <div className="px-3 py-2 bg-[#090d16] border border-[#232e42] rounded text-sm text-white font-mono font-medium">
        {value}
      </div>
    </div>
  );
}

// ── Members Settings ──────────────────────────────────────────────────────────

function MembersSettings({ onShowPop }: { onShowPop: (msg: PopNotification) => void }) {
  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: workspaces } = useWorkspaces();
  const currentWorkspace = workspaces?.find((w: any) => w.id === currentWorkspaceId);
  const { data: members, isLoading, error } = useWorkspaceMembers(currentWorkspaceId);
  const { mutate: removeMember } = useRemoveWorkspaceMember(currentWorkspaceId);
  
  const canManage = currentWorkspace?.role === 'owner' || currentWorkspace?.role === 'admin';

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState message="You don't have permission to view members or an error occurred." />;

  return (
    <div className="p-6 flex flex-col h-full">
      <div className="flex items-center justify-between mb-4 border-b border-[hsl(var(--border))] pb-4">
        <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">Workspace Members</h2>
        {canManage && <AddMemberModal onShowPop={onShowPop} />}
      </div>

      <div className="flex-1 overflow-auto bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] sticky top-0 uppercase tracking-wider text-xs">
            <tr>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Email</th>
              <th className="px-4 py-3 font-medium">Role</th>
              <th className="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[hsl(var(--border))]">
            {members?.map((member: any) => (
              <tr key={member.user_id} className="hover:bg-[hsl(var(--surface-3))] transition-colors">
                <td className="px-4 py-3 text-[hsl(var(--foreground))] font-medium">{member.full_name}</td>
                <td className="px-4 py-3 text-[hsl(var(--foreground-muted))]">{member.email}</td>
                <td className="px-4 py-3">
                  <span className="px-2 py-0.5 bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded text-xs uppercase text-[hsl(var(--foreground-subtle))]">
                    {member.role}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  {canManage && (
                    <button 
                      onClick={() => {
                        removeMember(member.user_id, {
                          onSuccess: () => onShowPop({ type: 'success', text: `Removed ${member.email} from workspace.` }),
                          onError: () => onShowPop({ type: 'error', text: "You don't have permission to perform this action." })
                        });
                      }}
                      className="p-1 text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--critical))] hover:bg-[hsl(var(--critical-subtle))] rounded transition-colors cursor-pointer"
                      title="Remove Member"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {members?.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-[hsl(var(--foreground-muted))]">No members found.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AddMemberModal({ onShowPop }: { onShowPop: (msg: PopNotification) => void }) {
  const [isOpen, setIsOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const { currentWorkspaceId } = useWorkspaceStore();
  const { mutate: addMember, isPending } = useAddWorkspaceMember(currentWorkspaceId);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    addMember({ email, role }, {
      onSuccess: () => {
        setIsOpen(false);
        setEmail('');
        setRole('viewer');
        onShowPop({ type: 'success', text: `Member ${email} added successfully.` });
      },
      onError: (err: any) => {
        onShowPop({ type: 'error', text: extractErrorMessage(err, "Failed to add member.") });
      }
    });
  };

  if (!isOpen) {
    return (
      <button onClick={() => setIsOpen(true)} className="flex items-center gap-2 px-3 py-1.5 bg-[hsl(var(--accent))] text-white rounded hover:bg-[hsl(var(--accent)/0.9)] text-sm font-medium transition-colors cursor-pointer">
        <Plus className="w-4 h-4" />
        Add Member
      </button>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-lg w-full max-w-md shadow-xl flex flex-col">
        <div className="p-4 border-b border-[hsl(var(--border))] flex justify-between items-center">
          <h3 className="font-semibold text-[hsl(var(--foreground))]">Add Workspace Member</h3>
          <button onClick={() => setIsOpen(false)} className="text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))] cursor-pointer"><XCircle className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[hsl(var(--foreground-subtle))] mb-1">Email Address</label>
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] focus:outline-none focus:border-[hsl(var(--accent)/0.5)]" 
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[hsl(var(--foreground-subtle))] mb-1">Role</label>
            <select 
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-3 py-2 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] focus:outline-none focus:border-[hsl(var(--accent)/0.5)]"
            >
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setIsOpen(false)} className="px-4 py-2 text-sm text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground))] cursor-pointer">Cancel</button>
            <button type="submit" disabled={isPending} className="px-4 py-2 bg-[hsl(var(--accent))] text-white rounded text-sm font-medium hover:bg-[hsl(var(--accent)/0.9)] disabled:opacity-50 flex items-center gap-2 cursor-pointer">
              {isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Add Member
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Integrations Settings ─────────────────────────────────────────────────────

function IntegrationsSettings({ onShowPop }: { onShowPop: (msg: PopNotification) => void }) {
  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: workspaces } = useWorkspaces();
  const currentWorkspace = workspaces?.find((w: any) => w.id === currentWorkspaceId);
  const { data: gmail, isLoading, error } = useGmailConnection(currentWorkspaceId);
  const { mutate: sync, isPending: isSyncing } = useSyncGmail(currentWorkspaceId);
  const updateConfigMutation = useUpdateGmailConfig(currentWorkspaceId);

  const [isConnecting, setIsConnecting] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);

  const handleConnect = async () => {
    if (!currentWorkspaceId) return;
    try {
      setIsConnecting(true);
      const url = await integrationsApi.getConnectUrl(currentWorkspaceId);
      if (url) {
        window.location.href = url;
      }
    } catch (err: any) {
      onShowPop({ type: 'error', text: extractErrorMessage(err, 'Failed to initiate Gmail connection.') });
    } finally {
      setIsConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!currentWorkspaceId) return;
    if (!window.confirm('Are you sure you want to disconnect Gmail?')) return;
    try {
      setIsDisconnecting(true);
      await integrationsApi.disconnectGmail(currentWorkspaceId);
      onShowPop({ type: 'info', text: 'Gmail integration disconnected.' });
      window.location.reload();
    } catch (err: any) {
      onShowPop({ type: 'error', text: extractErrorMessage(err, 'Failed to disconnect integration.') });
    } finally {
      setIsDisconnecting(false);
    }
  };

  const handleToggleMonitoring = async () => {
    if (!gmail || updateConfigMutation.isPending) return;
    const nextState = !gmail.monitoring_enabled;
    try {
      await updateConfigMutation.mutateAsync({ monitoring_enabled: nextState });
      onShowPop({
        type: 'success',
        text: `Gmail continuous monitoring set to ${nextState ? 'ENABLED (ON)' : 'PAUSED (OFF)'}.`,
      });
    } catch (err: any) {
      onShowPop({ type: 'error', text: extractErrorMessage(err, 'Failed to update monitoring setting.') });
    }
  };

  const handleModeChange = async (mode: 'AUTO' | 'MANUAL') => {
    if (!gmail || updateConfigMutation.isPending || gmail.analysis_mode === mode) return;
    try {
      await updateConfigMutation.mutateAsync({ analysis_mode: mode });
      onShowPop({
        type: 'success',
        text: `Analysis mode updated to: ${mode === 'AUTO' ? 'Automatically Analyze New Emails' : 'Fetch Emails for Manual Analysis'}.`,
      });
    } catch (err: any) {
      onShowPop({ type: 'error', text: extractErrorMessage(err, 'Failed to update analysis mode.') });
    }
  };

  const canManage = currentWorkspace?.role === 'owner' || currentWorkspace?.role === 'admin' || currentWorkspace?.role === 'analyst';

  if (isLoading) return <LoadingState />;
  if (error) return <ErrorState message="Unable to load integration status." />;

  const isConnected = gmail?.status === 'ACTIVE' || gmail?.status === 'QUEUED';

  return (
    <div className="p-6">
      <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-4 border-b border-[hsl(var(--border))] pb-2">Workspace Integrations</h2>
      
      <div className="max-w-3xl mt-6 space-y-6">
        <div className="card-surface border border-[hsl(var(--border))] rounded-lg p-6 space-y-6">
          <div className="flex items-start justify-between pb-4 border-b border-[hsl(var(--border-subtle))]">
            <div className="flex gap-4">
              <div className="w-12 h-12 bg-white rounded flex items-center justify-center flex-shrink-0 shadow-sm">
                <svg viewBox="0 0 24 24" className="w-8 h-8">
                  <path fill="#EA4335" d="M2.25 18V6l9.75 7.5L21.75 6v12Z" />
                  <path fill="#C5221F" d="M2.25 18H6V9.75L2.25 6.938Z" />
                  <path fill="#FABB05" d="M21.75 18h-3.75V9.75l3.75-2.812Z" />
                  <path fill="#4285F4" d="M21.75 6V3.75c0-.966-.84-1.5-1.5-1.5-.478 0-.916.206-1.218.525L12 8.25 5.968 2.775A1.87 1.87 0 0 0 4.5 2.25c-.825 0-1.5.675-1.5 1.5V6l9 6.75Z" />
                </svg>
              </div>
              <div>
                <h3 className="font-semibold text-[hsl(var(--foreground))] text-base flex items-center gap-2">
                  Google Workspace (Gmail)
                  {isConnected ? (
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">Connected</span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]">Not Connected</span>
                  )}
                </h3>
                <p className="text-xs text-[hsl(var(--foreground-subtle))] mt-0.5">
                  Tenant-isolated mail connector with encrypted token storage.
                </p>
              </div>
            </div>

            {isConnected && canManage && (
              <button
                onClick={handleToggleMonitoring}
                disabled={updateConfigMutation.isPending}
                className={cn(
                  "px-3 py-1.5 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors border cursor-pointer font-mono",
                  gmail?.monitoring_enabled
                    ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 hover:bg-emerald-500/25"
                    : "bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700"
                )}
              >
                Monitoring: {gmail?.monitoring_enabled ? 'ON' : 'OFF'}
              </button>
            )}
          </div>

          {isConnected ? (
            <div className="space-y-5">
              {/* Telemetry Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[hsl(var(--surface-2))] p-4 rounded-md border border-[hsl(var(--border-subtle))] text-xs font-mono">
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase text-[10px]">Connected Account</span>
                  <span className="font-semibold text-[hsl(var(--foreground))] truncate block mt-1">{gmail?.email_address}</span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase text-[10px]">Workspace</span>
                  <span className="font-semibold text-[hsl(var(--foreground))] truncate block mt-1">{currentWorkspace?.name || 'Current'}</span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase text-[10px]">Emails Fetched</span>
                  <span className="font-semibold text-blue-400 block mt-1 text-sm">{gmail?.emails_fetched ?? 0}</span>
                </div>
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block uppercase text-[10px]">Emails Analyzed</span>
                  <span className="font-semibold text-emerald-400 block mt-1 text-sm">{gmail?.emails_analyzed ?? 0}</span>
                </div>
              </div>

              {/* Analysis Mode Control */}
              <div className="space-y-2.5">
                <label className="text-xs font-bold text-[hsl(var(--foreground))] uppercase tracking-wider font-mono">
                  Analysis Mode
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => handleModeChange('AUTO')}
                    disabled={updateConfigMutation.isPending || !canManage}
                    className={cn(
                      "p-3.5 rounded-lg border text-left transition-all cursor-pointer",
                      gmail?.analysis_mode === 'AUTO'
                        ? "bg-blue-950/40 border-blue-500/50 shadow-md"
                        : "bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:border-[hsl(var(--border-subtle))] opacity-75 hover:opacity-100"
                    )}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-bold text-xs text-[hsl(var(--foreground))]">Automatically Analyze New Emails</span>
                      {gmail?.analysis_mode === 'AUTO' && (
                        <span className="text-[9px] uppercase font-bold bg-blue-500/20 text-blue-400 border border-blue-500/40 px-1.5 py-0.5 rounded">Active</span>
                      )}
                    </div>
                    <p className="text-[11px] text-[hsl(var(--foreground-muted))] leading-relaxed">
                      Fetches new messages and automatically executes full threat analysis and risk fusion.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleModeChange('MANUAL')}
                    disabled={updateConfigMutation.isPending || !canManage}
                    className={cn(
                      "p-3.5 rounded-lg border text-left transition-all cursor-pointer",
                      gmail?.analysis_mode === 'MANUAL'
                        ? "bg-amber-950/40 border-amber-500/50 shadow-md"
                        : "bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:border-[hsl(var(--border-subtle))] opacity-75 hover:opacity-100"
                    )}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-bold text-xs text-[hsl(var(--foreground))]">Fetch Emails for Manual Analysis</span>
                      {gmail?.analysis_mode === 'MANUAL' && (
                        <span className="text-[9px] uppercase font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 px-1.5 py-0.5 rounded">Active</span>
                      )}
                    </div>
                    <p className="text-[11px] text-[hsl(var(--foreground-muted))] leading-relaxed">
                      Stores incoming emails without analyzing. You choose and click "Analyze" on specific emails.
                    </p>
                  </button>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="pt-4 border-t border-[hsl(var(--border))] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="text-xs text-[hsl(var(--foreground-subtle))] font-mono">
                  {gmail?.last_sync_at ? `Last sync: ${new Date(gmail.last_sync_at).toLocaleString()}` : 'Never synced'}
                </div>

                {canManage && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <button 
                      onClick={handleDisconnect}
                      disabled={isDisconnecting}
                      className="px-3 py-1.5 bg-transparent border border-[hsl(var(--border))] text-[hsl(var(--critical))] hover:bg-[hsl(var(--critical-subtle))] rounded text-xs font-medium transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      {isDisconnecting ? 'Disconnecting...' : 'Disconnect'}
                    </button>
                    <button 
                      onClick={() => {
                        sync(undefined, {
                          onSuccess: () => onShowPop({ type: 'success', text: 'Gmail sync queued successfully.' }),
                          onError: () => onShowPop({ type: 'error', text: 'Failed to trigger sync.' })
                        });
                      }}
                      disabled={isSyncing || gmail?.status === 'QUEUED'}
                      className="px-4 py-1.5 bg-blue-600 text-white hover:bg-blue-500 rounded text-xs font-semibold transition-colors disabled:opacity-50 flex items-center gap-2 cursor-pointer"
                    >
                      {isSyncing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                      Sync Now
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="pt-2 flex items-center justify-between">
              <p className="text-xs text-[hsl(var(--foreground-muted))]">
                Connect your account to monitor inbox emails for phishing and malware threats.
              </p>
              {canManage ? (
                <button 
                  onClick={handleConnect}
                  disabled={isConnecting}
                  className="px-4 py-2 bg-[hsl(var(--accent))] text-white rounded text-sm font-medium hover:bg-[hsl(var(--accent)/0.9)] transition-colors flex items-center gap-2 disabled:opacity-50 cursor-pointer"
                >
                  {isConnecting && <Loader2 className="w-4 h-4 animate-spin" />}
                  {isConnecting ? 'Connecting...' : 'Connect Account'}
                  {!isConnecting && <ExternalLink className="w-4 h-4" />}
                </button>
              ) : (
                <p className="text-xs text-[hsl(var(--foreground-muted))]">Admin access required to connect.</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function LoadingState() {
  return (
    <div className="flex items-center justify-center h-full">
      <Loader2 className="w-6 h-6 animate-spin text-[hsl(var(--accent))]" />
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full text-[hsl(var(--foreground-muted))]">
      <Shield className="w-8 h-8 mb-3 opacity-20" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ── Billing Settings ──────────────────────────────────────────────────────────

function BillingSettings() {
  return (
    <div className="p-6 space-y-8 max-w-3xl font-mono">
      <div>
        <h2 className="text-lg font-semibold text-white mb-1 border-b border-[#232e42] pb-2">
          Subscription Plan & ISP Telemetry License
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Manage your SOC subscription tier, billing details, and enterprise telecom trace features.
        </p>
      </div>

      {/* Active License Banner */}
      <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="space-y-1">
          <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1">
            <Sparkles className="w-3.5 h-3.5" /> DEVELOPMENT MODE — FULL ACCESS UNLOCKED
          </span>
          <h3 className="text-sm font-bold text-white">Full Forensics & ISP Subpoena Intelligence Plan</h3>
          <p className="text-xs text-slate-300">
            Current Tier: <span className="text-emerald-400 font-bold">Unlimited Developer Enterprise License</span> (All features free & fully unlocked).
          </p>
        </div>
        <span className="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-xs font-bold uppercase shrink-0 self-start sm:self-center">
          Full Unlocked
        </span>
      </div>

      {/* Feature Plan Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-4 rounded-lg bg-[#090d16] border border-[#232e42] space-y-3">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block border-b border-[#1f2a3e] pb-2">
            Standard Tier (Included)
          </span>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> MaxMind GeoIP2 Public Geolocation</li>
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Autonomous System (ASN) & Routing Type</li>
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> RFC 1918 Private LAN Interception</li>
          </ul>
        </div>

        <div className="p-4 rounded-lg bg-[#0d1424] border-2 border-[#3b82f6] space-y-3 relative">
          <span className="text-xs font-bold text-blue-400 uppercase tracking-wider block border-b border-[#1f2a3e] pb-2">
            Enterprise Telecom Tier (Enabled)
          </span>
          <ul className="space-y-2 text-xs text-slate-200">
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Carrier Billing Authority Telemetry</li>
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Law Enforcement Subpoena Notice Generator</li>
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Internal LAN DHCP/AD PowerShell Guide</li>
            <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Priority Threat Intelligence Sync</li>
          </ul>
        </div>
      </div>

      {/* Billing Details Note */}
      <div className="p-4 rounded bg-[#121824] border border-[#1f2a3e] text-xs text-slate-400 space-y-2">
        <p className="font-bold text-slate-200">Billing Preferences & Invoicing</p>
        <p>
          Subscription billing management will be activated upon enterprise commercial launch. For custom enterprise deployment or SLA agreements, contact your account administrator.
        </p>
      </div>
    </div>
  );
}
