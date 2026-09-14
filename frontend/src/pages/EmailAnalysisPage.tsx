// SentinelTrace Frontend — Email Analysis Page (List + Upload)

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  Search, Filter, Upload, Mail, ExternalLink, Trash2, RefreshCw, MapPin, Globe, AlertTriangle, Loader2,
} from 'lucide-react';
import { useAnalyses, useDeleteAnalysis, useAnalyzeEmail } from '@/api/hooks';
import { EmailUploader } from '@/components/email/EmailUploader';
import { SeverityBadge, StatusBadge } from '@/components/threats/SeverityBadge';
import { formatRelativeTime, THREAT_CATEGORY_LABELS } from '@/utils';
import { cn } from '@/utils';
import type { AnalysisStatus, SeverityLevel } from '@/types';

export function EmailAnalysisPage() {
  const [showUpload, setShowUpload] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<AnalysisStatus | ''>('');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | ''>('');
  const [sourceFilter, setSourceFilter] = useState<'upload' | 'google' | ''>('');
  const [page, setPage] = useState(1);
  const [analysisToDelete, setAnalysisToDelete] = useState<any | null>(null);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data, isLoading, refetch, isFetching } = useAnalyses({
    page,
    page_size: 25,
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    source: sourceFilter || undefined,
    search: search || undefined,
  });

  const deleteAnalysis = useDeleteAnalysis();
  const analyzeEmailMutation = useAnalyzeEmail();

  const handleAnalyzeClick = async (e: React.MouseEvent, analysisId: string) => {
    e.stopPropagation();
    try {
      setAnalyzingId(analysisId);
      await analyzeEmailMutation.mutateAsync(analysisId);
    } catch (err) {
      console.error('Failed to trigger analysis:', err);
    } finally {
      setAnalyzingId(null);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Email Analysis & Ingested Messages</h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
            Submit, synchronize, and review forensic email threat investigations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 rounded hover:bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] transition-colors cursor-pointer"
            title="Refresh"
          >
            <RefreshCw className={cn('w-4 h-4', isFetching && 'animate-spin')} />
          </button>
          <button
            onClick={() => setShowUpload(!showUpload)}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] text-sm font-medium hover:bg-[hsl(var(--accent-hover))] transition-colors cursor-pointer"
          >
            <Upload className="w-4 h-4" />
            Upload .eml
          </button>
        </div>
      </div>

      {/* Source Selection Tabs */}
      <div className="flex items-center gap-2 border-b border-[hsl(var(--border))] pb-2">
        <button
          onClick={() => { setSourceFilter(''); setPage(1); }}
          className={cn(
            "px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer",
            sourceFilter === ''
              ? "bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)]"
              : "text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] hover:text-[hsl(var(--foreground))]"
          )}
        >
          All Sources
        </button>
        <button
          onClick={() => { setSourceFilter('upload'); setPage(1); }}
          className={cn(
            "px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer",
            sourceFilter === 'upload'
              ? "bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)]"
              : "text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] hover:text-[hsl(var(--foreground))]"
          )}
        >
          <Upload className="w-3.5 h-3.5" />
          Uploaded .EML Files
        </button>
        <button
          onClick={() => { setSourceFilter('google'); setPage(1); }}
          className={cn(
            "px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-2 cursor-pointer",
            sourceFilter === 'google'
              ? "bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)]"
              : "text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] hover:text-[hsl(var(--foreground))]"
          )}
        >
          <Mail className="w-3.5 h-3.5 text-red-400" />
          Gmail Ingestion
        </button>
      </div>

      {/* Upload Panel */}
      {showUpload && (
        <div className="card-surface p-6">
          <h2 className="font-semibold text-[hsl(var(--foreground))] mb-4 flex items-center gap-2">
            <Upload className="w-4 h-4 text-[hsl(var(--accent))]" />
            Upload Email for Analysis
          </h2>
          <EmailUploader
            onSuccess={(id) => {
              setShowUpload(false);
              navigate(`/emails/${id}`);
            }}
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[hsl(var(--foreground-subtle))]" />
          <input
            type="text"
            placeholder="Search subject, sender…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full pl-9 pr-3 py-2 bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:border-[hsl(var(--accent)/0.5)] focus:outline-none"
          />
        </div>

        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value as any); setPage(1); }}
          className="px-3 py-2 bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="PENDING">Not Analyzed (Pending)</option>
          <option value="PROCESSING">Processing</option>
          <option value="COMPLETE">Complete (Analyzed)</option>
          <option value="FAILED">Failed</option>
          <option value="QUARANTINED">Quarantined</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value as any); setPage(1); }}
          className="px-3 py-2 bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        {(search || statusFilter || severityFilter || sourceFilter) && (
          <button
            onClick={() => { setSearch(''); setStatusFilter(''); setSeverityFilter(''); setSourceFilter(''); setPage(1); }}
            className="text-xs text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground))] transition-colors cursor-pointer"
          >
            Clear filters
          </button>
        )}

        <span className="ml-auto text-xs text-[hsl(var(--foreground-subtle))]">
          {data?.total ?? 0} results
        </span>
      </div>

      {/* Table */}
      <div className="card-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[hsl(var(--border))] bg-[hsl(var(--surface-2))]">
                {['Subject / Sender', 'Source', 'Category', 'Status', 'Severity', 'Score', 'Time', 'Actions'].map((h) => (
                  <th key={h} className="text-left py-3 px-4 text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[hsl(var(--border-subtle))]">
              {isLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    {Array.from({ length: 8 }).map((_, j) => (
                      <td key={j} className="py-3 px-4">
                        <div className="h-4 bg-[hsl(var(--surface-3))] rounded w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : data?.items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[hsl(var(--foreground-muted))] text-sm">
                    <Mail className="w-8 h-8 mx-auto mb-3 text-[hsl(var(--foreground-subtle))]" />
                    No emails or forensic analyses found
                  </td>
                </tr>
              ) : (
                data?.items.map((analysis) => {
                  const isGmail = analysis.source_provider === 'google' || analysis.source_provider === 'gmail';
                  const isPending = analysis.status === 'PENDING';
                  const isProcessing = analysis.status === 'PROCESSING';
                  const isFailed = analysis.status === 'FAILED';
                  const isAnalyzing = analyzingId === analysis.id;

                  return (
                    <tr
                      key={analysis.id}
                      className="hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
                      onClick={() => navigate(`/emails/${analysis.id}`)}
                    >
                      <td className="py-3 px-4">
                        <p className="font-medium text-[hsl(var(--foreground))] truncate max-w-[200px]">
                          {analysis.subject || '(no subject)'}
                        </p>
                        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5 truncate max-w-[200px]">
                          {analysis.sender_email || '—'}
                        </p>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {isGmail ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                            <Mail className="w-3 h-3" />
                            Gmail
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] border border-[hsl(var(--border))]">
                            <Upload className="w-3 h-3 text-[hsl(var(--accent))]" />
                            .EML Upload
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs text-[hsl(var(--foreground-muted))]">
                          {analysis.threat_category
                            ? THREAT_CATEGORY_LABELS[analysis.threat_category] || analysis.threat_category
                            : '—'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {isPending ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                            NOT ANALYZED
                          </span>
                        ) : (
                          <StatusBadge status={analysis.status} animate />
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {analysis.severity ? <SeverityBadge severity={analysis.severity} /> : <span className="text-[hsl(var(--foreground-subtle))] text-xs">—</span>}
                      </td>
                      <td className="py-3 px-4">
                        {analysis.threat_score != null ? (
                          <span className="text-xs font-mono font-medium text-[hsl(var(--foreground))]">
                            {analysis.threat_score.toFixed(0)}
                          </span>
                        ) : <span className="text-[hsl(var(--foreground-subtle))] text-xs">—</span>}
                      </td>
                      <td className="py-3 px-4 text-xs text-[hsl(var(--foreground-muted))] whitespace-nowrap">
                        {formatRelativeTime(analysis.created_at)}
                      </td>
                      <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-2">
                          {isPending && (
                            <button
                              onClick={(e) => handleAnalyzeClick(e, analysis.id)}
                              disabled={isAnalyzing}
                              className="px-2.5 py-1 text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 rounded transition-colors disabled:opacity-50 flex items-center gap-1.5 cursor-pointer shadow-sm"
                              title="Queue threat analysis for this email"
                            >
                              {isAnalyzing ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                              Analyze
                            </button>
                          )}

                          {isFailed && (
                            <button
                              onClick={(e) => handleAnalyzeClick(e, analysis.id)}
                              disabled={isAnalyzing}
                              className="px-2 py-1 text-xs font-bold text-amber-300 bg-amber-950/60 hover:bg-amber-900/60 border border-amber-800/60 rounded transition-colors disabled:opacity-50 flex items-center gap-1 cursor-pointer"
                              title="Retry failed analysis"
                            >
                              {isAnalyzing ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                              Retry
                            </button>
                          )}

                          {!isPending && !isFailed && (
                            <Link
                              to={`/emails/${analysis.id}`}
                              className="p-1.5 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--accent))] transition-colors"
                              title="View Analysis"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </Link>
                          )}

                          <Link
                            to={`/geo?analysis_id=${encodeURIComponent(analysis.id)}`}
                            className="p-1.5 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-emerald-400 transition-colors"
                            title="Geolocate Originating IP & Hops"
                          >
                            <MapPin className="w-3.5 h-3.5" />
                          </Link>

                          <button
                            onClick={() => setAnalysisToDelete(analysis)}
                            className="p-1.5 rounded hover:bg-[hsl(var(--critical-subtle))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--critical))] transition-colors cursor-pointer"
                            title="Delete Analysis"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {data && data.total > 25 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[hsl(var(--border))]">
            <span className="text-xs text-[hsl(var(--foreground-muted))]">
              Page {page} of {Math.ceil(data.total / 25)}
            </span>
            <div className="flex gap-2">
              <button
                disabled={page === 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1.5 text-xs rounded border border-[hsl(var(--border))] text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] disabled:opacity-40 transition-colors"
              >
                Previous
              </button>
              <button
                disabled={page >= Math.ceil(data.total / 25)}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1.5 text-xs rounded border border-[hsl(var(--border))] text-[hsl(var(--foreground-muted))] hover:bg-[hsl(var(--surface-2))] disabled:opacity-40 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── SOC Purge Delete Confirmation Modal ───────────────────────────── */}
      {analysisToDelete && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#121824] border border-red-900/60 rounded-lg p-6 max-w-md w-full space-y-5 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3 pb-3 border-b border-[#232e42]">
              <div className="p-2 rounded bg-red-950/80 border border-red-800/60 text-red-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white font-mono">Confirm Permanent Deletion</h3>
                <p className="text-xs text-[hsl(var(--foreground-subtle))] font-mono">SOC Purge Action</p>
              </div>
            </div>

            <div className="space-y-3 font-mono text-xs text-slate-300 leading-relaxed">
              <p>
                Are you sure you want to permanently purge this email analysis (<strong className="text-white">{analysisToDelete.subject || 'Selected Sample'}</strong>) from the SentinelTrace database and workspace storage?
              </p>
              <div className="p-3 bg-red-950/40 border border-red-900/50 rounded text-red-200">
                ⚠️ <strong>Warning:</strong> This action is permanent and cannot be undone. All extracted IOCs, network trace telemetry, and reports tied to ID <code className="text-white">{analysisToDelete.id.slice(0, 8)}</code> will be deleted from the database.
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setAnalysisToDelete(null)}
                disabled={deleteAnalysis.isPending}
                className="px-4 py-2 bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] rounded text-xs font-mono font-semibold transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  try {
                    await deleteAnalysis.mutateAsync(analysisToDelete.id);
                    setAnalysisToDelete(null);
                    await queryClient.invalidateQueries();
                    refetch();
                  } catch (err) {
                    console.error('Failed to delete analysis:', err);
                  }
                }}
                disabled={deleteAnalysis.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-mono font-bold transition-colors inline-flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
              >
                {deleteAnalysis.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                <span>Confirm Delete & Purge DB</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
