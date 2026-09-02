// SentinelTrace Frontend — Email Analysis Page (List + Upload)

import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Search, Filter, Upload, Mail, ExternalLink, Trash2, RefreshCw,
} from 'lucide-react';
import { useAnalyses, useDeleteAnalysis } from '@/api/hooks';
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
  const [page, setPage] = useState(1);
  const navigate = useNavigate();

  const { data, isLoading, refetch, isFetching } = useAnalyses({
    page,
    page_size: 25,
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    search: search || undefined,
  });

  const deleteAnalysis = useDeleteAnalysis();

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Email Analysis</h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
            Submit and review email threat analyses
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 rounded hover:bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] transition-colors"
            title="Refresh"
          >
            <RefreshCw className={cn('w-4 h-4', isFetching && 'animate-spin')} />
          </button>
          <button
            onClick={() => setShowUpload(!showUpload)}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] text-sm font-medium hover:bg-[hsl(var(--accent-hover))] transition-colors"
          >
            <Upload className="w-4 h-4" />
            Upload .eml
          </button>
        </div>
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
          <option value="PENDING">Pending</option>
          <option value="PROCESSING">Processing</option>
          <option value="COMPLETE">Complete</option>
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

        {(search || statusFilter || severityFilter) && (
          <button
            onClick={() => { setSearch(''); setStatusFilter(''); setSeverityFilter(''); setPage(1); }}
            className="text-xs text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground))] transition-colors"
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
                {['Subject / Sender', 'Category', 'Status', 'Severity', 'Score', 'Time', ''].map((h) => (
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
                    {Array.from({ length: 7 }).map((_, j) => (
                      <td key={j} className="py-3 px-4">
                        <div className="h-4 bg-[hsl(var(--surface-3))] rounded w-full" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : data?.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[hsl(var(--foreground-muted))] text-sm">
                    <Mail className="w-8 h-8 mx-auto mb-3 text-[hsl(var(--foreground-subtle))]" />
                    No analyses found
                  </td>
                </tr>
              ) : (
                data?.items.map((analysis) => (
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
                    <td className="py-3 px-4">
                      <span className="text-xs text-[hsl(var(--foreground-muted))]">
                        {analysis.threat_category
                          ? THREAT_CATEGORY_LABELS[analysis.threat_category] || analysis.threat_category
                          : '—'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={analysis.status} animate />
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
                      <div className="flex items-center gap-1">
                        <Link
                          to={`/emails/${analysis.id}`}
                          className="p-1.5 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--accent))] transition-colors"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Link>
                        <button
                          onClick={() => {
                            if (confirm('Delete this analysis?')) {
                              deleteAnalysis.mutate(analysis.id);
                            }
                          }}
                          className="p-1.5 rounded hover:bg-[hsl(var(--critical-subtle))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--critical))] transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
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
    </div>
  );
}
