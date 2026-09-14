// SentinelTrace Frontend — Forensic Reports Page (Matching Screenshot 5 visual language)

import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  FileText, FileDown, Search, Filter, RefreshCw, Eye, CheckCircle2, AlertCircle, Clock, Trash2, AlertTriangle, Loader2
} from 'lucide-react';
import { useAnalyses, useDeleteAnalysis, downloadReportPdf } from '@/api/hooks';
import { useWorkspaceStore } from '@/store/workspace';
import { formatDate, truncateHash } from '@/utils';
import { HashDisplay } from '@/components/HashDisplay';

export function ReportsPage() {
  const queryClient = useQueryClient();
  const { currentWorkspaceId } = useWorkspaceStore();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [reportToDelete, setReportToDelete] = useState<any | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const deleteAnalysis = useDeleteAnalysis();

  const { data, isLoading, refetch, isRefetching } = useAnalyses({
    page,
    page_size: pageSize,
    search: search ? search : undefined,
  });

  const totalItems = data?.total || 0;
  const totalPages = Math.ceil(totalItems / pageSize) || 1;
  const startItem = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const endItem = Math.min(page * pageSize, totalItems);

  const analyses = useMemo(() => {
    const items = data?.items || [];
    if (statusFilter === 'ALL') return items;
    if (statusFilter === 'VERIFIED') return items.filter((a: any) => a.status === 'COMPLETE');
    if (statusFilter === 'PENDING') return items.filter((a: any) => a.status !== 'COMPLETE');
    return items;
  }, [data?.items, statusFilter]);

  const handleDownload = async (analysisId: string, subject?: string) => {
    try {
      setDownloadingId(analysisId);
      const safeSubject = (subject || 'evidence')
        .replace(/[^a-zA-Z0-9_-]/g, '_')
        .slice(0, 30);
      const filename = `sentineltrace-report-${safeSubject}-${analysisId.slice(0, 8)}.pdf`;
      await downloadReportPdf(analysisId, filename);
    } catch (err) {
      console.error('Report download failed:', err);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Forensic Reports
          </h1>
          <p className="text-xs text-[#94a3b8] mt-0.5">
            Manage and verify generated case reports.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/investigate"
            className="px-4 py-2 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded transition-colors flex items-center gap-2"
          >
            + New Investigation
          </Link>
        </div>
      </div>

      {/* ── Search & Filter Controls ──────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#121824] border border-[#232e42] rounded p-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
          <input
            type="text"
            placeholder="Search reports..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[#090d16] border border-[#232e42] rounded text-xs text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#94a3b8] font-mono">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#090d16] border border-[#232e42] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-[#3b82f6] font-mono cursor-pointer"
            >
              <option value="ALL">All</option>
              <option value="VERIFIED">Verified</option>
              <option value="PENDING">Pending</option>
            </select>
          </div>

          <button
            onClick={() => refetch()}
            disabled={isLoading || isRefetching}
            className="p-1.5 bg-[#090d16] border border-[#232e42] rounded text-[#94a3b8] hover:text-white transition-colors"
            title="Refresh reports"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Reports Table ─────────────────────────────────────────────────── */}
      <div className="bg-[#121824] border border-[#232e42] rounded overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center space-y-3">
            <RefreshCw className="w-6 h-6 text-[#3b82f6] animate-spin mx-auto" />
            <p className="text-xs text-[#94a3b8] font-mono">Loading case report registry…</p>
          </div>
        ) : analyses.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <FileText className="w-10 h-10 text-[#64748b] mx-auto opacity-50" />
            <p className="text-sm font-semibold text-white">No Forensic Reports Found</p>
            <p className="text-xs text-[#94a3b8] max-w-sm mx-auto">
              Run an email or entity investigation to generate cryptographically anchored case reports.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#090d16] border-b border-[#232e42] text-[#94a3b8] font-semibold">
                <tr>
                  <th className="py-3 px-4 font-mono">Report ID</th>
                  <th className="py-3 px-4 font-mono">Case Ref</th>
                  <th className="py-3 px-4 font-mono">Type</th>
                  <th className="py-3 px-4 font-mono">Created Date</th>
                  <th className="py-3 px-4 font-mono">Integrity Hash (SHA-256)</th>
                  <th className="py-3 px-4 font-mono">Status</th>
                  <th className="py-3 px-4 font-mono text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#232e42]">
                {analyses.map((item: any, idx: number) => {
                  const reportId = `REP-2026-${String(idx + 101).padStart(4, '0')}`;
                  const caseRef = `CAS-${item.id.slice(0, 4).toUpperCase()}-X`;
                  const isVerified = item.status === 'COMPLETE';
                  const isPdfDownloading = downloadingId === item.id;

                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-[#161c2b] transition-colors font-mono"
                    >
                      {/* Report ID */}
                      <td className="py-3 px-4 text-[#3b82f6] font-bold">
                        <Link to={`/emails/${item.id}`} className="hover:underline">
                          {reportId}
                        </Link>
                      </td>

                      {/* Case Ref */}
                      <td className="py-3 px-4 text-[#94a3b8]">
                        {caseRef}
                      </td>

                      {/* Type */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 text-white font-sans">
                          <FileText className="w-3.5 h-3.5 text-[#f97316]" />
                          <span>PDF Forensic</span>
                        </div>
                      </td>

                      {/* Created Date */}
                      <td className="py-3 px-4 text-[#94a3b8]">
                        {formatDate(item.created_at)}
                      </td>

                      {/* Integrity Hash */}
                      <td className="py-3 px-4 text-[#94a3b8] font-mono">
                        <HashDisplay hash={item.raw_eml_sha256} truncateLength={14} />
                      </td>

                      {/* Status Badge */}
                      <td className="py-3 px-4">
                        {isVerified ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[#2563eb]/40 bg-[#1b2434] text-[#3b82f6] text-[10px] font-bold tracking-wider uppercase font-mono">
                            <CheckCircle2 className="w-3 h-3 text-[#3b82f6]" />
                            VERIFIED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[#f97316]/40 bg-[#121824] text-[#f97316] text-[10px] font-bold tracking-wider uppercase font-mono">
                            <Clock className="w-3 h-3 text-[#f97316]" />
                            PENDING
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2 text-[#94a3b8]">
                          <Link
                            to={`/emails/${item.id}`}
                            className="p-1 hover:text-white transition-colors"
                            title="View Report"
                          >
                            <Eye className="w-4 h-4" />
                          </Link>
                          <button
                            onClick={() => handleDownload(item.id, item.subject)}
                            disabled={isPdfDownloading}
                            className="p-1 hover:text-white transition-colors disabled:opacity-50"
                            title="Download PDF Report"
                          >
                            <FileDown className={`w-4 h-4 ${isPdfDownloading ? 'animate-bounce text-[#3b82f6]' : ''}`} />
                          </button>
                          <button
                            onClick={() => setReportToDelete(item)}
                            className="p-1 hover:text-red-400 transition-colors"
                            title="Delete Forensic Report"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Table Footer Pagination ─────────────────────────────────────── */}
        <div className="p-3 bg-[#090d16] border-t border-[#232e42] flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-[#64748b] font-mono">
          <span>
            Showing {startItem} to {endItem} of {totalItems} entries (Page {page} of {totalPages})
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || isLoading}
              className="px-2.5 py-1 border border-[#232e42] rounded text-white bg-[#121824] hover:bg-[#1f2a3e] disabled:opacity-40 disabled:hover:bg-[#121824] transition-colors cursor-pointer font-bold text-xs"
              title="Previous Page"
            >
              &lt;
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || isLoading}
              className="px-2.5 py-1 border border-[#232e42] rounded text-white bg-[#121824] hover:bg-[#1f2a3e] disabled:opacity-40 disabled:hover:bg-[#121824] transition-colors cursor-pointer font-bold text-xs"
              title="Next Page"
            >
              &gt;
            </button>
          </div>
        </div>
      </div>

      {/* ── Delete Report Confirmation Modal ────────────────────────────────────── */}
      {reportToDelete && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#121824] border border-red-900/60 rounded-lg p-6 max-w-md w-full space-y-5 shadow-2xl animate-in fade-in zoom-in-95 duration-150 font-mono">
            <div className="flex items-center gap-3 pb-3 border-b border-[#232e42]">
              <div className="p-2 rounded bg-red-950/80 border border-red-800/60 text-red-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Delete Forensic Report</h3>
                <p className="text-xs text-[#94a3b8]">Permanent Purge Confirmation</p>
              </div>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <p>
                Are you sure you want to delete this forensic report record (<strong className="text-white">{reportToDelete.subject || reportToDelete.id.slice(0, 8)}</strong>)?
              </p>
              <div className="p-3 bg-red-950/40 border border-red-900/50 rounded text-red-200">
                ⚠️ <strong>Warning:</strong> Deleting this report permanently removes the evidence trace and analysis records from the database.
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setReportToDelete(null)}
                disabled={deleteAnalysis.isPending}
                className="px-4 py-2 bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] rounded text-xs font-semibold transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={async () => {
                  try {
                    await deleteAnalysis.mutateAsync(reportToDelete.id);
                    setReportToDelete(null);
                    await queryClient.invalidateQueries();
                    refetch();
                  } catch (err) {
                    console.error('Failed to delete report:', err);
                  }
                }}
                disabled={deleteAnalysis.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-bold transition-colors inline-flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
              >
                {deleteAnalysis.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                <span>Confirm Delete & Purge Report</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
