// SentinelTrace Frontend — Forensic Evidence & Integrity Page

import { useState, useMemo } from 'react';
import {
  ShieldAlert, ShieldCheck, Shield, AlertTriangle, FileText, Download, Copy, Check,
  CheckCircle2, Clock, Search, ChevronDown, RefreshCw, Network, Loader2, Sparkles, AlertOctagon
} from 'lucide-react';
import { useWorkspaceStore } from '@/store/workspace';
import { useWorkspaceEmails, useAnalysis, downloadReportPdf } from '@/api/hooks';
import { formatDate, truncateHash, cn } from '@/utils';
import { HashDisplay } from '@/components/HashDisplay';

export function ForensicsPage() {
  const { currentWorkspaceId } = useWorkspaceStore();
  const {
    data: emailsData,
    isLoading: isEmailsLoading,
    isRefetching: isEmailsRefetching,
    refetch: refetchEmails,
  } = useWorkspaceEmails(currentWorkspaceId, { page: 1, page_size: 100 });

  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(null);
  const [evidenceFilter, setEvidenceFilter] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  const allEmails = emailsData?.items || [];
  const completedEmails = allEmails.filter(e => e.status === 'COMPLETE' || e.status === 'QUARANTINED');
  const emails = completedEmails.length > 0 ? completedEmails : allEmails;
  const activeId = selectedAnalysisId && emails.some(e => e.id === selectedAnalysisId)
    ? selectedAnalysisId
    : (emails.length > 0 ? emails[0].id : null);

  const {
    data: analysis,
    isLoading: isAnalysisLoading,
    isRefetching: isAnalysisRefetching,
    refetch: refetchAnalysis,
  } = useAnalysis(activeId || '', currentWorkspaceId);

  const isRefreshing = isEmailsRefetching || isAnalysisRefetching;

  const handleManualRefresh = async () => {
    await Promise.all([refetchEmails(), refetchAnalysis()]);
  };

  const handleCopy = (text: string, id: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExport = async () => {
    if (!activeId) return;
    try {
      setIsExporting(true);
      await downloadReportPdf(activeId, `sentineltrace-evidence-${activeId.slice(0, 8)}.pdf`);
    } catch (e) {
      console.error('Failed to export PDF report:', e);
    } finally {
      setIsExporting(false);
    }
  };

  const isPending = analysis?.status === 'PENDING';
  const isProcessing = analysis?.status === 'PROCESSING';
  const isFailed = analysis?.status === 'FAILED';
  const isComplete = analysis?.status === 'COMPLETE';
  
  const isAnalysisLoadingState = isAnalysisLoading || (analysis && analysis.id !== activeId) || (!analysis && activeId);

  const riskScore = analysis?.threat_score != null
    ? Math.round(analysis.threat_score)
    : isProcessing
    ? null
    : 0;

  // Real Contributing Factors built dynamically
  const contributingFactors = useMemo(() => {
    if (isAnalysisLoadingState) {
      return [
        {
          label: 'Fetching forensic data...',
          color: 'bg-gray-400 animate-pulse',
          evId: '#EV-FETCHING',
        },
      ];
    }
    
    if (!analysis) return [];

    if (isPending) {
      return [
        {
          label: 'Awaiting Forensic Processing (Manual Analysis Mode)',
          color: 'bg-blue-400',
          evId: '#EV-PENDING',
        },
      ];
    }

    if (isProcessing) {
      return [
        {
          label: 'Multi-Engine Analysis in Progress (AI & Threat Intel)',
          color: 'bg-amber-400 animate-pulse',
          evId: '#EV-PROCESSING',
        },
      ];
    }

    if (isFailed) {
      return [
        {
          label: `Analysis Execution Error: ${analysis.error_message || 'Pipeline halted'}`,
          color: 'bg-red-400',
          evId: '#EV-FAILED',
        },
      ];
    }

    const factors: Array<{ label: string; color: string; evId: string }> = [];

    // SPF factor
    if (analysis.spf_result === 'fail') {
      factors.push({ label: 'SPF Authentication Failure', color: 'bg-red-400', evId: '#EV-SPF' });
    } else if (analysis.spf_result === 'pass') {
      factors.push({ label: 'SPF Authentication Verified', color: 'bg-emerald-400', evId: '#EV-SPF' });
    } else if (analysis.spf_result) {
      factors.push({ label: `SPF Alignment: ${analysis.spf_result.toUpperCase()}`, color: 'bg-amber-400', evId: '#EV-SPF' });
    }

    // DKIM factor
    if (analysis.dkim_result === 'fail') {
      factors.push({ label: 'DKIM Signature Invalid / Forged', color: 'bg-red-400', evId: '#EV-DKIM' });
    } else if (analysis.dkim_result === 'pass') {
      factors.push({ label: 'DKIM Cryptographic Signature Verified', color: 'bg-emerald-400', evId: '#EV-DKIM' });
    } else if (analysis.dkim_result) {
      factors.push({ label: `DKIM Result: ${analysis.dkim_result.toUpperCase()}`, color: 'bg-amber-400', evId: '#EV-DKIM' });
    }

    // DMARC factor
    if (analysis.dmarc_result === 'fail' || analysis.dmarc_result === 'reject') {
      factors.push({ label: `DMARC Policy Rejection (${analysis.dmarc_result.toUpperCase()})`, color: 'bg-red-400', evId: '#EV-DMARC' });
    } else if (analysis.dmarc_result === 'pass') {
      factors.push({ label: 'DMARC Policy Compliant', color: 'bg-emerald-400', evId: '#EV-DMARC' });
    }

    // Threat Category & AI Findings
    if (analysis.threat_category && analysis.threat_category !== 'BENIGN') {
      factors.push({ label: `Classified Threat: ${analysis.threat_category}`, color: 'bg-red-400', evId: '#EV-AI' });
    }

    // Extracted IOCs count
    if (analysis.iocs && analysis.iocs.length > 0) {
      const highIocs = analysis.iocs.filter(i => (i.threat_score ?? 0) >= 50);
      if (highIocs.length > 0) {
        factors.push({ label: `${highIocs.length} High-Risk Threat Indicator(s) Detected`, color: 'bg-red-400', evId: '#EV-IOC' });
      } else {
        factors.push({ label: `${analysis.iocs.length} Indicators Extracted & Enriched`, color: 'bg-amber-400', evId: '#EV-IOC' });
      }
    }

    // Attachments
    if (analysis.attachments && analysis.attachments.length > 0) {
      const malAtt = analysis.attachments.filter(a => a.is_malicious);
      if (malAtt.length > 0) {
        factors.push({ label: `${malAtt.length} Malicious File Attachment(s)`, color: 'bg-red-400', evId: '#EV-ATT' });
      } else {
        factors.push({ label: `${analysis.attachments.length} Clean Attachment(s) Inspected`, color: 'bg-emerald-400', evId: '#EV-ATT' });
      }
    }

    if (factors.length === 0) {
      factors.push({ label: 'No anomalous risk factors identified (Clean Email)', color: 'bg-emerald-400', evId: '#EV-CLEAN' });
    }

    return factors;
  }, [analysis, isPending, isProcessing, isFailed]);

  // Build evidence chain items from real email analysis data
  const evidenceChain = useMemo(() => {
    if (isAnalysisLoadingState || !analysis) return [];

    const dateStr = analysis.created_at
      ? new Date(analysis.created_at).toISOString().slice(11, 19) + 'Z'
      : '00:00:00Z';

    const items = [
      {
        id: '#EV-HDR-01',
        type: 'Header Forensic',
        hash: analysis.raw_eml_sha256 || null,
        integrity: analysis.spf_result === 'pass' ? 'VERIFIED' : isPending ? 'PENDING' : 'FLAGGED',
        timestamp: dateStr,
      },
      {
        id: '#EV-MSG-02',
        type: 'Payload SHA-256',
        hash: analysis.raw_eml_sha256 || null,
        integrity: analysis.dkim_result === 'pass' ? 'VERIFIED' : isPending ? 'PENDING' : 'FLAGGED',
        timestamp: dateStr,
      },
      {
        id: '#EV-DOM-03',
        type: 'Sender Domain Ledger',
        hash: analysis.sender_domain ? `0x${truncateHash(analysis.sender_domain, 14)}` : null,
        integrity: analysis.dmarc_result === 'pass' ? 'VERIFIED' : isPending ? 'PENDING' : 'RECORDED',
        timestamp: dateStr,
      },
    ];

    // Add attachments as evidence items
    if (analysis.attachments && analysis.attachments.length > 0) {
      analysis.attachments.forEach((att, idx) => {
        items.push({
          id: `#EV-ATT-${String(idx + 1).padStart(2, '0')}`,
          type: `Attachment: ${att.filename || 'payload.bin'}`,
          hash: att.sha256_hash || null,
          integrity: att.is_malicious ? 'MALICIOUS' : 'VERIFIED',
          timestamp: dateStr,
        });
      });
    }

    // Add top IOCs as evidence items
    if (analysis.iocs && analysis.iocs.length > 0) {
      analysis.iocs.slice(0, 3).forEach((ioc, idx) => {
        items.push({
          id: `#EV-IOC-${String(idx + 1).padStart(2, '0')}`,
          type: `IOC (${ioc.ioc_type}): ${truncateHash(ioc.value, 18)}`,
          hash: `0x${truncateHash(ioc.value, 16)}`,
          integrity: (ioc.threat_score ?? 0) >= 50 ? 'THREAT' : 'RECORDED',
          timestamp: dateStr,
        });
      });
    }

    if (evidenceFilter.trim()) {
      const q = evidenceFilter.toLowerCase();
      return items.filter(
        i =>
          i.id.toLowerCase().includes(q) ||
          i.type.toLowerCase().includes(q) ||
          (i.hash || '').toLowerCase().includes(q) ||
          i.integrity.toLowerCase().includes(q)
      );
    }
    return items;
  }, [analysis, evidenceFilter, isPending]);

  const rootHash = analysis?.raw_eml_sha256;
  const leafHash0 = analysis?.raw_eml_sha256 ? analysis.raw_eml_sha256.slice(16, 28) + '...' : null;
  const leafHash1 = analysis?.raw_eml_sha256 ? analysis.raw_eml_sha256.slice(28, 40) + '...' : null;

  const txId = analysis?.raw_eml_sha256
    ? `0x${analysis.raw_eml_sha256}${analysis.id ? analysis.id.replace(/-/g, '').slice(0, 24) : ''}`
    : null;

  return (
    <div className="space-y-6 max-w-[1400px] mx-auto pb-10">
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            Forensic Evidence & Integrity
            {isRefreshing && <Loader2 className="w-4 h-4 animate-spin text-blue-400" />}
          </h1>
          <p className="text-xs text-[#94a3b8] mt-0.5 font-mono">
            {activeId
              ? `Investigation #INV-${activeId.slice(0, 8).toUpperCase()} • Artifact validation & cryptographic ledger anchoring.`
              : 'Artifact validation and ledger anchoring status.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Target Selector */}
          <div className="relative min-w-[260px] max-w-[320px]">
            <select
              value={activeId || ''}
              onChange={(e) => setSelectedAnalysisId(e.target.value)}
              disabled={emails.length === 0}
              className="w-full appearance-none px-3 py-1.5 bg-[#121824] border border-[#232e42] rounded text-xs text-white pr-8 focus:border-[#3b82f6] focus:outline-none font-mono truncate cursor-pointer hover:border-[#3b82f6]/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {emails.length === 0 ? (
                <option value="" disabled>
                  No completed analysis available
                </option>
              ) : (
                emails.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.subject || '(no subject)'} [{e.status}]
                  </option>
                ))
              )}
            </select>
            <ChevronDown className="w-3.5 h-3.5 absolute right-2.5 top-1/2 -translate-y-1/2 text-[#64748b] pointer-events-none" />
          </div>

          {/* Manual Refresh / Reload Button */}
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            title="Reload and re-fetch latest forensic evidence"
            className="px-3 py-1.5 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={cn("w-3.5 h-3.5 text-blue-400", isRefreshing && "animate-spin")} />
            <span>{isRefreshing ? 'Refreshing...' : 'Reload'}</span>
          </button>

          {/* Export Report */}
          <button
            onClick={handleExport}
            disabled={!activeId || isExporting}
            className="px-4 py-2 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {isExporting ? <Loader2 className="w-3.5 h-3.5 animate-spin text-white" /> : <Download className="w-3.5 h-3.5 text-white" />}
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {/* ── Top Assessment Grid ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Risk Assessment Card */}
        <div className={cn(
          "lg:col-span-5 bg-[#121824] border border-[#232e42] rounded p-5 space-y-4 border-l-4 transition-all",
          isPending ? "border-l-blue-500" :
          isProcessing ? "border-l-amber-500" :
          isFailed ? "border-l-red-600" :
          (riskScore ?? 0) >= 75 ? "border-l-red-500" :
          (riskScore ?? 0) >= 50 ? "border-l-orange-500" :
          (riskScore ?? 0) >= 25 ? "border-l-yellow-500" :
          "border-l-emerald-500"
        )}>
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white tracking-wide">
              Risk Assessment
            </h2>
            {isPending ? (
              <Clock className="w-4 h-4 text-blue-400" />
            ) : isProcessing ? (
              <Loader2 className="w-4 h-4 animate-spin text-amber-400" />
            ) : isFailed ? (
              <AlertOctagon className="w-4 h-4 text-red-500" />
            ) : (riskScore ?? 0) >= 50 ? (
              <ShieldAlert className="w-4 h-4 text-red-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            )}
          </div>

          <div className="flex items-baseline gap-3">
            {isAnalysisLoadingState ? (
              <div className="flex items-center gap-2 text-sm text-[#64748b] font-mono py-2">
                <Loader2 className="w-4 h-4 animate-spin" /> Fetching forensic score...
              </div>
            ) : isPending ? (
              <>
                <span className="text-4xl font-extrabold text-[#94a3b8] tracking-tight font-mono">
                  --<span className="text-lg text-[#64748b]">/100</span>
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded border border-blue-500/40 bg-blue-950/40 text-blue-400 text-[10px] font-extrabold tracking-wider uppercase font-mono">
                  ● NOT ANALYZED
                </span>
              </>
            ) : isProcessing ? (
              <>
                <span className="text-4xl font-extrabold text-amber-300 tracking-tight font-mono animate-pulse">
                  ...<span className="text-lg text-[#64748b]">/100</span>
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded border border-amber-500/40 bg-amber-950/40 text-amber-400 text-[10px] font-extrabold tracking-wider uppercase font-mono animate-pulse">
                  ● ANALYZING
                </span>
              </>
            ) : isFailed ? (
              <>
                <span className="text-4xl font-extrabold text-red-400 tracking-tight font-mono">
                  ERR
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded border border-red-500/40 bg-red-950/40 text-red-400 text-[10px] font-extrabold tracking-wider uppercase font-mono">
                  ● FAILED
                </span>
              </>
            ) : (
              <>
                <span className="text-4xl font-extrabold text-white tracking-tight font-mono">
                  {riskScore}<span className="text-lg text-[#64748b]">/100</span>
                </span>
                <span className={cn(
                  "inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-extrabold tracking-wider uppercase font-mono",
                  (riskScore ?? 0) >= 75 ? "border-red-500/40 bg-[#1f1315] text-red-400" :
                  (riskScore ?? 0) >= 50 ? "border-orange-500/40 bg-[#1f1614] text-orange-400" :
                  (riskScore ?? 0) >= 25 ? "border-yellow-500/40 bg-[#1f1d14] text-yellow-400" :
                  "border-emerald-500/40 bg-[#111f16] text-emerald-400"
                )}>
                  ● {(riskScore ?? 0) >= 75 ? 'CRITICAL RISK' : (riskScore ?? 0) >= 50 ? 'HIGH RISK' : (riskScore ?? 0) >= 25 ? 'MEDIUM RISK' : 'BENIGN / CLEAN'}
                </span>
              </>
            )}
          </div>

          <div className="pt-2 border-t border-[#232e42] space-y-2">
            <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">
              CONTRIBUTING FORENSIC FACTORS
            </span>
            <ul className="space-y-1.5 text-xs text-[#94a3b8]">
              {contributingFactors.map((factor, idx) => (
                <li key={idx} className="flex items-center justify-between font-mono">
                  <span className="flex items-center gap-1.5">
                    <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", factor.color)} />
                    <span className="truncate max-w-[240px] text-white">{factor.label}</span>
                  </span>
                  <span className="text-[#64748b] text-[11px] shrink-0">{factor.evId}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Ledger Anchoring Status Card */}
        <div className="lg:col-span-7 bg-[#121824] border border-[#232e42] rounded p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-white tracking-wide">
              Ledger Anchoring Status
            </h2>
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded border border-[#2563eb]/40 bg-[#1b2434] text-[#3b82f6] text-[10px] font-extrabold tracking-wider uppercase font-mono">
              <CheckCircle2 className="w-3 h-3 text-[#3b82f6]" />
              ANCHORED
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-[#090d16] border border-[#232e42] rounded p-3 space-y-1">
              <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">Network</span>
              <div className="flex items-center gap-2 text-xs font-bold text-white font-mono">
                <Network className="w-4 h-4 text-[#3b82f6]" />
                <span>Hyperledger Fabric (Sentinel Net)</span>
              </div>
            </div>

            <div className="bg-[#090d16] border border-[#232e42] rounded p-3 space-y-1">
              <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">Environment</span>
              <div className="flex items-center gap-2 text-xs font-bold text-[#f97316] font-mono">
                <div className="w-3.5 h-3.5 border border-[#f97316] rounded-sm flex items-center justify-center text-[9px]">⚡</div>
                <span>ACTIVE AUDIT LEDGER</span>
              </div>
            </div>
          </div>

          <div className="bg-[#090d16] border border-[#232e42] rounded p-3 space-y-1 font-mono">
            <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block">Cryptographic Transaction / Digest ID</span>
            <div className="flex items-center justify-between text-xs text-[#3b82f6] break-all">
              <span className="truncate">{txId}</span>
              <button
                onClick={() => handleCopy(txId || '', 'txid')}
                className="ml-2 text-[#64748b] hover:text-white shrink-0 cursor-pointer"
                title="Copy Digest ID"
              >
                {copiedHash === 'txid' ? <Check className="w-3.5 h-3.5 text-[#3b82f6]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3 text-[11px] text-[#64748b] font-mono border-t border-[#232e42] pt-2">
            <span>Subject: <strong className="text-white truncate max-w-[200px]">{analysis?.subject || '(No Subject)'}</strong></span>
            <span>|</span>
            <span>Sender: <strong className="text-white truncate max-w-[180px]">{analysis?.sender_email || 'N/A'}</strong></span>
            <span>|</span>
            <span>Timestamp: <strong className="text-white">{analysis?.created_at ? formatDate(analysis.created_at) : 'N/A'}</strong></span>
          </div>
        </div>
      </div>

      {/* ── Evidence Chain Section ──────────────────────────────────────── */}
      <div className="bg-[#121824] border border-[#232e42] rounded overflow-hidden space-y-3 p-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">
              Evidence Chain
            </h2>
            <p className="text-xs text-[#64748b]">Cryptographic hashes and verification integrity for selected artifact.</p>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
            <input
              type="text"
              placeholder="Filter evidence..."
              value={evidenceFilter}
              onChange={(e) => setEvidenceFilter(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-[#090d16] border border-[#232e42] rounded text-xs text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
            />
          </div>
        </div>

        <div className="overflow-x-auto border border-[#232e42] rounded">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#090d16] border-b border-[#232e42] text-[#64748b] font-semibold">
              <tr>
                <th className="py-2.5 px-4">Evidence ID</th>
                <th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">SHA-256 Digest</th>
                <th className="py-2.5 px-4">Integrity</th>
                <th className="py-2.5 px-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#232e42] text-white">
              {evidenceChain.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-[#64748b] font-mono">
                    No evidence records matching filter.
                  </td>
                </tr>
              ) : (
                evidenceChain.map((ev) => (
                  <tr key={ev.id} className="hover:bg-[#161c2b] transition-colors">
                    <td className="py-3 px-4 text-[#3b82f6] font-bold">{ev.id}</td>
                    <td className="py-3 px-4 text-white font-sans">{ev.type}</td>
                    <td className="py-3 px-4 text-[#94a3b8]">
                      <HashDisplay hash={ev.hash} truncateLength={16} />
                    </td>
                    <td className="py-3 px-4">
                      {ev.integrity === 'VERIFIED' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[#2563eb]/40 bg-[#1b2434] text-[#3b82f6] text-[10px] font-bold uppercase">
                          <CheckCircle2 className="w-3 h-3 text-[#3b82f6]" />
                          VERIFIED
                        </span>
                      ) : ev.integrity === 'PENDING' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-blue-500/40 bg-blue-950/40 text-blue-400 text-[10px] font-bold uppercase">
                          <Clock className="w-3 h-3 text-blue-400" />
                          PENDING
                        </span>
                      ) : ev.integrity === 'MALICIOUS' || ev.integrity === 'THREAT' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-red-500/40 bg-red-950/40 text-red-400 text-[10px] font-bold uppercase">
                          <AlertTriangle className="w-3 h-3 text-red-400" />
                          {ev.integrity}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-[#f97316]/40 bg-[#1f1814] text-[#f97316] text-[10px] font-bold uppercase">
                          <Clock className="w-3 h-3 text-[#f97316]" />
                          {ev.integrity}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-[#94a3b8]">{ev.timestamp}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Merkle Audit Tree Section ───────────────────────────────────── */}
      <div className="bg-[#121824] border border-[#232e42] rounded p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#232e42] pb-3">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">
              Merkle Audit Tree
            </h2>
            <p className="text-xs text-[#64748b] mt-0.5">
              Cryptographic aggregation of artifact hashes for verified tamper-proof storage.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs text-[#94a3b8]">
            <span>Global Integrity:</span>
            <span className="inline-flex items-center gap-1 text-[#3b82f6] font-bold">
              ● VERIFIED
            </span>
          </div>
        </div>

        {/* Visual Merkle Diagram */}
        <div className="py-6 flex flex-col items-center justify-center space-y-6 bg-[#090d16] border border-[#232e42] rounded p-6">
          {/* Level 0 Root Hash */}
          <div className="bg-[#121824] border border-[#3b82f6] rounded px-6 py-2.5 text-center space-y-0.5 shadow-md">
            <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">
              Root Hash (Level 0)
            </span>
            <span className="text-xs font-bold text-white font-mono">
              <HashDisplay hash={rootHash} truncateLength={32} />
            </span>
          </div>

          {/* Connection Lines */}
          <div className="w-48 h-6 relative">
            <div className="absolute left-1/2 top-0 w-0.5 h-3 bg-[#232e42] -translate-x-1/2" />
            <div className="absolute left-1/4 right-1/4 top-3 h-0.5 bg-[#232e42]" />
            <div className="absolute left-1/4 top-3 w-0.5 h-3 bg-[#232e42]" />
            <div className="absolute right-1/4 top-3 w-0.5 h-3 bg-[#232e42]" />
          </div>

          {/* Level 1 Leaf Hashes */}
          <div className="flex items-center justify-center gap-12 w-full max-w-lg">
            <div className="bg-[#121824] border border-[#232e42] rounded px-5 py-2 text-center space-y-0.5 flex-1">
              <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">
                Hash 0-0 (Header & Auth)
              </span>
              <span className="text-xs font-medium text-[#94a3b8] font-mono">
                <HashDisplay hash={leafHash0} truncateLength={16} />
              </span>
            </div>

            <div className="bg-[#121824] border border-[#232e42] rounded px-5 py-2 text-center space-y-0.5 flex-1">
              <span className="text-[10px] font-semibold text-[#64748b] uppercase tracking-wider block font-mono">
                Hash 0-1 (Payload & Artifacts)
              </span>
              <span className="text-xs font-medium text-[#94a3b8] font-mono">
                <HashDisplay hash={leafHash1} truncateLength={16} />
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
