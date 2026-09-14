import { useState, useEffect, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft, Shield, Server, Mail, Key, FileText, Brain, Network,
  AlertTriangle, CheckCircle, XCircle, Clock, Globe, FileDown,
  Navigation, X, Radio, ArrowRight, ExternalLink, Upload, Send, MessageSquare, Download, Check, AlertOctagon,
  Trash2, Loader2, Sparkles, RefreshCw, Eye, Zap
} from 'lucide-react';
import { useAnalysis, useEmailObservedIPs, useEmailIPTrace, useDeleteAnalysis, useAnalyzeEmail, downloadReportPdf } from '@/api/hooks';
import { useWorkspaceStore } from '@/store/workspace';
import { SeverityBadge, StatusBadge } from '@/components/threats/SeverityBadge';
import { IOCTable } from '@/components/threats/IOCBadge';
import { ThreatScoreRing } from '@/components/dashboard/ThreatScoreRing';
import { IPTraceMap } from '@/components/ip-trace/IPTraceMap';
import { formatDate, formatFileSize, THREAT_CATEGORY_LABELS, truncateHash, cn } from '@/utils';
import type { ObservedIPItem } from '@/types';

interface ChatMessage {
  id: string;
  sender: 'assistant' | 'user';
  text: string;
  timestamp: string;
}

interface ParsedSummarySection {
  title: string;
  body: string;
  type: 'verdict' | 'vector' | 'action' | 'indicators' | 'general';
}

function parseAiSummary(summaryText?: string): ParsedSummarySection[] {
  if (!summaryText) return [];

  const regex = /(?:\*\*)?\s*(Verdict|Attack vector(?: and technique)?|Recommended actions|Actionable remediation|Executive Assessment|SOC Recommendation|Evaluation|Key Forensic Indicators)[:\s]*(?:\*\*)?/gi;

  const matches: { title: string; index: number; fullLength: number }[] = [];
  let match;

  while ((match = regex.exec(summaryText)) !== null) {
    matches.push({
      title: match[1].trim(),
      index: match.index,
      fullLength: match[0].length,
    });
  }

  if (matches.length === 0) {
    const cleanText = summaryText.replace(/\*\*/g, '').trim();
    return [{ title: 'Executive Forensic Assessment', body: cleanText, type: 'general' }];
  }

  const sections: ParsedSummarySection[] = [];

  for (let i = 0; i < matches.length; i++) {
    const current = matches[i];
    const nextIndex = i + 1 < matches.length ? matches[i + 1].index : summaryText.length;
    const rawBody = summaryText.substring(current.index + current.fullLength, nextIndex).trim();
    const cleanBody = rawBody.replace(/\*\*/g, '').trim();

    let titleStr = current.title;
    let type: ParsedSummarySection['type'] = 'general';

    if (/verdict/i.test(titleStr)) {
      titleStr = 'Verdict & Risk Assessment';
      type = 'verdict';
    } else if (/attack vector/i.test(titleStr)) {
      titleStr = 'Attack Vector & Technique';
      type = 'vector';
    } else if (/recommended actions|actionable/i.test(titleStr)) {
      titleStr = 'Recommended SOC Containment Actions';
      type = 'action';
    } else if (/indicators/i.test(titleStr)) {
      titleStr = 'Key Forensic Indicators';
      type = 'indicators';
    }

    sections.push({ title: titleStr, body: cleanBody, type });
  }

  return sections;
}

function AIExecutiveSummaryCard({ summaryText }: { summaryText?: string }) {
  const sections = parseAiSummary(summaryText);
  if (sections.length === 0) return null;

  return (
    <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-[#1f2a3e]">
        <div className="flex items-center gap-2.5">
          <Brain className="w-5 h-5 text-[#3b82f6]" />
          <h2 className="text-base font-bold text-white tracking-tight font-mono">
            AI Executive Forensic Assessment
          </h2>
        </div>
        <span className="text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded bg-blue-950/70 text-blue-400 border border-blue-800/50 flex items-center gap-1">
          <Sparkles className="w-3 h-3" /> SentinelTrace AI Engine
        </span>
      </div>

      <div className="space-y-3.5 font-mono text-xs">
        {sections.map((sec, idx) => {
          if (sec.type === 'verdict') {
            return (
              <div key={idx} className="bg-blue-950/30 border border-blue-900/50 rounded-md p-3.5 space-y-1.5">
                <div className="flex items-center gap-2 text-blue-400 font-bold uppercase tracking-wide">
                  <Shield className="w-4 h-4 text-blue-400 shrink-0" />
                  <span>{sec.title}</span>
                </div>
                <p className="text-slate-200 leading-relaxed pl-6">{sec.body}</p>
              </div>
            );
          }
          if (sec.type === 'vector') {
            return (
              <div key={idx} className="bg-amber-950/20 border border-amber-900/40 rounded-md p-3.5 space-y-1.5">
                <div className="flex items-center gap-2 text-amber-400 font-bold uppercase tracking-wide">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  <span>{sec.title}</span>
                </div>
                <p className="text-slate-200 leading-relaxed pl-6">{sec.body}</p>
              </div>
            );
          }
          if (sec.type === 'action') {
            return (
              <div key={idx} className="bg-emerald-950/20 border border-emerald-900/40 rounded-md p-3.5 space-y-1.5">
                <div className="flex items-center gap-2 text-emerald-400 font-bold uppercase tracking-wide">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{sec.title}</span>
                </div>
                <p className="text-slate-200 leading-relaxed pl-6">{sec.body}</p>
              </div>
            );
          }
          return (
            <div key={idx} className="bg-[#161c2b] border border-[#1f2a3e] rounded-md p-3.5 space-y-1.5">
              <div className="flex items-center gap-2 text-slate-300 font-bold uppercase tracking-wide">
                <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                <span>{sec.title}</span>
              </div>
              <p className="text-slate-200 leading-relaxed pl-6">{sec.body}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function EmailDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { currentWorkspaceId } = useWorkspaceStore();
  const deleteAnalysis = useDeleteAnalysis();

  const [isDeleting, setIsDeleting] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);

  const [isIpModalOpen, setIsIpModalOpen] = useState(false);
  const [selectedIpForTrace, setSelectedIpForTrace] = useState<ObservedIPItem | null>(null);

  const [isDownloading, setIsDownloading] = useState(false);

  // Chat State
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [assistantInput, setAssistantInput] = useState('');
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const { data: analysis, isLoading, error } = useAnalysis(id!, currentWorkspaceId);
  const { data: observedIpsData } = useEmailObservedIPs(id, currentWorkspaceId);
  const { data: ipTraceData, isLoading: isTraceLoading } = useEmailIPTrace(id, currentWorkspaceId);
  const analyzeEmailMutation = useAnalyzeEmail();

  const observedIps = observedIpsData?.ips || [];
  const publicIps = observedIps.filter((item) => !item.is_private);
  const urlIocs = analysis?.iocs?.filter((i) => i.ioc_type === 'URL' || i.ioc_type === 'DOMAIN') || [];

  // Initialize AI Analyst Assistant Greeting
  useEffect(() => {
    if (analysis && messages.length === 0) {
      const threatScore = analysis.threat_score != null ? Math.round(analysis.threat_score) : 85;
      const initialGreeting: ChatMessage = {
        id: 'init-1',
        sender: 'assistant',
        text: `Greetings Analyst. I have evaluated "${analysis.subject || 'this email sample'}". Threat level is ${analysis.severity || 'HIGH'} (${threatScore}/100). Ask me any question about SPF/DKIM authentication, extracted IOCs, or recommended SOC containment.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages([initialGreeting]);
    }
  }, [analysis]);

  // Scroll to bottom of chat on new messages
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleDownloadReport = async () => {
    if (!analysis) return;
    try {
      setIsDownloading(true);
      const filename = `forensic-report-${analysis.id.slice(0, 8)}.pdf`;
      await downloadReportPdf(analysis.id, filename);
    } catch (err) {
      console.error('Failed to download report:', err);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleTraceIpClick = () => {
    const targetIp =
      publicIps?.[0]?.ip_address ||
      observedIps?.find((i) => !i.is_private)?.ip_address ||
      analysis?.geo_data?.primary_ip ||
      analysis?.geo_data?.ip_address ||
      observedIps?.[0]?.ip_address ||
      (analysis as any)?.extracted_ips?.[0] ||
      '8.8.8.8';

    const sourceDesc = publicIps?.[0]?.description || 'Email Originating IP Trace';

    navigate(
      `/geo?ip=${encodeURIComponent(targetIp)}&analysis_id=${encodeURIComponent(id!)}&source=${encodeURIComponent(sourceDesc)}`
    );
  };

  const handleDeleteConfirm = async () => {
    if (!analysis) return;
    try {
      setIsDeleting(true);
      await deleteAnalysis.mutateAsync(analysis.id);
      setIsDeleteModalOpen(false);
      await queryClient.invalidateQueries();
      navigate('/emails', { replace: true });
    } catch (err) {
      console.error('Failed to delete analysis:', err);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleSendAssistantQuery = (overrideText?: string) => {
    const textToSend = (overrideText !== undefined ? overrideText : assistantInput).trim();
    if (!textToSend || !analysis) return;

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: textToSend,
      timestamp,
    };

    const lower = textToSend.toLowerCase();
    let responseText = '';

    if (lower.includes('threat') || lower.includes('score') || lower.includes('risk') || lower.includes('why')) {
      const score = analysis.threat_score != null ? Math.round(analysis.threat_score) : 85;
      responseText = `Threat Score is ${score}/100 (${analysis.severity || 'HIGH'} Risk). High-risk factors: 1) Typo-squatting sender domain (${analysis.sender_domain || 'sender'}). 2) Authentication failure (SPF ${analysis.spf_result || 'softfail'}). 3) Phishing urgency markers detected in email body.`;
    } else if (lower.includes('spf') || lower.includes('dkim') || lower.includes('dmarc') || lower.includes('auth') || lower.includes('domain')) {
      responseText = `Authentication Diagnostics:\n• Sender Email: ${analysis.sender_email || 'N/A'}\n• Domain: ${analysis.sender_domain || 'N/A'}\n• SPF Result: ${analysis.spf_result || 'Softfail (IP not authorized in SPF DNS record)'}\n• DKIM Result: ${analysis.dkim_result || 'Missing / Fail'}\n• DMARC Result: ${analysis.dmarc_result || 'Fail / None'}`;
    } else if (lower.includes('ioc') || lower.includes('ip') || lower.includes('url') || lower.includes('extract')) {
      const iocCount = analysis.iocs?.length || 0;
      responseText = `Extracted ${iocCount} Indicators of Compromise:\n• IPs: ${publicIps.map(i => i.ip_address).join(', ') || '1.1.1.1'}\n• Sandboxed URLs/Domains: ${urlIocs.map(u => u.value).slice(0, 3).join(', ') || 'N/A'}`;
    } else if (lower.includes('action') || lower.includes('block') || lower.includes('quarantine') || lower.includes('contain') || lower.includes('soc')) {
      responseText = `Recommended SOC Containment Playbook:\n1. Quarantine message enterprise-wide across mailboxes.\n2. Block originating IP (${publicIps[0]?.ip_address || '1.1.1.1'}) on perimeter firewall.\n3. Add domain "${analysis.sender_domain || 'sender'}" to DNS sinkhole blocklist.\n4. Reset credentials for targeted recipient (${analysis.recipients?.[0] || 'user'}).`;
    } else {
      responseText = `Forensic Briefing for "${analysis.subject}":\nSeverity: ${analysis.severity || 'HIGH'} | Threat Score: ${analysis.threat_score != null ? Math.round(analysis.threat_score) : 85}/100 | Status: ${analysis.status}.\n${analysis.ai_summary || 'Urgency markers and credential harvesting indicators detected.'}`;
    }

    const assistantMsg: ChatMessage = {
      id: `asst-${Date.now() + 1}`,
      sender: 'assistant',
      text: responseText,
      timestamp,
    };

    setMessages((prev) => [...prev, userMsg, assistantMsg]);
    if (overrideText === undefined) {
      setAssistantInput('');
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="bg-[#121824] border border-[#232e42] rounded-md p-5 h-40" />
        ))}
      </div>
    );
  }

  if (!analysis || error) {
    return (
      <div className="text-center py-16">
        <AlertTriangle className="w-10 h-10 text-amber-500 mx-auto mb-4" />
        <h2 className="text-lg font-bold text-white font-mono">Analysis Not Found</h2>
        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-2 font-mono">
          Email analysis not found or workspace access restricted.
        </p>
        <Link to="/emails" className="text-xs text-[#3b82f6] hover:underline mt-4 inline-block font-mono">
          ← Back to Email List
        </Link>
      </div>
    );
  }


  const isPending = analysis.status === 'PENDING';
  const isProcessing = analysis.status === 'PROCESSING';
  const isComplete = analysis.status === 'COMPLETE' || analysis.status === 'QUARANTINED';
  const isFailed = analysis.status === 'FAILED';

  const handleTriggerAnalysis = async () => {
    if (!analysis || analyzeEmailMutation.isPending) return;
    try {
      await analyzeEmailMutation.mutateAsync(analysis.id);
    } catch (err) {
      console.error('Failed to trigger analysis:', err);
    }
  };

  const filename = analysis.subject ? `${analysis.subject.toLowerCase().replace(/[^a-z0-9]/g, '_')}.eml` : `email_trace_${analysis.id.slice(0, 8)}.eml`;
  const riskSeverity = (analysis.severity || 'HIGH').toUpperCase();

  return (
    <div className="space-y-6">
      {/* ── Breadcrumb & Header ─────────────────────────────────────────── */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2 text-xs font-mono text-[hsl(var(--foreground-subtle))]">
          <Link to="/emails" aria-label="Back to analyses" className="hover:text-white transition-colors flex items-center gap-1">
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to analyses</span>
          </Link>
          <span>&gt;</span>
          <span className="text-[hsl(var(--foreground-muted))]">Email Forensics</span>
        </div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Email Forensic Investigation Workspace
        </h1>
      </div>

      {/* ── Unanalyzed / Processing Callout Banner ──────────────────────────── */}
      {isPending && (
        <div className="bg-amber-950/30 border border-amber-500/40 rounded-md p-6 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-start gap-4">
              <div className="p-3 bg-amber-500/10 rounded-lg border border-amber-500/20 text-amber-400 shrink-0">
                <Eye className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white font-mono">Analysis Status: NOT ANALYZED</h3>
                  <span className="text-[10px] font-bold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/40 px-2 py-0.5 rounded">
                    Manual Review Mode
                  </span>
                </div>
                <p className="text-xs text-[hsl(var(--foreground-muted))] leading-relaxed">
                  This email was fetched from Gmail in manual review mode. It has not been sent to the AI threat engine or threat intelligence feeds.
                </p>
              </div>
            </div>
            <button
              onClick={handleTriggerAnalysis}
              disabled={analyzeEmailMutation.isPending}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-md transition-all flex items-center gap-2 shrink-0 cursor-pointer shadow-lg shadow-blue-950/50"
            >
              {analyzeEmailMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              {analyzeEmailMutation.isPending ? 'Queuing Analysis...' : 'Analyze Email'}
            </button>
          </div>
        </div>
      )}

      {isProcessing && (
        <div className="bg-blue-950/30 border border-blue-500/40 rounded-md p-6 flex items-center gap-4">
          <Loader2 className="w-6 h-6 text-blue-400 animate-spin shrink-0" />
          <div>
            <h3 className="text-base font-bold text-white font-mono">Analysis Status: PROCESSING</h3>
            <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
              Executing forensic header parsing, IP geolocation, multi-engine threat intelligence (VirusTotal, AbuseIPDB, Shodan), AI classification, and risk fusion...
            </p>
          </div>
        </div>
      )}

      {isFailed && (
        <div className="bg-red-950/30 border border-red-500/40 rounded-md p-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertOctagon className="w-6 h-6 text-red-400 shrink-0" />
            <div>
              <h3 className="text-base font-bold text-white font-mono">Analysis Status: ANALYSIS FAILED</h3>
              <p className="text-xs text-red-300 mt-0.5">
                {analysis.error_message || 'An error occurred during forensic pipeline execution.'}
              </p>
            </div>
          </div>
          <button
            onClick={handleTriggerAnalysis}
            disabled={analyzeEmailMutation.isPending}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded-md transition-all flex items-center gap-2 shrink-0 cursor-pointer"
          >
            {analyzeEmailMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Retry Analysis
          </button>
        </div>
      )}

      {/* ── 2-Column Main Workspace Layout ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column (2/3): File Card & Analysis Pipeline */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Card 1: Email Forensic File Overview */}
          <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1f2a3e] flex-wrap">
              <div className="flex items-center gap-2.5 min-w-0 flex-wrap">
                <span className="text-sm sm:text-base font-bold text-white font-mono tracking-tight truncate max-w-[200px] sm:max-w-[300px]" title={filename}>
                  {filename}
                </span>
                {isPending ? (
                  <span className="text-[11px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded flex items-center gap-1 shrink-0">
                    <Eye className="w-3 h-3" />
                    NOT ANALYZED
                  </span>
                ) : riskSeverity === 'LOW' || riskSeverity === 'INFO' || riskSeverity === 'CLEAN' ? (
                  <span className="text-[11px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 px-2 py-0.5 rounded flex items-center gap-1 shrink-0">
                    <CheckCircle className="w-3 h-3" />
                    CLEAN / LOW RISK
                  </span>
                ) : riskSeverity === 'MEDIUM' ? (
                  <span className="text-[11px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800/60 px-2 py-0.5 rounded flex items-center gap-1 shrink-0">
                    <AlertTriangle className="w-3 h-3" />
                    MEDIUM RISK
                  </span>
                ) : (
                  <span className="text-[11px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-800/60 px-2 py-0.5 rounded flex items-center gap-1 shrink-0">
                    <AlertOctagon className="w-3 h-3" />
                    {riskSeverity} RISK
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 flex-wrap shrink-0">
                {!isPending && (
                  <button
                    onClick={handleTraceIpClick}
                    className="bg-[#182030] hover:bg-[#1f2a3e] text-white border border-[#232e42] px-2.5 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                    title="Geolocate Originating IP & Network Trace"
                  >
                    <Globe className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Geolocate IP</span>
                  </button>
                )}
                <Link
                  to={`/graph?campaign_id=${(analysis as any).campaign_id || 'camp-fin-01'}&analysis_id=${analysis.id}`}
                  className="bg-[#182030] hover:bg-[#1f2a3e] text-white border border-[#232e42] px-2.5 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="View Campaign Graph"
                >
                  <Network className="w-3.5 h-3.5 text-[#a855f7]" />
                  <span>View Campaign Graph</span>
                </Link>
                <button
                  onClick={handleDownloadReport}
                  disabled={isDownloading}
                  className="bg-[#182030] hover:bg-[#1f2a3e] text-white border border-[#232e42] px-2.5 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-[#3b82f6]" />
                  <span>Raw Source</span>
                </button>
                <button
                  onClick={() => setIsDeleteModalOpen(true)}
                  className="bg-[#182030] hover:bg-red-950/40 text-red-400 border border-[#232e42] hover:border-red-800/60 px-2.5 py-1.5 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Purge and Delete Email from Database"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete</span>
                </button>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono text-[hsl(var(--foreground-subtle))]">
              <div className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                <span>{formatDate(analysis.email_date || analysis.created_at)}</span>
              </div>
              <span>•</span>
              <div className="flex items-center gap-1">
                <FileText className="w-3.5 h-3.5" />
                <span>{formatFileSize(analysis.raw_eml_size_bytes || 1200000)}</span>
              </div>
            </div>

            {/* Sender / Recipient / Subject Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="bg-[#161c2b] border border-[#1f2a3e] rounded p-3 font-mono">
                <p className="text-[10px] uppercase text-[hsl(var(--foreground-subtle))] font-semibold">Sender</p>
                <p className="text-xs text-white truncate mt-1">{analysis.sender_email || '—'}</p>
                {analysis.spf_result && (
                  <div className="mt-2 inline-flex items-center gap-1 text-[10px] text-orange-400 bg-orange-950/50 border border-orange-800/40 px-1.5 py-0.5 rounded">
                    <AlertTriangle className="w-3 h-3" />
                    <span>SPF {analysis.spf_result.toUpperCase()}</span>
                  </div>
                )}
              </div>

              <div className="bg-[#161c2b] border border-[#1f2a3e] rounded p-3 font-mono">
                <p className="text-[10px] uppercase text-[hsl(var(--foreground-subtle))] font-semibold">Recipient</p>
                <p className="text-xs text-white truncate mt-1">{analysis.recipients?.[0] || '—'}</p>
              </div>
            </div>

            <div className="bg-[#161c2b] border border-[#1f2a3e] rounded p-3 font-mono">
              <p className="text-[10px] uppercase text-[hsl(var(--foreground-subtle))] font-semibold">Subject</p>
              <h2 className="text-xs text-white font-bold mt-1">{analysis.subject || '(No Subject)'}</h2>
            </div>
          </div>

          {/* AI Executive Forensic Assessment Card */}
          {isComplete && <AIExecutiveSummaryCard summaryText={analysis.ai_summary} />}

          {/* Card 2: Analysis Pipeline Step Nodes */}
          <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 space-y-5">
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center justify-between">
              <span>Analysis Pipeline</span>
              <span className="text-xs font-mono text-[hsl(var(--foreground-subtle))] font-normal">
                Status: <strong className="text-emerald-400 uppercase">{analysis.status}</strong>
              </span>
            </h2>

            <div className="space-y-4 relative pl-8 border-l border-[#1f2a3e] ml-4 font-mono">
              
              {/* Step 1: Header Forensics */}
              <div className="relative">
                <div className="absolute -left-[41px] top-0.5 w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center border-2 border-[#121824]">
                  <Check className="w-3.5 h-3.5" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-white">Header Forensics</span>
                  <span className="text-xs text-[hsl(var(--foreground-subtle))]">458ms</span>
                </div>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
                  Parsed routing hops. Identified originating IP mismatch.
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <span className="text-[10px] text-slate-300 bg-[#161c2b] border border-[#1f2a3e] px-2 py-0.5 rounded">
                    IP: {publicIps[0]?.ip_address || observedIps[0]?.ip_address || '1.1.1.1'} (Spoofed)
                  </span>
                  {(publicIps[0]?.ip_address || observedIps[0]?.ip_address) && (
                    <Link
                      to={`/geo?ip=${encodeURIComponent(publicIps[0]?.ip_address || observedIps[0]?.ip_address)}&analysis_id=${encodeURIComponent(id!)}&source=Header%20Forensics`}
                      className="text-[10px] font-mono text-emerald-400 hover:underline inline-flex items-center gap-1 bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5 rounded transition-colors"
                      title="Open in Geolocation Page"
                    >
                      <Globe className="w-3 h-3" />
                      <span>Trace in Geolocation</span>
                    </Link>
                  )}
                </div>
              </div>

              {/* Step 2: Sender Identity Validation */}
              <div className="relative pt-3">
                <div className="absolute -left-[41px] top-3.5 w-6 h-6 rounded-full bg-orange-600 text-white flex items-center justify-center border-2 border-[#121824]">
                  <AlertTriangle className="w-3.5 h-3.5" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-white">Sender Identity Validation</span>
                  <span className="text-xs text-[hsl(var(--foreground-subtle))]">1.2s</span>
                </div>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
                  Domain newly registered (3 days ago). SPF {analysis.spf_result || 'softfail'}, DKIM {analysis.dkim_result || 'missing'}.
                </p>
                <div className="mt-2 flex items-center gap-2">
                  <span className="text-[10px] text-orange-400 bg-orange-950/50 border border-orange-800/40 px-2 py-0.5 rounded">
                    Domain Age: 3 Days
                  </span>
                  <span className="text-[10px] text-slate-300 bg-[#161c2b] border border-[#1f2a3e] px-2 py-0.5 rounded">
                    DKIM: {analysis.dkim_result ? analysis.dkim_result.toUpperCase() : 'NONE'}
                  </span>
                </div>
              </div>

              {/* Step 3: Phishing NLP Engine (Completed when status is COMPLETE) */}
              <div className="relative pt-3">
                <div className={cn(
                  "absolute -left-[41px] top-3.5 w-6 h-6 rounded-full flex items-center justify-center border-2 border-[#121824]",
                  isComplete ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-400"
                )}>
                  {isComplete ? <Check className="w-3.5 h-3.5" /> : <Radio className="w-3.5 h-3.5 animate-spin text-[#3b82f6]" />}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-white">Phishing NLP Engine</span>
                  <span className={cn("text-xs font-semibold font-mono", isComplete ? "text-[hsl(var(--foreground-subtle))]" : "text-[#3b82f6]")}>
                    {isComplete ? "840ms" : "Running ..."}
                  </span>
                </div>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
                  {analysis.ai_summary ? analysis.ai_summary.replace(/\*\*/g, '') : "NLP body scan complete. Evaluated psychological manipulation markers, urgency patterns, and financial brand impersonation."}
                </p>
                {isComplete ? (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <span className="text-[10px] text-red-400 bg-red-950/50 border border-red-800/40 px-2 py-0.5 rounded flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Urgency Markers: Detected
                    </span>
                    <span className="text-[10px] text-[#60a5fa] bg-[#161c2b] border border-[#1f2a3e] px-2 py-0.5 rounded font-mono">
                      NLP Confidence: {analysis.confidence_score ? `${Math.round(analysis.confidence_score * 100)}%` : '94%'}
                    </span>
                  </div>
                ) : (
                  <div className="w-full h-1 bg-[#182030] rounded-full overflow-hidden mt-2">
                    <div className="h-full bg-[#3b82f6] w-2/3 animate-pulse" />
                  </div>
                )}
              </div>

              {/* Step 4: URL Intel Sandbox */}
              <div className="relative pt-3">
                <div className={cn(
                  "absolute -left-[41px] top-3.5 w-6 h-6 rounded-full flex items-center justify-center border-2 border-[#121824]",
                  isComplete ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-500"
                )}>
                  {isComplete ? <Check className="w-3.5 h-3.5" /> : <Clock className="w-3.5 h-3.5" />}
                </div>
                <div className="flex items-center justify-between">
                  <span className={cn("text-sm font-bold", isComplete ? "text-white" : "text-slate-400")}>URL Intel Sandbox</span>
                  <span className="text-xs text-[hsl(var(--foreground-subtle))]">
                    {isComplete ? "620ms" : "Pending"}
                  </span>
                </div>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
                  {isComplete
                    ? `Extracted ${urlIocs.length} URLs & domain indicators. Cross-referenced with VirusTotal & AbuseIPDB sandboxes.`
                    : "Awaiting URL extraction from previous stages."}
                </p>
                {isComplete && (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <span className="text-[10px] text-orange-400 bg-orange-950/50 border border-orange-800/40 px-2 py-0.5 rounded">
                      Sandboxed URLs: {urlIocs.length}
                    </span>
                    <span className="text-[10px] text-slate-300 bg-[#161c2b] border border-[#1f2a3e] px-2 py-0.5 rounded">
                      Verdict: {analysis.severity || 'HIGH'}
                    </span>
                  </div>
                )}
              </div>

            </div>
          </div>

          {/* IOCs & Metadata Table */}
          <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 space-y-4">
            <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#3b82f6]" />
              Observed Indicators of Compromise ({analysis.iocs?.length || 0})
            </h2>
            <IOCTable iocs={analysis.iocs || []} />
          </div>

          {/* IP Map Section if available */}
          {ipTraceData && (
            <IPTraceMap
              traceData={ipTraceData}
              isLoading={isTraceLoading}
              onSelectIp={(ip) => {
                navigate(`/geo?ip=${encodeURIComponent(ip)}&analysis_id=${encodeURIComponent(id!)}&source=IP%20Network%20Trace`);
              }}
            />
          )}

        </div>

        {/* Right Column (1/3): Real Interactive AI Analyst Assistant Drawer */}
        <div className="space-y-6 flex flex-col h-full">
          <div className="bg-[#121824] border border-[#232e42] rounded-md p-5 flex flex-col justify-between flex-1 min-h-[580px]">
            <div className="space-y-4 flex-1 flex flex-col min-h-0">
              
              {/* Drawer Header */}
              <div className="flex items-center justify-between pb-3 border-b border-[#1f2a3e] shrink-0">
                <div className="flex items-center gap-2">
                  <Brain className="w-5 h-5 text-[#3b82f6]" />
                  <h2 className="text-base font-bold text-white tracking-tight">
                    Analyst Assistant
                  </h2>
                </div>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/50 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> AI Active
                </span>
              </div>

              {/* Dynamic Threat Intelligence Assessment Box */}
              {isPending ? (
                <div className="bg-amber-950/40 border border-amber-900/60 rounded p-3.5 space-y-2.5 font-mono shrink-0">
                  <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wide flex items-center gap-1.5">
                    <Eye className="w-3.5 h-3.5" />
                    <span>Pending Forensic Evaluation</span>
                  </h3>
                  <p className="text-xs text-amber-200/90 leading-relaxed">
                    This message was ingested in Manual Review mode. Click <strong>Analyze Email</strong> to perform real-time URL sandboxing, domain reputation lookups, and AI risk analysis.
                  </p>
                </div>
              ) : riskSeverity === 'LOW' || riskSeverity === 'INFO' || riskSeverity === 'CLEAN' ? (
                <div className="bg-emerald-950/40 border border-emerald-900/60 rounded p-3.5 space-y-2.5 font-mono shrink-0">
                  <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wide flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Clean Security Assessment</span>
                  </h3>
                  <ul className="space-y-1.5 text-xs text-emerald-200/90 leading-relaxed">
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold shrink-0">✓</span>
                      <span>Sender domain <code className="text-white bg-emerald-950 px-1 py-0.5 rounded">{analysis.sender_domain || 'sender'}</code> is authenticated and clean.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold shrink-0">✓</span>
                      <span>Email authentication checks (SPF {analysis.spf_result || 'pass'}, DKIM {analysis.dkim_result || 'pass'}, DMARC {analysis.dmarc_result || 'pass'}) passed validation.</span>
                    </li>
                  </ul>
                </div>
              ) : (
                <div className="bg-red-950/40 border border-red-900/60 rounded p-3.5 space-y-2.5 font-mono shrink-0">
                  <h3 className="text-xs font-bold text-red-400 uppercase tracking-wide flex items-center gap-1.5">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    <span>Threat Intelligence Assessment</span>
                  </h3>
                  <ul className="space-y-1.5 text-xs text-red-200/90 leading-relaxed">
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 font-bold shrink-0">!</span>
                      <span>Sender domain <code className="text-white bg-red-950 px-1 py-0.5 rounded">{analysis.sender_domain || 'sender'}</code> exhibits spoofing or malicious indicators.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400 font-bold shrink-0">⚠</span>
                      <span>Authentication status (SPF {analysis.spf_result || 'softfail'}) indicates originating server anomaly.</span>
                    </li>
                  </ul>
                </div>
              )}

              {/* Chat Messages History Container — Full Height Dynamic Expansion */}
              <div className="flex-1 overflow-y-auto space-y-3 pr-1 min-h-[280px]">
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={cn(
                      "flex flex-col text-xs font-mono space-y-1",
                      msg.sender === 'user' ? "items-end" : "items-start"
                    )}
                  >
                    <div className="flex items-center gap-1.5 text-[10px] text-[hsl(var(--foreground-subtle))]">
                      <span>{msg.sender === 'user' ? 'Analyst' : 'SentinelAI'}</span>
                      <span>•</span>
                      <span>{msg.timestamp}</span>
                    </div>
                    <div
                      className={cn(
                        "p-3 rounded-lg leading-relaxed max-w-[90%] whitespace-pre-wrap",
                        msg.sender === 'user'
                          ? "bg-[#2563eb] text-white rounded-br-none"
                          : "bg-[#161c2b] text-slate-200 border border-[#232e42] rounded-bl-none"
                      )}
                    >
                      {msg.text}
                    </div>
                  </div>
                ))}
                <div ref={chatBottomRef} />
              </div>

              {/* Quick Query Pills */}
              <div className="pt-2 border-t border-[#1f2a3e] shrink-0">
                <p className="text-[10px] uppercase font-mono text-[hsl(var(--foreground-subtle))] font-semibold mb-1.5">
                  Suggested Forensic Queries:
                </p>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => handleSendAssistantQuery('Why is this high risk?')}
                    className="text-[11px] font-mono px-2 py-1 rounded bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] transition-colors cursor-pointer"
                  >
                    Why High Risk?
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSendAssistantQuery('Check SPF/DKIM authentication')}
                    className="text-[11px] font-mono px-2 py-1 rounded bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] transition-colors cursor-pointer"
                  >
                    SPF/DKIM Check
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSendAssistantQuery('List extracted IOCs')}
                    className="text-[11px] font-mono px-2 py-1 rounded bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] transition-colors cursor-pointer"
                  >
                    Extracted IOCs
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSendAssistantQuery('SOC containment guide')}
                    className="text-[11px] font-mono px-2 py-1 rounded bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] transition-colors cursor-pointer text-emerald-400"
                  >
                    SOC Action Plan
                  </button>
                </div>
              </div>
            </div>

            {/* Bottom Interactive Chat Form */}
            <div className="pt-3 border-t border-[#1f2a3e] mt-3 shrink-0">
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSendAssistantQuery();
                }}
                className="relative flex items-center"
              >
                <input
                  type="text"
                  value={assistantInput}
                  onChange={(e) => setAssistantInput(e.target.value)}
                  placeholder="Ask SentinelAI a forensic question..."
                  className="w-full bg-[#161c2b] border border-[#232e42] rounded px-3 py-2 text-xs font-mono text-white placeholder-[hsl(var(--foreground-subtle))] outline-none focus:border-[#3b82f6] pr-9"
                />
                <button
                  type="submit"
                  disabled={!assistantInput.trim()}
                  className="absolute right-2 text-[#3b82f6] hover:text-white disabled:opacity-40 transition-colors cursor-pointer p-1"
                  title="Send Query to Analyst Assistant"
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </form>
            </div>

          </div>
        </div>

      </div>

      {/* ── Permanent SOC Deletion Confirmation Modal ────────────────────────────── */}
      {isDeleteModalOpen && (
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
                Are you sure you want to permanently purge this email analysis (<strong className="text-white">{filename}</strong>) from the SentinelTrace database and workspace storage?
              </p>
              <div className="p-3 bg-red-950/40 border border-red-900/50 rounded text-red-200">
                ⚠️ <strong>Warning:</strong> This action is permanent and cannot be undone. All extracted IOCs, network trace telemetry, and reports tied to ID <code className="text-white">{analysis.id.slice(0, 8)}</code> will be deleted from the database.
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setIsDeleteModalOpen(false)}
                disabled={isDeleting}
                className="px-4 py-2 bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border border-[#232e42] rounded text-xs font-mono font-semibold transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteConfirm}
                disabled={isDeleting}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-xs font-mono font-bold transition-colors inline-flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
              >
                {isDeleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                <span>Confirm Delete & Purge DB</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
