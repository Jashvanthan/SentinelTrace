// SentinelTrace Frontend — Email Analysis Detail Page

import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft, Shield, Server, Mail, Key, FileText, Brain, Network,
  AlertTriangle, CheckCircle, XCircle, Clock, Hash,
} from 'lucide-react';
import { useAnalysis } from '@/api/hooks';
import { SeverityBadge, StatusBadge } from '@/components/threats/SeverityBadge';
import { IOCTable } from '@/components/threats/IOCBadge';
import { formatDate, formatFileSize, formatRelativeTime, THREAT_CATEGORY_LABELS, truncateHash } from '@/utils';
import { cn } from '@/utils';

export function EmailDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: analysis, isLoading } = useAnalysis(id!);

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="card-surface p-5">
            <div className="h-5 w-1/3 bg-[hsl(var(--surface-3))] rounded mb-4" />
            <div className="space-y-2">
              <div className="h-4 bg-[hsl(var(--surface-3))] rounded w-full" />
              <div className="h-4 bg-[hsl(var(--surface-3))] rounded w-3/4" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="text-center py-16">
        <AlertTriangle className="w-10 h-10 text-[hsl(var(--high))] mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">Analysis Not Found</h2>
        <Link to="/emails" className="text-sm text-[hsl(var(--accent))] hover:underline mt-2 inline-block">
          ← Back to analyses
        </Link>
      </div>
    );
  }

  const authPass = (result?: string) =>
    result === 'pass' || result === 'dkim=pass' ? 'pass' :
    result === 'fail' || result === 'softfail' ? 'fail' : 'none';

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Back + Header */}
      <div>
        <Link
          to="/emails"
          className="inline-flex items-center gap-1.5 text-sm text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))] transition-colors mb-3"
        >
          <ArrowLeft className="w-4 h-4" /> Back to analyses
        </Link>
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <h1 className="text-xl font-bold text-[hsl(var(--foreground))] truncate">
              {analysis.subject || '(no subject)'}
            </h1>
            <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
              From: <span className="font-mono text-[hsl(var(--foreground))]">{analysis.sender_email || '—'}</span>
              {analysis.sender_domain && <span className="text-[hsl(var(--foreground-subtle))]"> · {analysis.sender_domain}</span>}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <StatusBadge status={analysis.status} animate />
            {analysis.severity && <SeverityBadge severity={analysis.severity} size="lg" />}
          </div>
        </div>
      </div>

      {/* AI Summary */}
      {analysis.ai_summary && (
        <div className="card-surface p-5">
          <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-3">
            <Brain className="w-4 h-4 text-[hsl(var(--accent))]" />
            AI Threat Summary
          </h2>
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            {analysis.threat_category && (
              <span className="text-xs px-2 py-1 rounded-md bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]">
                {THREAT_CATEGORY_LABELS[analysis.threat_category] || analysis.threat_category}
              </span>
            )}
            {analysis.confidence_score != null && (
              <span className="text-xs text-[hsl(var(--foreground-subtle))]">
                Confidence: {(analysis.confidence_score * 100).toFixed(0)}%
              </span>
            )}
            {analysis.ai_model_used && (
              <span className="text-xs text-[hsl(var(--foreground-subtle))]">
                Model: {analysis.ai_model_used}
              </span>
            )}
          </div>
          <p className="text-sm text-[hsl(var(--foreground-muted))] leading-relaxed whitespace-pre-wrap">
            {analysis.ai_summary}
          </p>
          {analysis.ai_indicators && analysis.ai_indicators.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider mb-2">Key Indicators</p>
              <ul className="space-y-1">
                {analysis.ai_indicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-[hsl(var(--foreground-muted))]">
                    <span className="text-[hsl(var(--accent))] mt-0.5">›</span>
                    {ind}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Authentication Results */}
      <div className="card-surface p-5">
        <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-4">
          <Key className="w-4 h-4 text-[hsl(var(--accent))]" />
          Email Authentication
        </h2>
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: 'SPF', result: analysis.spf_result },
            { label: 'DKIM', result: analysis.dkim_result },
            { label: 'DMARC', result: analysis.dmarc_result },
          ].map(({ label, result }) => {
            const status = authPass(result || '');
            return (
              <div key={label} className="text-center p-4 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]">
                <div className={cn('flex items-center justify-center mb-2', {
                  'text-[hsl(var(--low))]': status === 'pass',
                  'text-[hsl(var(--critical))]': status === 'fail',
                  'text-[hsl(var(--foreground-subtle))]': status === 'none',
                })}>
                  {status === 'pass' ? <CheckCircle className="w-6 h-6" /> :
                   status === 'fail' ? <XCircle className="w-6 h-6" /> :
                   <Clock className="w-6 h-6" />}
                </div>
                <p className="text-xs font-semibold text-[hsl(var(--foreground))]">{label}</p>
                <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5 font-mono">
                  {result || 'unknown'}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Email Metadata */}
      <div className="card-surface p-5">
        <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-4">
          <Mail className="w-4 h-4 text-[hsl(var(--accent))]" />
          Email Metadata
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3">
          {[
            { label: 'Message-ID', value: analysis.message_id, mono: true },
            { label: 'Date', value: formatDate(analysis.email_date || analysis.created_at) },
            { label: 'Reply-To', value: analysis.reply_to, mono: true },
            { label: 'Recipients', value: analysis.recipients?.join(', ') },
            { label: 'SHA-256', value: truncateHash(analysis.raw_eml_sha256, 24), mono: true },
            { label: 'File Size', value: formatFileSize(analysis.raw_eml_size_bytes) },
          ].map(({ label, value, mono }) =>
            value ? (
              <div key={label}>
                <p className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">{label}</p>
                <p className={cn('text-sm text-[hsl(var(--foreground))] mt-0.5 break-all', mono && 'font-mono')}>
                  {value}
                </p>
              </div>
            ) : null
          )}
        </div>
      </div>

      {/* IOCs */}
      <div className="card-surface p-5">
        <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-4">
          <AlertTriangle className="w-4 h-4 text-[hsl(var(--accent))]" />
          Indicators of Compromise ({analysis.iocs?.length || 0})
        </h2>
        <IOCTable iocs={analysis.iocs || []} />
      </div>

      {/* Attachments */}
      {analysis.attachments && analysis.attachments.length > 0 && (
        <div className="card-surface p-5">
          <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-4">
            <FileText className="w-4 h-4 text-[hsl(var(--accent))]" />
            Attachments ({analysis.attachments.length})
          </h2>
          <div className="space-y-2">
            {analysis.attachments.map((att) => (
              <div key={att.id} className="flex items-center justify-between p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate">{att.filename || 'unnamed'}</p>
                  <p className="text-xs text-[hsl(var(--foreground-muted))] font-mono mt-0.5">
                    SHA-256: {truncateHash(att.sha256_hash)}
                  </p>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                  <span className="text-xs text-[hsl(var(--foreground-muted))]">{formatFileSize(att.size_bytes)}</span>
                  {att.is_malicious === true ? (
                    <span className="severity-critical text-xs px-1.5 py-0.5 rounded">Malicious</span>
                  ) : att.is_malicious === false ? (
                    <span className="severity-low text-xs px-1.5 py-0.5 rounded">Clean</span>
                  ) : (
                    <span className="text-xs text-[hsl(var(--foreground-subtle))]">Unknown</span>
                  )}
                  {att.vt_detections != null && att.vt_total_engines != null && (
                    <span className="text-xs text-[hsl(var(--foreground-muted))]">
                      {att.vt_detections}/{att.vt_total_engines} VT
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Received Headers */}
      {analysis.received_headers && analysis.received_headers.length > 0 && (
        <div className="card-surface p-5">
          <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-[hsl(var(--accent))]" />
            Received Chain ({analysis.received_headers.length} hops)
          </h2>
          <div className="space-y-2">
            {analysis.received_headers.map((header, i) => (
              <div key={i} className="flex gap-3">
                <span className="text-xs text-[hsl(var(--foreground-subtle))] w-5 flex-shrink-0 mt-0.5">{i + 1}</span>
                <pre className="text-xs font-mono text-[hsl(var(--foreground-muted))] whitespace-pre-wrap break-all">
                  {header}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Graph link */}
      <div className="card-surface p-4">
        <Link
          to={`/graph?analysis_id=${analysis.id}`}
          className="flex items-center justify-between text-sm hover:bg-[hsl(var(--surface-2))] rounded transition-colors p-1"
        >
          <span className="flex items-center gap-2 text-[hsl(var(--accent))]">
            <Network className="w-4 h-4" />
            View in Campaign Graph
          </span>
          <ArrowLeft className="w-4 h-4 text-[hsl(var(--foreground-muted))] rotate-180" />
        </Link>
      </div>
    </div>
  );
}
