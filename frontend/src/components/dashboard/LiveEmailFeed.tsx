// SentinelTrace Frontend — LiveEmailFeed Component (Step 14)
// Auto-refreshed recent email analysis feed using TanStack Query polling.
// NOT SSE / WebSocket. Uses refetchInterval: 30000 via useWorkspaceStats hook.

import { Link } from 'react-router-dom';
import { AlertCircle, Mail, RefreshCw } from 'lucide-react';
import type { RecentEmailSummary } from '@/types';
import { SeverityBadge, StatusBadge } from '@/components/threats/SeverityBadge';
import { formatRelativeTime, THREAT_CATEGORY_LABELS, truncate } from '@/utils';
import type { ThreatCategory } from '@/types';

interface LiveEmailFeedProps {
  emails: RecentEmailSummary[];
  isLoading: boolean;
  isError: boolean;
  /** Timestamp of the last successful data fetch (from TanStack Query dataUpdatedAt). */
  lastUpdatedAt?: number;
}

export function LiveEmailFeed({
  emails,
  isLoading,
  isError,
  lastUpdatedAt,
}: LiveEmailFeedProps) {
  return (
    <section
      className="card-surface"
      aria-label="Recent email analyses feed — auto-refreshed every 30 seconds"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-[hsl(var(--border))]">
        <div className="flex items-center gap-2">
          <h2 className="font-semibold text-[hsl(var(--foreground))]">Recent Analyses</h2>
          <span
            className="inline-flex items-center gap-1 text-xs text-[hsl(var(--foreground-muted))] bg-[hsl(var(--surface-2))] px-2 py-0.5 rounded-full"
            title="Auto-refreshed every 30 seconds"
          >
            <RefreshCw className="w-3 h-3" aria-hidden="true" />
            Auto-refresh
          </span>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdatedAt && !isLoading && (
            <span className="text-xs text-[hsl(var(--foreground-subtle))]">
              Updated {formatRelativeTime(new Date(lastUpdatedAt).toISOString())}
            </span>
          )}
          <Link
            to="/emails"
            className="text-xs text-[hsl(var(--accent))] hover:underline"
            aria-label="View all email analyses"
          >
            View all →
          </Link>
        </div>
      </div>

      {/* Content */}
      <div className="divide-y divide-[hsl(var(--border-subtle))]" role="list">
        {isLoading ? (
          <EmailFeedSkeleton />
        ) : isError ? (
          <EmailFeedError />
        ) : emails.length === 0 ? (
          <EmailFeedEmpty />
        ) : (
          emails.map((email) => (
            <EmailFeedRow key={email.id} email={email} />
          ))
        )}
      </div>
    </section>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function EmailFeedRow({ email }: { email: RecentEmailSummary }) {
  return (
    <Link
      to={`/emails/${email.id}`}
      className="flex items-center gap-4 px-5 py-3.5 hover:bg-[hsl(var(--surface-2))] transition-colors"
      role="listitem"
      aria-label={`Email: ${email.subject ?? '(no subject)'} from ${email.sender_email ?? 'unknown sender'}`}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate">
            {email.subject ?? '(no subject)'}
          </p>
          {email.threat_category &&
            email.threat_category !== 'UNKNOWN' &&
            email.threat_category !== 'BENIGN' && (
              <span className="text-xs text-[hsl(var(--foreground-subtle))]">
                ·{' '}
                {THREAT_CATEGORY_LABELS[email.threat_category as ThreatCategory] ??
                  email.threat_category}
              </span>
            )}
        </div>
        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
          {email.sender_email ?? '—'} · {formatRelativeTime(email.created_at)}
          {email.threat_score !== null && email.threat_score !== undefined && (
            <span className="ml-2 font-medium" aria-label={`Threat score: ${email.threat_score}`}>
              Score: {email.threat_score.toFixed(0)}
            </span>
          )}
        </p>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <StatusBadge status={email.status} animate />
        {email.severity && <SeverityBadge severity={email.severity} />}
      </div>
    </Link>
  );
}

function EmailFeedSkeleton() {
  return (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <div
          key={i}
          className="px-5 py-3.5 animate-pulse flex gap-4"
          role="listitem"
          aria-hidden="true"
        >
          <div className="flex-1 space-y-2">
            <div className="h-4 w-3/5 bg-[hsl(var(--surface-3))] rounded" />
            <div className="h-3 w-2/5 bg-[hsl(var(--surface-3))] rounded" />
          </div>
          <div className="h-5 w-16 bg-[hsl(var(--surface-3))] rounded" />
        </div>
      ))}
    </>
  );
}

function EmailFeedError() {
  return (
    <div className="px-5 py-10 flex flex-col items-center gap-2 text-center" role="alert">
      <AlertCircle className="w-6 h-6 text-[hsl(var(--critical))]" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">
        Could not load recent analyses.
      </p>
      <p className="text-xs text-[hsl(var(--foreground-subtle))]">
        Will retry automatically.
      </p>
    </div>
  );
}

function EmailFeedEmpty() {
  return (
    <div className="px-5 py-12 text-center" role="listitem">
      <Mail className="w-8 h-8 text-[hsl(var(--foreground-subtle))] mx-auto mb-3" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">No analyses yet</p>
      <Link
        to="/emails"
        className="text-sm text-[hsl(var(--accent))] hover:underline mt-2 inline-block"
      >
        Upload your first email →
      </Link>
    </div>
  );
}
