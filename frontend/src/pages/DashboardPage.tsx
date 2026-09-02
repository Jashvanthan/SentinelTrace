// SentinelTrace Frontend — Dashboard Page

import { useMemo } from 'react';
import {
  AlertTriangle, CheckCircle2, Clock, Mail, ShieldAlert, Target,
  TrendingUp, Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAnalyses } from '@/api/hooks';
import { MetricCard } from '@/components/dashboard/MetricCard';
import { SeverityBadge } from '@/components/threats/SeverityBadge';
import { StatusBadge } from '@/components/threats/SeverityBadge';
import { formatRelativeTime, THREAT_CATEGORY_LABELS, truncate } from '@/utils';
import type { EmailAnalysisSummary, ThreatCategory } from '@/types';

export function DashboardPage() {
  const { data, isLoading } = useAnalyses({ page_size: 100 });

  const stats = useMemo(() => {
    if (!data) return null;
    const items = data.items;
    return {
      total: data.total,
      pending: items.filter((i) => i.status === 'PENDING' || i.status === 'PROCESSING').length,
      critical: items.filter((i) => i.severity === 'CRITICAL').length,
      high: items.filter((i) => i.severity === 'HIGH').length,
      medium: items.filter((i) => i.severity === 'MEDIUM').length,
      complete: items.filter((i) => i.status === 'COMPLETE').length,
      recent: items.slice(0, 8),
    };
  }, [data]);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Security Overview</h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
            Threat detection dashboard — {new Date().toLocaleDateString('en-US', { dateStyle: 'full' })}
          </p>
        </div>
        <Link
          to="/emails"
          className="flex items-center gap-2 px-4 py-2 rounded-md bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] text-sm font-medium hover:bg-[hsl(var(--accent-hover))] transition-colors"
        >
          <Mail className="w-4 h-4" />
          Analyze Email
        </Link>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Analyses"
          value={isLoading ? '…' : stats?.total ?? 0}
          icon={Mail}
          variant="default"
          subtitle="All time"
        />
        <MetricCard
          title="Critical Threats"
          value={isLoading ? '…' : stats?.critical ?? 0}
          icon={AlertTriangle}
          variant="critical"
          subtitle="Require immediate action"
        />
        <MetricCard
          title="High Severity"
          value={isLoading ? '…' : stats?.high ?? 0}
          icon={ShieldAlert}
          variant="high"
          subtitle="Require investigation"
        />
        <MetricCard
          title="In Progress"
          value={isLoading ? '…' : stats?.pending ?? 0}
          icon={Clock}
          variant="info"
          subtitle="Being analyzed"
        />
      </div>

      {/* Recent Analyses */}
      <div className="card-surface">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[hsl(var(--border))]">
          <h2 className="font-semibold text-[hsl(var(--foreground))]">Recent Analyses</h2>
          <Link
            to="/emails"
            className="text-xs text-[hsl(var(--accent))] hover:underline"
          >
            View all →
          </Link>
        </div>

        <div className="divide-y divide-[hsl(var(--border-subtle))]">
          {isLoading ? (
            Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="px-5 py-3 animate-pulse flex gap-4">
                <div className="h-4 w-1/4 bg-[hsl(var(--surface-3))] rounded" />
                <div className="h-4 w-1/3 bg-[hsl(var(--surface-3))] rounded" />
                <div className="h-4 w-16 bg-[hsl(var(--surface-3))] rounded ml-auto" />
              </div>
            ))
          ) : stats?.recent.length === 0 ? (
            <div className="px-5 py-12 text-center">
              <Mail className="w-8 h-8 text-[hsl(var(--foreground-subtle))] mx-auto mb-3" />
              <p className="text-sm text-[hsl(var(--foreground-muted))]">No analyses yet</p>
              <Link to="/emails" className="text-sm text-[hsl(var(--accent))] hover:underline mt-2 inline-block">
                Upload your first email →
              </Link>
            </div>
          ) : (
            stats?.recent.map((analysis) => (
              <AnalysisRow key={analysis.id} analysis={analysis} />
            ))
          )}
        </div>
      </div>

      {/* Threat Category Distribution */}
      {stats && stats.total > 0 && (
        <ThreatDistribution items={data?.items || []} />
      )}
    </div>
  );
}

function AnalysisRow({ analysis }: { analysis: EmailAnalysisSummary }) {
  return (
    <Link
      to={`/emails/${analysis.id}`}
      className="flex items-center gap-4 px-5 py-3.5 hover:bg-[hsl(var(--surface-2))] transition-colors"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate">
            {analysis.subject || '(no subject)'}
          </p>
          {analysis.threat_category && analysis.threat_category !== 'UNKNOWN' && (
            <span className="text-xs text-[hsl(var(--foreground-subtle))]">
              · {THREAT_CATEGORY_LABELS[analysis.threat_category] || analysis.threat_category}
            </span>
          )}
        </div>
        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
          {analysis.sender_email || '—'} · {formatRelativeTime(analysis.created_at)}
        </p>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <StatusBadge status={analysis.status} animate />
        {analysis.severity && <SeverityBadge severity={analysis.severity} />}
      </div>
    </Link>
  );
}

function ThreatDistribution({ items }: { items: EmailAnalysisSummary[] }) {
  const categories = useMemo(() => {
    const counts: Record<string, number> = {};
    items.forEach((i) => {
      if (i.threat_category && i.threat_category !== 'UNKNOWN' && i.threat_category !== 'BENIGN') {
        counts[i.threat_category] = (counts[i.threat_category] || 0) + 1;
      }
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [items]);

  if (!categories.length) return null;
  const max = Math.max(...categories.map(([, v]) => v));

  return (
    <div className="card-surface p-5">
      <h2 className="font-semibold text-[hsl(var(--foreground))] mb-4 flex items-center gap-2">
        <Target className="w-4 h-4 text-[hsl(var(--accent))]" />
        Threat Category Distribution
      </h2>
      <div className="space-y-3">
        {categories.map(([cat, count]) => (
          <div key={cat} className="flex items-center gap-3">
            <span className="text-xs text-[hsl(var(--foreground-muted))] w-40 shrink-0">
              {THREAT_CATEGORY_LABELS[cat as ThreatCategory] || cat}
            </span>
            <div className="flex-1 h-2 rounded-full bg-[hsl(var(--surface-3))]">
              <div
                className="h-2 rounded-full bg-[hsl(var(--accent))] transition-all"
                style={{ width: `${(count / max) * 100}%` }}
              />
            </div>
            <span className="text-xs text-[hsl(var(--foreground-muted))] w-6 text-right">{count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
