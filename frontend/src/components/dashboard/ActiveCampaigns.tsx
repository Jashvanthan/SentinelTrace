// SentinelTrace Frontend — ActiveCampaigns Component (Step 14)
// Displays the top 3 active/monitoring campaigns from the workspace stats.
// Links to the existing Campaign Graph page. Does NOT implement the graph.

import { Link } from 'react-router-dom';
import { AlertCircle, Network, Shield } from 'lucide-react';
import type { CampaignSummary } from '@/types';
import { formatRelativeTime } from '@/utils';

interface ActiveCampaignsProps {
  campaigns: CampaignSummary[];
  isLoading: boolean;
  isError: boolean;
}

const CAMPAIGN_STATUS_STYLES: Record<string, { label: string; className: string }> = {
  ACTIVE: {
    label: 'Active',
    className: 'bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border border-[hsl(var(--critical)/0.3)]',
  },
  MONITORING: {
    label: 'Monitoring',
    className: 'bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)]',
  },
  MITIGATED: {
    label: 'Mitigated',
    className: 'bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)]',
  },
  CLOSED: {
    label: 'Closed',
    className: 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]',
  },
};

function CampaignStatusBadge({ status }: { status: string }) {
  const style = CAMPAIGN_STATUS_STYLES[status] ?? {
    label: status,
    className: 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-md font-medium whitespace-nowrap ${style.className}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80 inline-block mr-1" aria-hidden="true" />
      {/* Text label ensures color is not the only indicator */}
      {style.label}
    </span>
  );
}

export function ActiveCampaigns({ campaigns, isLoading, isError }: ActiveCampaignsProps) {
  return (
    <section className="card-surface" aria-label="Active threat campaigns">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-[hsl(var(--border))]">
        <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
          <Network className="w-4 h-4 text-[hsl(var(--accent))]" aria-hidden="true" />
          Active Campaigns
        </h2>
        <Link
          to="/graph"
          className="text-xs text-[hsl(var(--accent))] hover:underline"
          aria-label="View campaign correlation graph"
        >
          View graph →
        </Link>
      </div>

      {/* Content */}
      <div className="divide-y divide-[hsl(var(--border-subtle))]">
        {isLoading ? (
          <CampaignSkeleton />
        ) : isError ? (
          <CampaignError />
        ) : campaigns.length === 0 ? (
          <CampaignEmpty />
        ) : (
          campaigns.map((campaign) => (
            <CampaignRow key={campaign.id} campaign={campaign} />
          ))
        )}
      </div>
    </section>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function CampaignRow({ campaign }: { campaign: CampaignSummary }) {
  const lastActivity = campaign.last_seen_at ?? campaign.updated_at;
  return (
    <Link
      to="/graph"
      className="flex items-start gap-3 px-5 py-3.5 hover:bg-[hsl(var(--surface-2))] transition-colors"
      aria-label={`Campaign: ${campaign.name}, status: ${campaign.status}, ${campaign.member_count} correlated emails`}
    >
      <div
        className="flex-shrink-0 w-8 h-8 rounded-lg bg-[hsl(var(--accent-subtle))] flex items-center justify-center mt-0.5"
        aria-hidden="true"
      >
        <Shield className="w-4 h-4 text-[hsl(var(--accent))]" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate">
            {campaign.name}
          </p>
          <CampaignStatusBadge status={campaign.status} />
        </div>

        <div className="flex items-center gap-3 mt-1 text-xs text-[hsl(var(--foreground-muted))]">
          <span aria-label={`${campaign.member_count} correlated emails`}>
            {campaign.member_count} email{campaign.member_count !== 1 ? 's' : ''}
          </span>
          {campaign.confidence !== null && campaign.confidence !== undefined && (
            <span aria-label={`Confidence: ${Math.round(campaign.confidence * 100)}%`}>
              · {Math.round(campaign.confidence * 100)}% conf.
            </span>
          )}
          <span>· Last seen {formatRelativeTime(lastActivity)}</span>
        </div>
      </div>
    </Link>
  );
}

function CampaignSkeleton() {
  return (
    <>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="flex gap-3 px-5 py-3.5 animate-pulse">
          <div className="w-8 h-8 bg-[hsl(var(--surface-3))] rounded-lg flex-shrink-0" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-2/3 bg-[hsl(var(--surface-3))] rounded" />
            <div className="h-3 w-1/2 bg-[hsl(var(--surface-3))] rounded" />
          </div>
        </div>
      ))}
    </>
  );
}

function CampaignError() {
  return (
    <div className="px-5 py-8 flex flex-col items-center gap-2 text-center" role="alert">
      <AlertCircle className="w-5 h-5 text-[hsl(var(--critical))]" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">
        Could not load campaigns.
      </p>
    </div>
  );
}

function CampaignEmpty() {
  return (
    <div className="px-5 py-10 text-center">
      <Network className="w-7 h-7 text-[hsl(var(--foreground-subtle))] mx-auto mb-2" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">No active campaigns</p>
      <p className="text-xs text-[hsl(var(--foreground-subtle))] mt-1">
        Correlate emails to identify threat campaigns.
      </p>
    </div>
  );
}
