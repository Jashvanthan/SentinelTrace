// SentinelTrace Frontend — ThreatSummary Component (Step 14)
// Displays IOC type distribution and high/critical IOC count for the current week.
// Uses pure CSS bar visualization — no fake heatmap, no fabricated data.

import { AlertCircle, ShieldAlert } from 'lucide-react';
import { getIOCTypeLabel } from '@/utils';

interface ThreatSummaryProps {
  iocTypeDistribution: Record<string, number>;
  highCriticalIocsThisWeek: number;
  isLoading: boolean;
  isError: boolean;
}

export function ThreatSummary({
  iocTypeDistribution,
  highCriticalIocsThisWeek,
  isLoading,
  isError,
}: ThreatSummaryProps) {
  // Sort IOC types by count descending, take top 6
  const sortedTypes = Object.entries(iocTypeDistribution)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 6);

  const maxCount = sortedTypes.length > 0 ? sortedTypes[0][1] : 0;

  return (
    <section className="card-surface p-5" aria-label="IOC threat summary">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-[hsl(var(--accent))]" aria-hidden="true" />
          IOC Threat Summary
        </h2>
        {/* High/critical IOC count badge */}
        {!isLoading && !isError && (
          <div
            className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border border-[hsl(var(--critical)/0.3)]"
            aria-label={`${highCriticalIocsThisWeek} high or critical IOCs detected this week`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
            <span className="font-semibold">{highCriticalIocsThisWeek}</span>
            <span>high/critical this week</span>
          </div>
        )}
      </div>

      {/* Content */}
      {isLoading ? (
        <ThreatSummarySkeleton />
      ) : isError ? (
        <ThreatSummaryError />
      ) : sortedTypes.length === 0 ? (
        <ThreatSummaryEmpty />
      ) : (
        <div className="space-y-3" role="list" aria-label="IOC type distribution">
          {sortedTypes.map(([iocType, count]) => (
            <div key={iocType} className="flex items-center gap-3" role="listitem">
              <span
                className="text-xs text-[hsl(var(--foreground-muted))] w-28 shrink-0 truncate"
                title={getIOCTypeLabel(iocType)}
                aria-label={`IOC type: ${getIOCTypeLabel(iocType)}`}
              >
                {getIOCTypeLabel(iocType)}
              </span>

              {/* CSS bar — width is proportional to count, not hardcoded */}
              <div
                className="flex-1 h-2 rounded-full bg-[hsl(var(--surface-3))]"
                role="presentation"
                aria-hidden="true"
              >
                <div
                  className="h-2 rounded-full bg-[hsl(var(--accent))] transition-all duration-500"
                  style={{ width: maxCount > 0 ? `${(count / maxCount) * 100}%` : '0%' }}
                />
              </div>

              <span
                className="text-xs text-[hsl(var(--foreground-muted))] w-8 text-right tabular-nums"
                aria-label={`${count} IOCs`}
              >
                {count}
              </span>
            </div>
          ))}

          {/* IOC threshold note — transparency for derived metric */}
          <p className="text-xs text-[hsl(var(--foreground-subtle))] mt-2 pt-2 border-t border-[hsl(var(--border-subtle))]">
            High/critical: IOCs with threat score ≥ 70 created this week
          </p>
        </div>
      )}
    </section>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function ThreatSummarySkeleton() {
  return (
    <div className="space-y-3 animate-pulse" aria-hidden="true">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="h-3 w-24 bg-[hsl(var(--surface-3))] rounded" />
          <div className="flex-1 h-2 bg-[hsl(var(--surface-3))] rounded-full" />
          <div className="h-3 w-6 bg-[hsl(var(--surface-3))] rounded" />
        </div>
      ))}
    </div>
  );
}

function ThreatSummaryError() {
  return (
    <div className="flex flex-col items-center gap-2 py-6 text-center" role="alert">
      <AlertCircle className="w-5 h-5 text-[hsl(var(--critical))]" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">
        Could not load IOC data.
      </p>
    </div>
  );
}

function ThreatSummaryEmpty() {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-center">
      <ShieldAlert className="w-7 h-7 text-[hsl(var(--foreground-subtle))]" aria-hidden="true" />
      <p className="text-sm text-[hsl(var(--foreground-muted))]">No IOC data yet</p>
      <p className="text-xs text-[hsl(var(--foreground-subtle))]">
        IOCs are extracted during email analysis.
      </p>
    </div>
  );
}
