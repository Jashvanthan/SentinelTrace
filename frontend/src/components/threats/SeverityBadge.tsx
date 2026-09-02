// SentinelTrace Frontend — Severity Badge Component

import { cn, getSeverityClass } from '@/utils';
import type { SeverityLevel } from '@/types';

interface SeverityBadgeProps {
  severity?: SeverityLevel | null;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export function SeverityBadge({ severity, className, size = 'md' }: SeverityBadgeProps) {
  const sizeClasses = {
    sm: 'text-xs px-1.5 py-0.5 rounded',
    md: 'text-xs px-2 py-0.5 rounded-md font-medium',
    lg: 'text-sm px-3 py-1 rounded-md font-semibold',
  };

  return (
    <span
      className={cn(
        getSeverityClass(severity),
        sizeClasses[size],
        'inline-flex items-center gap-1 whitespace-nowrap',
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      {severity || 'UNKNOWN'}
    </span>
  );
}

// ── Status Badge ──────────────────────────────────────────────────────────────

import type { AnalysisStatus } from '@/types';

const STATUS_STYLES: Record<AnalysisStatus, string> = {
  PENDING: 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]',
  PROCESSING: 'bg-[hsl(var(--info-subtle))] text-[hsl(var(--info))] border border-[hsl(var(--info)/0.3)]',
  COMPLETE: 'bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)]',
  FAILED: 'bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border border-[hsl(var(--critical)/0.3)]',
  QUARANTINED: 'bg-[hsl(var(--high-subtle))] text-[hsl(var(--high))] border border-[hsl(var(--high)/0.3)]',
};

interface StatusBadgeProps {
  status: AnalysisStatus;
  className?: string;
  animate?: boolean;
}

export function StatusBadge({ status, className, animate }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-md font-medium whitespace-nowrap',
        STATUS_STYLES[status],
        className
      )}
    >
      {(status === 'PROCESSING' || status === 'PENDING') && animate && (
        <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
      )}
      {status}
    </span>
  );
}
