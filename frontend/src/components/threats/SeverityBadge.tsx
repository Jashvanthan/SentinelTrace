// SentinelTrace Frontend — Severity & Status Badge Component (SOC Reference UI)

import { cn } from '@/utils';
import type { SeverityLevel, AnalysisStatus } from '@/types';

interface SeverityBadgeProps {
  severity?: SeverityLevel | string | null;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-950/70 text-red-400 border border-red-800/50',
  HIGH: 'bg-orange-950/70 text-orange-400 border border-orange-800/50',
  MEDIUM: 'bg-blue-950/70 text-blue-400 border border-blue-800/50',
  MODERATE: 'bg-blue-950/70 text-blue-400 border border-blue-800/50',
  LOW: 'bg-slate-900 text-slate-400 border border-slate-700/50',
  INFO: 'bg-slate-900 text-slate-400 border border-slate-700/50',
  CLEAN: 'bg-slate-900 text-slate-400 border border-slate-700/50',
  VERIFIED: 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/50',
};

export function SeverityBadge({ severity, className, size = 'md' }: SeverityBadgeProps) {
  const sevKey = (severity || 'UNKNOWN').toUpperCase();
  const style = SEVERITY_STYLES[sevKey] || SEVERITY_STYLES.LOW;

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 rounded-[3px] font-mono font-semibold uppercase tracking-wider',
    md: 'text-xs px-2 py-0.5 rounded-[3px] font-mono font-semibold uppercase tracking-wider',
    lg: 'text-xs px-2.5 py-1 rounded-[3px] font-mono font-semibold uppercase tracking-wider',
  };

  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap', style, sizeClasses[size], className)}>
      <span className="w-1 h-1 rounded-full bg-current opacity-90" />
      {sevKey}
    </span>
  );
}

// ── Status Badge ──────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  PENDING: 'bg-[#182030] text-[#94a3b8] border border-[#232e42]',
  PROCESSING: 'bg-[#1b2942] text-[#60a5fa] border border-[#2563eb]/40',
  INVESTIGATING: 'bg-[#1b2942] text-[#60a5fa] border border-[#2563eb]/40',
  TRIAGE: 'bg-[#1e293b] text-[#94a3b8] border border-[#334155]',
  COMPLETE: 'bg-slate-900 text-slate-300 border border-slate-700',
  FAILED: 'bg-red-950/80 text-red-400 border border-red-800/50',
  QUARANTINED: 'bg-orange-950/80 text-orange-400 border border-orange-800/50',
  VERIFIED: 'bg-blue-950/80 text-blue-400 border border-blue-800/50',
  ANCHORED: 'bg-blue-950/80 text-blue-400 border border-blue-800/50',
};

interface StatusBadgeProps {
  status: AnalysisStatus | string;
  className?: string;
  animate?: boolean;
}

export function StatusBadge({ status, className, animate }: StatusBadgeProps) {
  const statusKey = (status || 'PENDING').toUpperCase();
  const style = STATUS_STYLES[statusKey] || STATUS_STYLES.PENDING;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-[3px] font-mono font-semibold uppercase tracking-wider whitespace-nowrap',
        style,
        className
      )}
    >
      {(statusKey === 'PROCESSING' || statusKey === 'PENDING') && animate && (
        <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
      )}
      {statusKey}
    </span>
  );
}

