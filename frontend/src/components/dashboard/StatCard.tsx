// SentinelTrace Frontend — StatCard Component (SOC Reference UI)

import type { LucideIcon } from 'lucide-react';
import { cn } from '@/utils';

interface StatCardProps {
  title: string;
  value?: string | number | null;
  subtitle?: string;
  badgeText?: string;
  trend?: string;
  icon: LucideIcon;
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info';
  isLoading?: boolean;
  className?: string;
  ariaLabel?: string;
}

const VARIANT_BORDER_COLORS: Record<string, string> = {
  default: 'border-l-2 border-l-[#3b82f6]',
  critical: 'border-l-2 border-l-[#ef4444]',
  high: 'border-l-2 border-l-[#f97316]',
  medium: 'border-l-2 border-l-[#3b82f6]',
  low: 'border-l-2 border-l-[#94a3b8]',
  info: 'border-l-2 border-l-[#3b82f6]',
};

export function StatCard({
  title,
  value,
  subtitle,
  badgeText,
  trend,
  icon: Icon,
  variant = 'default',
  isLoading = false,
  className,
  ariaLabel,
}: StatCardProps) {
  const displayValue = value === null || value === undefined ? '—' : value;

  return (
    <div
      className={cn(
        'bg-[#121824] border border-[#232e42] rounded-md p-4 transition-all duration-150 relative overflow-hidden',
        VARIANT_BORDER_COLORS[variant],
        className
      )}
      role="region"
      aria-label={ariaLabel ?? title}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold text-[hsl(var(--foreground-muted))] uppercase tracking-wider font-mono">
          {title}
        </p>
        <Icon className="w-4 h-4 text-[hsl(var(--foreground-subtle))]" />
      </div>

      <div className="mt-3 flex items-baseline justify-between gap-2">
        {isLoading ? (
          <div className="h-8 w-24 bg-[#1a2232] rounded animate-pulse" />
        ) : (
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white tracking-tight font-mono">
              {displayValue}
            </span>
            {trend && (
              <span className="text-xs font-mono font-medium text-emerald-400">
                {trend}
              </span>
            )}
          </div>
        )}

        {badgeText && !isLoading && (
          <span className="text-[10px] uppercase font-mono font-semibold bg-red-950/80 text-red-400 border border-red-800/50 px-2 py-0.5 rounded">
            {badgeText}
          </span>
        )}
      </div>

      {subtitle && !isLoading && (
        <p className="mt-1 text-[11px] text-[hsl(var(--foreground-subtle))] font-mono">
          {subtitle}
        </p>
      )}
    </div>
  );
}

