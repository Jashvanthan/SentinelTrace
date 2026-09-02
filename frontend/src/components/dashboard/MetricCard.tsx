// SentinelTrace Frontend — Metric Card Component

import { cn } from '@/utils';
import type { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  iconColor?: string;
  trend?: { value: number; label: string };
  className?: string;
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const VARIANT_ICON_COLORS: Record<string, string> = {
  default: 'text-[hsl(var(--accent))] bg-[hsl(var(--accent-subtle))]',
  critical: 'text-[hsl(var(--critical))] bg-[hsl(var(--critical-subtle))]',
  high: 'text-[hsl(var(--high))] bg-[hsl(var(--high-subtle))]',
  medium: 'text-[hsl(var(--medium))] bg-[hsl(var(--medium-subtle))]',
  low: 'text-[hsl(var(--low))] bg-[hsl(var(--low-subtle))]',
  info: 'text-[hsl(var(--info))] bg-[hsl(var(--info-subtle))]',
};

export function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  className,
  variant = 'default',
}: MetricCardProps) {
  return (
    <div className={cn('metric-card p-5', className)}>
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
            {title}
          </p>
          <p className="mt-1.5 text-2xl font-bold text-[hsl(var(--foreground))] tabular-nums">
            {value}
          </p>
          {subtitle && (
            <p className="mt-0.5 text-xs text-[hsl(var(--foreground-muted))]">{subtitle}</p>
          )}
          {trend && (
            <p className={cn(
              'mt-1 text-xs font-medium',
              trend.value >= 0 ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--low))]'
            )}>
              {trend.value >= 0 ? '↑' : '↓'} {Math.abs(trend.value)} {trend.label}
            </p>
          )}
        </div>
        <div className={cn(
          'flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center',
          VARIANT_ICON_COLORS[variant]
        )}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
