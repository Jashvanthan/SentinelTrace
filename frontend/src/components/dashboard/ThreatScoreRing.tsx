// SentinelTrace Frontend — ThreatScoreRing Component (Step 14)
// SVG ring gauge displaying workspace risk score (0–100).
// Color thresholds match existing severity tokens.
// Accessible: numeric score always present as text, not color-only.

import { cn } from '@/utils';

interface ThreatScoreRingProps {
  /** Score 0–100. null = no data yet. */
  score: number | null | undefined;
  /** Ring diameter in pixels. */
  size?: number;
  /** Stroke width of the ring track. */
  strokeWidth?: number;
  isLoading?: boolean;
  className?: string;
}

/** Returns CSS color variable based on risk thresholds. */
function getRiskColor(score: number): { fg: string; label: string } {
  if (score >= 80) return { fg: 'hsl(var(--critical))', label: 'Critical Risk' };
  if (score >= 60) return { fg: 'hsl(var(--high))', label: 'High Risk' };
  if (score >= 40) return { fg: 'hsl(var(--medium))', label: 'Medium Risk' };
  if (score >= 20) return { fg: 'hsl(var(--low))', label: 'Low Risk' };
  return { fg: 'hsl(var(--info))', label: 'Minimal Risk' };
}

/** Returns plain-text risk label for accessibility. */
function getRiskLabel(score: number | null | undefined): string {
  if (score === null || score === undefined) return 'No data';
  const { label } = getRiskColor(score);
  return `${score.toFixed(1)} — ${label}`;
}

export function ThreatScoreRing({
  score,
  size = 140,
  strokeWidth = 10,
  isLoading = false,
  className,
}: ThreatScoreRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const cx = size / 2;
  const cy = size / 2;

  const safeScore = score !== null && score !== undefined ? Math.max(0, Math.min(100, score)) : null;
  const progress = safeScore !== null ? (safeScore / 100) * circumference : 0;
  const { fg, label: riskLabel } = safeScore !== null
    ? getRiskColor(safeScore)
    : { fg: 'hsl(var(--foreground-subtle))', label: 'No data' };

  if (isLoading) {
    return (
      <div
        className={cn('flex flex-col items-center gap-3', className)}
        aria-label="Workspace risk score loading"
        aria-busy="true"
      >
        <div
          className="rounded-full bg-[hsl(var(--surface-3))] animate-pulse"
          style={{ width: size, height: size }}
        />
        <div className="h-4 w-28 bg-[hsl(var(--surface-3))] rounded animate-pulse" />
      </div>
    );
  }

  return (
    <div
      className={cn('relative flex flex-col items-center gap-2', className)}
      role="img"
      aria-label={`Risk Score: ${getRiskLabel(score)}`}
    >
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          aria-hidden="true"
          style={{ transform: 'rotate(-90deg)' }}
        >
          {/* Track */}
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke="hsl(var(--surface-3))"
            strokeWidth={strokeWidth}
          />
          {/* Progress arc */}
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke={fg}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
          />
        </svg>

        {/* Centered overlay text inside the circle */}
        <div
          className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
          aria-hidden="true"
        >
          <span
            className="text-2xl font-bold tabular-nums"
            style={{ color: safeScore !== null ? fg : 'hsl(var(--foreground-muted))' }}
          >
            {safeScore !== null ? safeScore.toFixed(0) : '—'}
          </span>
          <span className="text-[10px] text-[hsl(var(--foreground-muted))] mt-0.5">/ 100</span>
        </div>
      </div>

      {/* Text representation below the circle */}
      <div className="text-center">
        <p
          className="text-sm font-semibold"
          style={{ color: safeScore !== null ? fg : 'hsl(var(--foreground-muted))' }}
        >
          {safeScore !== null ? riskLabel : 'No Data'}
        </p>
        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
          Threat Risk Score
        </p>
      </div>
    </div>
  );
}
