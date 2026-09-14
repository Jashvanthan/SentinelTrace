// SentinelTrace Frontend — IOC Badge Component

import { cn, getIOCTypeLabel } from '@/utils';
import type { IOC } from '@/types';

interface IOCBadgeProps {
  ioc: IOC;
  className?: string;
  showType?: boolean;
}

const IOC_TYPE_COLORS: Record<string, string> = {
  IP_ADDRESS: 'bg-[hsl(210,50%,15%)] text-[hsl(var(--info))] border-[hsl(var(--info)/0.25)]',
  DOMAIN: 'bg-[hsl(270,40%,15%)] text-[hsl(270,80%,70%)] border-[hsl(270,60%,40%/0.25)]',
  URL: 'bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border-[hsl(var(--medium)/0.25)]',
  FILE_HASH_SHA256: 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border-[hsl(var(--border))]',
  FILE_HASH_MD5: 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border-[hsl(var(--border))]',
  EMAIL: 'bg-[hsl(var(--accent-subtle))] text-[hsl(var(--accent))] border-[hsl(var(--accent)/0.25)]',
};

export function IOCBadge({ ioc, className, showType = true }: IOCBadgeProps) {
  const colorClass = IOC_TYPE_COLORS[ioc.ioc_type] ||
    'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border-[hsl(var(--border))]';

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-xs',
        colorClass,
        className
      )}
      title={ioc.value}
    >
      {ioc.is_malicious && (
        <span className="text-[hsl(var(--critical))]" title="Malicious">⚠</span>
      )}
      {showType && (
        <span className="text-[0.65rem] opacity-70 font-sans">{getIOCTypeLabel(ioc.ioc_type)}</span>
      )}
      <span className="truncate max-w-[200px]">{ioc.value}</span>
    </span>
  );
}

// ── IOC Table ─────────────────────────────────────────────────────────────────

interface IOCTableProps {
  iocs: IOC[];
}

import { Link } from 'react-router-dom';
import { Globe, Network, ShieldAlert, ExternalLink, MapPin } from 'lucide-react';

function isIpIndicator(iocType?: string, value?: string): boolean {
  if (value && typeof value === 'string') {
    const val = value.trim();
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$/;
    if (ipv4Regex.test(val) || ipv6Regex.test(val)) {
      return true;
    }
  }
  if (iocType && typeof iocType === 'string') {
    const t = iocType.toUpperCase();
    if (['IP', 'IP_ADDRESS', 'IPADDRESS', 'IPV4', 'IPV6'].includes(t)) {
      return true;
    }
  }
  return false;
}

export function IOCTable({ iocs }: IOCTableProps) {
  if (!iocs.length) {
    return (
      <div className="text-center py-8 text-[hsl(var(--foreground-subtle))] text-sm">
        No IOCs extracted
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[hsl(var(--border))]">
            <th className="text-left py-2 px-3 text-[hsl(var(--foreground-subtle))] font-medium text-xs uppercase tracking-wider">Type</th>
            <th className="text-left py-2 px-3 text-[hsl(var(--foreground-subtle))] font-medium text-xs uppercase tracking-wider">Indicator</th>
            <th className="text-left py-2 px-3 text-[hsl(var(--foreground-subtle))] font-medium text-xs uppercase tracking-wider">Verdict</th>
            <th className="text-left py-2 px-3 text-[hsl(var(--foreground-subtle))] font-medium text-xs uppercase tracking-wider">Score</th>
            <th className="text-right py-2 px-3 text-[hsl(var(--foreground-subtle))] font-medium text-xs uppercase tracking-wider">Pivots</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[hsl(var(--border-subtle))]">
          {iocs.map((ioc) => (
            <tr key={ioc.id} className="hover:bg-[hsl(var(--surface-2))] transition-colors group">
              <td className="py-2 px-3">
                <span className="text-xs text-[hsl(var(--foreground-muted))] font-sans whitespace-nowrap">
                  {getIOCTypeLabel(ioc.ioc_type)}
                </span>
              </td>
              <td className="py-2 px-3">
                <span className="font-mono text-xs text-[hsl(var(--foreground))] break-all">
                  {ioc.value.length > 80 ? `${ioc.value.slice(0, 80)}…` : ioc.value}
                </span>
              </td>
              <td className="py-2 px-3 whitespace-nowrap">
                {ioc.is_malicious === true || (ioc.threat_score ?? 0) >= 70 ? (
                  <span className="severity-critical text-xs px-1.5 py-0.5 rounded font-mono font-bold">Malicious</span>
                ) : (ioc.threat_score ?? 0) >= 40 ? (
                  <span className="severity-medium text-xs px-1.5 py-0.5 rounded font-mono font-bold">Suspicious</span>
                ) : (
                  <span className="severity-low text-xs px-1.5 py-0.5 rounded font-mono font-bold">Clean</span>
                )}
              </td>
              <td className="py-2 px-3 whitespace-nowrap">
                <ThreatScoreBar score={ioc.threat_score ?? 0} />
              </td>
              <td className="py-2 px-3 text-right whitespace-nowrap">
                <div className="inline-flex items-center gap-1.5 justify-end">
                  <Link
                    to={`/intel?search=${encodeURIComponent(ioc.value)}`}
                    className="p-1 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--accent))] transition-colors"
                    title="Investigate in Threat Intelligence Repository"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                  </Link>
                  <Link
                    to={`/graph?query=${encodeURIComponent(ioc.value)}`}
                    className="p-1 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-purple-400 transition-colors"
                    title="Correlate in Campaign Graph"
                  >
                    <Network className="w-3.5 h-3.5" />
                  </Link>
                  {isIpIndicator(ioc.ioc_type, ioc.value) && (
                    <Link
                      to={`/geo?ip=${encodeURIComponent(ioc.value)}`}
                      className="p-1 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-emerald-400 transition-colors"
                      title="Geolocate IP Origin on Map"
                    >
                      <MapPin className="w-3.5 h-3.5" />
                    </Link>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ThreatScoreBar({ score }: { score: number }) {
  const color = score >= 70 ? 'hsl(var(--critical))' : score >= 40 ? 'hsl(var(--medium))' : 'hsl(var(--low))';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-[hsl(var(--surface-3))] max-w-[60px]">
        <div
          className="h-1.5 rounded-full transition-all"
          style={{ width: `${score}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs text-[hsl(var(--foreground-muted))]">{score}</span>
    </div>
  );
}
