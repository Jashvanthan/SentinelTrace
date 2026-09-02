// SentinelTrace Frontend — Threat Intel Page

import { useState } from 'react';
import { ShieldAlert, Search, Globe, Hash, Link as LinkIcon, Mail } from 'lucide-react';
import apiClient from '@/lib/api';
import { cn } from '@/utils';
import type { EnrichmentResponse } from '@/types';

type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'email';

const TYPE_OPTIONS: { value: IndicatorType; label: string; icon: typeof Globe; placeholder: string }[] = [
  { value: 'ip', label: 'IP Address', icon: Globe, placeholder: '8.8.8.8' },
  { value: 'domain', label: 'Domain', icon: Globe, placeholder: 'example.com' },
  { value: 'url', label: 'URL', icon: LinkIcon, placeholder: 'https://malicious.example.com/payload' },
  { value: 'hash', label: 'File Hash', icon: Hash, placeholder: 'SHA-256 or MD5 hash' },
  { value: 'email', label: 'Email', icon: Mail, placeholder: 'attacker@example.com' },
];

export function ThreatIntelPage() {
  const [indicator, setIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState<IndicatorType>('ip');
  const [result, setResult] = useState<EnrichmentResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleEnrich = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiClient.post<EnrichmentResponse>('/intel/enrich', {
        indicator: indicator.trim(),
        indicator_type: indicatorType,
      });
      setResult(res.data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Enrichment failed');
    } finally {
      setLoading(false);
    }
  };

  const selectedType = TYPE_OPTIONS.find((t) => t.value === indicatorType)!;

  return (
    <div className="space-y-5 max-w-3xl">
      <div>
        <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Threat Intelligence</h1>
        <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
          Enrich indicators against VirusTotal, AbuseIPDB, and Shodan
        </p>
      </div>

      {/* Query Form */}
      <form onSubmit={handleEnrich} className="card-surface p-6 space-y-4">
        {/* Type selector */}
        <div className="flex flex-wrap gap-2">
          {TYPE_OPTIONS.map((t) => (
            <button
              key={t.value}
              type="button"
              onClick={() => { setIndicatorType(t.value); setResult(null); }}
              className={cn(
                'px-3 py-1.5 rounded-md text-xs font-medium border transition-colors',
                indicatorType === t.value
                  ? 'bg-[hsl(var(--accent-subtle))] text-[hsl(var(--accent))] border-[hsl(var(--accent)/0.3)]'
                  : 'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-3))]'
              )}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[hsl(var(--foreground-subtle))]" />
            <input
              type="text"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              placeholder={selectedType.placeholder}
              className="w-full pl-9 pr-3 py-2.5 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:border-[hsl(var(--accent)/0.5)] focus:outline-none font-mono"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading || !indicator.trim()}
            className="px-5 py-2.5 rounded-md bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] text-sm font-medium hover:bg-[hsl(var(--accent-hover))] disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {loading ? (
              <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
            ) : (
              <ShieldAlert className="w-4 h-4" />
            )}
            {loading ? 'Enriching…' : 'Enrich'}
          </button>
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="p-4 rounded-md bg-[hsl(var(--critical-subtle))] border border-[hsl(var(--critical)/0.3)] text-sm text-[hsl(var(--critical))]">
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Verdict Card */}
          <div className={cn(
            'card-surface p-5 border-l-4',
            result.is_malicious
              ? 'border-l-[hsl(var(--critical))]'
              : 'border-l-[hsl(var(--low))]'
          )}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">Verdict</p>
                <p className={cn('text-xl font-bold mt-1', result.is_malicious ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--low))]')}>
                  {result.is_malicious ? '⚠ MALICIOUS' : '✓ CLEAN'}
                </p>
                <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1 font-mono">{result.indicator}</p>
              </div>
              <div className="text-right">
                <p className="text-xs text-[hsl(var(--foreground-subtle))]">Threat Score</p>
                <p className={cn('text-3xl font-bold tabular-nums', result.aggregate_threat_score >= 70 ? 'text-[hsl(var(--critical))]' : result.aggregate_threat_score >= 40 ? 'text-[hsl(var(--medium))]' : 'text-[hsl(var(--low))]')}>
                  {result.aggregate_threat_score}
                </p>
                <p className="text-xs text-[hsl(var(--foreground-subtle))]">/ 100</p>
              </div>
            </div>
          </div>

          {/* VirusTotal */}
          {result.virustotal && (
            <ProviderCard title="VirusTotal" color="hsl(25, 90%, 52%)">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: 'Malicious', value: result.virustotal.malicious_count, alert: result.virustotal.malicious_count > 0 },
                  { label: 'Suspicious', value: result.virustotal.suspicious_count },
                  { label: 'Harmless', value: result.virustotal.harmless_count },
                  { label: 'Total Engines', value: result.virustotal.total_engines },
                ].map(({ label, value, alert }) => (
                  <div key={label} className="text-center">
                    <p className={cn('text-xl font-bold', alert ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--foreground))]')}>{value}</p>
                    <p className="text-xs text-[hsl(var(--foreground-muted))]">{label}</p>
                  </div>
                ))}
              </div>
            </ProviderCard>
          )}

          {/* AbuseIPDB */}
          {result.abuseipdb && (
            <ProviderCard title="AbuseIPDB" color="hsl(192, 90%, 45%)">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {[
                  { label: 'Abuse Score', value: `${result.abuseipdb.abuse_confidence_score}%`, alert: result.abuseipdb.abuse_confidence_score > 50 },
                  { label: 'Total Reports', value: result.abuseipdb.total_reports },
                  { label: 'Country', value: result.abuseipdb.country_code || '—' },
                  { label: 'ISP', value: result.abuseipdb.isp || '—' },
                  { label: 'Whitelisted', value: result.abuseipdb.is_whitelisted ? 'Yes' : 'No' },
                ].map(({ label, value, alert }) => (
                  <div key={label}>
                    <p className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">{label}</p>
                    <p className={cn('text-sm font-semibold mt-0.5', alert ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--foreground))]')}>{value}</p>
                  </div>
                ))}
              </div>
            </ProviderCard>
          )}

          {/* Shodan */}
          {result.shodan && !('error' in result.shodan) && (
            <ProviderCard title="Shodan" color="hsl(270, 70%, 60%)">
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: 'Open Ports', value: result.shodan.ports?.join(', ') || '—' },
                  { label: 'Country', value: result.shodan.country_name || '—' },
                  { label: 'Organization', value: result.shodan.org || '—' },
                  { label: 'OS', value: result.shodan.os || '—' },
                  { label: 'CVEs', value: result.shodan.vulns?.length ? result.shodan.vulns.join(', ') : 'None' },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">{label}</p>
                    <p className="text-sm font-mono text-[hsl(var(--foreground))] mt-0.5 break-all">{value}</p>
                  </div>
                ))}
              </div>
            </ProviderCard>
          )}
        </div>
      )}
    </div>
  );
}

function ProviderCard({ title, color, children }: { title: string; color: string; children: React.ReactNode }) {
  return (
    <div className="card-surface p-5">
      <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
        <span style={{ color }}>{title}</span>
      </h3>
      {children}
    </div>
  );
}
