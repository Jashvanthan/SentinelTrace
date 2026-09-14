import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, Search, Globe, Hash, Link as LinkIcon, Mail,
  AlertTriangle, CheckCircle, Clock, ChevronRight, X, AlertCircle,
  Zap, Loader2, ShieldCheck, MapPin, ExternalLink, Network, FileText,
  Info, ChevronDown, ArrowUpRight, HelpCircle, Sparkles, Filter
} from 'lucide-react';
import { useThreatIntelligence, useWorkspaceStats } from '@/api/hooks';
import { useWorkspaceStore } from '@/store/workspace';
import apiClient from '@/lib/api';
import { cn, extractErrorMessage } from '@/utils';
import type { IOCResponse, EnrichmentResponse, GeoLocationResponse } from '@/types';

type IndicatorType = 'ip' | 'domain' | 'url' | 'hash';

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

const TYPE_ICONS: Record<string, any> = {
  IP_ADDRESS: Globe,
  DOMAIN: Globe,
  URL: LinkIcon,
  FILE_HASH_MD5: Hash,
  FILE_HASH_SHA256: Hash,
  EMAIL: Mail,
};

export function ThreatIntelPage() {
  const { currentWorkspaceId } = useWorkspaceStore();
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [iocType, setIocType] = useState<string>('');
  const [page, setPage] = useState(1);
  const [selectedIoc, setSelectedIoc] = useState<IOCResponse | null>(null);
  const [showGuide, setShowGuide] = useState(false);

  // Live lookup states
  const [liveIndicator, setLiveIndicator] = useState('');
  const [liveType, setLiveType] = useState<IndicatorType>('ip');
  const [isEnriching, setIsEnriching] = useState(false);
  const [liveResult, setLiveResult] = useState<EnrichmentResponse | null>(null);
  const [geoResult, setGeoResult] = useState<GeoLocationResponse | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  // Fetch Stats for Overview Cards
  const { data: stats } = useWorkspaceStats(currentWorkspaceId);

  // Fetch IOCs
  const { data: iocData, isLoading, error } = useThreatIntelligence(currentWorkspaceId, {
    search: debouncedSearch || undefined,
    ioc_type: iocType || undefined,
    page,
    page_size: 20
  });

  const handleLiveEnrich = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!liveIndicator.trim()) return;

    setIsEnriching(true);
    setLiveError(null);
    setLiveResult(null);
    setGeoResult(null);

    try {
      const enrichRes = await apiClient.post<EnrichmentResponse>('/intel/enrich', {
        indicator: liveIndicator.trim(),
        indicator_type: liveType,
      });
      setLiveResult(enrichRes.data);

      if (liveType === 'ip') {
        try {
          const geoRes = await apiClient.post<GeoLocationResponse>('/geo/locate', {
            ip_address: liveIndicator.trim(),
          });
          setGeoResult(geoRes.data);
        } catch {
          // Geo error non-fatal
        }
      }
    } catch (err: any) {
      setLiveError(extractErrorMessage(err, 'Failed to enrich indicator. Please check the value and try again.'));
    } finally {
      setIsEnriching(false);
    }
  };

  return (
    <div className="space-y-6 flex flex-col h-full max-w-7xl mx-auto">
      {/* Header & Page Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[hsl(var(--accent-subtle))] border border-[hsl(var(--accent)/0.3)]">
              <ShieldAlert className="w-5 h-5 text-[hsl(var(--accent))]" />
            </div>
            <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Threat Intelligence Repository</h1>
          </div>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            Centralized Indicators of Compromise (IOC) database extracted from email forensics, enriched across VirusTotal, AbuseIPDB, and Shodan.
          </p>
        </div>

        <button
          onClick={() => setShowGuide(!showGuide)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-xs font-medium text-[hsl(var(--foreground))] border border-[hsl(var(--border))] transition-colors self-start sm:self-auto cursor-pointer"
        >
          <HelpCircle className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
          <span>{showGuide ? 'Hide Functionality Guide' : 'Page Functionality Guide'}</span>
          <ChevronDown className={cn("w-3 h-3 transition-transform", showGuide && "rotate-180")} />
        </button>
      </div>

      {/* Interactive Page Functionality & SOC Workflow Guide */}
      {showGuide && (
        <div className="card-surface p-5 rounded-lg border border-[hsl(var(--accent)/0.3)] bg-[hsl(var(--accent-subtle)/0.3)] space-y-4 text-xs animate-in fade-in duration-200">
          <div className="flex items-center gap-2 text-sm font-semibold text-[hsl(var(--foreground))]">
            <Sparkles className="w-4 h-4 text-[hsl(var(--accent))]" />
            <span>How Threat Intelligence Connects to Email Analysis & the SOC Workflow</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-[hsl(var(--foreground-muted))] leading-relaxed">
            <div className="p-3 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md space-y-1.5">
              <p className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-sky-400" />
                1. Extracted from Inbound Emails
              </p>
              <p>
                Whenever an email sample is uploaded or synced from Gmail, the <strong>Email Forensics Engine</strong> extracts all IP addresses, sender domains, embedded URLs, and attachment SHA-256 hashes into this repository.
              </p>
              <Link to="/emails" className="text-[hsl(var(--accent))] hover:underline inline-flex items-center gap-1 text-[11px] font-medium pt-1">
                Go to Email Analysis <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="p-3 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md space-y-1.5">
              <p className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                2. Multi-Provider Intelligence
              </p>
              <p>
                Each indicator is cross-referenced with <strong>VirusTotal</strong> (AV engine verdicts), <strong>AbuseIPDB</strong> (reputation and abuse confidence scores), and <strong>Shodan / IP Geolocation</strong> to compute an aggregate threat risk score (0-100).
              </p>
            </div>

            <div className="p-3 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md space-y-1.5">
              <p className="font-semibold text-[hsl(var(--foreground))] flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-purple-400" />
                3. Cross-Module Investigation Pivots
              </p>
              <p>
                Click any indicator row to inspect its originating email, trace infrastructure topology in the <strong>Campaign Graph</strong>, geolocate sender IPs in <strong>Geolocation</strong>, or download tamper-evident <strong>Forensic Reports</strong>.
              </p>
              <Link to="/graph" className="text-[hsl(var(--accent))] hover:underline inline-flex items-center gap-1 text-[11px] font-medium pt-1">
                Explore Campaign Graph <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Overview Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 flex-shrink-0">
        <MetricCard label="Total IOCs" value={stats?.ioc_type_distribution ? Object.values(stats.ioc_type_distribution).reduce((a, b) => Number(a) + Number(b), 0) : (iocData?.total ?? '—')} />
        <MetricCard label="High/Critical Risk" value={stats?.high_critical_iocs_this_week ?? '—'} alert={!!(stats?.high_critical_iocs_this_week && stats.high_critical_iocs_this_week > 0)} />
        <MetricCard label="Threats Detected" value={stats?.threats_detected ?? '—'} />
        <MetricCard label="Active Campaigns" value={stats?.active_campaigns ?? '—'} />
      </div>

      {/* Live Enrichment Lookup Box */}
      <div className="card-surface p-5 rounded-lg border border-[hsl(var(--border))] space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-[hsl(var(--accent))]" />
          <h2 className="text-sm font-semibold text-[hsl(var(--foreground))]">Live Threat Lookup (VirusTotal, AbuseIPDB, Shodan)</h2>
        </div>
        <form onSubmit={handleLiveEnrich} className="flex flex-col sm:flex-row gap-3">
          <select
            value={liveType}
            onChange={(e) => setLiveType(e.target.value as IndicatorType)}
            className="px-3 py-2 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] focus:outline-none focus:border-[hsl(var(--accent)/0.5)]"
          >
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash">File Hash (SHA-256/MD5)</option>
          </select>
          <div className="relative flex-1">
            <input
              type="text"
              value={liveIndicator}
              onChange={(e) => setLiveIndicator(e.target.value)}
              placeholder="e.g. 8.8.8.8, paypal-alert.org, or file hash..."
              className="w-full px-3 py-2 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:border-[hsl(var(--accent)/0.5)] focus:outline-none font-mono"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="submit"
              disabled={isEnriching || !liveIndicator.trim()}
              className="flex items-center justify-center gap-2 px-5 py-2 bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] rounded-md text-sm font-medium hover:bg-[hsl(var(--accent-hover))] disabled:opacity-50 transition-colors cursor-pointer"
            >
              {isEnriching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              Enrich
            </button>
            {(liveType === 'ip' || isIpIndicator(liveType, liveIndicator)) && liveIndicator.trim() && (
              <Link
                to={`/geo?ip=${encodeURIComponent(liveIndicator.trim())}`}
                className="flex items-center justify-center gap-1.5 px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-md text-sm font-medium transition-colors cursor-pointer"
              >
                <MapPin className="w-4 h-4" />
                <span>Geolocate IP</span>
              </Link>
            )}
          </div>
        </form>

        {liveError && (
          <div className="p-3 bg-[hsl(var(--critical-subtle))] border border-[hsl(var(--critical)/0.3)] rounded-md text-xs text-[hsl(var(--critical))] flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{liveError}</span>
          </div>
        )}

        {liveResult && (
          <div className="p-4 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[hsl(var(--border))] pb-3">
              <div>
                <span className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">Indicator: </span>
                <span className="font-mono text-sm font-semibold text-[hsl(var(--foreground))]">{liveResult.indicator}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-[hsl(var(--foreground-subtle))]">Threat Score:</span>
                <span className={cn(
                  "px-2 py-0.5 rounded text-xs font-bold font-mono",
                  liveResult.aggregate_threat_score >= 70 ? "bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))]" :
                  liveResult.aggregate_threat_score >= 30 ? "bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))]" :
                  "bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))]"
                )}>
                  {liveResult.aggregate_threat_score}/100
                </span>
                <span className={cn(
                  "px-2 py-0.5 rounded text-xs font-bold",
                  liveResult.is_malicious ? "bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))]" : "bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))]"
                )}>
                  {liveResult.is_malicious ? "MALICIOUS" : "CLEAN"}
                </span>
              </div>
            </div>

            {/* Providers Breakdown */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md">
                <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase mb-1">VirusTotal</p>
                {liveResult.virustotal ? (
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    {liveResult.virustotal.malicious_count ?? 0} / {liveResult.virustotal.total_engines ?? 0} detections
                  </p>
                ) : (
                  <p className="text-xs text-[hsl(var(--foreground-muted))]">No data</p>
                )}
              </div>

              <div className="p-3 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md">
                <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase mb-1">AbuseIPDB</p>
                {liveResult.abuseipdb ? (
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    Abuse Confidence: {liveResult.abuseipdb.abuse_confidence_score ?? 0}% ({liveResult.abuseipdb.total_reports ?? 0} reports)
                  </p>
                ) : (
                  <p className="text-xs text-[hsl(var(--foreground-muted))]">No data</p>
                )}
              </div>

              <div className="p-3 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase">Geolocation / ISP</p>
                  {(liveType === 'ip' || isIpIndicator(liveResult.indicator_type || liveType, liveResult.indicator) || geoResult) && (
                    <Link
                      to={`/geo?ip=${encodeURIComponent(liveResult.indicator)}`}
                      className="text-[11px] font-mono text-emerald-400 hover:underline inline-flex items-center gap-1 bg-emerald-950/60 border border-emerald-800/50 px-2.5 py-1 rounded transition-colors font-semibold"
                      title="Open full map trace"
                    >
                      <MapPin className="w-3.5 h-3.5" />
                      <span>Trace on Map</span>
                    </Link>
                  )}
                </div>
                {geoResult ? (
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    {geoResult.city ? `${geoResult.city}, ` : ''}{geoResult.country || 'Unknown'} ({geoResult.isp || geoResult.org || 'ISP'})
                  </p>
                ) : liveResult.shodan ? (
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    Ports: {liveResult.shodan.ports?.join(', ') || 'None'}
                  </p>
                ) : (
                  <p className="text-xs text-[hsl(var(--foreground-muted))]">No data</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main UI Layout */}
      <div className="flex-1 min-h-[400px] flex flex-col lg:flex-row gap-4">
        <div className="flex-1 flex flex-col min-h-0 card-surface border border-[hsl(var(--border))] rounded-lg overflow-hidden">
          {/* Controls */}
          <div className="p-4 border-b border-[hsl(var(--border))] bg-[hsl(var(--surface-2))] space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[hsl(var(--foreground-subtle))]" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                  placeholder="Search IOC, subject, sender, or domain..."
                  className="w-full pl-9 pr-3 py-2 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:border-[hsl(var(--accent)/0.5)] focus:outline-none font-mono"
                />
              </div>
              <select
                value={iocType}
                onChange={(e) => { setIocType(e.target.value); setPage(1); }}
                className="bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md text-sm px-3 py-2 text-[hsl(var(--foreground))] focus:outline-none focus:border-[hsl(var(--accent)/0.5)]"
              >
                <option value="">All Indicator Types</option>
                <option value="IP_ADDRESS">IP Address</option>
                <option value="DOMAIN">Domain</option>
                <option value="URL">URL</option>
                <option value="FILE_HASH_SHA256">SHA-256 Hash</option>
                <option value="EMAIL">Email Address</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="flex-1 overflow-auto">
            {error ? (
              <div className="flex flex-col items-center justify-center h-48 text-[hsl(var(--critical))]">
                <AlertCircle className="w-8 h-8 mb-2" />
                <p className="text-sm">Unable to access threat intelligence.</p>
              </div>
            ) : isLoading ? (
              <div className="flex items-center justify-center h-48">
                <div className="w-6 h-6 border-2 border-[hsl(var(--accent))] border-t-transparent rounded-full animate-spin" />
              </div>
            ) : !iocData || !(iocData as any).items || (iocData as any).items.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-[hsl(var(--foreground-muted))]">
                <ShieldAlert className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">No indicators match your current filters.</p>
              </div>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[hsl(var(--border))] bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
                    <th className="px-4 py-3 font-medium">Indicator</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Associated Email</th>
                    <th className="px-4 py-3 font-medium">Verdict</th>
                    <th className="px-4 py-3 font-medium">Threat Score</th>
                    <th className="px-4 py-3 font-medium">Last Seen</th>
                    <th className="px-4 py-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[hsl(var(--border))]">
                  {(iocData as any).items.map((ioc: IOCResponse) => {
                    const Icon = TYPE_ICONS[ioc.ioc_type] || Globe;
                    const isSelected = selectedIoc?.id === ioc.id;

                    return (
                      <tr 
                        key={ioc.id} 
                        onClick={() => setSelectedIoc(ioc)}
                        className={cn(
                          "hover:bg-[hsl(var(--surface-2))] cursor-pointer transition-colors group",
                          isSelected && "bg-[hsl(var(--surface-2))] border-l-2 border-l-[hsl(var(--accent))]"
                        )}
                      >
                        <td className="px-4 py-3 font-mono font-medium text-[hsl(var(--foreground))] max-w-[220px]">
                          <div className="flex items-center gap-2 truncate">
                            <Icon className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))] flex-shrink-0" />
                            <span className="truncate" title={ioc.value}>{ioc.value}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[hsl(var(--foreground-muted))] whitespace-nowrap">
                          {ioc.ioc_type}
                        </td>
                        <td className="px-4 py-3 max-w-[220px]">
                          {ioc.analysis_id ? (
                            <Link
                              to={`/emails/${ioc.analysis_id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="text-[hsl(var(--accent))] hover:underline flex flex-col group/link"
                              title={ioc.email_subject || 'View email analysis'}
                            >
                              <span className="truncate font-medium text-[hsl(var(--foreground))] group-hover/link:text-[hsl(var(--accent))]">
                                {ioc.email_subject || 'Analyzed Inbound Email'}
                              </span>
                              {ioc.sender_email && (
                                <span className="text-[11px] text-[hsl(var(--foreground-subtle))] truncate font-mono">
                                  {ioc.sender_email}
                                </span>
                              )}
                            </Link>
                          ) : (
                            <span className="text-[hsl(var(--foreground-subtle))] italic">Manual Lookup</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge isMalicious={ioc.is_malicious} />
                        </td>
                        <td className="px-4 py-3 font-mono">
                          <SeverityBadge score={ioc.threat_score} />
                        </td>
                        <td className="px-4 py-3 text-[hsl(var(--foreground-subtle))] whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <Clock className="w-3 h-3" />
                            {ioc.last_seen_at || ioc.created_at ? new Date(ioc.last_seen_at || ioc.created_at!).toLocaleDateString() : '—'}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            {ioc.analysis_id && (
                              <Link
                                to={`/emails/${ioc.analysis_id}`}
                                className="p-1 rounded hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--accent))] transition-colors"
                                title="Open Associated Email Analysis"
                              >
                                <Mail className="w-3.5 h-3.5" />
                              </Link>
                            )}
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
                                className="px-2 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900/80 border border-emerald-800/60 text-emerald-400 hover:text-emerald-300 transition-colors inline-flex items-center gap-1 text-[11px] font-medium"
                                title="Trace IP in Geolocation"
                              >
                                <MapPin className="w-3.5 h-3.5" />
                                <span>Geolocate IP</span>
                              </Link>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
          
          {/* Pagination */}
          {iocData && (iocData as any).total > 0 && (
            <div className="p-3 border-t border-[hsl(var(--border))] flex items-center justify-between text-xs text-[hsl(var(--foreground-muted))]">
              <span>Showing {(page - 1) * 20 + 1} to {Math.min(page * 20, (iocData as any).total)} of {(iocData as any).total} entries</span>
              <div className="flex gap-2">
                <button 
                  disabled={page === 1} 
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  className="px-3 py-1 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded disabled:opacity-50 cursor-pointer"
                >
                  Prev
                </button>
                <button 
                  disabled={page * 20 >= (iocData as any).total} 
                  onClick={() => setPage(p => p + 1)}
                  className="px-3 py-1 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded disabled:opacity-50 cursor-pointer"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Investigation Detail Panel */}
        {selectedIoc && (
          <div className="w-full lg:w-96 flex-shrink-0 card-surface border border-[hsl(var(--border))] rounded-lg flex flex-col relative">
            <button 
              onClick={() => setSelectedIoc(null)}
              className="absolute top-4 right-4 p-1 hover:bg-[hsl(var(--surface-3))] rounded text-[hsl(var(--foreground-subtle))] transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="p-5 border-b border-[hsl(var(--border))] bg-[hsl(var(--surface-2))]">
              <h2 className="text-sm font-semibold text-[hsl(var(--foreground))] uppercase tracking-wider mb-2">Indicator Details</h2>
              <div className="p-3 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded-md font-mono text-xs break-all text-[hsl(var(--foreground))]">
                {selectedIoc.value}
              </div>
              <div className="flex items-center gap-2 mt-3">
                <SeverityBadge score={selectedIoc.threat_score} />
                <StatusBadge isMalicious={selectedIoc.is_malicious} />
              </div>
            </div>
            
            <div className="p-5 flex-1 overflow-y-auto space-y-5">
              {/* Originating Email Analysis Relationship Card */}
              {selectedIoc.analysis_id ? (
                <div className="p-3.5 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-2">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-[hsl(var(--accent))] uppercase tracking-wider">
                    <Mail className="w-3.5 h-3.5" />
                    <span>Originating Email Analysis</span>
                  </div>
                  <p className="text-xs font-semibold text-[hsl(var(--foreground))] line-clamp-2">
                    {selectedIoc.email_subject || 'Analyzed Inbound Email'}
                  </p>
                  {selectedIoc.sender_email && (
                    <p className="text-[11px] text-[hsl(var(--foreground-muted))] font-mono truncate">
                      From: {selectedIoc.sender_email}
                    </p>
                  )}
                  <Link
                    to={`/emails/${selectedIoc.analysis_id}`}
                    className="mt-2 inline-flex items-center justify-center gap-1.5 w-full py-1.5 px-3 rounded text-xs font-medium bg-[hsl(var(--accent-subtle))] hover:bg-[hsl(var(--accent)/0.2)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)] transition-colors"
                  >
                    <span>View Email Forensics & Verdict</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-xs text-[hsl(var(--foreground-muted))]">
                  Ad-hoc indicator lookup (not tied to an email sample).
                </div>
              )}

              {/* Cross-Module Pivot Navigation */}
              <div className="space-y-2 pt-2 border-t border-[hsl(var(--border))]">
                <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
                  Cross-Module Investigation Pivots
                </p>
                <div className="grid grid-cols-1 gap-2">
                  <Link
                    to={`/graph?query=${encodeURIComponent(selectedIoc.value)}`}
                    className="flex items-center justify-between p-2.5 rounded-md bg-[hsl(var(--surface-3))] hover:bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-xs text-[hsl(var(--foreground))] transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <Network className="w-3.5 h-3.5 text-purple-400" />
                      <span>Explore in Campaign Graph</span>
                    </span>
                    <ExternalLink className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))]" />
                  </Link>

                  {isIpIndicator(selectedIoc.ioc_type, selectedIoc.value) && (
                    <Link
                      to={`/geo?ip=${encodeURIComponent(selectedIoc.value)}`}
                      className="flex items-center justify-between p-2.5 rounded-md bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-800/50 text-xs text-emerald-300 transition-colors font-medium"
                    >
                      <span className="flex items-center gap-2">
                        <MapPin className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Trace IP in Geolocation & Network Map</span>
                      </span>
                      <ExternalLink className="w-3.5 h-3.5 text-emerald-400" />
                    </Link>
                  )}

                  <Link
                    to="/reports"
                    className="flex items-center justify-between p-2.5 rounded-md bg-[hsl(var(--surface-3))] hover:bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-xs text-[hsl(var(--foreground))] transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
                      <span>Evidence Reports Dossiers</span>
                    </span>
                    <ExternalLink className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))]" />
                  </Link>
                </div>
              </div>

              {/* Indicator Metadata Table */}
              <div className="space-y-2 pt-2 border-t border-[hsl(var(--border))]">
                <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
                  Indicator Telemetry
                </p>
                <div className="space-y-1">
                  <DetailRow label="Type" value={selectedIoc.ioc_type} />
                  <DetailRow label="Threat Score" value={selectedIoc.threat_score !== null && selectedIoc.threat_score !== undefined ? `${selectedIoc.threat_score} / 100` : 'N/A'} />
                  <DetailRow label="Confidence" value={selectedIoc.confidence_score !== null && selectedIoc.confidence_score !== undefined ? `${typeof selectedIoc.confidence_score === 'number' && selectedIoc.confidence_score <= 1 ? Math.round(selectedIoc.confidence_score * 100) : selectedIoc.confidence_score}%` : 'N/A'} />
                  <DetailRow label="Source" value={selectedIoc.source} />
                  <DetailRow label="First Seen" value={selectedIoc.first_seen_at ? new Date(selectedIoc.first_seen_at).toLocaleString() : '—'} />
                  <DetailRow label="Last Seen" value={selectedIoc.last_seen_at || selectedIoc.created_at ? new Date(selectedIoc.last_seen_at || selectedIoc.created_at!).toLocaleString() : '—'} />
                </div>
              </div>

              {selectedIoc.tags && selectedIoc.tags.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase mb-2">Tags</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedIoc.tags.map(tag => (
                      <span key={tag} className="px-2 py-1 bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] rounded text-[11px] text-[hsl(var(--foreground-muted))]">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Shared UI Components ──────────────────────────────────────────────────────

function MetricCard({ label, value, alert }: { label: string; value: string | number; alert?: boolean }) {
  return (
    <div className={cn(
      "card-surface p-4 rounded-lg border",
      alert ? "border-[hsl(var(--critical)/0.3)] bg-[hsl(var(--critical-subtle))]" : "border-[hsl(var(--border))]"
    )}>
      <p className="text-xs text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">{label}</p>
      <p className={cn("text-2xl font-bold mt-1", alert ? "text-[hsl(var(--critical))]" : "text-[hsl(var(--foreground))]")}>{value}</p>
    </div>
  );
}

function SeverityBadge({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) {
    return <span className="text-xs text-[hsl(var(--foreground-muted))] font-mono">N/A</span>;
  }
  const isCritical = score >= 70;
  const isMedium = score >= 40;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold border",
        isCritical
          ? "bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border-[hsl(var(--critical)/0.3)]"
          : isMedium
          ? "bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border-[hsl(var(--medium)/0.3)]"
          : "bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border-[hsl(var(--low)/0.3)]"
      )}
    >
      {score} / 100
    </span>
  );
}

function StatusBadge({ isMalicious }: { isMalicious: boolean | null }) {
  if (isMalicious === true) {
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border border-[hsl(var(--critical)/0.3)]">MALICIOUS</span>;
  }
  if (isMalicious === false) {
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)]">BENIGN</span>;
  }
  return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))]">UNVERIFIED</span>;
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center text-xs py-1 border-b border-[hsl(var(--border))] last:border-0">
      <span className="text-[hsl(var(--foreground-subtle))]">{label}</span>
      <span className="font-medium text-[hsl(var(--foreground))]">{value || '—'}</span>
    </div>
  );
}
