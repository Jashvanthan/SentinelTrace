// SentinelTrace Frontend — Infrastructure Geolocation & Network Telemetry Page

import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Globe, Search, MapPin, ShieldAlert, ShieldCheck, Server,
  Clock, Navigation, ExternalLink, RefreshCw, AlertTriangle, Radio,
  Network, Mail, Layers, Shield, CreditCard, FileText, Copy, Check,
  Sparkles, Lock, Building, Terminal, X, ShieldQuestion
} from 'lucide-react';
import apiClient from '@/lib/api';
import type { GeoLocationResponse } from '@/types';
import { cn } from '@/utils';
import { useWorkspaceStore } from '@/store/workspace';
import { useThreatIntelligence, useAnalysis, useEmailObservedIPs, useEmailIPTrace } from '@/api/hooks';
import { IPTraceMap } from '@/components/ip-trace/IPTraceMap';

const SAMPLE_IPS = [
  { label: 'Cloudflare Anycast', ip: '1.1.1.1', type: 'Edge Anycast' },
  { label: 'Quad9 Security DNS', ip: '9.9.9.9', type: 'Anycast DNS' },
  { label: 'Tor Exit Node (Sample)', ip: '185.220.101.5', type: 'Anonymizer' },
  { label: 'AWS Cloud Transit', ip: '52.95.110.1', type: 'Cloud Hosting' },
  { label: 'DigitalOcean Cloud', ip: '138.68.10.1', type: 'Datacenter' },
  { label: 'Linode VPS', ip: '45.33.32.156', type: 'VPS / Hosting' },
];

function normalizeIp(ip: string): string {
  const trimmed = ip.trim();
  const parts = trimmed.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
    const numbers = parts.map((p) => parseInt(p, 10));
    if (numbers.every((n) => n >= 0 && n <= 255)) {
      return numbers.join('.');
    }
  }
  return trimmed;
}

function parseIpv4ToUint(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let uint = 0;
  for (let i = 0; i < 4; i++) {
    const n = parseInt(parts[i], 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    uint = ((uint << 8) + n) >>> 0;
  }
  return uint;
}

function isIpv4InSubnet(ipUint: number, networkUint: number, maskBits: number): boolean {
  const mask = maskBits === 0 ? 0 : (0xFFFFFFFF << (32 - maskBits)) >>> 0;
  return (ipUint & mask) === (networkUint & mask);
}

function isValidIp(ip: string): boolean {
  const normalized = normalizeIp(ip);
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$/;
  return ipv4Regex.test(normalized) || ipv6Regex.test(normalized);
}

function isPrivateIp(ip: string): boolean {
  const normalized = normalizeIp(ip);
  const ipUint = parseIpv4ToUint(normalized);

  if (ipUint !== null) {
    // 127.0.0.0/8 (Loopback)
    if (isIpv4InSubnet(ipUint, 0x7F000000, 8)) return true;
    // 10.0.0.0/8 (Private)
    if (isIpv4InSubnet(ipUint, 0x0A000000, 8)) return true;
    // 172.16.0.0/12 (Private)
    if (isIpv4InSubnet(ipUint, 0xAC100000, 12)) return true;
    // 192.168.0.0/16 (Private)
    if (isIpv4InSubnet(ipUint, 0xC0A80000, 16)) return true;
    // 169.254.0.0/16 (Link-Local)
    if (isIpv4InSubnet(ipUint, 0xA9FE0000, 16)) return true;
    // 100.64.0.0/10 (Shared Address Space / CGN)
    if (isIpv4InSubnet(ipUint, 0x64400000, 10)) return true;
    // 0.0.0.0/8 (Current network / Unspecified)
    if (isIpv4InSubnet(ipUint, 0x00000000, 8)) return true;
    // 224.0.0.0/4 (Multicast)
    if (isIpv4InSubnet(ipUint, 0xE0000000, 4)) return true;
    // 240.0.0.0/4 (Reserved)
    if (isIpv4InSubnet(ipUint, 0xF0000000, 4)) return true;
    return false;
  }

  // IPv6 checks
  const lower = normalized.toLowerCase();
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('ff')) return true;

  return false;
}

export function GeolocationPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const ipParam = searchParams.get('ip');
  const analysisIdParam = searchParams.get('analysis_id');
  const sourceParam = searchParams.get('source');

  const [ipInput, setIpInput] = useState(ipParam || '');
  const [activeIp, setActiveIp] = useState<string | null>(ipParam ? normalizeIp(ipParam) : null);
  const [geoData, setGeoData] = useState<GeoLocationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<GeoLocationResponse[]>([]);

  const [isSubpoenaModalOpen, setIsSubpoenaModalOpen] = useState(false);
  const [isSubscriptionModalOpen, setIsSubscriptionModalOpen] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2500);
  };

  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: iocData } = useThreatIntelligence(currentWorkspaceId);
  const { data: analysis } = useAnalysis(analysisIdParam || '', currentWorkspaceId);
  const { data: observedIpsData } = useEmailObservedIPs(analysisIdParam || undefined, currentWorkspaceId);
  const { data: emailTraceData, isLoading: isEmailTraceLoading } = useEmailIPTrace(analysisIdParam || undefined, currentWorkspaceId);

  // Extract recent IP IOCs from workspace threat intelligence if available
  const workspaceIps = (iocData?.items || [])
    .filter((ioc) => ioc.ioc_type === 'IP' || ioc.ioc_type === 'IPAddress' || ioc.ioc_type === 'IP_ADDRESS')
    .slice(0, 5);

  const handleLookup = useCallback(async (targetIp?: string, updateUrl = true) => {
    const rawIp = (targetIp !== undefined ? targetIp : ipInput).trim();
    
    if (!rawIp) {
      setError('Please enter an IP address to trace.');
      setGeoData(null);
      setActiveIp(null);
      return;
    }

    // Client-side strict validation
    if (!isValidIp(rawIp)) {
      setError(`Invalid IP address format: "${rawIp}". Geolocation requires a valid IPv4 or IPv6 address.`);
      setGeoData(null);
      setActiveIp(rawIp);
      return;
    }

    const queryIp = normalizeIp(rawIp);

    if (updateUrl) {
      const newParams = new URLSearchParams(searchParams);
      newParams.set('ip', queryIp);
      setSearchParams(newParams);
    }

    setActiveIp(queryIp);
    setError(null);

    // RFC 1918 / Private network handling without calling external providers
    if (isPrivateIp(queryIp)) {
      setIsLoading(false);
      const privateResult: GeoLocationResponse = {
        ip_address: queryIp,
        country: 'Private Network (RFC 1918 / RFC 6598)',
        country_code: 'LAN',
        region: 'Internal Intranet Range',
        city: 'Local Enclave',
        provider: 'Local Network Filter (No External Query)',
        is_proxy: false,
        is_vpn: false,
        is_tor: false,
        is_hosting: false,
        routing_type: 'private_lan',
        routing_label: 'Private / Reserved IP (No Public Geo)',
      };
      setGeoData(privateResult);
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.ip_address !== queryIp);
        return [privateResult, ...filtered].slice(0, 8);
      });
      return;
    }

    setIsLoading(true);

    try {
      const res = await apiClient.post<GeoLocationResponse>('/geo/locate', {
        ip_address: queryIp,
      });
      setGeoData(res.data);
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.ip_address !== res.data.ip_address);
        return [res.data, ...filtered].slice(0, 8);
      });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      let errMsg = `Failed to resolve geolocation telemetry for ${queryIp}`;
      if (typeof detail === 'string') {
        errMsg = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        errMsg = detail[0]?.msg || detail[0]?.message || errMsg;
      }
      setError(errMsg);
      setGeoData(null);
    } finally {
      setIsLoading(false);
    }
  }, [ipInput, searchParams, setSearchParams]);

  // Synchronize lookup when URL ?ip= or ?analysis_id= parameter changes
  useEffect(() => {
    if (ipParam) {
      setIpInput(ipParam);
      handleLookup(ipParam, false);
    } else if (analysisIdParam && observedIpsData?.ips && observedIpsData.ips.length > 0) {
      const defaultIp =
        observedIpsData.ips.find((i: any) => !i.is_private)?.ip_address ||
        observedIpsData.ips[0]?.ip_address;
      if (defaultIp) {
        setIpInput(defaultIp);
        handleLookup(defaultIp, false);
      }
    } else if (!ipParam && !analysisIdParam) {
      setActiveIp(null);
      setGeoData(null);
      setError(null);
    }
  }, [ipParam, analysisIdParam, observedIpsData]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[hsl(var(--foreground))] flex items-center gap-2.5">
            <Globe className="w-6 h-6 text-[hsl(var(--accent))]" />
            Infrastructure Geolocation & Network Trace
          </h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            Global network telemetry, autonomous system mapping, and telecom/ISP subscriber forensic tracing
          </p>
        </div>

        {/* Subscription Plan Status Badge & Switcher */}
        <div className="flex items-center gap-2.5">
          <div className="hidden sm:flex flex-col items-end text-right font-mono">
            <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-emerald-400" /> FULL ACCESS ENABLED (DEV MODE)
            </span>
            <span className="text-[11px] text-[hsl(var(--foreground-muted))]">
              Unlimited ISP Billing, Subpoena & Network Telemetry
            </span>
          </div>

          <button
            onClick={() => setIsSubscriptionModalOpen(true)}
            className="px-3.5 py-2 rounded-lg bg-[#182030] hover:bg-[#1f2a3e] border border-[#232e42] text-white text-xs font-mono font-semibold flex items-center gap-2 transition-all cursor-pointer shadow-sm hover:border-[#3b82f6]"
          >
            <CreditCard className="w-4 h-4 text-[#3b82f6]" />
            <span>Full Access Plan</span>
          </button>
        </div>
      </div>

      {/* Geolocation Limitations Advisory */}
      <div className="card-surface p-3.5 border-l-4 border-l-[hsl(var(--accent))] bg-[hsl(var(--surface-1))] flex items-start gap-3 text-xs">
        <Globe className="w-4 h-4 text-[hsl(var(--accent))] shrink-0 mt-0.5" />
        <p className="text-[hsl(var(--foreground-muted))] leading-relaxed">
          <strong className="text-[hsl(var(--foreground))]">Investigative Intelligence Advisory:</strong> IP geolocation represents observed source network routing, hosting infrastructure, and approximate regional telemetry. Geolocation is an intelligence signal and does not establish physical identity or physical location of an actor.
        </p>
      </div>

      {/* Interactive Email Forensic Source Trace & Observed IP Banner */}
      {analysisIdParam && (
        <div className="card-surface p-4 border border-[hsl(var(--accent)/0.3)] bg-[#121824] rounded-lg space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1f2a3e] pb-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#2563eb]/20 text-[#60a5fa] border border-[#2563eb]/40 uppercase tracking-wider">
                  Forensic Email Source Trace
                </span>
                {sourceParam && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161c2b] border border-[#232e42] text-[hsl(var(--foreground-muted))]">
                    {sourceParam}
                  </span>
                )}
              </div>
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <Mail className="w-4 h-4 text-[#3b82f6]" />
                <span>{analysis?.subject || 'Analyzed Email Sample'}</span>
              </h3>
              {analysis?.sender_email && (
                <p className="text-xs font-mono text-[hsl(var(--foreground-muted))]">
                  Sender: <span className="text-white">{analysis.sender_email}</span>
                </p>
              )}
            </div>

            <Link
              to={`/emails/${analysisIdParam}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-semibold bg-[#182030] hover:bg-[#1f2a3e] text-white border border-[#232e42] transition-colors shrink-0 cursor-pointer"
            >
              <span>View Full Email Forensics</span>
              <ExternalLink className="w-3.5 h-3.5 text-[#3b82f6]" />
            </Link>
          </div>

          {/* Observed IP Selector Chips from this email sample */}
          {observedIpsData?.ips && observedIpsData.ips.length > 0 && (
            <div className="space-y-2 pt-1 font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-[hsl(var(--foreground-subtle))] uppercase tracking-wider font-semibold">
                  Observed Email IPs ({observedIpsData.ips.length}) — Click to Trace on Map:
                </span>
                <span className="text-[11px] text-[#60a5fa]">
                  {observedIpsData.public_ips_count} Public IP(s) Observed
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {observedIpsData.ips.map((item: any) => {
                  const isCurrent = activeIp === item.ip_address;
                  return (
                    <button
                      key={item.ip_address}
                      onClick={() => {
                        setIpInput(item.ip_address);
                        handleLookup(item.ip_address);
                      }}
                      className={cn(
                        "px-2.5 py-1 rounded text-xs font-mono flex items-center gap-1.5 transition-all cursor-pointer border",
                        isCurrent
                          ? "bg-[#2563eb] text-white border-[#3b82f6] shadow-sm font-bold"
                          : "bg-[#161c2b] hover:bg-[#1f2a3e] text-slate-300 border-[#232e42]"
                      )}
                    >
                      <MapPin className={cn("w-3 h-3", isCurrent ? "text-white" : "text-emerald-400")} />
                      <span>{item.ip_address}</span>
                      {item.description && (
                        <span className={cn("text-[10px]", isCurrent ? "text-blue-100" : "text-slate-500")}>
                          ({item.description})
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Search Bar & Quick Chips */}
      <div className="card-surface p-5 space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLookup(ipInput);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-[hsl(var(--foreground-subtle))]" />
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter IPv4 or IPv6 address (e.g. 185.220.101.5, 203.0.113.25)"
              className="w-full pl-10 pr-4 py-2.5 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-lg text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))] focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !ipInput.trim()}
            className="px-6 py-2.5 bg-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-hover))] text-[hsl(var(--accent-foreground))] rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Querying…
              </>
            ) : (
              <>
                <Navigation className="w-4 h-4" />
                Trace IP Telemetry
              </>
            )}
          </button>
        </form>

        {/* Preset Chips */}
        <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-[hsl(var(--border))]">
          <span className="text-xs text-[hsl(var(--foreground-subtle))] font-medium mr-1">
            Quick Reference Targets:
          </span>
          {SAMPLE_IPS.map((sample) => (
            <button
              key={sample.ip}
              type="button"
              onClick={() => {
                setIpInput(sample.ip);
                handleLookup(sample.ip);
              }}
              className="text-xs px-2.5 py-1 rounded bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))] border border-[hsl(var(--border))] transition-colors flex items-center gap-1.5 font-mono cursor-pointer"
            >
              <span>{sample.ip}</span>
              <span className="text-[10px] text-[hsl(var(--foreground-subtle))]">({sample.label})</span>
            </button>
          ))}
          {workspaceIps.map((ioc) => (
            <button
              key={ioc.id}
              type="button"
              onClick={() => {
                setIpInput(ioc.value);
                handleLookup(ioc.value);
              }}
              className="text-xs px-2.5 py-1 rounded bg-[hsl(var(--accent-subtle))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)] transition-colors flex items-center gap-1.5 font-mono cursor-pointer"
            >
              <Radio className="w-3 h-3" />
              <span>{ioc.value}</span>
              <span className="text-[10px]">IOC</span>
            </button>
          ))}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-lg bg-[hsl(var(--destructive-subtle))] border border-[hsl(var(--destructive)/0.3)] text-sm text-[hsl(var(--destructive))] flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State when no IP is provided */}
      {!isLoading && !error && !geoData && !activeIp && (
        <div className="card-surface p-12 text-center flex flex-col items-center justify-center gap-4">
          <div className="w-14 h-14 rounded-full bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex items-center justify-center text-[hsl(var(--accent))]">
            <Globe className="w-7 h-7" />
          </div>
          <div className="max-w-md">
            <h3 className="text-base font-semibold text-[hsl(var(--foreground))]">
              No IP Address Selected
            </h3>
            <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1.5">
              Open Geolocation from an observed IP in an email investigation, select a quick reference target, or enter an IPv4/IPv6 address above to trace network routing telemetry.
            </p>
          </div>
        </div>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="card-surface p-12 flex flex-col items-center justify-center gap-3 animate-pulse">
          <RefreshCw className="w-8 h-8 text-[hsl(var(--accent))] animate-spin" />
          <p className="text-sm text-[hsl(var(--foreground-muted))]">
            Tracing routing path and querying autonomous systems for {activeIp}…
          </p>
        </div>
      )}

      {/* Private IP Advisory */}
      {!isLoading && geoData && isPrivateIp(geoData.ip_address) && (
        <div className="p-4 rounded-lg bg-[hsl(var(--warning-subtle,var(--medium-subtle)))] border border-[hsl(var(--medium)/0.3)] text-xs text-[hsl(var(--foreground))] flex items-start gap-3">
          <Shield className="w-4 h-4 text-[hsl(var(--medium))] shrink-0 mt-0.5" />
          <div>
            <strong className="block font-semibold text-[hsl(var(--medium))]">Private / Reserved Address Space:</strong>
            The IP address <span className="font-mono font-bold">{geoData.ip_address}</span> belongs to a private network (RFC 1918 / RFC 6598 / Loopback). Public internet geolocation and external multi-provider queries are not applicable.
          </div>
        </div>
      )}

      {/* Telemetry Result */}
      {!isLoading && geoData && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Info Card */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card-surface p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[hsl(var(--border))] gap-3">
                <div>
                  <div className="flex items-center gap-3">
                    <span className="text-2xl font-mono font-bold text-[hsl(var(--foreground))]">
                      {geoData.ip_address}
                    </span>
                    {geoData.country_code && (
                      <span className="text-xs font-semibold px-2 py-0.5 rounded bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-[hsl(var(--foreground-muted))] uppercase tracking-wider">
                        {geoData.country_code}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1 flex items-center gap-1.5">
                    <MapPin className="w-4 h-4 text-[hsl(var(--accent))]" />
                    {[geoData.city, geoData.region, geoData.country].filter(Boolean).join(', ') || 'Global Infrastructure'}
                  </p>
                </div>

                {/* Routing Classification Badges */}
                <div className="flex items-center gap-2 flex-wrap">
                  {geoData.is_tor ? (
                    <span className="px-2.5 py-1 rounded text-xs font-bold bg-[hsl(var(--critical-subtle))] text-[hsl(var(--critical))] border border-[hsl(var(--critical)/0.3)] flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Tor Exit Node
                    </span>
                  ) : geoData.is_vpn ? (
                    <span className="px-2.5 py-1 rounded text-xs font-semibold bg-[hsl(var(--high-subtle))] text-[hsl(var(--high))] border border-[hsl(var(--high)/0.3)] flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Commercial VPN Gateway
                    </span>
                  ) : geoData.is_hosting ? (
                    <span className="px-2.5 py-1 rounded text-xs font-semibold bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)] flex items-center gap-1">
                      <Server className="w-3.5 h-3.5" /> Datacenter / Cloud Infrastructure
                    </span>
                  ) : geoData.is_proxy ? (
                    <span className="px-2.5 py-1 rounded text-xs font-semibold bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)] flex items-center gap-1">
                      <ShieldAlert className="w-3.5 h-3.5" /> Proxy Relay
                    </span>
                  ) : (
                    <span className="px-2.5 py-1 rounded text-xs font-semibold bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)] flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" /> {geoData.routing_label || 'Direct Public Routing'}
                    </span>
                  )}
                </div>
              </div>

              {/* Network Hop Trace Visualizer */}
              <div className="p-4 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-3">
                <p className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase tracking-wider flex items-center gap-2">
                  <Network className="w-4 h-4 text-[hsl(var(--accent))]" />
                  Observed Network Routing Path
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs">
                  <div className="p-2.5 rounded bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))]">
                    <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block">1. INGRESS IP</span>
                    <span className="font-mono font-medium text-[hsl(var(--foreground))] truncate block mt-0.5">{geoData.ip_address}</span>
                  </div>
                  <div className="p-2.5 rounded bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))]">
                    <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block">2. AUTONOMOUS SYSTEM</span>
                    <span className="font-mono font-medium text-[hsl(var(--foreground))] truncate block mt-0.5">{geoData.asn || 'AS-Not Advertised'}</span>
                  </div>
                  <div className="p-2.5 rounded bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))]">
                    <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block">3. CARRIER / ISP</span>
                    <span className="font-medium text-[hsl(var(--foreground))] truncate block mt-0.5">{geoData.isp || geoData.org || 'Direct Network'}</span>
                  </div>
                  <div className="p-2.5 rounded bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))]">
                    <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block">4. REGIONAL FACILITY</span>
                    <span className="font-medium text-[hsl(var(--foreground))] truncate block mt-0.5">{geoData.city || geoData.region || geoData.country || 'Global Node'}</span>
                  </div>
                </div>
              </div>

              {/* Data Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-5">
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Country / Continent</p>
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    {geoData.country || 'Unknown'} {geoData.continent ? `(${geoData.continent})` : ''}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">City / Region / Postal</p>
                  <p className="text-sm font-medium text-[hsl(var(--foreground))]">
                    {[geoData.city, geoData.region, geoData.postal].filter(Boolean).join(', ') || 'Global Node'}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Estimated Coordinates</p>
                  <p className="text-sm font-mono text-[hsl(var(--foreground))]">
                    {geoData.latitude != null && geoData.longitude != null
                      ? `${geoData.latitude.toFixed(4)}, ${geoData.longitude.toFixed(4)}`
                      : 'Not reported'}
                    {geoData.accuracy_radius != null && (
                      <span className="block text-[11px] text-[hsl(var(--foreground-muted))] mt-0.5">
                        Accuracy Radius: ±{geoData.accuracy_radius} km
                      </span>
                    )}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Autonomous System (ASN)</p>
                  <p className="text-sm font-mono text-[hsl(var(--foreground))]">
                    {geoData.asn || 'Not advertised'}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Network Carrier / ISP</p>
                  <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate" title={geoData.isp || undefined}>
                    {geoData.isp || 'Unknown'}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Organization / Network</p>
                  <p className="text-sm font-medium text-[hsl(var(--foreground))] truncate" title={geoData.org || geoData.network || undefined}>
                    {geoData.org || geoData.network || 'Unknown'}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Timezone</p>
                  <p className="text-sm font-medium text-[hsl(var(--foreground))] flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-[hsl(var(--foreground-subtle))]" />
                    {geoData.timezone || 'UTC'}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Authoritative Source</p>
                  <p className="text-sm font-mono text-[hsl(var(--foreground))]">
                    {geoData.provider}
                  </p>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wider text-[hsl(var(--foreground-subtle))] mb-1">Telemetry Confidence</p>
                  <p className="text-sm font-medium text-[hsl(var(--accent))]">
                    {geoData.location_confidence === 'PROVIDER_DISAGREEMENT'
                      ? 'Provider Disagreement Flagged'
                      : geoData.routing_label || 'Direct Public Routing'}
                  </p>
                </div>
              </div>

              {/* Multi-Provider Telemetry Comparison (if available) */}
              {geoData.provider_comparison && geoData.provider_comparison.length > 0 && (
                <div className="pt-4 border-t border-[hsl(var(--border))] space-y-2">
                  <p className="text-xs font-semibold uppercase tracking-wider text-[hsl(var(--foreground-subtle))] flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
                    Cross-Provider Verification & Consensus
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {geoData.provider_comparison.map((cmp, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-xs space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-[hsl(var(--foreground))] uppercase">{cmp.provider}</span>
                          <span className={cn(
                            'text-[10px] px-1.5 py-0.2 rounded uppercase font-semibold',
                            cmp.status === 'AGREED' ? 'bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))]' : 'bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))]'
                          )}>
                            {cmp.status || 'REPORTED'}
                          </span>
                        </div>
                        <p className="text-[11px] text-[hsl(var(--foreground-muted))]">
                          {[cmp.city, cmp.country].filter(Boolean).join(', ')} · ASN: {cmp.asn || 'N/A'}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Interactive Map Visualizer */}
            <div className="card-surface p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
                  <MapPin className="w-4 h-4 text-[hsl(var(--accent))]" />
                  Geographic Location Mapping
                </h3>
                {geoData.latitude != null && geoData.longitude != null && (
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${geoData.latitude}&mlon=${geoData.longitude}#map=11/${geoData.latitude}/${geoData.longitude}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-[hsl(var(--accent))] hover:underline inline-flex items-center gap-1"
                  >
                    Open in OpenStreetMap <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>

              {geoData.latitude != null && geoData.longitude != null ? (
                <div className="w-full h-80 rounded-lg overflow-hidden border border-[hsl(var(--border))] relative bg-[hsl(222,20%,10%)]">
                  <iframe
                    title="Geographic Location Map"
                    width="100%"
                    height="100%"
                    frameBorder="0"
                    scrolling="no"
                    marginHeight={0}
                    marginWidth={0}
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${geoData.longitude - 0.15}%2C${geoData.latitude - 0.1}%2C${geoData.longitude + 0.15}%2C${geoData.latitude + 0.1}&layer=mapnik&marker=${geoData.latitude}%2C${geoData.longitude}`}
                    className="w-full h-full filter invert-[0.9] hue-rotate-[180deg] contrast-[1.1]"
                  />
                  <div className="absolute bottom-2 left-2 bg-[hsl(var(--surface-1)/0.9)] backdrop-blur px-3 py-1 rounded text-xs font-mono text-[hsl(var(--foreground))] border border-[hsl(var(--border))]">
                    Lat: {geoData.latitude.toFixed(4)} | Lon: {geoData.longitude.toFixed(4)}
                  </div>
                </div>
              ) : (
                <div className="h-48 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex flex-col items-center justify-center text-center p-6">
                  <MapPin className="w-8 h-8 text-[hsl(var(--foreground-subtle))] mb-2" />
                  <p className="text-sm font-medium text-[hsl(var(--foreground-muted))]">
                    Exact latitude and longitude coordinates are not available for this network block.
                  </p>
                  <p className="text-xs text-[hsl(var(--foreground-subtle))] mt-1">
                    Country level telemetry: {geoData.country || 'Unknown'}
                  </p>
                </div>
              )}
            </div>

            {/* ISP Billing Authority & Law Enforcement Subpoena Telemetry Card */}
            {!isPrivateIp(geoData.ip_address) && (
              <div className="p-4 rounded-lg bg-[#0d1424] border border-[#232e42] space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1a2336] pb-3">
                  <div className="flex items-center gap-2">
                    <Building className="w-4 h-4 text-[#3b82f6]" />
                    <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                      ISP Billing Authority & Law Enforcement Subpoena Telemetry
                    </h4>
                  </div>
                  <button
                    onClick={() => setIsSubpoenaModalOpen(true)}
                    className="px-3 py-1.5 rounded bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shrink-0"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Generate Law Enforcement Subpoena</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-1">
                    <span className="text-[10px] text-slate-400 block uppercase">Carrier Billing Entity</span>
                    <span className="font-bold text-white truncate block">
                      {geoData.org || geoData.isp || 'Registered Telecommunications Carrier'}
                    </span>
                    <span className="text-[10px] text-blue-400 block">ASN: {geoData.asn || 'AS-GLOBAL'}</span>
                  </div>

                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-1">
                    <span className="text-[10px] text-slate-400 block uppercase">RIR Registry Subnet Allocation</span>
                    <span className="font-bold text-emerald-400 truncate block">
                      {geoData.network || `${geoData.ip_address}/24 Allocation Block`}
                    </span>
                    <span className="text-[10px] text-slate-400 block">Registrar: ARIN / RIPE NCC Authority</span>
                  </div>

                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-1">
                    <span className="text-[10px] text-slate-400 block uppercase">Abuse & Legal Subpoena Desk</span>
                    <span className="font-bold text-slate-200 truncate block">
                      abuse@{geoData.isp?.toLowerCase().replace(/[^a-z0-9]/g, '') || 'carrier'}.net
                    </span>
                    <span className="text-[10px] text-slate-500 block">Legal Compliance Department</span>
                  </div>

                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-1">
                    <span className="text-[10px] text-slate-400 block uppercase">Subpoena Response SLA</span>
                    <span className="font-bold text-amber-400 block">24 - 48 Hours (Court Order Required)</span>
                    <span className="text-[10px] text-slate-500 block">DHCP Subscriber Lease Records</span>
                  </div>
                </div>
              </div>
            )}

            {/* Private LAN IP Enterprise DHCP & AD Correlation Blueprint */}
            {isPrivateIp(geoData.ip_address) && (
              <div className="p-5 rounded-lg bg-[#0d1424] border border-[#3b82f6]/40 space-y-4">
                <div className="flex items-center gap-2 border-b border-[#1a2336] pb-3">
                  <ShieldQuestion className="w-5 h-5 text-[#60a5fa]" />
                  <div>
                    <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                      Internal LAN User & Location Correlation Guide
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Private IP <span className="text-white font-bold">{geoData.ip_address}</span> cannot be mapped on public internet maps. Follow internal SOC correlation:
                    </p>
                  </div>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  {/* Step 1 */}
                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-amber-400 font-bold">Step 1: Windows DHCP Lease Lookup</span>
                      <button
                        onClick={() => copyToClipboard(`Get-DhcpServerv4Lease -IPAddress "${geoData.ip_address}"`, 'dhcp')}
                        className="px-2 py-1 rounded bg-[#182030] hover:bg-[#1f2a3e] text-slate-300 text-[10px] border border-[#232e42] flex items-center gap-1"
                      >
                        {copiedText === 'dhcp' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedText === 'dhcp' ? 'Copied' : 'Copy PowerShell'}</span>
                      </button>
                    </div>
                    <code className="block p-2 rounded bg-[#090d16] text-blue-300 text-[11px] overflow-x-auto">
                      Get-DhcpServerv4Lease -IPAddress "{geoData.ip_address}"
                    </code>
                    <p className="text-[11px] text-slate-400">
                      Extracts device Hostname, MAC Address (`00:1A:2B:3C:4D:5E`), and Lease Expiration timestamp.
                    </p>
                  </div>

                  {/* Step 2 */}
                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-emerald-400 font-bold">Step 2: Active Directory User Login Search</span>
                      <button
                        onClick={() => copyToClipboard(`Get-ADComputer -Filter "IPv4Address -eq '${geoData.ip_address}'" -Properties *`, 'ad')}
                        className="px-2 py-1 rounded bg-[#182030] hover:bg-[#1f2a3e] text-slate-300 text-[10px] border border-[#232e42] flex items-center gap-1"
                      >
                        {copiedText === 'ad' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedText === 'ad' ? 'Copied' : 'Copy PowerShell'}</span>
                      </button>
                    </div>
                    <code className="block p-2 rounded bg-[#090d16] text-emerald-300 text-[11px] overflow-x-auto">
                      Get-ADComputer -Filter "IPv4Address -eq '{geoData.ip_address}'" -Properties *
                    </code>
                    <p className="text-[11px] text-slate-400">
                      Correlates the IP to the logged-in domain user, department, and assigned computer desk ID.
                    </p>
                  </div>

                  {/* Step 3 */}
                  <div className="p-3 rounded bg-[#121824] border border-[#1f2a3e] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-blue-400 font-bold">Step 3: Local Router / Switch ARP Cache Query</span>
                      <button
                        onClick={() => copyToClipboard(`arp -a ${geoData.ip_address}`, 'arp')}
                        className="px-2 py-1 rounded bg-[#182030] hover:bg-[#1f2a3e] text-slate-300 text-[10px] border border-[#232e42] flex items-center gap-1"
                      >
                        {copiedText === 'arp' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedText === 'arp' ? 'Copied' : 'Copy Command'}</span>
                      </button>
                    </div>
                    <code className="block p-2 rounded bg-[#090d16] text-blue-300 text-[11px] overflow-x-auto">
                      arp -a {geoData.ip_address}
                    </code>
                    <p className="text-[11px] text-slate-400">
                      Resolves the hardware physical MAC address on local subnet segments.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Threat Profile & History */}
          <div className="space-y-6">
            {/* Threat Risk Assessment */}
            <div className="card-surface p-5 space-y-4">
              <h3 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
                <Server className="w-4 h-4 text-[hsl(var(--accent))]" />
                Infrastructure Profile
              </h3>

              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex justify-between items-center">
                  <span className="text-[hsl(var(--foreground-muted))]">Classification</span>
                  <span className="font-semibold text-[hsl(var(--foreground))]">
                    {geoData.routing_label || (geoData.is_tor ? 'Tor Exit' : geoData.is_vpn ? 'VPN Gateway' : geoData.is_hosting ? 'Datacenter' : 'Direct Routing')}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex justify-between items-center">
                  <span className="text-[hsl(var(--foreground-muted))]">Hosting / Datacenter</span>
                  <span className={cn('font-semibold', geoData.is_hosting ? 'text-[hsl(var(--medium))]' : 'text-[hsl(var(--low))]')}>
                    {geoData.is_hosting ? 'Cloud / VPS Hosting' : 'Eyeball / Residential'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex justify-between items-center">
                  <span className="text-[hsl(var(--foreground-muted))]">VPN Gateway</span>
                  <span className={cn('font-semibold', geoData.is_vpn ? 'text-[hsl(var(--high))]' : 'text-[hsl(var(--low))]')}>
                    {geoData.is_vpn ? 'Detected (Commercial VPN)' : 'Clear (No VPN Detected)'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex justify-between items-center">
                  <span className="text-[hsl(var(--foreground-muted))]">Tor Anonymizer</span>
                  <span className={cn('font-semibold', geoData.is_tor ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--low))]')}>
                    {geoData.is_tor ? 'Detected (Tor Exit Node)' : 'Clear (Standard Routing)'}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] flex justify-between items-center">
                  <span className="text-[hsl(var(--foreground-muted))]">Proxy Relay</span>
                  <span className={cn('font-semibold', geoData.is_proxy ? 'text-[hsl(var(--critical))]' : 'text-[hsl(var(--low))]')}>
                    {geoData.is_proxy ? 'Detected (Active Proxy)' : 'Clear (Direct Network)'}
                  </span>
                </div>
              </div>
            </div>

            {/* Recent Lookups */}
            {history.length > 0 && (
              <div className="card-surface p-5 space-y-3">
                <h3 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center justify-between">
                  <span>Recent Traced Lookups</span>
                  <span className="text-xs font-normal text-[hsl(var(--foreground-subtle))]">
                    {history.length} items
                  </span>
                </h3>
                <div className="space-y-2">
                  {history.map((item) => (
                    <button
                      key={item.ip_address}
                      type="button"
                      onClick={() => {
                        setIpInput(item.ip_address);
                        handleLookup(item.ip_address);
                      }}
                      className={cn(
                        'w-full text-left p-2.5 rounded-md border transition-colors flex items-center justify-between text-xs cursor-pointer',
                        item.ip_address === activeIp
                          ? 'bg-[hsl(var(--accent-subtle))] border-[hsl(var(--accent)/0.5)]'
                          : 'bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-3))]'
                      )}
                    >
                      <div className="min-w-0 flex-1">
                        <p className="font-mono font-medium text-[hsl(var(--foreground))] truncate">
                          {item.ip_address}
                        </p>
                        <p className="text-[10px] text-[hsl(var(--foreground-muted))] truncate">
                          {[item.city, item.country].filter(Boolean).join(', ') || 'Global'}
                        </p>
                      </div>
                      <span className="text-[10px] text-[hsl(var(--foreground-subtle))] uppercase ml-2 shrink-0">
                        {item.country_code || 'GEO'}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Email Routing Hop Topology Map */}
      {emailTraceData && (
        <div className="space-y-3 pt-4">
          <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
            <Network className="w-4 h-4 text-[#3b82f6]" />
            <span>Associated Email Hop Topology & Network Trace</span>
          </h2>
          <IPTraceMap
            traceData={emailTraceData}
            isLoading={isEmailTraceLoading}
            onSelectIp={(ip) => {
              setIpInput(ip);
              handleLookup(ip);
            }}
          />
        </div>
      )}
      {/* Law Enforcement Subpoena Form Modal */}
      {isSubpoenaModalOpen && geoData && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-surface bg-[#0d1424] border border-[#232e42] rounded-xl max-w-2xl w-full p-6 space-y-5 shadow-2xl relative font-mono">
            <button
              onClick={() => setIsSubpoenaModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded hover:bg-[#182030] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 border-b border-[#1f2a3e] pb-4">
              <div className="p-2.5 rounded-lg bg-[#2563eb]/20 text-[#60a5fa] border border-[#2563eb]/40">
                <FileText className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white uppercase tracking-wider">
                  ISP Law Enforcement Subpoena Notice Template
                </h3>
                <p className="text-xs text-slate-400">
                  Target IP: <span className="text-emerald-400 font-bold">{geoData.ip_address}</span> | ASN: {geoData.asn || 'N/A'}
                </p>
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <p className="text-slate-300">
                Copy this formal legal disclosure request to submit to the target ISP compliance desk to request subscriber billing details:
              </p>

              <div className="p-4 rounded bg-[#090d16] border border-[#1f2a3e] text-slate-300 text-[11px] leading-relaxed space-y-2 overflow-y-auto max-h-60 select-all">
                <p className="font-bold text-white">SUBPOENA & SUBSCRIBER IDENTIFICATION DISCLOSURE NOTICE</p>
                <p>TO: Legal Compliance & Abuse Desk ({geoData.isp || 'Carrier / ISP Billing Entity'})</p>
                <p>RE: Formal Inquiry / Incident Trace for Target Public IP: <span className="text-emerald-400 font-bold">{geoData.ip_address}</span></p>
                <p>TIMESTAMP OF INCIDENT (UTC): {new Date().toISOString()}</p>
                <p>LOCATION TELEMETRY: {[geoData.city, geoData.region, geoData.country].filter(Boolean).join(', ') || 'Global'}</p>
                <p>PURPOSE: SOC Security Forensics & Subscriber Identity Resolution.</p>
                <p>Pursuant to applicable cybersecurity disclosure regulations, please provide subscriber account identity, physical billing address, and NAT DHCP allocation logs associated with IP {geoData.ip_address} for the specified timestamp.</p>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 border-t border-[#1f2a3e] pt-4">
              <button
                onClick={() => setIsSubpoenaModalOpen(false)}
                className="px-4 py-2 rounded bg-[#182030] hover:bg-[#1f2a3e] text-slate-300 text-xs font-semibold border border-[#232e42] transition-colors"
              >
                Close
              </button>
              <button
                onClick={() => copyToClipboard(`SUBPOENA DISCLOSURE NOTICE\nTO: Legal Compliance (${geoData.isp})\nTARGET IP: ${geoData.ip_address}\nTIMESTAMP: ${new Date().toISOString()}\nLOCATION: ${geoData.city}, ${geoData.country}`, 'subpoena')}
                className="px-4 py-2 rounded bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedText === 'subpoena' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                <span>{copiedText === 'subpoena' ? 'Copied Subpoena Template' : 'Copy Subpoena Notice'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Subscription Plan Management Preview Modal */}
      {isSubscriptionModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-surface bg-[#0d1424] border border-[#232e42] rounded-xl max-w-3xl w-full p-6 space-y-6 shadow-2xl relative font-mono">
            <button
              onClick={() => setIsSubscriptionModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded hover:bg-[#182030] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 border-b border-[#1f2a3e] pb-4">
              <div className="p-2.5 rounded-lg bg-[#2563eb]/20 text-[#60a5fa] border border-[#2563eb]/40">
                <CreditCard className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white uppercase tracking-wider">
                  SentinelTrace Enterprise Subscription & Forensics License
                </h3>
                <p className="text-xs text-slate-400">
                  Manage plan features, ISP subscriber deep lookups, and SOC capabilities
                </p>
              </div>
            </div>

            {/* Active Preview Banner */}
            <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-emerald-400 font-bold">
                <Sparkles className="w-4 h-4" />
                <span>DEVELOPMENT ENVIRONMENT — FULL ENTERPRISE ACCESS UNLOCKED (FREE & UNLIMITED)</span>
              </div>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-bold uppercase">
                Full Unlocked
              </span>
            </div>

            {/* Plan Comparison Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              {/* Standard Plan */}
              <div className="p-4 rounded-lg bg-[#121824] border border-[#1f2a3e] space-y-3">
                <div className="flex items-center justify-between border-b border-[#1a2336] pb-2">
                  <span className="font-bold text-white text-sm">Standard SOC Tier</span>
                  <span className="text-slate-400 font-bold">Included</span>
                </div>
                <ul className="space-y-2 text-slate-300 text-[11px]">
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> MaxMind GeoIP2 Public Tracing</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Basic ASN & Country Mapping</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> RFC 1918 LAN Interception</li>
                  <li className="flex items-center gap-2 text-slate-500"><X className="w-3.5 h-3.5 text-rose-400" /> ISP Legal Subpoena Generator</li>
                </ul>
              </div>

              {/* Enterprise Plan */}
              <div className="p-4 rounded-lg bg-[#162032] border-2 border-[#3b82f6] space-y-3 relative overflow-hidden">
                <div className="absolute top-0 right-0 bg-[#2563eb] text-white text-[9px] font-bold px-3 py-0.5 rounded-bl uppercase">
                  Current Active Plan
                </div>
                <div className="flex items-center justify-between border-b border-[#232e42] pb-2">
                  <span className="font-bold text-white text-sm">Enterprise Deep Telecom Plan</span>
                  <span className="text-blue-400 font-bold">Full Access</span>
                </div>
                <ul className="space-y-2 text-slate-200 text-[11px]">
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> All Standard SOC Features</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> ISP Carrier Billing Telemetry</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Law Enforcement Subpoena Form</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Internal LAN DHCP/AD PowerShell Guide</li>
                  <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-400" /> Priority API Rate Limits</li>
                </ul>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-[#1f2a3e] pt-4 text-xs">
              <span className="text-slate-400">
                Note: No subscription charge is required for current enterprise preview evaluation.
              </span>
              <button
                onClick={() => setIsSubscriptionModalOpen(false)}
                className="px-5 py-2 rounded bg-[#2563eb] hover:bg-[#1d4ed8] text-white font-semibold transition-colors cursor-pointer"
              >
                Continue With Active License
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
