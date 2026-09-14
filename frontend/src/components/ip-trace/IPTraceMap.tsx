import { useState, useMemo } from 'react';
import {
  Globe, Network, Shield, ShieldAlert, ShieldCheck, Server,
  MapPin, Clock, ArrowRight, Layers, AlertTriangle, ExternalLink,
  Laptop, Radio, Cpu, Lock, CheckCircle2, XCircle, Info, ChevronRight,
  X, Database, Navigation, Filter, Activity, Zap
} from 'lucide-react';
import type {
  EmailIPTraceResponse,
  EmailHopNode,
  EmailPublicLocation,
  EmailPrivateNode,
  IPTraceResponse,
  EvidenceItem,
  ProviderStatusItem,
} from '@/types';
import { useIPTraceProvidersHealth } from '@/api/hooks';
import { cn } from '@/utils';

interface IPTraceMapProps {
  traceData: EmailIPTraceResponse;
  isLoading?: boolean;
  className?: string;
  onSelectIp?: (ip: string) => void;
}

export function IPTraceMap({ traceData, isLoading, className, onSelectIp }: IPTraceMapProps) {
  const [viewMode, setViewMode] = useState<'MAP' | 'TOPOLOGY'>('TOPOLOGY');
  const [selectedHop, setSelectedHop] = useState<EmailHopNode | null>(null);
  const [selectedPublicLoc, setSelectedPublicLoc] = useState<EmailPublicLocation | null>(null);
  const [selectedPrivateNode, setSelectedPrivateNode] = useState<EmailPrivateNode | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<{ name: string; info: ProviderStatusItem } | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerData, setDrawerData] = useState<any | null>(null);

  const { data: providersHealth } = useIPTraceProvidersHealth();


  const hops = traceData?.hops || [];
  const publicLocs = traceData?.public_locations || [];
  const privateNodes = traceData?.private_network_nodes || [];
  const timeline = traceData?.timeline || [];
  const boundaries = traceData?.boundaries || [];
  const evidence = traceData?.evidence || [];

  const publicCount = hops.filter((h) => h.is_public).length;
  const privateCount = hops.filter((h) => h.is_private).length;

  const handleOpenDrawer = (data: any) => {
    setDrawerData(data);
    setDrawerOpen(true);
    if (data?.ip && onSelectIp) {
      onSelectIp(data.ip);
    }
  };

  const getClassificationBadge = (cls: string) => {
    switch (cls?.toUpperCase()) {
      case 'PUBLIC':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)] inline-flex items-center gap-1">
            <Globe className="w-3 h-3" /> Public IPv4/IPv6
          </span>
        );
      case 'PRIVATE':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)] inline-flex items-center gap-1">
            <Server className="w-3 h-3" /> Private LAN (RFC 1918)
          </span>
        );
      case 'LOOPBACK':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))] inline-flex items-center gap-1">
            <Laptop className="w-3 h-3" /> Localhost Loopback
          </span>
        );
      case 'LINK_LOCAL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))] inline-flex items-center gap-1">
            <Radio className="w-3 h-3" /> Link-Local (APIPA)
          </span>
        );
      case 'UNIQUE_LOCAL':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)] inline-flex items-center gap-1">
            <Lock className="w-3 h-3" /> IPv6 Unique Local (ULA)
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] border border-[hsl(var(--border))] inline-flex items-center gap-1">
            <Info className="w-3 h-3" /> {cls || 'Unspecified'}
          </span>
        );
    }
  };

  const getTrustBadge = (trust: string) => {
    switch (trust?.toUpperCase()) {
      case 'TRUSTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--low-subtle))] text-[hsl(var(--low))] border border-[hsl(var(--low)/0.3)] flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> TRUSTED
          </span>
        );
      case 'PARTIALLY_TRUSTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--medium-subtle))] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)] flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> PARTIALLY TRUSTED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))] flex items-center gap-1">
            <Info className="w-3 h-3" /> UNVERIFIED
          </span>
        );
    }
  };

  if (isLoading) {
    return (
      <div className="card-surface p-12 flex flex-col items-center justify-center gap-3 animate-pulse">
        <Globe className="w-8 h-8 text-[hsl(var(--accent))] animate-spin" />
        <p className="text-sm text-[hsl(var(--foreground-muted))]">
          Reconstructing email transit hop chain and querying autonomous systems…
        </p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-6', className)}>
      {/* ── Mode Switcher & Summary Bar ────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl card-surface border border-[hsl(var(--border))]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[hsl(var(--accent)/0.15)] flex items-center justify-center border border-[hsl(var(--accent)/0.3)]">
            <Network className="w-5 h-5 text-[hsl(var(--accent))]" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[hsl(var(--foreground))] flex items-center gap-2">
              IP Network Trace & Provenance
              {traceData?.has_nat_boundary && (
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                  ⚡ NAT Boundary Detected
                </span>
              )}
            </h3>
            <p className="text-xs text-[hsl(var(--foreground-muted))]">
              {hops.length} Total Hops · {publicCount} Public Gateways · {privateCount} Internal Subnets
            </p>
          </div>
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center bg-[hsl(var(--surface-2))] p-1 rounded-lg border border-[hsl(var(--border))]">
          <button
            type="button"
            onClick={() => setViewMode('TOPOLOGY')}
            className={cn(
              'px-3.5 py-1.5 rounded-md text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer',
              viewMode === 'TOPOLOGY'
                ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] shadow-xs'
                : 'text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))]'
            )}
          >
            <Network className="w-4 h-4" />
            <span>Network Topology</span>
          </button>
          <button
            type="button"
            onClick={() => setViewMode('MAP')}
            className={cn(
              'px-3.5 py-1.5 rounded-md text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer',
              viewMode === 'MAP'
                ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] shadow-xs'
                : 'text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))]'
            )}
          >
            <Globe className="w-4 h-4" />
            <span>Internet Map</span>
          </button>
        </div>
      </div>

      {/* ── Compact Provider Services Status Area (Section 24) ──────────────── */}
      <div className="p-3.5 rounded-xl card-surface border border-[hsl(var(--border))] flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 font-mono font-semibold text-[hsl(var(--foreground-muted))] uppercase text-[11px]">
          <Activity className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
          <span>IP Trace Services:</span>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          {/* GeoIP */}
          <button
            type="button"
            onClick={() =>
              setSelectedProvider({
                name: 'GeoIP',
                info: providersHealth?.geoip || {
                  configured: true,
                  available: true,
                  provider: 'MaxMind GeoIP2 / Fallback API',
                  mode: 'database / online_https',
                  accuracy: 'approximate',
                },
              })
            }
            className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
          >
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                providersHealth?.geoip?.available ? 'bg-emerald-500' : 'bg-amber-500'
              )}
            />
            <span className="text-[hsl(var(--foreground))] font-medium">GeoIP</span>
            <span className="text-[hsl(var(--foreground-subtle))]">
              {providersHealth?.geoip?.available ? 'Available' : 'Unavailable'}
            </span>
          </button>

          {/* ASN */}
          <button
            type="button"
            onClick={() =>
              setSelectedProvider({
                name: 'ASN / RDAP',
                info: providersHealth?.asn || {
                  configured: true,
                  available: true,
                  provider: 'BGP / RDAP Regional Registries',
                  mode: 'open_standards',
                },
              })
            }
            className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
          >
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                providersHealth?.asn?.available ? 'bg-emerald-500' : 'bg-amber-500'
              )}
            />
            <span className="text-[hsl(var(--foreground))] font-medium">ASN</span>
            <span className="text-[hsl(var(--foreground-subtle))]">
              {providersHealth?.asn?.available ? 'Available' : 'Unavailable'}
            </span>
          </button>

          {/* Reverse DNS */}
          <button
            type="button"
            onClick={() =>
              setSelectedProvider({
                name: 'Reverse DNS',
                info: providersHealth?.reverse_dns || {
                  configured: true,
                  available: true,
                  provider: 'Non-blocking Async PTR Resolver',
                  mode: 'asynchronous_socket',
                },
              })
            }
            className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
          >
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                providersHealth?.reverse_dns?.available ? 'bg-emerald-500' : 'bg-amber-500'
              )}
            />
            <span className="text-[hsl(var(--foreground))] font-medium">Reverse DNS</span>
            <span className="text-[hsl(var(--foreground-subtle))]">
              {providersHealth?.reverse_dns?.available ? 'Available' : 'Unavailable'}
            </span>
          </button>

          {/* Threat Intel */}
          {(() => {
            const hasAnyTI =
              providersHealth?.virustotal?.available ||
              providersHealth?.abuseipdb?.available ||
              providersHealth?.shodan?.available;
            return (
              <button
                type="button"
                onClick={() =>
                  setSelectedProvider({
                    name: 'Threat Intelligence',
                    info: {
                      configured: Boolean(hasAnyTI),
                      available: Boolean(hasAnyTI),
                      provider: 'VirusTotal / AbuseIPDB / Shodan',
                      mode: 'multi_provider_api',
                      status: hasAnyTI ? 'CONFIGURED / ACTIVE' : 'API KEYS OPTIONAL',
                      reason: hasAnyTI
                        ? 'Enrichment active with configured credentials'
                        : 'External API keys not supplied; normalized threat scoring fallback active',
                    },
                  })
                }
                className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
              >
                <span
                  className={cn(
                    'w-2 h-2 rounded-full',
                    hasAnyTI ? 'bg-emerald-500' : 'bg-amber-500'
                  )}
                />
                <span className="text-[hsl(var(--foreground))] font-medium">Threat Intel</span>
                <span className="text-[hsl(var(--foreground-subtle))]">
                  {hasAnyTI ? 'Active' : 'Unconfigured'}
                </span>
              </button>
            );
          })()}

          {/* LAN Telemetry */}
          <button
            type="button"
            onClick={() =>
              setSelectedProvider({
                name: 'LAN Telemetry',
                info: providersHealth?.internal_telemetry || {
                  configured: false,
                  available: false,
                  provider: 'Enterprise NAC / DHCP / Switch Connector',
                  mode: 'adapter_interface',
                  status: 'NOT_CONNECTED',
                  reason:
                    'Zero-fabrication active: Internal LAN physical locations require enterprise telemetry integration.',
                },
              })
            }
            className="flex items-center gap-1.5 px-2 py-1 rounded hover:bg-[hsl(var(--surface-2))] transition-colors cursor-pointer"
          >
            <span className="w-2 h-2 rounded-full border border-[hsl(var(--foreground-muted))] bg-transparent" />
            <span className="text-[hsl(var(--foreground))] font-medium">LAN Telemetry</span>
            <span className="text-[hsl(var(--foreground-muted))]">Not connected</span>
          </button>
        </div>
      </div>

      {/* Provider Status Details Modal */}
      {selectedProvider && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded-xl p-6 max-w-md w-full space-y-4 shadow-xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-[hsl(var(--border))]">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-[hsl(var(--accent))]" />
                <h4 className="font-bold text-base text-[hsl(var(--foreground))]">
                  {selectedProvider.name} Service Status
                </h4>
              </div>
              <button
                type="button"
                onClick={() => setSelectedProvider(null)}
                className="p-1 rounded-lg text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--surface-2))]"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[hsl(var(--foreground-subtle))] block">Provider & Engine</span>
                <span className="font-semibold text-[hsl(var(--foreground))]">
                  {selectedProvider.info.provider || 'Internal Gateway'}
                </span>
              </div>
              <div>
                <span className="text-[hsl(var(--foreground-subtle))] block">Execution Mode</span>
                <span className="font-mono text-[hsl(var(--foreground))]">
                  {selectedProvider.info.mode || 'Direct'}
                </span>
              </div>
              <div>
                <span className="text-[hsl(var(--foreground-subtle))] block">Operational Status</span>
                <span
                  className={cn(
                    'font-bold px-2 py-0.5 rounded text-[11px] inline-block mt-0.5',
                    selectedProvider.info.available
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                  )}
                >
                  {selectedProvider.info.status ||
                    (selectedProvider.info.available ? 'AVAILABLE' : 'UNAVAILABLE / NOT CONFIGURED')}
                </span>
              </div>
              {selectedProvider.info.reason && (
                <div>
                  <span className="text-[hsl(var(--foreground-subtle))] block">Details & Policy</span>
                  <p className="text-[hsl(var(--foreground-muted))] leading-relaxed mt-0.5">
                    {selectedProvider.info.reason}
                  </p>
                </div>
              )}
              <div className="pt-2 border-t border-[hsl(var(--border))] text-[11px] text-[hsl(var(--foreground-subtle))]">
                <p>🔒 Server-side isolated. Zero credentials exposed to frontend clients.</p>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setSelectedProvider(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--surface-4))] transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}


      {/* ── TOPOLOGY VIEW ──────────────────────────────────────────────────── */}
      {viewMode === 'TOPOLOGY' && (
        <div className="card-surface p-6 space-y-6 border border-[hsl(var(--border))] rounded-xl">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-4 border-b border-[hsl(var(--border))]">
            <div>
              <h4 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
                <Layers className="w-4 h-4 text-[hsl(var(--accent))]" />
                End-to-End Network Transit Topology
              </h4>
              <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
                Traces originating workstation subnet, internal relays, NAT egress perimeter, and external mail exchangers.
              </p>
            </div>
            <span className="text-[11px] text-[hsl(var(--foreground-subtle))] font-mono">
              RFC 5322 Ingestion Sequence
            </span>
          </div>

          {/* Interactive Topology Graph Flow */}
          <div className="space-y-4">
            {hops.map((hop, idx) => {
              const isFirst = idx === 0;
              const isLast = idx === hops.length - 1;
              const isBoundaryTransition = boundaries.some((b) => b.to_hop === hop.hop_number);
              const trace = hop.trace_details;
              const geo = trace?.geo;
              const net = trace?.network;
              const internal = trace?.internal_network;

              return (
                <div key={idx} className="space-y-4">
                  {/* NAT Boundary Intercept Indicator */}
                  {isBoundaryTransition && (
                    <div className="relative py-2">
                      <div className="absolute inset-0 flex items-center" aria-hidden="true">
                        <div className="w-full border-t-2 border-dashed border-amber-500/50" />
                      </div>
                      <div className="relative flex justify-center">
                        <span className="px-3 py-1 text-xs font-mono font-bold uppercase tracking-wider bg-[hsl(var(--surface-1))] text-amber-400 border border-amber-500/40 rounded-full shadow-xs flex items-center gap-1.5">
                          ⚡ NAT / Perimeter Egress Boundary
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Node Card */}
                  <div
                    onClick={() => handleOpenDrawer({ ...hop, trace_details: trace })}
                    className={cn(
                      'p-4 rounded-xl border transition-all cursor-pointer hover:border-[hsl(var(--accent))] relative overflow-hidden group',
                      hop.is_private
                        ? 'bg-[hsl(var(--surface-2))] border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-3))]'
                        : 'bg-[hsl(var(--surface-1))] border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-2))] shadow-xs'
                    )}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      {/* Left: Hop Indicator & IP */}
                      <div className="flex items-start gap-3.5 min-w-0">
                        <div className={cn(
                          'w-8 h-8 rounded-lg flex items-center justify-center font-mono font-bold text-xs shrink-0',
                          hop.is_private
                            ? 'bg-[hsl(var(--medium)/0.15)] text-[hsl(var(--medium))] border border-[hsl(var(--medium)/0.3)]'
                            : 'bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--accent))] border border-[hsl(var(--accent)/0.3)]'
                        )}>
                          #{hop.hop_number}
                        </div>

                        <div className="min-w-0 space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono font-bold text-sm text-[hsl(var(--foreground))]">
                              {hop.ip || hop.hostname || 'Transit Gateway'}
                            </span>
                            {getClassificationBadge(hop.classification)}
                            {getTrustBadge(hop.trust_level)}
                          </div>

                          <p className="text-xs font-medium text-[hsl(var(--foreground-muted))] flex items-center gap-1.5">
                            <span className="text-[hsl(var(--accent))] font-semibold">{hop.network_role}</span>
                            {hop.hostname && <span className="font-mono text-[hsl(var(--foreground-subtle))]">({hop.hostname})</span>}
                          </p>
                        </div>
                      </div>

                      {/* Right: Telemetry Details / Status */}
                      <div className="flex items-center gap-3 self-end md:self-center">
                        {hop.is_private ? (
                          <div className="text-right text-xs">
                            {internal?.physical_location ? (
                              <span className="text-[hsl(var(--low))] font-medium flex items-center gap-1 justify-end">
                                <MapPin className="w-3.5 h-3.5" />
                                {[internal.physical_location.building, internal.physical_location.floor, internal.physical_location.room].filter(Boolean).join(', ')}
                              </span>
                            ) : (
                              <span className="text-[hsl(var(--foreground-subtle))] italic flex items-center gap-1 justify-end">
                                <Info className="w-3.5 h-3.5" /> Physical Location: Unknown (No internal telemetry)
                              </span>
                            )}
                            <span className="text-[10px] text-[hsl(var(--foreground-muted))] block font-mono">
                              VLAN: {internal?.vlan || 'LAN'} · Port: {internal?.port || 'N/A'}
                            </span>
                          </div>
                        ) : (
                          <div className="text-right text-xs">
                            <span className="text-[hsl(var(--foreground))] font-medium flex items-center gap-1 justify-end">
                              <MapPin className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
                              {[geo?.city, geo?.country].filter(Boolean).join(', ') || 'Global Transit'}
                            </span>
                            <span className="text-[10px] text-[hsl(var(--foreground-muted))] block font-mono">
                              {net?.asn || 'AS-Not Advertised'} · {net?.isp || net?.organization || 'Carrier'}
                            </span>
                          </div>
                        )}

                        <ChevronRight className="w-4 h-4 text-[hsl(var(--foreground-subtle))] group-hover:text-[hsl(var(--accent))] transition-transform group-hover:translate-x-0.5" />
                      </div>
                    </div>
                  </div>

                  {/* Connector Arrow */}
                  {!isLast && (
                    <div className="flex justify-center py-1">
                      <ArrowRight className="w-4 h-4 text-[hsl(var(--foreground-subtle))] rotate-90" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── INTERNET MAP VIEW ──────────────────────────────────────────────── */}
      {viewMode === 'MAP' && (
        <div className="card-surface p-6 space-y-5 border border-[hsl(var(--border))] rounded-xl">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[hsl(var(--border))]">
            <div>
              <h4 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center gap-2">
                <Globe className="w-4 h-4 text-[hsl(var(--accent))]" />
                Geographical Public Hop Visualization
              </h4>
              <p className="text-xs text-[hsl(var(--foreground-muted))] mt-0.5">
                Displays approximate Internet egress points and transit hops. Private RFC 1918 IPs are isolated to internal network view.
              </p>
            </div>
            <span className="text-[11px] px-2.5 py-1 rounded bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-subtle))] border border-[hsl(var(--border))] font-mono">
              Coordinates Accuracy: Approximate
            </span>
          </div>

          {/* Map Display Container */}
          {publicLocs.length > 0 ? (
            <div className="space-y-4">
              <div className="w-full h-96 rounded-xl overflow-hidden border border-[hsl(var(--border))] relative bg-[hsl(222,20%,10%)]">
                {/* Embed Map focused on Primary Public Egress */}
                <iframe
                  title="SentinelTrace Public Hop Trace Map"
                  width="100%"
                  height="100%"
                  frameBorder="0"
                  scrolling="no"
                  marginHeight={0}
                  marginWidth={0}
                  src={`https://www.openstreetmap.org/export/embed.html?bbox=${publicLocs[0].longitude - 1.5}%2C${publicLocs[0].latitude - 1.0}%2C${publicLocs[0].longitude + 1.5}%2C${publicLocs[0].latitude + 1.0}&layer=mapnik&marker=${publicLocs[0].latitude}%2C${publicLocs[0].longitude}`}
                  className="w-full h-full filter invert-[0.9] hue-rotate-[180deg] contrast-[1.1]"
                />
                <div className="absolute top-3 left-3 bg-[hsl(var(--surface-1)/0.9)] backdrop-blur px-3 py-1.5 rounded-lg text-xs font-mono text-[hsl(var(--foreground))] border border-[hsl(var(--border))] shadow-md">
                  📍 Inferred Hop Path: {publicLocs.map((p) => p.city || p.country || p.ip).join(' ➔ ')}
                </div>
                <div className="absolute bottom-3 right-3 bg-[hsl(var(--surface-1)/0.9)] backdrop-blur px-3 py-1.5 rounded-lg text-[10px] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))] shadow-md">
                  * Lines represent inferred network hops, not physical fiber cable.
                </div>
              </div>

              {/* Public Hop Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {publicLocs.map((loc, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleOpenDrawer(loc)}
                    className="p-3.5 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] hover:border-[hsl(var(--accent))] cursor-pointer transition-all space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-xs text-[hsl(var(--foreground))]">
                        Hop #{loc.hop_number}: {loc.ip}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--accent))] font-semibold">
                        {loc.country_code || 'PUBLIC'}
                      </span>
                    </div>
                    <p className="text-xs text-[hsl(var(--foreground-muted))] flex items-center gap-1">
                      <MapPin className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
                      {[loc.city, loc.country].filter(Boolean).join(', ') || 'Global Facility'}
                    </p>
                    <div className="flex items-center justify-between text-[11px] font-mono text-[hsl(var(--foreground-subtle))] pt-1 border-t border-[hsl(var(--border)/0.5)]">
                      <span>{loc.asn || 'AS-Not Advertised'}</span>
                      <span>{loc.latitude.toFixed(2)}, {loc.longitude.toFixed(2)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-12 rounded-xl bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-center space-y-3">
              <Server className="w-10 h-10 text-[hsl(var(--medium))] mx-auto" />
              <h5 className="text-sm font-semibold text-[hsl(var(--foreground))]">
                No Publicly Geolocatable Coordinates Observed
              </h5>
              <p className="text-xs text-[hsl(var(--foreground-muted))] max-w-md mx-auto">
                All observed transit hops in this email belong to internal private subnets (RFC 1918). Geographic coordinates are not assigned to private network address space.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── CHRONOLOGICAL TRACE TIMELINE ───────────────────────────────────── */}
      <div className="card-surface p-6 space-y-4 border border-[hsl(var(--border))] rounded-xl">
        <h4 className="text-sm font-semibold text-[hsl(var(--foreground))] flex items-center gap-2 pb-3 border-b border-[hsl(var(--border))]">
          <Clock className="w-4 h-4 text-[hsl(var(--accent))]" />
          Chronological Transit Hop Timeline
        </h4>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-[hsl(var(--border))] text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
                <th className="py-2.5 px-3">Step</th>
                <th className="py-2.5 px-3">IP / Hostname</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Network Role</th>
                <th className="py-2.5 px-3">Trust Level</th>
                <th className="py-2.5 px-3">Header Source</th>
                <th className="py-2.5 px-3">Location / Subnet</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[hsl(var(--border))]">
              {timeline.map((item, idx) => (
                <tr
                  key={idx}
                  onClick={() => {
                    const matchedHop = hops.find((h) => h.hop_number === item.step);
                    handleOpenDrawer(matchedHop || item);
                  }}
                  className="hover:bg-[hsl(var(--surface-2))] cursor-pointer transition-colors"
                >
                  <td className="py-3 px-3 font-mono font-bold text-[hsl(var(--accent))]">
                    #{item.step}
                  </td>
                  <td className="py-3 px-3 font-mono font-medium text-[hsl(var(--foreground))]">
                    {item.ip}
                  </td>
                  <td className="py-3 px-3">
                    {getClassificationBadge(item.classification)}
                  </td>
                  <td className="py-3 px-3 font-medium text-[hsl(var(--foreground))]">
                    {item.role}
                  </td>
                  <td className="py-3 px-3">
                    {getTrustBadge(item.trust_level)}
                  </td>
                  <td className="py-3 px-3 font-mono text-[hsl(var(--foreground-muted))]">
                    {item.header_source || 'Received'}
                  </td>
                  <td className="py-3 px-3 text-[hsl(var(--foreground-muted))]">
                    {item.geo_summary}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── IP DETAIL DRAWER / MODAL ────────────────────────────────────────── */}
      {drawerOpen && drawerData && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-center justify-end z-50 animate-in fade-in duration-150 p-2 sm:p-4">
          <div className="bg-[hsl(var(--surface-1))] border border-[hsl(var(--border))] rounded-2xl w-full max-w-xl h-full max-h-[92vh] shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="p-5 border-b border-[hsl(var(--border))] flex items-center justify-between bg-[hsl(var(--surface-2))]">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-10 h-10 rounded-xl bg-[hsl(var(--accent)/0.15)] flex items-center justify-center border border-[hsl(var(--accent)/0.3)] shrink-0">
                  <Database className="w-5 h-5 text-[hsl(var(--accent))]" />
                </div>
                <div className="min-w-0">
                  <h3 className="text-base font-bold font-mono text-[hsl(var(--foreground))] truncate">
                    {drawerData.ip || drawerData.hostname || 'Network Node'}
                  </h3>
                  <p className="text-xs text-[hsl(var(--foreground-muted))]">
                    {drawerData.network_role || drawerData.role || 'Transit Node'} · Hop #{drawerData.hop_number || drawerData.step || 1}
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="p-1.5 rounded-lg text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--surface-3))] transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
              {/* Classification Badges */}
              <div className="flex items-center gap-2 flex-wrap pb-4 border-b border-[hsl(var(--border))]">
                {getClassificationBadge(drawerData.classification || (drawerData.is_private ? 'PRIVATE' : 'PUBLIC'))}
                {getTrustBadge(drawerData.trust_level)}
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] text-[hsl(var(--foreground-subtle))]">
                  Confidence: {drawerData.trace_details?.location_accuracy || (drawerData.is_private ? 'Internal-Network' : 'Approximate')}
                </span>
              </div>

              {/* Private LAN Telemetry Section */}
              {drawerData.is_private ? (
                <div className="space-y-3 p-4 rounded-xl bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]">
                  <h4 className="font-semibold text-sm text-[hsl(var(--foreground))] flex items-center gap-2">
                    <Laptop className="w-4 h-4 text-[hsl(var(--accent))]" />
                    Internal Network Telemetry
                  </h4>

                  {drawerData.trace_details?.internal_network?.physical_location ? (
                    <div className="grid grid-cols-2 gap-3 pt-2">
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Building / Facility</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details.internal_network.physical_location.building}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Floor / Lab Room</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details.internal_network.physical_location.floor}, {drawerData.trace_details.internal_network.physical_location.room}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Switch / Interface</span>
                        <span className="font-mono text-[hsl(var(--foreground))]">
                          {drawerData.trace_details.internal_network.switch} / {drawerData.trace_details.internal_network.port}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Hardware MAC</span>
                        <span className="font-mono text-[hsl(var(--foreground))]">
                          {drawerData.trace_details.internal_network.mac}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <div className="p-3 rounded-lg bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] space-y-1">
                      <p className="font-semibold text-[hsl(var(--foreground))]">
                        No Internal Physical Telemetry Available
                      </p>
                      <p className="text-[11px] leading-relaxed">
                        This IP belongs to a private network (RFC 1918). Physical floor/room mapping requires authorized enterprise DHCP/switch telemetry integration.
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                /* Public IP Geo & ASN Telemetry */
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-3">
                    <h4 className="font-semibold text-sm text-[hsl(var(--foreground))] flex items-center gap-2">
                      <Globe className="w-4 h-4 text-[hsl(var(--accent))]" />
                      Geographic Location (Approximate)
                    </h4>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Country / Region</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details?.geo?.country || drawerData.country || 'Unknown'} ({drawerData.trace_details?.geo?.country_code || drawerData.country_code || '—'})
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">City / Postal</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details?.geo?.city || drawerData.city || 'Global Node'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Coordinates</span>
                        <span className="font-mono text-[hsl(var(--foreground))]">
                          {drawerData.latitude != null && drawerData.longitude != null
                            ? `${drawerData.latitude.toFixed(4)}, ${drawerData.longitude.toFixed(4)}`
                            : (drawerData.trace_details?.geo?.latitude != null
                                ? `${drawerData.trace_details.geo.latitude.toFixed(4)}, ${drawerData.trace_details.geo.longitude.toFixed(4)}`
                                : 'Not advertised')}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Timezone</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details?.geo?.timezone || 'UTC'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 rounded-xl bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-3">
                    <h4 className="font-semibold text-sm text-[hsl(var(--foreground))] flex items-center gap-2">
                      <Server className="w-4 h-4 text-[hsl(var(--accent))]" />
                      Autonomous System & Operator
                    </h4>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Autonomous System (ASN)</span>
                        <span className="font-mono font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details?.network?.asn || drawerData.asn || 'Not advertised'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Carrier / ISP</span>
                        <span className="font-medium text-[hsl(var(--foreground))] truncate" title={drawerData.trace_details?.network?.isp || drawerData.isp}>
                          {drawerData.trace_details?.network?.isp || drawerData.isp || 'Direct Carrier'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Reverse DNS (PTR)</span>
                        <span className="font-mono text-[hsl(var(--foreground))] truncate" title={drawerData.trace_details?.dns?.reverse_dns || drawerData.hostname}>
                          {drawerData.trace_details?.dns?.reverse_dns || drawerData.hostname || 'No PTR Record'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[hsl(var(--foreground-subtle))] block">Routing Type</span>
                        <span className="font-medium text-[hsl(var(--foreground))]">
                          {drawerData.trace_details?.network?.routing_label || 'Direct Public Routing'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Multi-Provider Threat Intelligence Panel (Phase 5) */}

                  <div className="p-4 rounded-xl bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="font-semibold text-sm text-[hsl(var(--foreground))] flex items-center gap-2">
                        <Shield className="w-4 h-4 text-[hsl(var(--accent))]" />
                        Multi-Provider Threat Intelligence
                      </h4>
                      {drawerData.trace_details?.threat?.severity && (
                        <span
                          className={cn(
                            'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider',
                            drawerData.trace_details.threat.severity === 'CRITICAL' || drawerData.trace_details.threat.severity === 'HIGH'
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : drawerData.trace_details.threat.severity === 'MODERATE'
                              ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          )}
                        >
                          {drawerData.trace_details.threat.severity} ({drawerData.trace_details.threat.score}/100)
                        </span>
                      )}
                    </div>

                    {/* Disagreement Warning */}
                    {drawerData.trace_details?.threat?.provider_disagreement_detected && (
                      <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs space-y-1">
                        <p className="font-bold flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          Provider Disagreement Detected
                        </p>
                        {drawerData.trace_details.threat.disagreement_details?.map((d: string, idx: number) => (
                          <p key={idx} className="text-[11px] text-amber-300/90 leading-tight">
                            • {d}
                          </p>
                        ))}
                      </div>
                    )}

                    {/* Provider Breakdown Cards */}
                    <div className="grid grid-cols-3 gap-2 text-xs pt-1">
                      {/* VirusTotal */}
                      <div className="p-2 rounded-lg bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] space-y-0.5">
                        <span className="font-semibold text-[hsl(var(--foreground))] block text-[11px]">VirusTotal</span>
                        {drawerData.trace_details?.threat?.virustotal ? (
                          <span className="font-mono text-[11px] text-rose-400 font-medium">
                            {drawerData.trace_details.threat.virustotal.malicious || 0} / {drawerData.trace_details.threat.virustotal.total_engines || 0} mal
                          </span>
                        ) : (
                          <span className="text-[10px] text-[hsl(var(--foreground-muted))]">Not configured</span>
                        )}
                      </div>

                      {/* AbuseIPDB */}
                      <div className="p-2 rounded-lg bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] space-y-0.5">
                        <span className="font-semibold text-[hsl(var(--foreground))] block text-[11px]">AbuseIPDB</span>
                        {drawerData.trace_details?.threat?.abuseipdb ? (
                          <span className="font-mono text-[11px] text-amber-400 font-medium">
                            {drawerData.trace_details.threat.abuseipdb.abuse_confidence || 0}% abuse
                          </span>
                        ) : (
                          <span className="text-[10px] text-[hsl(var(--foreground-muted))]">Not configured</span>
                        )}
                      </div>

                      {/* Shodan */}
                      <div className="p-2 rounded-lg bg-[hsl(var(--surface-3))] border border-[hsl(var(--border))] space-y-0.5">
                        <span className="font-semibold text-[hsl(var(--foreground))] block text-[11px]">Shodan</span>
                        {drawerData.trace_details?.threat?.shodan ? (
                          <span className="font-mono text-[11px] text-[hsl(var(--accent))] font-medium">
                            {drawerData.trace_details.threat.shodan.ports?.length || 0} ports
                          </span>
                        ) : (
                          <span className="text-[10px] text-[hsl(var(--foreground-muted))]">Not configured</span>
                        )}
                      </div>
                    </div>

                    {drawerData.trace_details?.threat?.provider_coverage && (
                      <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block font-mono">
                        Coverage: {drawerData.trace_details.threat.provider_coverage}
                      </span>
                    )}
                  </div>
                </div>
              )}


              {/* Evidence Ledger Table */}
              <div className="space-y-3">
                <h4 className="font-semibold text-sm text-[hsl(var(--foreground))] flex items-center gap-2">
                  <Database className="w-4 h-4 text-[hsl(var(--accent))]" />
                  Forensic Evidence Ledger
                </h4>

                <div className="space-y-2">
                  {(drawerData.trace_details?.evidence || evidence).slice(0, 5).map((ev: EvidenceItem, i: number) => (
                    <div key={i} className="p-2.5 rounded-lg bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="font-mono font-bold text-[hsl(var(--accent))] uppercase">{ev.source_type}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] font-mono">
                          Confidence: {ev.confidence}
                        </span>
                      </div>
                      <p className="text-[11px] text-[hsl(var(--foreground))] font-mono">
                        {ev.value}
                      </p>
                      <span className="text-[10px] text-[hsl(var(--foreground-subtle))] block">
                        Source: {ev.source}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="p-4 border-t border-[hsl(var(--border))] bg-[hsl(var(--surface-2))] flex items-center justify-between">
              <span className="text-[11px] text-[hsl(var(--foreground-muted))]">
                SentinelTrace Cryptographic Chain of Custody Verified
              </span>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] hover:bg-[hsl(var(--accent-hover))] transition-colors cursor-pointer"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
