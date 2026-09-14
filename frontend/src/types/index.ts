// SentinelTrace Frontend — TypeScript Type Definitions

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';
export type AuthProvider = 'LOCAL' | 'GOOGLE';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  auth_provider: AuthProvider;
  avatar_url?: string;
  created_at: string;
  last_login_at?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export type AnalysisStatus = 'PENDING' | 'PROCESSING' | 'COMPLETE' | 'FAILED' | 'QUARANTINED';

export type ThreatCategory =
  | 'PHISHING'
  | 'SPEAR_PHISHING'
  | 'BEC'
  | 'MALWARE'
  | 'SPAM'
  | 'RANSOMWARE'
  | 'CREDENTIAL_HARVEST'
  | 'SOCIAL_ENGINEERING'
  | 'UNKNOWN'
  | 'BENIGN';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface IOC {
  id: string;
  ioc_type: string;
  value: string;
  is_malicious?: boolean;
  confidence_score?: number;
  threat_score?: number;
  tags?: string[];
  enrichment_data?: Record<string, unknown>;
  source?: string;
}

export interface EmailAttachment {
  id: string;
  filename?: string;
  content_type?: string;
  size_bytes?: number;
  sha256_hash?: string;
  is_malicious?: boolean;
  vt_detections?: number;
  vt_total_engines?: number;
}

export interface EmailAnalysisSummary {
  id: string;
  subject?: string;
  sender_email?: string;
  sender_domain?: string;
  status: AnalysisStatus;
  threat_category?: ThreatCategory;
  severity?: SeverityLevel;
  confidence_score?: number;
  threat_score?: number;
  source_provider?: string;
  source_message_id?: string;
  created_at: string;
  completed_at?: string;
  campaign_id?: string;
  raw_eml_sha256?: string;
  error_message?: string;
}

export interface EmailAnalysisDetail extends EmailAnalysisSummary {
  sender_display_name?: string;
  reply_to?: string;
  recipients?: string[];
  message_id?: string;
  email_date?: string;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  received_headers?: string[];
  ai_summary?: string;
  // Privacy Boundary: Internal model reasoning is treated as internal detail and never exposed to UI
  ai_indicators?: string[];
  ai_model_used?: string;
  enrichment_data?: Record<string, unknown>;
  geo_data?: Record<string, unknown>;
  diagnostic_status?: Record<string, any>;
  raw_eml_sha256?: string;
  raw_eml_size_bytes?: number;
  iocs: IOC[];
  attachments: EmailAttachment[];
  error_message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface EnrichmentResponse {
  indicator: string;
  indicator_type: string;
  virustotal?: VirusTotalResult;
  abuseipdb?: AbuseIPDBResult;
  shodan?: ShodanResult;
  aggregate_threat_score: number;
  is_malicious: boolean;
  errors: Record<string, string>;
}

export interface VirusTotalResult {
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  total_engines: number;
  threat_names: string[];
  last_analysis_date?: string;
  reputation?: number;
}

export interface AbuseIPDBResult {
  ip_address: string;
  abuse_confidence_score: number;
  total_reports: number;
  country_code?: string;
  isp?: string;
  domain?: string;
  is_whitelisted: boolean;
}

export interface ShodanResult {
  ip_str: string;
  ports: number[];
  hostnames: string[];
  country_name?: string;
  city?: string;
  org?: string;
  isp?: string;
  os?: string;
  vulns: string[];
  last_update?: string;
}

export interface GeoLocationResponse {
  ip_address: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  postal?: string;
  latitude?: number;
  longitude?: number;
  accuracy_radius?: number;
  timezone?: string;
  continent?: string;
  network?: string;
  isp?: string;
  org?: string;
  asn?: string;
  is_proxy?: boolean;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_hosting?: boolean;
  routing_type?: string;
  routing_label?: string;
  provider: string;
  location_status?: string;
  location_confidence?: string;
  provider_comparison?: Array<{
    provider: string;
    country?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    isp?: string;
    status?: string;
  }>;
}

export interface IOCResponse {
  id: string;
  analysis_id?: string | null;
  email_subject?: string | null;
  sender_email?: string | null;
  ioc_type: string;
  value: string;
  is_malicious: boolean | null;
  confidence_score: number | null;
  threat_score: number | null;
  tags: string[] | null;
  enrichment_data: Record<string, unknown> | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  source: string | null;
  created_at?: string | null;
}

export interface IOCListResponse {
  items: IOCResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface CampaignNode {
  id: string;
  node_type: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface CampaignEdge {
  source: string;
  target: string;
  relationship_type: string;
  properties: Record<string, unknown>;
}

export interface CampaignGraphResponse {
  campaign_id?: string;
  nodes: CampaignNode[];
  edges: CampaignEdge[];
  analysis_count: number;
}

export interface AnalysisTriggerResponse {
  analysis_id: string;
  status: AnalysisStatus;
  message: string;
}

export interface DashboardStats {
  total_analyses: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  recent_analyses: EmailAnalysisSummary[];
  threat_category_distribution: Record<string, number>;
}

// ── Step 14: Workspace Statistics ─────────────────────────────────────────────

/**
 * Lightweight campaign summary returned in the stats top_campaigns list.
 * Maps 1:1 to the backend CampaignSummary Pydantic schema.
 */
export interface CampaignSummary {
  id: string;
  name: string;
  status: string;
  confidence: number | null;
  correlation_score: number | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  member_count: number;
  created_at: string;
  updated_at: string;
}

/**
 * Minimal email analysis record for the dashboard live feed.
 * Excludes GCS paths, OAuth tokens, and other credential material.
 * Maps to backend RecentEmailSummary.
 */
export interface RecentEmailSummary {
  id: string;
  subject: string | null;
  sender_email: string | null;
  sender_domain: string | null;
  status: AnalysisStatus;
  threat_category: ThreatCategory | null;
  severity: SeverityLevel | null;
  threat_score: number | null;
  created_at: string;
  completed_at: string | null;
}

/**
 * Aggregated workspace-level statistics returned by
 * GET /api/v1/workspaces/{workspace_id}/stats
 *
 * Note: average_threat_score and workspace_risk_score share the same
 * database calculation in Step 14 (AVG of EmailAnalysis.threat_score).
 * They are separate fields because Step 19+ may compute workspace_risk_score
 * with additional weighting.
 *
 * Note: high_critical_iocs_this_week is a derived proxy — IOC.threat_score >= 70
 * within the current calendar week. The IOC model has no explicit severity field.
 */
export interface WorkspaceStats {
  total_emails_scanned: number;
  threats_detected: number;
  active_campaigns: number;
  average_threat_score: number | null;
  workspace_risk_score: number | null;
  high_critical_iocs_this_week: number;
  ioc_type_distribution: Record<string, number>;
  top_campaigns: CampaignSummary[];
  recent_emails: RecentEmailSummary[];
}

export interface WorkspaceMember {
  id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
}

export interface GmailIntegrationStatus {
  id?: string;
  email_address?: string;
  status: 'NOT_CONNECTED' | 'ACTIVE' | 'QUEUED' | 'ERROR';
  last_sync_at?: string;
  error_message?: string;
}

export interface ActivityLogItem {
  id: string;
  action: string;
  resource_type?: string | null;
  resource_id?: string | null;
  user_id?: string | null;
  user_email?: string | null;
  user_name?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  outcome: string;
  details?: Record<string, any> | null;
  error_message?: string | null;
  created_at: string;
}

export interface ActivityLogSummary {
  total_events: number;
  success_count: number;
  failure_count: number;
  unique_users_count: number;
  top_actions: Record<string, number>;
}

export interface ActivityLogResponse {
  items: ActivityLogItem[];
  total: number;
  page: number;
  page_size: number;
  summary: ActivityLogSummary;
}

export interface ObservedIPItem {
  ip_address: string;
  source: 'received_hop' | 'origin_header' | 'extracted_ioc' | string;
  hop_number?: number | null;
  is_private: boolean;
  classification?: string;
  description: string;
}

export interface EmailObservedIPsResponse {
  analysis_id: string;
  ips: ObservedIPItem[];
  public_ips_count: number;
  total_ips_count: number;
}

// ── IP Network Trace & Forensic Hop Chain Types ─────────────────────────────

export interface EvidenceItem {
  source_type: string;
  source: string;
  timestamp: string;
  value: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | string;
  hop_number?: number | null;
}

export interface IPTraceGeoInfo {
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  postal?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy: 'approximate' | 'internal-network' | 'unknown' | string;
  accuracy_radius?: number | null;
  timezone?: string | null;
  continent?: string | null;
  provider?: string | null;
}

export interface IPTraceNetworkInfo {
  asn?: string | null;
  organization?: string | null;
  isp?: string | null;
  routing_type: string;
  routing_label: string;
  is_hosting?: boolean;
  is_vpn?: boolean;
  is_tor?: boolean;
  is_proxy?: boolean;
}

export interface IPTraceThreatInfo {
  score: number;
  severity?: 'CLEAN' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | string;
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'NO_DATA' | 'NOT_APPLICABLE' | 'UNAVAILABLE' | string;
  is_malicious: boolean;
  provider_coverage?: string | null;
  score_explanation?: Array<{ provider: string; points: number; detail: string }> | null;
  provider_disagreement_detected?: boolean;
  disagreement_details?: string[] | null;
  virustotal?: Record<string, any> | null;
  abuseipdb?: Record<string, any> | null;
  shodan?: Record<string, any> | null;
}


export interface IPTraceInternalNetworkInfo {
  mac?: string | null;
  hostname?: string | null;
  vlan?: string | number | null;
  switch?: string | null;
  port?: string | null;
  access_point?: string | null;
  ssid?: string | null;
  physical_location?: {
    building?: string;
    floor?: string;
    room?: string;
  } | null;
  location_confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | string;
  reason?: string | null;
}

export interface IPTraceResponse {
  ip: string;
  version: number;
  classification: 'PUBLIC' | 'PRIVATE' | 'LOOPBACK' | 'LINK_LOCAL' | 'MULTICAST' | 'RESERVED' | 'UNSPECIFIED' | 'UNIQUE_LOCAL' | 'DOCUMENTATION' | 'INVALID' | string;
  is_public: boolean;
  is_private: boolean;
  is_geolocatable: boolean;
  routing_role: string;
  geo?: IPTraceGeoInfo | null;
  network?: IPTraceNetworkInfo | null;
  dns?: {
    reverse_dns?: string | null;
    status?: string | null;
  } | null;
  threat?: IPTraceThreatInfo | null;
  internal_network?: IPTraceInternalNetworkInfo | null;
  status: string;
  location_accuracy: string;
  evidence: EvidenceItem[];
}

export interface EmailHopNode {
  hop_number: number;
  ip?: string | null;
  classification: string;
  is_public: boolean;
  is_private: boolean;
  network_role: string;
  trust_level: 'TRUSTED' | 'PARTIALLY_TRUSTED' | 'UNTRUSTED' | 'UNKNOWN' | string;
  hostname?: string | null;
  by_host?: string | null;
  timestamp?: string | null;
  header_name?: string | null;
  raw_header?: string | null;
  trace_details?: IPTraceResponse | null;
}

export interface EmailTimelineItem {
  step: number;
  timestamp: string;
  ip: string;
  classification: string;
  role: string;
  hostname?: string | null;
  trust_level: string;
  header_source?: string | null;
  geo_summary?: string | null;
}

export interface EmailPublicLocation {
  hop_number: number;
  ip: string;
  latitude: number;
  longitude: number;
  city?: string | null;
  country?: string | null;
  country_code?: string | null;
  asn?: string | null;
  isp?: string | null;
  threat_score: number;
  threat_status: string;
  role: string;
}

export interface EmailPrivateNode {
  hop_number: number;
  ip: string;
  classification: string;
  hostname?: string | null;
  mac?: string | null;
  vlan?: string | number | null;
  switch?: string | null;
  port?: string | null;
  access_point?: string | null;
  physical_location?: {
    building?: string;
    floor?: string;
    room?: string;
  } | null;
  role: string;
  status: string;
}

export interface EmailBoundary {
  boundary_type: string;
  label: string;
  from_hop: number;
  to_hop: number;
  ip?: string | null;
  description: string;
}

export interface EmailIPTraceResponse {
  analysis_id: string;
  total_hops: number;
  hops: EmailHopNode[];
  timeline: EmailTimelineItem[];
  public_locations: EmailPublicLocation[];
  private_network_nodes: EmailPrivateNode[];
  boundaries: EmailBoundary[];
  has_nat_boundary: boolean;
  evidence: EvidenceItem[];
}

export interface ProviderStatusItem {
  configured: boolean;
  available: boolean;
  provider?: string | null;
  mode?: string | null;
  status?: string | null;
  reason?: string | null;
  accuracy?: string | null;
}

export interface ProvidersHealthResponse {
  geoip: ProviderStatusItem;
  asn: ProviderStatusItem;
  reverse_dns: ProviderStatusItem;
  virustotal: ProviderStatusItem;
  abuseipdb: ProviderStatusItem;
  shodan: ProviderStatusItem;
  internal_telemetry: ProviderStatusItem;
}

