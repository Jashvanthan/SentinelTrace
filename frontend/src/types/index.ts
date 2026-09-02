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
  created_at: string;
  completed_at?: string;
  campaign_id?: string;
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
  ai_reasoning?: string;
  ai_indicators?: string[];
  ai_model_used?: string;
  enrichment_data?: Record<string, unknown>;
  geo_data?: Record<string, unknown>;
  raw_eml_sha256?: string;
  raw_eml_size_bytes?: number;
  iocs: IOC[];
  attachments: EmailAttachment[];
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
  timezone?: string;
  isp?: string;
  org?: string;
  asn?: string;
  is_proxy?: boolean;
  is_vpn?: boolean;
  is_tor?: boolean;
  provider: string;
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
