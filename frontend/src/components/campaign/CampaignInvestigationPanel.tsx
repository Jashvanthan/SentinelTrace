import { Link } from 'react-router-dom';
import { Mail, Globe, Shield, AlertTriangle, FileText, Server, AlertCircle, ArrowUpRight, Copy, Check, FileDown, Navigation } from 'lucide-react';
import { useState } from 'react';
import { downloadReportPdf } from '@/api/hooks';

interface CampaignInvestigationPanelProps {
  selectedNode: any;
}

// SECURITY — EXPLICIT PROPERTY ALLOWLIST (No internal reasoning exposed)
function getSafeProperties(node: any) {
  const props = node.properties || {};
  const safeProps: Record<string, any> = {};

  switch (node.node_type || node.nodeType) {
    case 'Email':
      if (props.subject) safeProps.Subject = props.subject;
      if (props.sender) safeProps.Sender = props.sender;
      if (props.timestamp) safeProps.Timestamp = props.timestamp;
      if (props.verdict) safeProps.Verdict = props.verdict;
      if (props.risk_score !== undefined) safeProps['Risk Score'] = props.risk_score;
      break;
    case 'IPAddress':
      if (props.ip) safeProps.IP = props.ip;
      if (props.country) safeProps.Country = props.country;
      if (props.region) safeProps.Region = props.region;
      if (props.city) safeProps.City = props.city;
      if (props.asn) safeProps.ASN = props.asn;
      if (props.isp) safeProps.ISP = props.isp;
      if (props.reputation !== undefined) safeProps.Reputation = props.reputation;
      break;
    case 'Domain':
      if (props.domain) safeProps.Domain = props.domain;
      if (props.reputation !== undefined) safeProps.Reputation = props.reputation;
      break;
    case 'Sender':
      if (props.sender) safeProps.Sender = props.sender;
      if (props.domain) safeProps.Domain = props.domain;
      break;
    case 'IOC':
      if (props.type) safeProps.Type = props.type;
      if (props.value) safeProps.Value = props.value;
      if (props.severity) safeProps.Severity = props.severity;
      if (props.threat_status) safeProps['Threat Status'] = props.threat_status;
      break;
    case 'Attachment':
      if (props.filename) safeProps.Filename = props.filename;
      if (props.mime_type) safeProps['MIME Type'] = props.mime_type;
      if (props.hash) safeProps['SHA-256 Hash'] = props.hash;
      if (props.detection_status) safeProps['Detection Status'] = props.detection_status;
      break;
    case 'ThreatRecord':
      if (props.source) safeProps.Source = props.source;
      if (props.score !== undefined) safeProps.Score = props.score;
      if (props.description) safeProps.Description = props.description;
      break;
    case 'Campaign':
      if (props.name) safeProps.Name = props.name;
      if (props.status) safeProps.Status = props.status;
      if (props.confidence !== undefined) safeProps.Confidence = props.confidence;
      break;
    default:
      if (props.name) safeProps.Name = props.name;
      if (props.value) safeProps.Value = props.value;
      break;
  }

  // Structured summary allowed — internal model reasoning is strictly blocked
  if (props.ai_summary) safeProps['AI Summary'] = props.ai_summary;

  return safeProps;
}

export function CampaignInvestigationPanel({ selectedNode }: CampaignInvestigationPanelProps) {
  const [copied, setCopied] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  if (!selectedNode) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[hsl(var(--foreground-muted))] p-6 text-center">
        <AlertCircle className="w-8 h-8 mb-2 opacity-50 text-[hsl(var(--foreground-subtle))]" />
        <p className="text-sm font-medium text-[hsl(var(--foreground))]">Select an entity node</p>
        <p className="text-xs text-[hsl(var(--foreground-muted))] mt-1">
          Click on any email, domain, IP, sender, or IOC node in the graph to inspect correlated telemetry and investigation pivots.
        </p>
      </div>
    );
  }

  const safeProps = getSafeProperties(selectedNode);
  const nodeType = selectedNode.node_type || selectedNode.nodeType;
  const nodeVal = selectedNode.name || selectedNode.id;

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = async (analysisId: string) => {
    try {
      setIsDownloading(true);
      await downloadReportPdf(analysisId, `sentineltrace-report-${analysisId.slice(0, 8)}.pdf`);
    } catch (e) {
      console.error(e);
    } finally {
      setIsDownloading(false);
    }
  };

  const icons: Record<string, any> = {
    Email: Mail,
    Sender: Globe,
    Domain: Globe,
    IPAddress: Server,
    IOC: AlertTriangle,
    Attachment: FileText,
    ThreatRecord: Shield,
  };
  const Icon = icons[nodeType] || AlertCircle;

  return (
    <div className="p-4 h-full overflow-y-auto space-y-4">
      {/* Node Header */}
      <div className="flex items-center gap-3 pb-3 border-b border-[hsl(var(--border))]">
        <div className="w-10 h-10 rounded bg-[hsl(var(--surface-3))] flex items-center justify-center shrink-0">
          <Icon className="w-5 h-5" style={{ color: selectedNode.color || 'hsl(var(--foreground))' }} />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold text-[hsl(var(--foreground))] truncate text-sm" title={selectedNode.name}>
            {selectedNode.name || 'Entity Node'}
          </h3>
          <p className="text-xs text-[hsl(var(--foreground-muted))] uppercase tracking-wider font-mono">
            {nodeType}
          </p>
        </div>
      </div>

      {/* Entity Properties Table */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
            Telemetry Attributes
          </h4>
          <button
            type="button"
            onClick={() => handleCopy(nodeVal)}
            className="text-[11px] text-[hsl(var(--accent))] hover:underline flex items-center gap-1 cursor-pointer"
          >
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        <div className="bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-lg overflow-hidden text-xs">
          {Object.entries(safeProps).map(([key, value]) => (
            <div key={key} className="px-3 py-2 border-b border-[hsl(var(--border))] last:border-0 flex flex-col gap-0.5">
              <span className="text-[10px] text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">{key}</span>
              <span className="font-mono text-[hsl(var(--foreground))] break-all">
                {value != null ? String(value) : '—'}
              </span>
            </div>
          ))}
          {Object.keys(safeProps).length === 0 && (
            <div className="px-3 py-4 text-center text-xs text-[hsl(var(--foreground-muted))]">
              No safe attributes recorded.
            </div>
          )}
        </div>
      </div>

      {/* Cross-Module Investigation Action Pivots */}
      <div className="pt-2 space-y-2">
        <h4 className="text-xs font-semibold text-[hsl(var(--foreground-subtle))] uppercase tracking-wider">
          Investigation Pivots
        </h4>

        {nodeType === 'Email' && (
          <div className="space-y-2">
            <Link
              to={`/emails/${selectedNode.id}`}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-hover))] text-[hsl(var(--accent-foreground))] text-xs font-semibold rounded transition-colors"
            >
              <Mail className="w-3.5 h-3.5" />
              Open Email Forensic Deep Dive
            </Link>
            <button
              onClick={() => handleDownloadPdf(selectedNode.id)}
              disabled={isDownloading}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))] text-xs font-medium rounded transition-colors cursor-pointer disabled:opacity-50"
            >
              <FileDown className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
              {isDownloading ? 'Generating PDF...' : 'Download Forensic Evidence PDF'}
            </button>
          </div>
        )}

        {nodeType === 'IPAddress' && (
          <div className="space-y-2">
            <Link
              to={`/geo?ip=${encodeURIComponent(nodeVal)}`}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-hover))] text-[hsl(var(--accent-foreground))] text-xs font-semibold rounded transition-colors"
            >
              <Navigation className="w-3.5 h-3.5" />
              Geolocate IP & Trace ASN
            </Link>
            <Link
              to={`/intel?search=${encodeURIComponent(nodeVal)}`}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))] text-xs font-medium rounded transition-colors"
            >
              <Shield className="w-3.5 h-3.5 text-purple-400" />
              Search Threat Intel Repository
            </Link>
          </div>
        )}

        {(nodeType === 'Domain' || nodeType === 'Sender') && (
          <Link
            to={`/intel?search=${encodeURIComponent(nodeVal)}`}
            className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-hover))] text-[hsl(var(--accent-foreground))] text-xs font-semibold rounded transition-colors"
          >
            <Globe className="w-3.5 h-3.5" />
            Investigate Domain in Threat Intel
          </Link>
        )}

        {nodeType === 'IOC' && (
          <Link
            to={`/intel?search=${encodeURIComponent(nodeVal)}`}
            className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-hover))] text-[hsl(var(--accent-foreground))] text-xs font-semibold rounded transition-colors"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            Query Threat Intel Feeds
          </Link>
        )}

        {nodeType === 'Attachment' && (
          <Link
            to="/forensics"
            className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-[hsl(var(--surface-2))] hover:bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))] text-xs font-medium rounded transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-[hsl(var(--accent))]" />
            Inspect in Forensics Workbench
          </Link>
        )}
      </div>
    </div>
  );
}
