import { Page, expect } from '@playwright/test';

export const mockUser = {
  id: '1',
  email: 'analyst@sentineltrace.io',
  full_name: 'Alex Mercer (SOC Lead)',
  role: 'ADMIN',
};

export const mockWorkspacesList = [
  { id: '1', name: 'Primary SOC Team', role: 'owner', slug: 'primary-soc' },
  { id: '2', name: 'Incident Response Alpha', role: 'analyst', slug: 'ir-alpha' },
];

export const mockStats = {
  total_emails_scanned: 1248,
  threats_detected: 42,
  active_campaigns: 4,
  average_threat_score: 76.4,
  workspace_risk_score: 82.0,
  high_critical_iocs_this_week: 19,
  recent_emails: [
    {
      id: 'analysis-001',
      subject: 'URGENT: Payroll Account Verification Required',
      sender_email: 'payroll@update-portal-spoof.com',
      threat_category: 'CREDENTIAL_HARVEST',
      status: 'COMPLETE',
      severity: 'CRITICAL',
      threat_score: 95.0,
      created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    },
    {
      id: 'analysis-002',
      subject: 'Invoice INV-98214 Attached',
      sender_email: 'billing@vendor-notifications.net',
      threat_category: 'MALWARE_DELIVERY',
      status: 'COMPLETE',
      severity: 'HIGH',
      threat_score: 84.0,
      created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    },
    {
      id: 'analysis-003',
      subject: 'Weekly Team Sync Notes',
      sender_email: 'internal@company.com',
      threat_category: 'BENIGN',
      status: 'COMPLETE',
      severity: 'LOW',
      threat_score: 5.0,
      created_at: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    },
  ],
  top_campaigns: [
    {
      campaign_id: 'camp-fin-01',
      name: 'Q3 Financial Spoofing Cluster',
      threat_score: 92.0,
      email_count: 14,
      first_seen_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3).toISOString(),
      last_seen_at: new Date().toISOString(),
    },
  ],
  ioc_type_distribution: {
    IP_ADDRESS: 35,
    DOMAIN: 48,
    URL: 62,
    FILE_HASH_SHA256: 18,
  },
};

export const mockAnalysesList = {
  items: [
    {
      id: 'analysis-001',
      subject: 'URGENT: Payroll Account Verification Required',
      sender_email: 'payroll@update-portal-spoof.com',
      threat_category: 'CREDENTIAL_HARVEST',
      status: 'COMPLETE',
      severity: 'CRITICAL',
      threat_score: 95.0,
      created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    },
    {
      id: 'analysis-002',
      subject: 'Invoice INV-98214 Attached',
      sender_email: 'billing@vendor-notifications.net',
      threat_category: 'MALWARE_DELIVERY',
      status: 'COMPLETE',
      severity: 'HIGH',
      threat_score: 84.0,
      created_at: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    },
    {
      id: 'analysis-003',
      subject: 'Processing Scan Pending',
      sender_email: 'untrusted@tempmail.org',
      threat_category: null,
      status: 'PROCESSING',
      severity: null,
      threat_score: null,
      created_at: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    },
  ],
  total: 3,
  page: 1,
  page_size: 25,
};

export const mockAnalysisDetail = {
  id: 'analysis-001',
  subject: 'URGENT: Payroll Account Verification Required',
  sender_email: 'payroll@update-portal-spoof.com',
  sender_display_name: 'Corporate HR Direct',
  sender_domain: 'update-portal-spoof.com',
  status: 'COMPLETE',
  severity: 'CRITICAL',
  threat_category: 'CREDENTIAL_HARVEST',
  threat_score: 95.0,
  confidence_score: 0.98,
  spf_result: 'fail',
  dkim_result: 'fail',
  dmarc_result: 'fail',
  ai_summary: 'Critical threat detected. Targeted credential harvesting email using deceptive HR branding and fake Single Sign-On link to exfiltrate session tokens.',
  ai_indicators: [
    'Domain spoofing targeting internal HR portal',
    'SPF/DKIM/DMARC hard failures from unauthorized originating mail server',
    'Embedded credential harvesting link detected in HTML body',
  ],
  ai_model_used: 'Sentinel-AI-v4.2-Pro',
  message_id: '<20260909-123456-hr@update-portal-spoof.com>',
  email_date: new Date().toISOString(),
  created_at: new Date().toISOString(),
  reply_to: 'harvest@attacker-domain.org',
  recipients: ['victim@target-corp.com', 'finance-team@target-corp.com'],
  raw_eml_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  raw_eml_size_bytes: 48200,
  geo_data: {
    ip_address: '198.51.100.24',
    city: 'Frankfurt',
    country: 'Germany',
    isp: 'HostEurope Gmbh',
    org: 'Malicious Botnet Node',
    asn: 'AS20773',
  },
  enrichment_data: {
    virustotal: { malicious_count: 14, total_engines: 72 },
    abuseipdb: { abuse_confidence_score: 88 },
  },
  iocs: [
    {
      id: 'ioc-101',
      ioc_type: 'DOMAIN',
      value: 'update-portal-spoof.com',
      threat_score: 98,
      confidence_score: 95,
      is_malicious: true,
      source: 'VirusTotal / ThreatFox',
      first_seen_at: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
      last_seen_at: new Date().toISOString(),
      tags: ['credential-stealer', 'phish-kit'],
    },
    {
      id: 'ioc-102',
      ioc_type: 'IP_ADDRESS',
      value: '198.51.100.24',
      threat_score: 88,
      confidence_score: 90,
      is_malicious: true,
      source: 'AbuseIPDB',
      first_seen_at: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
      last_seen_at: new Date().toISOString(),
      tags: ['scanner', 'spam-origin'],
    },
  ],
  attachments: [
    {
      id: 'att-001',
      filename: 'employee_benefits_guide.pdf',
      size_bytes: 1048576,
      sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      is_malicious: true,
      vt_detections: 12,
      vt_total_engines: 65,
    },
  ],
  received_headers: [
    'from mail.evil-relay.net (198.51.100.24) by mx.google.com with ESMTPS id xyz123',
    'from host-internal.spoof (unknown [10.0.0.5]) by mail.evil-relay.net with SMTP',
  ],
  campaign_id: 'camp-fin-01',
};

export const mockIocsList = {
  items: [
    {
      id: 'ioc-101',
      ioc_type: 'DOMAIN',
      value: 'update-portal-spoof.com',
      threat_score: 98,
      confidence_score: 95,
      is_malicious: true,
      source: 'VirusTotal / ThreatFox',
      first_seen_at: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
      last_seen_at: new Date().toISOString(),
      tags: ['credential-stealer', 'phish-kit'],
    },
    {
      id: 'ioc-102',
      ioc_type: 'IP_ADDRESS',
      value: '198.51.100.24',
      threat_score: 88,
      confidence_score: 90,
      is_malicious: true,
      source: 'AbuseIPDB',
      first_seen_at: new Date(Date.now() - 1000 * 60 * 60 * 72).toISOString(),
      last_seen_at: new Date().toISOString(),
      tags: ['scanner', 'spam-origin'],
    },
    {
      id: 'ioc-103',
      ioc_type: 'URL',
      value: 'https://update-portal-spoof.com/sso/login.php',
      threat_score: 95,
      confidence_score: 99,
      is_malicious: true,
      source: 'URLhaus',
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      tags: ['phishing-url'],
    },
  ],
  total: 3,
  page: 1,
  page_size: 20,
};

export const mockGraphData = {
  nodes: [
    { id: 'node-1', node_type: 'Email', label: 'analysis-001 (Payroll Spoof)', properties: { score: 95 } },
    { id: 'node-2', node_type: 'Sender', label: 'payroll@update-portal-spoof.com', properties: {} },
    { id: 'node-3', node_type: 'Domain', label: 'update-portal-spoof.com', properties: { registrar: 'NameCheap' } },
    { id: 'node-4', node_type: 'IPAddress', label: '198.51.100.24', properties: { country: 'Germany' } },
    { id: 'node-5', node_type: 'IOC', label: 'https://update-portal-spoof.com/sso/login.php', properties: {} },
    { id: 'node-6', node_type: 'Attachment', label: 'employee_benefits_guide.pdf', properties: { size: 1048576 } },
  ],
  edges: [
    { source: 'node-1', target: 'node-2', relationship_type: 'SENT_BY' },
    { source: 'node-2', target: 'node-3', relationship_type: 'BELONGS_TO_DOMAIN' },
    { source: 'node-1', target: 'node-4', relationship_type: 'ORIGINATED_FROM' },
    { source: 'node-1', target: 'node-5', relationship_type: 'CONTAINS_IOC' },
    { source: 'node-1', target: 'node-6', relationship_type: 'HAS_ATTACHMENT' },
  ],
};

export const mockMembers = [
  { user_id: '1', email: 'analyst@sentineltrace.io', full_name: 'Alex Mercer (SOC Lead)', role: 'owner' },
  { user_id: '2', email: 'sarah.connor@sentineltrace.io', full_name: 'Sarah Connor', role: 'admin' },
  { user_id: '3', email: 'john.doe@sentineltrace.io', full_name: 'John Doe', role: 'viewer' },
];

export const mockGmailStatus = {
  id: 'gmail-conn-01',
  email_address: 'soc-ingest@sentineltrace-demo.com',
  status: 'ACTIVE',
  last_sync_at: new Date().toISOString(),
  error_message: null,
};

export async function setupStandardApiMocks(page: Page) {
  // Generic routes registered FIRST

  // Generic Email routes
  await page.route('**/api/**/emails/**', async (route) => {
    if (route.request().method() === 'DELETE') {
      await route.fulfill({ json: { success: true } });
    } else {
      await route.fulfill({ json: mockAnalysesList });
    }
  });

  await page.route('**/api/**/emails', async (route) => {
    await route.fulfill({ json: mockAnalysesList });
  });

  // Specific Email routes registered AFTER generic ones so they take precedence
  await page.route('**/api/**/emails/analysis-002**', async (route) => {
    await route.fulfill({ json: { ...mockAnalysisDetail, id: 'analysis-002', subject: 'Invoice INV-98214 Attached' } });
  });

  await page.route('**/api/**/emails/analysis-001**', async (route) => {
    await route.fulfill({ json: mockAnalysisDetail });
  });

  await page.route('**/api/**/emails/upload**', async (route) => {
    await route.fulfill({
      json: {
        analysis_id: 'analysis-001',
        status: 'PENDING',
      },
    });
  });

  // Auth routes
  await page.route('**/api/**/auth/login', async (route) => {
    await route.fulfill({
      json: {
        access_token: 'valid-mock-jwt-token',
        token_type: 'bearer',
        user: mockUser,
      },
    });
  });

  await page.route('**/api/**/auth/refresh', async (route) => {
    await route.fulfill({
      json: {
        access_token: 'valid-mock-jwt-token',
        token_type: 'bearer',
        user: mockUser,
      },
    });
  });

  await page.route('**/api/**/auth/me', async (route) => {
    await route.fulfill({ json: mockUser });
  });

  await page.route('**/api/**/users/me', async (route) => {
    await route.fulfill({ json: mockUser });
  });

  await page.route('**/api/**/auth/logout', async (route) => {
    await route.fulfill({ json: { message: 'Logged out successfully' } });
  });

  await page.route('**/api/**/health', async (route) => {
    await route.fulfill({ json: { status: 'healthy' } });
  });

  // Workspaces
  await page.route('**/api/**/workspaces', async (route) => {
    await route.fulfill({ json: mockWorkspacesList });
  });

  await page.route('**/api/**/workspaces/**/stats', async (route) => {
    await route.fulfill({ json: mockStats });
  });

  await page.route('**/api/**/workspaces/**/members', async (route) => {
    if (route.request().method() === 'POST') {
      const postData = route.request().postDataJSON();
      await route.fulfill({
        json: {
          user_id: 'new-user-4',
          email: postData?.email || 'new@company.com',
          full_name: 'New Workspace Member',
          role: postData?.role || 'viewer',
        },
      });
    } else {
      await route.fulfill({ json: mockMembers });
    }
  });

  await page.route('**/api/**/workspaces/**/members/**', async (route) => {
    if (route.request().method() === 'DELETE') {
      await route.fulfill({ json: { success: true } });
    }
  });

  await page.route('**/api/**/workspaces/**/integrations/gmail', async (route) => {
    await route.fulfill({ json: mockGmailStatus });
  });

  await page.route('**/api/**/workspaces/**/integrations/gmail/sync', async (route) => {
    await route.fulfill({ json: { status: 'QUEUED', message: 'Sync queued' } });
  });

  await page.route('**/api/**/workspaces/**/integrations/gmail/disconnect', async (route) => {
    await route.fulfill({ json: { status: 'DISCONNECTED', message: 'Integration disconnected' } });
  });

  // Threat Intel
  await page.route('**/api/**/intel/iocs**', async (route) => {
    await route.fulfill({ json: mockIocsList });
  });

  await page.route('**/api/**/intel/enrich', async (route) => {
    await route.fulfill({
      json: {
        indicator: 'update-portal-spoof.com',
        type: 'DOMAIN',
        reputation: 'MALICIOUS',
        score: 95,
      },
    });
  });

  // Graph
  await page.route('**/api/**/graph/campaign**', async (route) => {
    await route.fulfill({ json: mockGraphData });
  });
}

export async function loginAndNavigateTo(page: Page, path = '/dashboard') {
  await setupStandardApiMocks(page);
  await page.addInitScript(() => {
    window.localStorage.setItem(
      'sentineltrace-auth',
      JSON.stringify({
        state: {
          user: {
            id: '1',
            email: 'analyst@sentineltrace.io',
            full_name: 'Alex Mercer (SOC Lead)',
            role: 'ADMIN',
          },
          isAuthenticated: true,
          accessToken: 'mock-jwt-token-xyz',
        },
        version: 0,
      })
    );
    window.localStorage.setItem(
      'sentineltrace-workspace',
      JSON.stringify({
        state: {
          currentWorkspaceId: '1',
        },
        version: 0,
      })
    );
  });
  await page.goto(path);
  await page.waitForLoadState('domcontentloaded');
}
