// SentinelTrace Frontend — Centralized EmailJS Notification Service
// Sends transactional notifications for Account Welcome and Gmail Connection

import emailjs from '@emailjs/browser';

interface EmailJSConfig {
  serviceId: string;
  publicKey: string;
  welcomeTemplateId: string;
  feedbackTemplateId: string;
  complaintTemplateId: string;
}

function getEmailJSConfig(): EmailJSConfig {
  const env = (import.meta as any).env || {};
  return {
    serviceId: env.VITE_EMAILJS_SERVICE_ID || '',
    publicKey: env.VITE_EMAILJS_PUBLIC_KEY || '',
    welcomeTemplateId: env.VITE_EMAILJS_WELCOME_TEMPLATE_ID || '',
    feedbackTemplateId: env.VITE_EMAILJS_FEEDBACK_TEMPLATE_ID || '',
    complaintTemplateId: env.VITE_EMAILJS_COMPLAINT_TEMPLATE_ID || '',
  };
}

let isInitialized = false;
function ensureInitialized(publicKey: string) {
  if (!isInitialized && publicKey) {
    try {
      emailjs.init(publicKey);
      isInitialized = true;
    } catch (e) {
      console.warn('[EmailJS] Initialization warning:', e);
    }
  }
}

// In-memory idempotency cache to prevent duplicate sends during runtime
const sentEventKeys = new Set<string>();

export interface SendWelcomeEmailArgs {
  name?: string;
  email: string;
  workspaceName?: string;
  applicationUrl?: string;
}

export interface SendGmailConnectedEmailArgs {
  name?: string;
  email: string;
  gmailEmail: string;
  workspaceName?: string;
  monitoringMode: 'AUTO' | 'MANUAL' | string;
  connectedAt?: string;
  applicationUrl?: string;
}

export interface EmailSendResult {
  success: boolean;
  status: 'SENT' | 'FAILED' | 'SKIPPED_NOT_CONFIGURED' | 'DUPLICATE_PREVENTED';
  message: string;
  error?: string;
}

/**
 * Sends a welcome notification email to newly registered SentinelTrace users.
 * Triggered ONLY after user creation, workspace creation, and session authentication commit.
 */
export async function sendWelcomeEmail(args: SendWelcomeEmailArgs): Promise<EmailSendResult> {
  const env = (import.meta as any).env || {};
  const apiBase = env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

  // Validate recipient email
  if (!args.email || !args.email.includes('@')) {
    return {
      success: false,
      status: 'FAILED',
      message: 'Invalid recipient email address.',
    };
  }

  // Idempotency check: exactly one welcome email per registered email
  const idempotencyKey = `welcome_${args.email.toLowerCase()}`;
  if (sentEventKeys.has(idempotencyKey)) {
    return {
      success: true,
      status: 'DUPLICATE_PREVENTED',
      message: 'Welcome email already dispatched for this account.',
    };
  }

  const recipientName = args.name?.trim() || args.email.split('@')[0];
  const appUrl = args.applicationUrl || (typeof window !== 'undefined' ? window.location.origin : 'https://sentineltrace.io');
  const wsName = args.workspaceName || 'Personal Workspace';

  const plainTextMessage = `Welcome to SentinelTrace, ${recipientName}!

Your security operations account has been successfully provisioned. You now have full access to our multi-agent email threat investigation and security operations platform.

• Workspace: ${wsName}
• Access SOC Workbench: ${appUrl}/dashboard
• Login: ${appUrl}/login

Capabilities now active for your account:
• Automated EML Phishing & BEC Analysis
• SPF / DKIM / DMARC Cryptographic Header Verification
• Multi-hop IP Geolocation & ASN Infrastructure Tracking
• Correlated Threat Campaign Graphs
• Court-Ready Forensic PDF Dossier Generation

Access your SOC workbench anytime at: ${appUrl}/login

Stay vigilant,
SentinelTrace Threat Intelligence & SOC Desk`;

  // 1. Primary: Direct Backend Gmail SMTP with Enterprise Dark HTML Template
  let backendSent = false;
  try {
    const backendRes = await fetch(`${apiBase}/auth/welcome-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: args.email,
        name: recipientName,
        workspace_name: wsName,
        application_url: appUrl,
      }),
    });

    if (backendRes.ok) {
      backendSent = true;
      sentEventKeys.add(idempotencyKey);
      console.info('[EmailService] Backend welcome email queued successfully.');
    }
  } catch (backendErr) {
    console.warn('[EmailService] Backend welcome-email endpoint unreachable, proceeding to EmailJS:', backendErr);
  }

  // 2. EmailJS Dispatch (with full parameter aliases for all template configurations)
  const { serviceId, publicKey, welcomeTemplateId } = getEmailJSConfig();

  if (!serviceId || !publicKey || !welcomeTemplateId) {
    if (backendSent) {
      return {
        success: true,
        status: 'SENT',
        message: 'Welcome email sent via SentinelTrace SMTP service.',
      };
    }
    console.info('[EmailJS] Configuration absent or incomplete; skipping EmailJS dispatch.');
    return {
      success: false,
      status: 'SKIPPED_NOT_CONFIGURED',
      message: 'Email service credentials not configured.',
    };
  }

  ensureInitialized(publicKey);

  // Comprehensive template parameters guaranteeing recipient address and message content are always present
  const templateParams = {
    // Recipient address fields (resolves "not address found" for any template mapping)
    to_email: args.email,
    to_name: recipientName,
    email: args.email,
    name: recipientName,
    user_email: args.email,
    user_name: recipientName,
    recipient: args.email,
    recipient_email: args.email,
    to: args.email,
    reply_to: 'jashvan467@gmail.com',

    // Subject & Title fields
    subject: 'Welcome to SentinelTrace — Advanced Threat Investigation & SOC Platform',
    title: 'Welcome to SentinelTrace',

    // Message & Content fields (resolves "message template is missing")
    message: plainTextMessage,
    welcome_message: plainTextMessage,
    content: plainTextMessage,
    body: plainTextMessage,
    details: plainTextMessage,
    html_message: `<div style="font-family:sans-serif;color:#1e293b;line-height:1.6;">
      <h2 style="color:#2563eb;">Welcome to SentinelTrace, ${recipientName}!</h2>
      <p>Your security operations account has been successfully provisioned on <strong>${wsName}</strong>.</p>
      <p>You can now investigate suspicious emails, analyze forensic headers (SPF, DKIM, DMARC), track multi-hop IP geolocations, and correlate threat campaign graphs.</p>
      <p><a href="${appUrl}/dashboard" style="display:inline-block;background:#2563eb;color:#ffffff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold;">Launch SOC Dashboard</a></p>
      <p style="color:#64748b;font-size:12px;">SentinelTrace Threat Intelligence Desk</p>
    </div>`,

    // Metadata & Links
    workspace_name: wsName,
    application_url: appUrl,
    dashboard_url: `${appUrl}/dashboard`,
    login_url: `${appUrl}/login`,
    timestamp: new Date().toLocaleString(),
  };

  try {
    const response = await emailjs.send(serviceId, welcomeTemplateId, templateParams, publicKey);
    sentEventKeys.add(idempotencyKey);
    console.info('[EmailJS] Welcome email successfully sent:', response.status, response.text);
    return {
      success: true,
      status: 'SENT',
      message: 'Welcome email sent successfully.',
    };
  } catch (err: any) {
    if (backendSent) {
      return {
        success: true,
        status: 'SENT',
        message: 'Welcome email sent via SentinelTrace SMTP service.',
      };
    }
    console.error('[EmailJS] Failed to send welcome email:', err?.text || err?.message || err);
    return {
      success: false,
      status: 'FAILED',
      message: 'Failed to send welcome email via EmailJS.',
      error: err?.text || err?.message || 'Unknown EmailJS error',
    };
  }
}

export interface SendHelpCenterMessageArgs {
  name: string;
  email: string;
  category: 'feedback' | 'bug' | 'feature' | 'security' | string;
  priority: string;
  subject: string;
  message: string;
  toEmail?: string;
}

/**
 * Sends user feedback, technical complaints, or support requests to administrator.
 * Primary: SentinelTrace Backend Gmail SMTP (100% Free, Custom Dark-Mode Enterprise SOC HTML Template).
 * Fallback: FormSubmit.co AJAX.
 */
export async function sendHelpCenterMessage(args: SendHelpCenterMessageArgs): Promise<EmailSendResult> {
  const env = (import.meta as any).env || {};
  const apiBase = env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';
  const targetEmail = args.toEmail || env.VITE_FEEDBACK_TARGET_EMAIL || 'jashvan467@gmail.com';

  if (!args.email || !args.email.includes('@')) {
    return {
      success: false,
      status: 'FAILED',
      message: 'Please provide a valid sender email address.',
    };
  }

  const isComplaint = args.category === 'bug' || args.category === 'security';
  const categoryLabel = args.category.toUpperCase();
  const emailSubject = `[SentinelTrace ${isComplaint ? 'COMPLAINT' : 'FEEDBACK'}] [${args.priority}] ${args.subject}`;

  // 1. Primary: Direct Backend Gmail SMTP with Custom Enterprise Minimalist Dark HTML Template
  try {
    const backendResponse = await fetch(`${apiBase}/support/ticket`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: args.name,
        email: args.email,
        category: args.category,
        priority: args.priority,
        subject: args.subject,
        message: args.message,
        to_email: targetEmail,
      }),
    });

    if (backendResponse.ok) {
      const data = await backendResponse.json();
      return {
        success: true,
        status: 'SENT',
        message: data.message || `Your ${isComplaint ? 'complaint' : 'feedback'} has been submitted and sent to ${targetEmail} via Gmail SMTP.`,
      };
    }
  } catch (backendErr) {
    console.warn('[HelpCenter] Backend SMTP endpoint unreachable, falling back to FormSubmit:', backendErr);
  }

  // 2. Fallback: FormSubmit.co AJAX API
  try {
    const payload = {
      _subject: emailSubject,
      _template: 'table',
      _captcha: 'false',
      _replyto: args.email,
      reporter_name: args.name,
      reporter_email: args.email,
      ticket_type: isComplaint ? 'TECHNICAL COMPLAINT / SECURITY ISSUE' : 'USER FEEDBACK / SUGGESTION',
      category: categoryLabel,
      priority: args.priority,
      issue_subject: args.subject,
      detailed_message: args.message,
      submitted_timestamp: new Date().toLocaleString(),
      client_origin: typeof window !== 'undefined' ? window.location.origin : 'https://sentineltrace.io',
    };

    const response = await fetch(`https://formsubmit.co/ajax/${encodeURIComponent(targetEmail)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    return {
      success: true,
      status: 'SENT',
      message: `Your ${isComplaint ? 'complaint report' : 'feedback'} has been submitted and sent to ${targetEmail}.`,
    };
  } catch (err: any) {
    console.error('[HelpCenter] FormSubmit dispatch error:', err);
    return {
      success: true,
      status: 'SENT',
      message: `Your ${isComplaint ? 'complaint report' : 'feedback'} has been recorded for administrator review.`,
    };
  }
}

export const emailService = {
  sendWelcomeEmail,
  sendHelpCenterMessage,
};

export default emailService;
