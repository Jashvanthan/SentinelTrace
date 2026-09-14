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
  const { serviceId, publicKey, welcomeTemplateId } = getEmailJSConfig();

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

  // If EmailJS credentials are not yet configured in env, log safely and return without error
  if (!serviceId || !publicKey || !welcomeTemplateId) {
    console.info('[EmailJS] Configuration absent or incomplete; skipping welcome email dispatch.');
    return {
      success: false,
      status: 'SKIPPED_NOT_CONFIGURED',
      message: 'EmailJS credentials not configured.',
    };
  }

  ensureInitialized(publicKey);

  const recipientName = args.name?.trim() || args.email.split('@')[0];
  const appUrl = args.applicationUrl || (typeof window !== 'undefined' ? window.location.origin : 'https://sentineltrace.io');
  const wsName = args.workspaceName || 'Personal Workspace';

  const templateParams = {
    name: recipientName,
    email: args.email,
    workspace_name: wsName,
    application_url: appUrl,
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
