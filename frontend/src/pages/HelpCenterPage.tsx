// SentinelTrace Frontend — Help Center, Operational Guidelines, Contact Desk & User Feedback

import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  HelpCircle, BookOpen, MessageSquare, Mail, ShieldAlert,
  Send, CheckCircle2, AlertTriangle, ChevronDown, ChevronRight,
  ExternalLink, Sparkles, Server, Zap, Radio, Globe, FileText,
  Network, Key, Check, Copy, Phone, Clock, MessageCircle, Bug,
  FileCheck, Shield, Loader2, ArrowRight
} from 'lucide-react';
import { useAuthStore } from '@/store';
import { sendHelpCenterMessage } from '@/services/emailService';
import { cn } from '@/utils';

type HelpTab = 'guidelines' | 'feedback' | 'contact' | 'faq';

export function HelpCenterPage() {
  const { user } = useAuthStore();
  const [activeTab, setActiveTab] = useState<HelpTab>('guidelines');

  // Feedback Form State
  const [name, setName] = useState(user?.full_name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [category, setCategory] = useState<'feedback' | 'bug' | 'feature' | 'security'>('feedback');
  const [priority, setPriority] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('MEDIUM');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // FAQ Accordion State
  const [expandedFaq, setExpandedFaq] = useState<number | null>(0);

  const handleSubmitFeedback = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !subject.trim() || !message.trim()) {
      setSubmitStatus({ type: 'error', message: 'Please complete all required fields before submitting.' });
      return;
    }

    setIsSubmitting(true);
    setSubmitStatus(null);

    try {
      const result = await sendHelpCenterMessage({
        name: name.trim() || 'SentinelTrace Analyst',
        email: email.trim(),
        category,
        priority,
        subject: subject.trim(),
        message: message.trim(),
        toEmail: 'jashvan467@gmail.com',
      });

      if (result.success) {
        setSubmitStatus({
          type: 'success',
          message: 'Your inquiry, feedback, and complaint report have been successfully submitted and routed to the SentinelTrace administration team.',
        });
        setSubject('');
        setMessage('');
      } else {
        setSubmitStatus({
          type: 'error',
          message: result.message || 'Failed to dispatch report. Please try again or reach out directly.',
        });
      }
    } catch (err: any) {
      setSubmitStatus({
        type: 'error',
        message: 'An unexpected transmission error occurred. Your message has been logged for administrator review.',
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 font-sans">
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#232e42] pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[#2563eb]/20 border border-[#3b82f6]/40 text-[#60a5fa]">
              <HelpCircle className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              SentinelTrace Help Center & Operations Manual
            </h1>
          </div>
          <p className="text-xs text-[#94a3b8] font-mono">
            Comprehensive user guides, forensic workflow manuals, direct support contact, and incident reporting.
          </p>
        </div>

        {/* Quick Tab Switcher */}
        <div className="flex items-center gap-1.5 bg-[#121824] border border-[#232e42] rounded-lg p-1 text-xs font-mono overflow-x-auto">
          <button
            onClick={() => setActiveTab('guidelines')}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap",
              activeTab === 'guidelines'
                ? "bg-[#2563eb] text-white shadow-sm"
                : "text-[#94a3b8] hover:text-white hover:bg-[#161c2b]"
            )}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Guidelines</span>
          </button>

          <button
            onClick={() => setActiveTab('feedback')}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap",
              activeTab === 'feedback'
                ? "bg-[#2563eb] text-white shadow-sm"
                : "text-[#94a3b8] hover:text-white hover:bg-[#161c2b]"
            )}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Feedback & Issues</span>
          </button>

          <button
            onClick={() => setActiveTab('contact')}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap",
              activeTab === 'contact'
                ? "bg-[#2563eb] text-white shadow-sm"
                : "text-[#94a3b8] hover:text-white hover:bg-[#161c2b]"
            )}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Contact Support</span>
          </button>

          <button
            onClick={() => setActiveTab('faq')}
            className={cn(
              "px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer flex items-center gap-1.5 whitespace-nowrap",
              activeTab === 'faq'
                ? "bg-[#2563eb] text-white shadow-sm"
                : "text-[#94a3b8] hover:text-white hover:bg-[#161c2b]"
            )}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>FAQ</span>
          </button>
        </div>
      </div>

      {/* ── TAB 1: Complete Operational Guidelines ──────────────────────── */}
      {activeTab === 'guidelines' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Quick Overview Hero Banner */}
          <div className="card-surface p-6 rounded-xl border border-[#232e42] bg-gradient-to-r from-[#0d1424] to-[#121824] space-y-4">
            <div className="flex items-center gap-2 text-xs font-bold text-[#3b82f6] uppercase font-mono tracking-wider">
              <Sparkles className="w-4 h-4" />
              <span>Platform Core Overview</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              How SentinelTrace Defends Enterprise Communications
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
              SentinelTrace is an advanced cybersecurity Security Operations Center (SOC) platform engineered to detect, deconstruct, and neutralize phishing campaigns, business email compromise (BEC), malicious attachments, and credential harvesting operations. It fuses multi-engine threat intelligence, real-time Gmail OAuth sync, NLP psychological manipulation detection, and cryptographic blockchain audit ledgers.
            </p>
          </div>

          {/* Step-by-Step Feature Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {/* Step 1 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-blue-400 font-mono px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/40 uppercase">
                  Step 01 • Ingestion
                </span>
                <Mail className="w-4 h-4 text-blue-400" />
              </div>
              <h3 className="text-base font-bold text-white">Email Upload & Gmail Sync</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Ingest samples via drag-and-drop of raw <code>.eml</code> files or connect your Google Workspace / Gmail account via tenant-isolated OAuth 2.0. Ingested messages undergo SHA-256 integrity hashing upon receipt.
              </p>
              <Link to="/investigate" className="inline-flex items-center gap-1 text-xs text-[#3b82f6] hover:underline font-mono font-semibold pt-1">
                Go to Investigate Workspace <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Step 2 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-amber-400 font-mono px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/40 uppercase">
                  Step 02 • Workflow Modes
                </span>
                <Zap className="w-4 h-4 text-amber-400" />
              </div>
              <h3 className="text-base font-bold text-white">Auto vs. Manual Analysis</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Choose between <strong>Monitor & Auto-Analyze</strong> (continuous automated threat pipeline execution) or <strong>Monitor & Review</strong> (fetches emails into unanalyzed state, allowing manual inspection and on-demand analysis).
              </p>
              <Link to="/integrations" className="inline-flex items-center gap-1 text-xs text-amber-400 hover:underline font-mono font-semibold pt-1">
                Configure Gmail Modes <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Step 3 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-emerald-400 font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/40 uppercase">
                  Step 03 • Forensics
                </span>
                <Shield className="w-4 h-4 text-emerald-400" />
              </div>
              <h3 className="text-base font-bold text-white">SPF, DKIM, DMARC & NLP</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Evaluates email authentication records for domain spoofing, parses RFC headers, and runs NLP semantic evaluation to detect urgency cues, financial impersonation, and psychological coercion.
              </p>
            </div>

            {/* Step 4 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-purple-400 font-mono px-2 py-0.5 rounded bg-purple-950/60 border border-purple-800/40 uppercase">
                  Step 04 • Threat Intel
                </span>
                <Radio className="w-4 h-4 text-purple-400" />
              </div>
              <h3 className="text-base font-bold text-white">Multi-Engine Intelligence</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Extracted IPs, domains, URLs, and file hashes are cross-referenced with VirusTotal AV engines, AbuseIPDB reputation scores, and Shodan ports to compute an aggregate risk score (0-100).
              </p>
              <Link to="/intel" className="inline-flex items-center gap-1 text-xs text-purple-400 hover:underline font-mono font-semibold pt-1">
                Search Threat Intel Repo <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Step 5 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-orange-400 font-mono px-2 py-0.5 rounded bg-orange-950/60 border border-orange-800/40 uppercase">
                  Step 05 • Correlation
                </span>
                <Network className="w-4 h-4 text-orange-400" />
              </div>
              <h3 className="text-base font-bold text-white">Campaign Knowledge Graph</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Inspect 3D interactive force-directed graph topologies connecting threat actors, infrastructure, C2 beacons, and targeted recipients across disparate email campaigns.
              </p>
              <Link to="/campaigns" className="inline-flex items-center gap-1 text-xs text-orange-400 hover:underline font-mono font-semibold pt-1">
                Explore Campaign Graph <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            {/* Step 6 */}
            <div className="card-surface p-5 rounded-lg border border-[#232e42] bg-[#121824] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-sky-400 font-mono px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800/40 uppercase">
                  Step 06 • Evidentiary Output
                </span>
                <FileCheck className="w-4 h-4 text-sky-400" />
              </div>
              <h3 className="text-base font-bold text-white">Cryptographic PDF Dossiers</h3>
              <p className="text-xs text-[#94a3b8] leading-relaxed">
                Generate tamper-evident forensic PDF reports anchored with SHA-256 digests and Merkle trees, suitable for executive briefings, insurance claims, or law enforcement handover.
              </p>
              <Link to="/reports" className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline font-mono font-semibold pt-1">
                View Generated Reports <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: User Feedback, Complaints & Issue Submission ─────────── */}
      {activeTab === 'feedback' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Submission Form */}
            <div className="lg:col-span-2 card-surface p-6 rounded-xl border border-[#232e42] bg-[#121824] space-y-6">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <MessageSquare className="w-5 h-5 text-[#3b82f6]" />
                  <span>Submit Feedback, Complaints or Bug Reports</span>
                </h2>
                <p className="text-xs text-[#94a3b8] mt-1 font-mono">
                  Messages submitted here are immediately dispatched via EmailJS to the administrative desk (<strong className="text-white">jashvan467@gmail.com</strong>).
                </p>
              </div>

              {submitStatus && (
                <div className={cn(
                  "p-4 rounded-lg border text-xs font-mono flex items-start gap-3 animate-in fade-in duration-150",
                  submitStatus.type === 'success'
                    ? "bg-emerald-950/60 text-emerald-300 border-emerald-500/40"
                    : "bg-red-950/60 text-red-300 border-red-500/40"
                )}>
                  {submitStatus.type === 'success' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <p className="font-bold">{submitStatus.type === 'success' ? 'Transmission Confirmed' : 'Submission Notice'}</p>
                    <p className="leading-relaxed">{submitStatus.message}</p>
                  </div>
                </div>
              )}

              <form onSubmit={handleSubmitFeedback} className="space-y-5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                  <div className="space-y-1.5">
                    <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                      Your Full Name
                    </label>
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Jashvanthan A"
                      className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                      Email Address (for response)
                    </label>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="e.g. analyst@organization.com"
                      className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                  <div className="space-y-1.5">
                    <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                      Category
                    </label>
                    <select
                      value={category}
                      onChange={(e) => setCategory(e.target.value as any)}
                      className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white focus:outline-none focus:border-[#3b82f6] cursor-pointer"
                    >
                      <option value="feedback">General Feedback & Suggestion</option>
                      <option value="bug">Technical Complaint / Bug Report</option>
                      <option value="feature">Feature Request & Enhancement</option>
                      <option value="security">Security Vulnerability / Concern</option>
                    </select>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                      Priority Level
                    </label>
                    <select
                      value={priority}
                      onChange={(e) => setPriority(e.target.value as any)}
                      className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white focus:outline-none focus:border-[#3b82f6] cursor-pointer"
                    >
                      <option value="LOW">Low (General Inquiry)</option>
                      <option value="MEDIUM">Medium (Standard Feedback)</option>
                      <option value="HIGH">High (Workflow Blocking Issue)</option>
                      <option value="CRITICAL">Critical (Security or Data Hazard)</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1.5 font-mono text-xs">
                  <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                    Subject / Title
                  </label>
                  <input
                    type="text"
                    required
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="Brief headline of your feedback or complaint..."
                    className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6]"
                  />
                </div>

                <div className="space-y-1.5 font-mono text-xs">
                  <label className="text-[11px] font-semibold text-[#94a3b8] uppercase tracking-wider block">
                    Detailed Description / Steps to Reproduce
                  </label>
                  <textarea
                    rows={5}
                    required
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Provide full details, error messages observed, suggestions, or specific forensic expectations..."
                    className="w-full px-3.5 py-2.5 bg-[#090d16] border border-[#232e42] rounded-lg text-white placeholder-[#64748b] focus:outline-none focus:border-[#3b82f6] font-mono leading-relaxed"
                  />
                </div>

                <div className="flex items-center justify-between pt-2">
                  <span className="text-[11px] text-[#64748b] font-mono">
                    Recipient target: <code className="text-white">jashvan467@gmail.com</code>
                  </span>
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="px-6 py-2.5 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-bold font-mono rounded-lg transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-blue-950/50 disabled:opacity-50"
                  >
                    {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    <span>{isSubmitting ? 'Dispatching...' : 'Transmit Report'}</span>
                  </button>
                </div>
              </form>
            </div>

            {/* Right Column: Information & Policies */}
            <div className="space-y-4">
              <div className="card-surface p-5 rounded-xl border border-[#232e42] bg-[#121824] space-y-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  <span>Complaint & Bug Response SLA</span>
                </h3>
                <ul className="text-xs text-[#94a3b8] space-y-2.5 leading-relaxed">
                  <li className="flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span><strong>Critical & High Priority:</strong> Reviewed by the core engineering triage team within <strong>2 hours</strong>.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-blue-400 font-bold">•</span>
                    <span><strong>Standard Feedback:</strong> Acknowledged and tracked within <strong>24 business hours</strong>.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">•</span>
                    <span><strong>Direct Email Routing:</strong> Submissions are piped to <code>jashvan467@gmail.com</code> for immediate mobile dispatch.</span>
                  </li>
                </ul>
              </div>

              <div className="card-surface p-5 rounded-xl border border-[#232e42] bg-[#121824] space-y-3">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Privacy & Tenant Isolation</span>
                </h3>
                <p className="text-xs text-[#94a3b8] leading-relaxed">
                  Submitted error telemetry and feedback do not expose API keys, raw session passwords, or private OAuth tokens. All communications remain isolated to your tenant workspace.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: Official Contact Details & Channels ──────────────────── */}
      {activeTab === 'contact' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 font-mono text-xs">
            {/* Contact Card 1 */}
            <div className="card-surface p-6 rounded-xl border border-[#232e42] bg-[#121824] space-y-3">
              <div className="w-10 h-10 rounded-lg bg-blue-950/60 border border-blue-800/50 flex items-center justify-center text-blue-400">
                <Mail className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">Administrator Email</h3>
              <p className="text-[#94a3b8]">
                Direct inbox for enterprise security escalation, feature inquiries, and incident reports.
              </p>
              <div className="pt-2">
                <a
                  href="mailto:jashvan467@gmail.com"
                  className="text-[#60a5fa] hover:underline font-bold text-xs inline-flex items-center gap-1"
                >
                  jashvan467@gmail.com <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>

            {/* Contact Card 2 */}
            <div className="card-surface p-6 rounded-xl border border-[#232e42] bg-[#121824] space-y-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-950/60 border border-emerald-800/50 flex items-center justify-center text-emerald-400">
                <Clock className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">Operations & Triage Desk</h3>
              <p className="text-[#94a3b8]">
                Automated threat intelligence ingestion and Celery background workers run 24/7/365.
              </p>
              <div className="pt-2 text-emerald-400 font-bold">
                ● 24/7 Threat Monitoring Coverage
              </div>
            </div>

            {/* Contact Card 3 */}
            <div className="card-surface p-6 rounded-xl border border-[#232e42] bg-[#121824] space-y-3">
              <div className="w-10 h-10 rounded-lg bg-purple-950/60 border border-purple-800/50 flex items-center justify-center text-purple-400">
                <Globe className="w-5 h-5" />
              </div>
              <h3 className="text-sm font-bold text-white">Support Portal</h3>
              <p className="text-[#94a3b8]">
                Official SentinelTrace SOC portal documentation and community knowledge base.
              </p>
              <div className="pt-2">
                <span className="text-purple-300 font-bold">support@sentineltrace.io</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: Troubleshooting FAQ ─────────────────────────────────── */}
      {activeTab === 'faq' && (
        <div className="space-y-4 max-w-4xl animate-in fade-in duration-200">
          {[
            {
              q: 'How does Manual Review Mode work vs. Auto-Analyze Mode?',
              a: 'In Manual Review Mode, incoming emails fetched from Gmail are stored in an unanalyzed state (marked "NOT ANALYZED"). You can open any email in the forensic workspace and click the prominent "Analyze Email" button to run the multi-engine analysis on demand. In Auto-Analyze Mode, all newly synced messages are immediately processed upon receipt.'
            },
            {
              q: 'Why does an IP show as "Private / Reserved (RFC 1918)" in Geolocation?',
              a: 'IP addresses in ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 127.0.0.0/8 belong to internal private LAN subnets and cannot be located on public internet maps. SentinelTrace automatically detects these and provides a PowerShell guide (Get-DhcpServerv4Lease, Get-ADComputer, arp -a) to resolve the internal domain user.'
            },
            {
              q: 'What causes SPF "Softfail" or DKIM "Fail"?',
              a: 'An SPF Softfail occurs when the sending mail server IP is not explicitly authorized in the sender domain’s SPF DNS TXT record. DKIM Fail indicates that the cryptographic RSA signature in the header did not verify against the public key published in DNS, signaling potential message tampering or sender header spoofing.'
            },
            {
              q: 'How do I download tamper-proof PDF forensic reports?',
              a: 'Navigate to the Reports page or open any email analysis detail page and click "Raw Source" / "Export Report". SentinelTrace generates an authenticated PDF report containing SHA-256 evidence digests, AI Executive forensic assessments, and threat breakdown indicators.'
            },
            {
              q: 'Where do feedback submissions and complaint tickets go?',
              a: 'All submissions from the "Feedback & Issues" tab in this Help Center are routed directly to the administrator email at jashvan467@gmail.com with structured severity, user details, and timestamp metadata.'
            }
          ].map((item, idx) => {
            const isExpanded = expandedFaq === idx;
            return (
              <div
                key={idx}
                className="card-surface rounded-lg border border-[#232e42] bg-[#121824] overflow-hidden transition-colors"
              >
                <button
                  type="button"
                  onClick={() => setExpandedFaq(isExpanded ? null : idx)}
                  className="w-full p-4 text-left flex items-center justify-between gap-4 cursor-pointer hover:bg-[#161c2b] transition-colors"
                >
                  <span className="text-sm font-bold text-white flex items-center gap-2">
                    <span className="text-[#3b82f6] font-mono">Q{idx + 1}.</span>
                    <span>{item.q}</span>
                  </span>
                  <ChevronDown className={cn("w-4 h-4 text-[#94a3b8] transition-transform", isExpanded && "rotate-180")} />
                </button>
                {isExpanded && (
                  <div className="p-4 pt-0 border-t border-[#1f2a3e] bg-[#0d1424] text-xs text-slate-300 leading-relaxed font-mono">
                    <p className="pt-3">{item.a}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
