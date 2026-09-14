// SentinelTrace Frontend — Email Uploader Component

import { useCallback, useState } from 'react';
import { Upload, FileText, X, AlertCircle, CheckCircle2, Sparkles, Play } from 'lucide-react';
import { cn, formatFileSize } from '@/utils';
import { useUploadEmail } from '@/api/hooks';
import { useNotificationStore } from '@/store';

interface EmailUploaderProps {
  onSuccess?: (analysisId: string) => void;
}

const SAMPLE_EML_CONTENT = `From: Security Team <alert@security-service-update.org>
To: target.user@enterprise.com
Subject: Action Required: Immediate Password Verification Due to Suspicious Login
Date: Thu, 10 Sep 2026 14:22:15 +0000
Content-Type: text/plain; charset="UTF-8"
Received: from mail.attacker-infrastructure.xyz (mail.attacker-infrastructure.xyz [198.51.100.42])
 by mx.enterprise.com (Postfix) with ESMTPS id 4S9xQq1b7zZ3
 for <target.user@enterprise.com>; Thu, 10 Sep 2026 14:22:16 +0000

Dear User,

Our automated SOC systems detected an unauthorized sign-in attempt to your account from IP: 198.51.100.42 (Location: Moscow, Russia).

To secure your identity and prevent account lockout, please verify your credentials immediately using our secure portal:
http://security-portal-login.xyz/auth/verify?id=992812

If you do not complete this verification within 24 hours, your enterprise access will be suspended.

Sincerely,
Enterprise IT Security Operations
`;

export function EmailUploader({ onSuccess }: EmailUploaderProps) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [notes, setNotes] = useState('');
  const [priority, setPriority] = useState<'NORMAL' | 'HIGH' | 'CRITICAL'>('NORMAL');

  const upload = useUploadEmail();
  const notify = useNotificationStore((s) => s.addNotification);

  const handleFile = (f: File) => {
    if (!f.name.toLowerCase().endsWith('.eml')) {
      notify({ type: 'error', title: 'Invalid file type', description: 'Only .eml files are accepted' });
      return;
    }
    if (f.size > 50 * 1024 * 1024) {
      notify({ type: 'error', title: 'File too large', description: 'Maximum file size is 50 MB' });
      return;
    }
    setFile(f);
  };

  const handleLoadSample = (e: React.MouseEvent) => {
    e.stopPropagation();
    const sampleBlob = new Blob([SAMPLE_EML_CONTENT], { type: 'message/rfc822' });
    const sampleFile = new File([sampleBlob], 'sample_phishing_alert.eml', { type: 'message/rfc822' });
    setFile(sampleFile);
    setNotes('Loaded sample credential harvesting phishing email for automated evaluation.');
    notify({
      type: 'info',
      title: 'Sample EML Loaded',
      description: 'Loaded sample_phishing_alert.eml. Ready for analysis submission.',
    });
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) handleFile(dropped);
  }, []);

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!file) {
      notify({
        type: 'warning',
        title: 'No file attached',
        description: 'Please select an .eml file or click "Load Sample Phishing Email" first.',
      });
      return;
    }
    try {
      const result = await upload.mutateAsync({ file, notes: notes || undefined, priority });
      notify({
        type: 'success',
        title: 'Analysis started',
        description: `Email queued for analysis. ID: ${result.analysis_id.slice(0, 8)}…`,
      });
      onSuccess?.(result.analysis_id);
      setFile(null);
      setNotes('');
    } catch (err: any) {
      notify({
        type: 'error',
        title: 'Upload failed',
        description: err?.response?.data?.detail || err?.message || 'Could not submit email for analysis',
      });
    }
  };

  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onClick={() => document.getElementById('eml-file-input')?.click()}
        className={cn(
          'border-2 border-dashed rounded-lg p-7 text-center cursor-pointer relative',
          'transition-all duration-200',
          dragging
            ? 'border-[hsl(var(--accent))] bg-[hsl(var(--accent-subtle))]'
            : 'border-[hsl(var(--border))] hover:border-[hsl(var(--accent)/0.5)] hover:bg-[hsl(var(--surface-2))]',
          file && 'border-[hsl(var(--low)/0.5)] bg-[hsl(var(--low-subtle))]'
        )}
      >
        <input
          id="eml-file-input"
          type="file"
          accept=".eml"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
        />

        {file ? (
          <div className="flex flex-col items-center gap-3">
            <CheckCircle2 className="w-10 h-10 text-[hsl(var(--low))]" />
            <div>
              <p className="font-medium text-[hsl(var(--foreground))]">{file.name}</p>
              <p className="text-sm text-[hsl(var(--foreground-muted))]">{formatFileSize(file.size)}</p>
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); setFile(null); }}
              className="text-xs text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--critical))] transition-colors flex items-center gap-1"
            >
              <X className="w-3 h-3" /> Remove File
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3">
            <div className="w-12 h-12 rounded-full bg-[hsl(var(--surface-3))] flex items-center justify-center">
              <Upload className="w-6 h-6 text-[hsl(var(--foreground-muted))]" />
            </div>
            <div>
              <p className="font-medium text-[hsl(var(--foreground))]">
                Drop .eml file here or click to browse
              </p>
              <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
                Supports raw RFC 5322 email files (max 50 MB)
              </p>
            </div>
            <button
              type="button"
              onClick={handleLoadSample}
              className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-[hsl(var(--surface-3))] text-[hsl(var(--accent))] hover:bg-[hsl(var(--accent-subtle))] border border-[hsl(var(--border))] transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample Phishing Email (.eml)
            </button>
          </div>
        )}
      </div>

      {/* Options & Metadata */}
      <div className="space-y-3">
        {/* Priority */}
        <div>
          <label className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
            Analysis Priority
          </label>
          <div className="flex gap-2">
            {(['NORMAL', 'HIGH', 'CRITICAL'] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPriority(p)}
                className={cn(
                  'px-3 py-1.5 rounded text-xs font-medium border transition-colors',
                  priority === p
                    ? p === 'CRITICAL'
                      ? 'severity-critical'
                      : p === 'HIGH'
                      ? 'severity-high'
                      : 'bg-[hsl(var(--accent-subtle))] text-[hsl(var(--accent))] border-[hsl(var(--accent)/0.3)]'
                    : 'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-3))]'
                )}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        {/* Notes */}
        <div>
          <label className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
            Analyst Notes <span className="text-[hsl(var(--foreground-subtle))]">(optional)</span>
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
            maxLength={2048}
            placeholder="Add context or incident notes for this investigation..."
            className="w-full px-3 py-2 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))] rounded-md
                       text-sm text-[hsl(var(--foreground))] placeholder-[hsl(var(--foreground-subtle))]
                       focus:border-[hsl(var(--accent)/0.5)] focus:outline-none transition-colors resize-none"
          />
        </div>

        {/* Submit */}
        <button
          type="button"
          onClick={handleSubmit}
          disabled={upload.isPending || !file}
          className={cn(
            'w-full py-2.5 px-4 rounded-md font-medium text-sm transition-all duration-150',
            file
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] hover:bg-[hsl(var(--accent-hover))] cursor-pointer shadow-md'
              : 'bg-[hsl(var(--surface-3))] text-[hsl(var(--foreground-muted))] cursor-not-allowed border border-[hsl(var(--border))]',
            'focus:outline-none focus:ring-2 focus:ring-[hsl(var(--accent)/0.5)]',
            'disabled:opacity-50 disabled:cursor-not-allowed'
          )}
        >
          {upload.isPending ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              Submitting for Analysis…
            </span>
          ) : (
            <span className="flex items-center justify-center gap-2">
              <Play className="w-4 h-4 fill-current" />
              {file ? 'Submit for Analysis' : 'Attach .eml or Load Sample to Submit'}
            </span>
          )}
        </button>
      </div>

      {/* Info note */}
      <div className="flex items-start gap-2 p-3 rounded-md bg-[hsl(var(--info-subtle))] border border-[hsl(var(--info)/0.2)]">
        <AlertCircle className="w-4 h-4 text-[hsl(var(--info))] flex-shrink-0 mt-0.5" />
        <p className="text-xs text-[hsl(var(--info))]">
          Email files are analyzed with real-time AI & multi-engine threat intelligence (VirusTotal, AbuseIPDB, Shodan, Neo4j graph).
        </p>
      </div>
    </div>
  );
}
