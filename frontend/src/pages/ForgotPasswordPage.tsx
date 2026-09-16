import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Mail, ArrowLeft, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import apiClient from '@/lib/api';
import { cn, extractErrorMessage } from '@/utils';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [isPending, setIsPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (!email) {
      setFormError('Please enter your email address.');
      return;
    }

    setIsPending(true);
    try {
      await apiClient.post('/auth/forgot-password', { email });
      setFormSuccess('If that email exists in our system, you will receive a password reset link shortly.');
    } catch (err: any) {
      setFormError(extractErrorMessage(err, 'Failed to request password reset. Please try again later.'));
    } finally {
      setIsPending(false);
    }
  };

  return (
    <div className="min-h-screen bg-[hsl(var(--background))] grid-pattern flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-3">
            <img
              src="/sentineltrace-logo.jpg"
              alt="SentinelTrace"
              className="h-28 w-auto object-contain rounded-xl"
            />
          </div>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            Reset Your Password
          </p>
        </div>

        <div className="glass rounded-xl p-8 shadow-2xl border border-[hsl(var(--border))]">
          <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-4">
            Forgot Password
          </h2>

          {formError && (
            <div className="mb-4 p-3 rounded-lg bg-[hsl(var(--destructive-subtle))] border border-[hsl(var(--destructive)/0.3)] flex items-start gap-2.5 text-xs text-[hsl(var(--destructive))]">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{formError}</span>
            </div>
          )}

          {formSuccess ? (
            <div className="mb-4 p-3 rounded-lg bg-[hsl(var(--success-subtle))] border border-[hsl(var(--success)/0.3)] flex flex-col items-center justify-center gap-2.5 text-sm text-[hsl(var(--success))] text-center py-6">
              <CheckCircle2 className="w-8 h-8 flex-shrink-0 mb-2" />
              <span>{formSuccess}</span>
              <span className="text-xs mt-2 text-[hsl(var(--foreground-muted))]">Please check your inbox (and spam folder).</span>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <p className="text-sm text-[hsl(var(--foreground-muted))] mb-4">
                Enter your email address and we'll send you a link to reset your password.
              </p>
              
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                  Email
                </label>
                <div className="relative">
                  <input
                    id="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email"
                    className="w-full px-3 py-2.5 pl-10 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                               rounded-md text-sm text-[hsl(var(--foreground))]
                               placeholder-[hsl(var(--foreground-subtle))]
                               focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                  />
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-[hsl(var(--foreground-subtle))] w-4 h-4" />
                </div>
              </div>

              <button
                type="submit"
                disabled={isPending}
                className={cn(
                  'w-full py-2.5 px-4 rounded-md font-medium text-sm mt-2',
                  'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]',
                  'hover:bg-[hsl(var(--accent-hover))] transition-colors',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'flex items-center justify-center gap-2 shadow-md'
                )}
              >
                {isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Sending Link…
                  </>
                ) : (
                  'Send Reset Link'
                )}
              </button>
            </form>
          )}

          <div className="mt-6 text-center">
            <Link to="/login" className="inline-flex items-center gap-1.5 text-xs text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground))] transition-colors">
              <ArrowLeft className="w-3 h-3" />
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
