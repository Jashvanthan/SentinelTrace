import { useState } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import apiClient from '@/lib/api';
import { cn, extractErrorMessage } from '@/utils';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const navigate = useNavigate();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (!token) {
      setFormError('Invalid or missing reset token.');
      return;
    }

    if (password !== confirmPassword) {
      setFormError('Passwords do not match.');
      return;
    }

    if (password.length < 12) {
      setFormError('Password must be at least 12 characters long.');
      return;
    }

    setIsPending(true);
    try {
      const { data } = await apiClient.post('/auth/reset-password', { 
        token, 
        new_password: password 
      });
      setFormSuccess(data.message || 'Password reset successfully.');
      setTimeout(() => {
        navigate('/login');
      }, 3000);
    } catch (err: any) {
      setFormError(extractErrorMessage(err, 'Failed to reset password. The link may be expired.'));
    } finally {
      setIsPending(false);
    }
  };

  if (!token) {
    return (
      <div className="min-h-screen bg-[hsl(var(--background))] grid-pattern flex items-center justify-center p-4">
        <div className="w-full max-w-md glass rounded-xl p-8 shadow-2xl border border-[hsl(var(--border))] text-center">
          <AlertCircle className="w-12 h-12 text-[hsl(var(--destructive))] mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-2">Invalid Reset Link</h2>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mb-6">
            This password reset link is invalid or missing the required token.
          </p>
          <Link to="/forgot-password" className="inline-block px-4 py-2 bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))] rounded-md text-sm font-medium hover:bg-[hsl(var(--accent-hover))] transition-colors">
            Request New Link
          </Link>
        </div>
      </div>
    );
  }

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
            Create New Password
          </p>
        </div>

        <div className="glass rounded-xl p-8 shadow-2xl border border-[hsl(var(--border))]">
          <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-4">
            Reset Password
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
              <span className="text-xs mt-2 text-[hsl(var(--foreground-muted))]">Redirecting to login...</span>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                  New Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Create a secure password (min. 12 chars)"
                    className="w-full px-3 py-2.5 pr-10 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                               rounded-md text-sm text-[hsl(var(--foreground))]
                               placeholder-[hsl(var(--foreground-subtle))]
                               focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-[hsl(var(--foreground-subtle))] hover:text-[hsl(var(--foreground-muted))]"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    id="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    required
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm your new password"
                    className="w-full px-3 py-2.5 pr-10 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                               rounded-md text-sm text-[hsl(var(--foreground))]
                               placeholder-[hsl(var(--foreground-subtle))]
                               focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                  />
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
                    Resetting…
                  </>
                ) : (
                  'Reset Password'
                )}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
