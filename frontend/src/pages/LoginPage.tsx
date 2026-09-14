// SentinelTrace Frontend — Login & Registration Page
// Strict Google OAuth: Login (existing accounts) vs Register (new accounts)

import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Eye, EyeOff, ExternalLink, UserPlus, LogIn, AlertCircle, CheckCircle2, Loader2, Mail } from 'lucide-react';
import { useLogin, useRegister } from '@/api/hooks';
import { useAuthStore, useNotificationStore } from '@/store';
import apiClient, { setAccessToken } from '@/lib/api';
import { sendWelcomeEmail } from '@/services/emailService';
import { cn, extractErrorMessage } from '@/utils';

// Google pending registration state (parsed from URL)
interface GooglePendingState {
  pendingToken: string;
  email: string;
  name: string;
}

export function LoginPage() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  // Google pending registration state
  const [googlePending, setGooglePending] = useState<GooglePendingState | null>(null);
  const [isCompletingGoogleReg, setIsCompletingGoogleReg] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);

  const login = useLogin();
  const register = useRegister();
  const { setAuth } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const notify = useNotificationStore((s) => s.addNotification);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';

  // Parse URL params on mount — handles OAuth callbacks
  useEffect(() => {
    const search = location.search || '';
    const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);

    // ── Case 1: Existing Google user → login success ──
    if (params.has('google_auth') && params.get('google_auth') === 'success') {
      apiClient.post('/auth/refresh')
        .then((res) => {
          setAuth(res.data.user, res.data.access_token);
          setAccessToken(res.data.access_token);
          navigate(from, { replace: true });
        })
        .catch(() => {
          setFormError('Google sign-in failed. Please try again.');
          navigate('/login', { replace: true });
        });
      return;
    }

    // ── Case 2: Unknown Google identity from Login → redirect to register ──
    if (params.has('error') && params.get('error') === 'google_not_registered') {
      setMode('register');
      const errorEmail = params.get('email') || '';
      setFormError(
        `Your Google account (${errorEmail}) is not registered with SentinelTrace. ` +
        `Please create an account to continue.`
      );
      navigate('/login', { replace: true });
      return;
    }

    // ── Case 3: Google pending registration token (from Register → Continue with Google) ──
    if (params.has('google_pending')) {
      const pendingToken = params.get('google_pending') || '';
      const pendingEmail = params.get('email') || '';
      const pendingName = params.get('name') || '';

      // DO NOT use pendingToken as an access token.
      // Only display email/name for UX — backend validates the actual pending token.
      setGooglePending({
        pendingToken,
        email: decodeURIComponent(pendingEmail),
        name: decodeURIComponent(pendingName),
      });
      setMode('register');
      setFormError(null);
      // Clear the URL without reloading
      navigate('/login', { replace: true });
      return;
    }

    // ── Case 4: Google account collision (already registered) ──
    if (params.has('error') && params.get('error') === 'account_exists') {
      setMode('login');
      const errorEmail = params.get('email') || '';
      if (errorEmail) {
        setEmail(decodeURIComponent(errorEmail));
      }
      setFormError(
        errorEmail
          ? `The Google account (${decodeURIComponent(errorEmail)}) is already registered with SentinelTrace. Please sign in below.`
          : 'This Google account is already registered with SentinelTrace. Please sign in below.'
      );
      navigate('/login', { replace: true });
      return;
    }

    // ── Case 5: Generic Google auth failure ──
    if (params.has('error')) {
      const errorType = params.get('error');
      let msg = 'Google authentication could not be completed. Please try again.';
      if (errorType === 'cookie_missing') {
        msg = 'OAuth session cookie missing. Please enable cookies and try again.';
      }
      setFormError(msg);
      navigate('/login', { replace: true });
    }
  }, [location, from, navigate, setAuth, notify]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (!email || !password) {
      setFormError('Please fill in both email and password.');
      return;
    }

    if (mode === 'login') {
      try {
        const data = await login.mutateAsync({ email, password });
        setAuth(data.user, data.access_token);
        setAccessToken(data.access_token);
        navigate(from, { replace: true });
      } catch (err: any) {
        const msg = extractErrorMessage(err, 'Invalid email or password.');
        setFormError(msg);
        notify({ type: 'error', title: 'Login Failed', description: msg });
      }
    } else {
      try {
        await register.mutateAsync({
          email,
          password,
          full_name: fullName.trim() || undefined,
        });
        setFormSuccess('Account created successfully! Signing in...');
        const data: any = await login.mutateAsync({ email, password });
        setAuth(data.user, data.access_token);
        setAccessToken(data.access_token);

        // Dispatches EmailJS welcome notification safely (non-blocking)
        sendWelcomeEmail({
          name: data.user.full_name || fullName.trim() || data.user.email.split('@')[0],
          email: data.user.email,
          workspaceName: 'Personal Workspace',
          applicationUrl: window.location.origin,
        }).then((res) => {
          if (res.status === 'SENT') {
            notify({
              type: 'info',
              title: 'Welcome Email Sent',
              description: `Confirmation email sent to ${data.user.email}.`,
            });
          }
        }).catch(() => {});

        notify({
          type: 'success',
          title: 'Account Created',
          description: `Welcome to SentinelTrace, ${data.user.full_name || data.user.email}!`,
        });

        navigate(from, { replace: true });
      } catch (err: any) {
        const msg = extractErrorMessage(err, 'Registration failed. The email may already be registered.');
        setFormError(msg);
        notify({ type: 'error', title: 'Registration Failed', description: msg });
      }
    }
  };

  // Initiates Google OAuth with correct intent based on active tab
  const handleGoogleOAuth = async () => {
    try {
      setIsGoogleLoading(true);
      setFormError(null);
      const apiUrl = (import.meta as any).env?.VITE_API_BASE_URL || (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000/api/v1';
      const intent = mode === 'register' ? 'register' : 'login';
      const response = await fetch(`${apiUrl}/auth/google?intent=${intent}`, {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to initialize Google OAuth');
      const data = await response.json();
      window.location.href = data.authorization_url;
    } catch (err: any) {
      setIsGoogleLoading(false);
      const msg = extractErrorMessage(err, 'Failed to start Google OAuth flow');
      notify({
        type: 'error',
        title: 'Google OAuth Error',
        description: msg,
      });
    }
  };

  // Complete Google registration using the pending token
  const handleCompleteGoogleRegistration = async () => {
    if (!googlePending?.pendingToken) return;
    try {
      setIsCompletingGoogleReg(true);
      setFormError(null);
      const apiUrl = (import.meta as any).env?.VITE_API_BASE_URL || (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000/api/v1';
      const res = await fetch(`${apiUrl}/auth/google/complete-registration`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ pending_token: googlePending.pendingToken }),
      });
      const data = await res.json();
      if (!res.ok) {
        const detail = extractErrorMessage(data, 'Google registration could not be completed.');
        if (res.status === 401 && detail.toLowerCase().includes('expired')) {
          setFormError('Your Google registration session has expired. Please try again.');
        } else if (res.status === 409) {
          setFormError('This Google account is already registered. Please sign in instead.');
          setMode('login');
        } else {
          setFormError(detail);
        }
        setGooglePending(null);
        return;
      }
      // Success — set auth and navigate
      setAuth(data.user, data.access_token);
      setAccessToken(data.access_token);

      // Dispatches EmailJS welcome notification safely (non-blocking)
      sendWelcomeEmail({
        name: data.user.full_name || googlePending.name || data.user.email.split('@')[0],
        email: data.user.email,
        workspaceName: 'Personal Workspace',
        applicationUrl: window.location.origin,
      }).then((res) => {
        if (res.status === 'SENT') {
          notify({
            type: 'info',
            title: 'Welcome Email Sent',
            description: `Confirmation email sent to ${data.user.email}.`,
          });
        }
      }).catch(() => {});

      notify({ type: 'success', title: 'Account Created', description: `Welcome to SentinelTrace, ${data.user.full_name || data.user.email}!` });
      navigate(from, { replace: true });
    } catch (err: any) {
      setFormError(extractErrorMessage(err, 'Google registration could not be completed. Please try again.'));
    } finally {
      setIsCompletingGoogleReg(false);
    }
  };

  const isPending = login.isPending || register.isPending;

  return (
    <div className="min-h-screen bg-[hsl(var(--background))] grid-pattern flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-3">
            <img
              src="/sentineltrace-logo.jpg"
              alt="SentinelTrace"
              className="h-28 w-auto object-contain rounded-xl"
            />
          </div>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            AI-Assisted Threat Intelligence Platform
          </p>
        </div>

        {/* Form Card */}
        <div className="glass rounded-xl p-8 shadow-2xl border border-[hsl(var(--border))]">
          <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-4">
            {mode === 'login' ? 'Sign in' : 'Create an account'}
          </h2>

          {/* Mode Switch Tabs */}
          <div role="tablist" className="flex border-b border-[hsl(var(--border))] mb-6">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'login'}
              onClick={() => {
                setMode('login');
                setFormError(null);
                setFormSuccess(null);
                setGooglePending(null);
              }}
              className={cn(
                'flex-1 pb-3 text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition-colors',
                mode === 'login'
                  ? 'border-[hsl(var(--accent))] text-[hsl(var(--accent))]'
                  : 'border-transparent text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))]'
              )}
            >
              <LogIn className="w-4 h-4" />
              Existing Account
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'register'}
              onClick={() => {
                setMode('register');
                setFormError(null);
                setFormSuccess(null);
                setGooglePending(null);
                setEmail('');
                setPassword('');
                setFullName('');
              }}
              className={cn(
                'flex-1 pb-3 text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition-colors',
                mode === 'register'
                  ? 'border-[hsl(var(--accent))] text-[hsl(var(--accent))]'
                  : 'border-transparent text-[hsl(var(--foreground-muted))] hover:text-[hsl(var(--foreground))]'
              )}
            >
              <UserPlus className="w-4 h-4" />
              New Account
            </button>
          </div>

          {/* Google Pending Registration Banner */}
          {googlePending && (
            <div className="mb-6 p-4 rounded-lg bg-blue-500/10 border border-blue-500/30 space-y-3">
              <div className="flex items-start gap-2.5">
                <Mail className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-blue-300">Google Account Verified</p>
                  <p className="text-xs text-[#94a3b8] mt-1">
                    Your Google account is not yet registered with SentinelTrace.
                    Create your account to continue.
                  </p>
                  <p className="text-xs text-white font-mono mt-1.5 bg-[#121824] px-2 py-1 rounded inline-block">
                    {googlePending.email}
                  </p>
                </div>
              </div>
              <button
                onClick={handleCompleteGoogleRegistration}
                disabled={isCompletingGoogleReg}
                className={cn(
                  'w-full py-2.5 px-4 rounded-md font-semibold text-sm',
                  'bg-blue-600 hover:bg-blue-500 text-white transition-colors',
                  'flex items-center justify-center gap-2',
                  'disabled:opacity-60 disabled:cursor-not-allowed',
                )}
              >
                {isCompletingGoogleReg ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Creating your account...
                  </>
                ) : (
                  <>
                    <ExternalLink className="w-4 h-4" />
                    Continue with Google as {googlePending.name || googlePending.email}
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => setGooglePending(null)}
                className="w-full text-xs text-[#64748b] hover:text-[#94a3b8] transition-colors"
              >
                Cancel — use email & password instead
              </button>
            </div>
          )}

          {/* Error/Success Messages */}
          {formError && (
            <div className="mb-4 p-3 rounded-lg bg-[hsl(var(--destructive-subtle))] border border-[hsl(var(--destructive)/0.3)] flex items-start gap-2.5 text-xs text-[hsl(var(--destructive))]">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <div className="space-y-1.5">
                <span>{formError}</span>
                {/* If collision error, provide a quick switch */}
                {(formError.includes('already exists') || formError.includes('already registered')) && (
                  <button
                    type="button"
                    onClick={() => { setMode('login'); setFormError(null); setGooglePending(null); }}
                    className="block font-semibold underline hover:no-underline"
                  >
                    → Go to Login
                  </button>
                )}
              </div>
            </div>
          )}

          {formSuccess && (
            <div className="mb-4 p-3 rounded-lg bg-[hsl(var(--success-subtle))] border border-[hsl(var(--success)/0.3)] flex items-start gap-2.5 text-xs text-[hsl(var(--success))]">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{formSuccess}</span>
            </div>
          )}

          {/* Email/Password Form — hidden when google pending is active */}
          {!googlePending && (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Full Name (Registration only) */}
              {mode === 'register' && (
                <div>
                  <label htmlFor="fullName" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                    Full Name
                  </label>
                  <input
                    id="fullName"
                    type="text"
                    autoComplete="name"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Enter your full name"
                    className="w-full px-3 py-2.5 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                               rounded-md text-sm text-[hsl(var(--foreground))]
                               placeholder-[hsl(var(--foreground-subtle))]
                               focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                  />
                </div>
              )}

              {/* Email */}
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={mode === 'register' ? 'name@company.com' : 'Enter your email'}
                  className="w-full px-3 py-2.5 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                             rounded-md text-sm text-[hsl(var(--foreground))]
                             placeholder-[hsl(var(--foreground-subtle))]
                             focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                />
              </div>

              {/* Password */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={mode === 'register' ? 'Create a secure password (min. 8 chars)' : 'Enter your password'}
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

              {/* Submit */}
              <button
                type="submit"
                disabled={isPending}
                className={cn(
                  'w-full py-2.5 px-4 rounded-md font-medium text-sm',
                  'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]',
                  'hover:bg-[hsl(var(--accent-hover))] transition-colors',
                  'disabled:opacity-50 disabled:cursor-not-allowed',
                  'flex items-center justify-center gap-2 shadow-md'
                )}
              >
                {isPending ? (
                  <>
                    <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                    {mode === 'login' ? 'Signing in…' : 'Creating account…'}
                  </>
                ) : (
                  mode === 'login' ? 'Sign In' : 'Create Account'
                )}
              </button>
            </form>
          )}

          {/* Divider */}
          <div className="relative my-5">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-[hsl(var(--border))]" />
            </div>
            <div className="relative flex justify-center">
              <span className="px-3 text-xs text-[hsl(var(--foreground-subtle))] bg-[hsl(var(--surface-1))]">
                or continue with
              </span>
            </div>
          </div>

          {/* Google OAuth Button — intent changes based on active tab */}
          <button
            onClick={handleGoogleOAuth}
            disabled={isGoogleLoading}
            className={cn(
              'w-full py-2.5 px-4 rounded-md font-medium text-sm',
              'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))]',
              'hover:bg-[hsl(var(--surface-3))] transition-colors',
              'flex items-center justify-center gap-2',
              'disabled:opacity-60 disabled:cursor-not-allowed',
            )}
          >
            {isGoogleLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Redirecting to Google…
              </>
            ) : (
              <>
                <ExternalLink className="w-4 h-4" />
                {mode === 'register' ? 'Register with Google' : 'Sign in with Google'}
              </>
            )}
          </button>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-[hsl(var(--foreground-subtle))] mt-6">
          SentinelTrace — Secure SOC access only. All activity is audited.
        </p>
      </div>
    </div>
  );
}
