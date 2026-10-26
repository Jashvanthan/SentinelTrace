// SentinelTrace Frontend — Login & Registration Page
// Strict Google OAuth: Login (existing accounts) vs Register (new accounts)

import { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
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

  // Parse URL params on mount — handles OAuth callbacks
  useEffect(() => {
    const search = location.search || '';
    const params = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);

    // ── Session Expired Alert ──
    if (params.get('reason') === 'session_expired') {
      setFormError('Your session has expired after 24 hours for security. Please sign in again.');
    }

    // ── Case 1: Existing Google user → login success ──
    if (params.has('google_auth') && params.get('google_auth') === 'success') {
      const directToken = params.get('token');
      if (directToken) {
        setAccessToken(directToken);
        apiClient
          .get('/auth/me', {
            headers: { Authorization: `Bearer ${directToken}` },
          })
          .then((res) => {
            setAuth(res.data, directToken);
            setAccessToken(directToken);
            navigate('/dashboard', { replace: true });
          })
          .catch(() => {
            setFormError('Google sign-in succeeded, but profile could not be loaded. Please try again.');
            navigate('/login', { replace: true });
          });
        return;
      }

      apiClient
        .post('/auth/refresh')
        .then((res) => {
          setAuth(res.data.user, res.data.access_token, res.data.session_expires_in);
          setAccessToken(res.data.access_token);
          navigate('/dashboard', { replace: true });
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
      const detail = params.get('detail') || params.get('reason');
      let msg = 'Google authentication could not be completed. Please try again.';
      if (detail) {
        msg = `Google authentication failed: ${decodeURIComponent(detail)}`;
      } else if (errorType === 'cookie_missing') {
        msg = 'OAuth session cookie missing. Please enable cookies and try again.';
      }
      setFormError(msg);
      navigate('/login', { replace: true });
    }
  }, [location, navigate, setAuth, notify]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (!email || !password) {
      setFormError('Please fill in both email and password.');
      return;
    }

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      const netMsg = 'Network issue. Please check your internet connection.';
      setFormError(netMsg);
      notify({ type: 'error', title: 'Network Issue', description: netMsg });
      return;
    }

    if (mode === 'login') {
      try {
        const data: any = await login.mutateAsync({ email, password });
        setAuth(data.user, data.access_token, data.session_expires_in);
        setAccessToken(data.access_token);
        navigate('/dashboard', { replace: true });
      } catch (err: any) {
        const isNetworkErr =
          (typeof navigator !== 'undefined' && !navigator.onLine) ||
          err?.code === 'ERR_NETWORK' ||
          err?.message?.includes('Network Error') ||
          err?.message?.includes('Failed to fetch') ||
          err?.code === 'ECONNABORTED';

        if (isNetworkErr) {
          const netMsg = 'Network issue. Please check your internet connection.';
          setFormError(netMsg);
          notify({ type: 'error', title: 'Network Issue', description: netMsg });
          return;
        }

        if (err?.response?.status === 401 || err?.response?.status === 400) {
          const credMsg = 'Incorrect username or password';
          setFormError(credMsg);
          notify({ type: 'error', title: 'Login Failed', description: credMsg });
          return;
        }

        const msg = extractErrorMessage(err, 'Incorrect username or password');
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
        setAuth(data.user, data.access_token, data.session_expires_in);
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

        navigate('/dashboard', { replace: true });
      } catch (err: any) {
        const msg = extractErrorMessage(err, 'Registration failed. The email may already be registered.');
        setFormError(msg);
        notify({ type: 'error', title: 'Registration Failed', description: msg });
      }
    }
  };

  // Initiates Google OAuth with correct intent based on active tab
  const handleGoogleOAuth = async (e?: React.MouseEvent) => {
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }

    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      const netMsg = 'Network issue. Please check your internet connection.';
      setFormError(netMsg);
      notify({ type: 'error', title: 'Network Issue', description: netMsg });
      return;
    }

    try {
      setIsGoogleLoading(true);
      setFormError(null);
      const intent = mode === 'register' ? 'register' : 'login';
      const { data } = await apiClient.get<{ authorization_url: string; state: string }>(
        `/auth/google?intent=${intent}`
      );
      if (!data?.authorization_url) {
        throw new Error('Google OAuth service is currently unreachable. Please try again.');
      }
      // window.location.assign ensures clean navigation on mobile iOS and Android webviews
      window.location.assign(data.authorization_url);
    } catch (err: any) {
      setIsGoogleLoading(false);
      const isNetworkErr =
        (typeof navigator !== 'undefined' && !navigator.onLine) ||
        err?.code === 'ERR_NETWORK' ||
        err?.message?.includes('Network Error') ||
        err?.message?.includes('Failed to fetch') ||
        err?.code === 'ECONNABORTED';

      const msg = isNetworkErr
        ? 'Network issue. Please check your internet connection.'
        : extractErrorMessage(err, 'Failed to start Google sign-in. Please try again or use email login.');
      setFormError(msg);
      notify({
        type: 'error',
        title: isNetworkErr ? 'Network Issue' : 'Google OAuth Error',
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
      const { data } = await apiClient.post<any>('/auth/google/complete-registration', {
        pending_token: googlePending.pendingToken,
      });

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
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      const detail = extractErrorMessage(err, 'Google registration could not be completed.');
      if (detail.toLowerCase().includes('expired')) {
        setFormError('Your Google registration session has expired. Please try again.');
      } else if (detail.toLowerCase().includes('already registered')) {
        setFormError('This Google account is already registered. Please sign in instead.');
        setMode('login');
      } else {
        setFormError(detail);
      }
      setGooglePending(null);
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
                {mode === 'login' && (
                  <div className="flex justify-end mt-1.5">
                    <Link to="/forgot-password" className="text-xs text-[hsl(var(--accent))] hover:underline">
                      Forgot Password?
                    </Link>
                  </div>
                )}
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

          {/* Google OAuth Button — touch-optimized for mobile & desktop */}
          <button
            type="button"
            onClick={handleGoogleOAuth}
            disabled={isGoogleLoading}
            className={cn(
              'w-full min-h-[44px] py-3 px-4 rounded-md font-medium text-sm',
              'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))]',
              'hover:bg-[hsl(var(--surface-3))] active:scale-[0.99] transition-all touch-manipulation',
              'flex items-center justify-center gap-3 shadow-sm',
              'disabled:opacity-60 disabled:cursor-not-allowed',
            )}
          >
            {isGoogleLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-[hsl(var(--accent))]" />
                <span>Redirecting to Google…</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>{mode === 'register' ? 'Register with Google' : 'Sign in with Google'}</span>
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
