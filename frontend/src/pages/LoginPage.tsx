// SentinelTrace Frontend — Login Page

import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Eye, EyeOff, ExternalLink } from 'lucide-react';
import { useLogin } from '@/api/hooks';
import { useAuthStore, useNotificationStore } from '@/store';
import apiClient, { setAccessToken } from '@/lib/api';
import { cn } from '@/utils';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const login = useLogin();
  const { setAuth } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const notify = useNotificationStore((s) => s.addNotification);

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';

  useEffect(() => {
    const search = location.search || (location.state as any)?.from?.search || '';
    if (search.includes('google_auth=success')) {
      apiClient.post('/auth/refresh')
        .then((res) => {
          setAuth(res.data.user, res.data.access_token);
          setAccessToken(res.data.access_token);
          navigate(from, { replace: true });
        })
        .catch((err) => {
          notify({
            type: 'error',
            title: 'OAuth Error',
            description: 'Failed to complete Google authentication',
          });
          navigate('/login', { replace: true });
        });
    }
  }, [location, from, navigate, notify, setAuth]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    try {
      const data = await login.mutateAsync({ email, password });
      setAuth(data.user, data.access_token);
      setAccessToken(data.access_token);
      navigate(from, { replace: true });
    } catch (err: any) {
      notify({
        type: 'error',
        title: 'Login failed',
        description: err?.response?.data?.detail || 'Invalid credentials',
      });
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const response = await fetch(`${(import.meta as any).env?.VITE_API_URL || 'http://localhost:8000/api/v1'}/auth/google`);
      if (!response.ok) throw new Error('Failed to initialize Google login');
      const data = await response.json();
      window.location.href = data.authorization_url;
    } catch (err: any) {
      notify({
        type: 'error',
        title: 'Google Login Error',
        description: err.message || 'Failed to start Google OAuth flow',
      });
    }
  };

  return (
    <div className="min-h-screen bg-[hsl(var(--background))] grid-pattern flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[hsl(var(--accent))] mb-4">
            <Shield className="w-9 h-9 text-[hsl(var(--accent-foreground))]" />
          </div>
          <h1 className="text-2xl font-bold text-[hsl(var(--foreground))] tracking-tight">
            SentinelTrace
          </h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-1">
            AI-Assisted Threat Intelligence Platform
          </p>
        </div>

        {/* Form Card */}
        <div className="glass rounded-xl p-8 shadow-2xl">
          <h2 className="text-lg font-semibold text-[hsl(var(--foreground))] mb-6">Sign in</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5"
              >
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2.5 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                           rounded-md text-sm text-[hsl(var(--foreground))]
                           placeholder-[hsl(var(--foreground-subtle))]
                           focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                placeholder="analyst@example.com"
              />
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-[hsl(var(--foreground-muted))] mb-1.5"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-3 py-2.5 pr-10 bg-[hsl(var(--surface-2))] border border-[hsl(var(--border))]
                             rounded-md text-sm text-[hsl(var(--foreground))]
                             placeholder-[hsl(var(--foreground-subtle))]
                             focus:border-[hsl(var(--accent)/0.6)] focus:outline-none transition-colors"
                  placeholder="••••••••"
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
              disabled={login.isPending}
              className={cn(
                'w-full py-2.5 px-4 rounded-md font-medium text-sm',
                'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]',
                'hover:bg-[hsl(var(--accent-hover))] transition-colors',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                'flex items-center justify-center gap-2'
              )}
            >
              {login.isPending ? (
                <>
                  <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  Signing in…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

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

          {/* Google OAuth */}
          <button
            onClick={handleGoogleLogin}
            className={cn(
              'w-full py-2.5 px-4 rounded-md font-medium text-sm',
              'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground))] border border-[hsl(var(--border))]',
              'hover:bg-[hsl(var(--surface-3))] transition-colors',
              'flex items-center justify-center gap-2'
            )}
          >
            <ExternalLink className="w-4 h-4" />
            Google
          </button>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-[hsl(var(--foreground-subtle))] mt-6">
          SentinelTrace — Secure access only. All activity is audited.
        </p>
      </div>
    </div>
  );
}
