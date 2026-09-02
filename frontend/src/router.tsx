// SentinelTrace Frontend — App Router

import { lazy, Suspense } from 'react';
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { LoginPage } from '@/pages/LoginPage';

// Lazy-loaded pages
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const EmailAnalysisPage = lazy(() => import('@/pages/EmailAnalysisPage').then((m) => ({ default: m.EmailAnalysisPage })));
const EmailDetailPage = lazy(() => import('@/pages/EmailDetailPage').then((m) => ({ default: m.EmailDetailPage })));
const ThreatIntelPage = lazy(() => import('@/pages/ThreatIntelPage').then((m) => ({ default: m.ThreatIntelPage })));
const CampaignGraphPage = lazy(() => import('@/pages/CampaignGraphPage').then((m) => ({ default: m.CampaignGraphPage })));
const IntegrationsPage = lazy(() => import('@/pages/IntegrationsPage').then((m) => ({ default: m.IntegrationsPage })));

// Placeholder pages for remaining sections
const PlaceholderPage = ({ title }: { title: string }) => (
  <div className="flex flex-col items-center justify-center h-64 gap-4">
    <div className="text-4xl opacity-30">🔒</div>
    <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">{title}</h2>
    <p className="text-sm text-[hsl(var(--foreground-muted))]">Coming soon</p>
  </div>
);

const PageLoader = () => (
  <div className="flex items-center justify-center h-64">
    <div className="w-8 h-8 border-2 border-[hsl(var(--accent))] border-t-transparent rounded-full animate-spin" />
  </div>
);

const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <Navigate to="/dashboard" replace /> },
          {
            path: 'dashboard',
            element: (
              <Suspense fallback={<PageLoader />}>
                <DashboardPage />
              </Suspense>
            ),
          },
          {
            path: 'emails',
            element: (
              <Suspense fallback={<PageLoader />}>
                <EmailAnalysisPage />
              </Suspense>
            ),
          },
          {
            path: 'emails/:id',
            element: (
              <Suspense fallback={<PageLoader />}>
                <EmailDetailPage />
              </Suspense>
            ),
          },
          {
            path: 'intel',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ThreatIntelPage />
              </Suspense>
            ),
          },
          {
            path: 'graph',
            element: (
              <Suspense fallback={<PageLoader />}>
                <CampaignGraphPage />
              </Suspense>
            ),
          },
          {
            path: 'forensics',
            element: <PlaceholderPage title="Digital Forensics" />,
          },
          {
            path: 'geo',
            element: <PlaceholderPage title="Infrastructure Geolocation" />,
          },
          {
            path: 'reports',
            element: <PlaceholderPage title="Evidence Reports" />,
          },
          {
            path: 'activity',
            element: <PlaceholderPage title="Activity Log" />,
          },
          {
            path: 'settings',
            element: <PlaceholderPage title="Settings" />,
          },
          {
            path: 'integrations',
            element: (
              <Suspense fallback={<PageLoader />}>
                <IntegrationsPage />
              </Suspense>
            ),
          },
        ],
      },
    ],
  },
  {
    path: '*',
    element: (
      <div className="min-h-screen bg-[hsl(var(--background))] flex flex-col items-center justify-center gap-4">
        <h1 className="text-5xl font-bold text-[hsl(var(--foreground-subtle))]">404</h1>
        <p className="text-[hsl(var(--foreground-muted))]">Page not found</p>
        <a href="/dashboard" className="text-sm text-[hsl(var(--accent))] hover:underline">Go to Dashboard</a>
      </div>
    ),
  },
]);

export function AppRouter() {
  return <RouterProvider router={router} />;
}
