// SentinelTrace Frontend — Canonical App Router

import { lazy, Suspense } from 'react';
import { createBrowserRouter, RouterProvider, Navigate, Link } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { LoginPage } from '@/pages/LoginPage';

// Lazy-loaded SOC pages
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const EmailAnalysisPage = lazy(() => import('@/pages/EmailAnalysisPage').then((m) => ({ default: m.EmailAnalysisPage })));
const EmailDetailPage = lazy(() => import('@/pages/EmailDetailPage').then((m) => ({ default: m.EmailDetailPage })));
const ThreatIntelPage = lazy(() => import('@/pages/ThreatIntelPage').then((m) => ({ default: m.ThreatIntelPage })));
const CampaignGraphPage = lazy(() => import('@/pages/CampaignGraphPage').then((m) => ({ default: m.CampaignGraphPage })));
const ForensicsPage = lazy(() => import('@/pages/ForensicsPage').then((m) => ({ default: m.ForensicsPage })));
const GeolocationPage = lazy(() => import('@/pages/GeolocationPage').then((m) => ({ default: m.GeolocationPage })));
const ReportsPage = lazy(() => import('@/pages/ReportsPage').then((m) => ({ default: m.ReportsPage })));
const ActivityLogPage = lazy(() => import('@/pages/ActivityLogPage').then((m) => ({ default: m.ActivityLogPage })));
const IntegrationsPage = lazy(() => import('@/pages/IntegrationsPage').then((m) => ({ default: m.IntegrationsPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));

const PageLoader = () => (
  <div className="flex flex-col items-center justify-center h-64 gap-3">
    <div className="w-8 h-8 border-2 border-[#3b82f6] border-t-transparent rounded-full animate-spin" />
    <span className="text-xs text-[#94a3b8] font-mono">Loading SentinelTrace telemetry…</span>
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

          // Investigate & Email Analysis
          {
            path: 'investigate',
            element: (
              <Suspense fallback={<PageLoader />}>
                <EmailAnalysisPage />
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

          // Cases redirect
          {
            path: 'cases',
            element: <Navigate to="/investigate" replace />,
          },
          {
            path: 'cases/:id',
            element: (
              <Suspense fallback={<PageLoader />}>
                <EmailDetailPage />
              </Suspense>
            ),
          },

          // Threat Intel
          {
            path: 'intel',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ThreatIntelPage />
              </Suspense>
            ),
          },

          // Campaigns & Graph
          {
            path: 'campaigns',
            element: (
              <Suspense fallback={<PageLoader />}>
                <CampaignGraphPage />
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

          // Evidence & Forensics
          {
            path: 'evidence',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ForensicsPage />
              </Suspense>
            ),
          },
          {
            path: 'forensics',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ForensicsPage />
              </Suspense>
            ),
          },

          // Geolocation & Network Trace
          {
            path: 'geo',
            element: (
              <Suspense fallback={<PageLoader />}>
                <GeolocationPage />
              </Suspense>
            ),
          },

          // Reports
          {
            path: 'reports',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ReportsPage />
              </Suspense>
            ),
          },

          // Utility & Supporting SOC Areas
          {
            path: 'activity',
            element: (
              <Suspense fallback={<PageLoader />}>
                <ActivityLogPage />
              </Suspense>
            ),
          },
          {
            path: 'settings',
            element: (
              <Suspense fallback={<PageLoader />}>
                <SettingsPage />
              </Suspense>
            ),
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
      <div className="min-h-screen bg-[#090d16] flex flex-col items-center justify-center gap-4 text-center p-6">
        <span className="text-6xl font-extrabold text-[#232e42] font-mono">404</span>
        <h1 className="text-xl font-bold text-white tracking-tight">SOC Route Not Found</h1>
        <p className="text-xs text-[#94a3b8] max-w-sm font-mono">
          The requested investigation or system route is unavailable or restricted.
        </p>
        <Link
          to="/dashboard"
          className="mt-2 px-4 py-2 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded transition-colors font-mono"
        >
          Return to SOC Dashboard
        </Link>
      </div>
    ),
  },
]);

export function AppRouter() {
  return <RouterProvider router={router} />;
}
