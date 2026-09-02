// SentinelTrace Frontend — Protected Route

import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/store';
import type { UserRole } from '@/types';

interface ProtectedRouteProps {
  allowedRoles?: UserRole[];
}

export function ProtectedRoute({ allowedRoles }: ProtectedRouteProps) {
  const { isAuthenticated, user } = useAuthStore();
  const location = useLocation();

  if (!isAuthenticated || !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <div className="text-[hsl(var(--critical))] text-5xl">⛔</div>
        <h2 className="text-xl font-semibold text-[hsl(var(--foreground))]">Access Denied</h2>
        <p className="text-[hsl(var(--foreground-muted))]">
          You don't have permission to access this page.
        </p>
      </div>
    );
  }

  return <Outlet />;
}
