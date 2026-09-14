import { test, expect } from '@playwright/test';

test.describe('SentinelTrace E2E Smoke Tests', () => {
  
  test.beforeEach(async ({ page }) => {
    // Mock the auth endpoint so we can login without relying on the backend state
    await page.route('**/api/v1/auth/login', async route => {
      const json = { access_token: 'fake-jwt-token', token_type: 'bearer', user: { id: '1', email: 'test@example.com', full_name: 'Test User' } };
      await route.fulfill({ json });
    });

    // Mock the current user endpoint
    await page.route('**/api/v1/users/me', async route => {
      const json = { id: 1, email: 'test@example.com', full_name: 'Test User' };
      await route.fulfill({ json });
    });

    // Mock the workspaces list
    await page.route('**/api/v1/workspaces', async route => {
      const json = [{ id: 1, name: 'Default Workspace', role: 'owner' }];
      await route.fulfill({ json });
    });

    // Mock the stats endpoint for the dashboard
    await page.route('**/api/v1/workspaces/1/stats', async route => {
      const json = {
        total_emails: 42,
        critical_threats: 5,
        active_campaigns: 2,
        risk_score: 85.5
      };
      await route.fulfill({ json });
    });
    
    // Mock the recent threats endpoint for the dashboard
    await page.route('**/api/v1/workspaces/1/threats?limit=5', async route => {
      const json = []; // empty threats list for simplicity
      await route.fulfill({ json });
    });
  });

  test('successfully login and view dashboard', async ({ page }) => {
    await page.goto('/');

    // Check that we are redirected to login
    await expect(page).toHaveURL(/.*login/);
    await expect(page.getByRole('heading', { name: /SentinelTrace/i })).toBeVisible();

    // Fill in login form
    await page.getByLabel('Email').fill('test@example.com');
    await page.getByLabel(/Password/i).fill('password123');
    await page.locator('form button[type="submit"]').click();

    // Verify we reach the dashboard
    await expect(page).toHaveURL('/');
    
    // Check that the dashboard metrics load (using mocked data)
    await expect(page.getByText('42')).toBeVisible();
  });
});
