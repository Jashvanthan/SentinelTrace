import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo, mockUser } from './helpers/mock-api';

test.describe('Navigation and AppShell Component Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Sidebar collapse and expand buttons work correctly', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const aside = page.locator('aside.hidden.md\\:flex');
    await expect(aside.getByText('SentinelTrace')).toBeVisible();

    // Find the toggle button on the aside element (has chevron icon)
    const toggleButton = page.locator('aside.hidden.md\\:flex button.absolute');
    await expect(toggleButton).toBeVisible();

    // Click to collapse
    await toggleButton.click();
    await expect(aside).toHaveClass(/w-16/);

    // Click to expand
    await toggleButton.click();
    await expect(aside).toHaveClass(/w-60/);
    await expect(aside.getByText('SentinelTrace')).toBeVisible();
  });

  test('Workspace selector dropdown updates active workspace', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const wsSelect = page.locator('header select');
    await expect(wsSelect).toBeVisible();
    await expect(wsSelect).toHaveValue('1');

    // Switch workspace to IR Alpha (ID 2)
    await wsSelect.selectOption('2');
    await expect(wsSelect).toHaveValue('2');
  });

  test('Sidebar navigation links route to all primary pages and placeholders', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const sidebar = page.locator('aside.hidden.md\\:flex');

    // 1. Investigate
    await sidebar.getByRole('link', { name: 'Investigate', exact: true }).click();
    await expect(page).toHaveURL(/.*\/investigate/);
    await expect(page.getByRole('heading', { name: 'Email Analysis' })).toBeVisible();

    // 2. Threat Intel
    await sidebar.getByRole('link', { name: 'Threat Intel', exact: true }).click();
    await expect(page).toHaveURL(/.*\/intel/);
    await expect(page.getByRole('heading', { name: 'Threat Intelligence' })).toBeVisible();

    // 3. Campaigns
    await sidebar.getByRole('link', { name: 'Campaigns', exact: true }).click();
    await expect(page).toHaveURL(/.*\/campaigns/);
    await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible();

    // 4. Geolocation
    await sidebar.getByRole('link', { name: 'Geolocation', exact: true }).click();
    await expect(page).toHaveURL(/.*\/geo/);
    await expect(page.getByRole('heading', { name: 'Infrastructure Geolocation' })).toBeVisible();

    // 5. Reports
    await sidebar.getByRole('link', { name: 'Reports', exact: true }).click();
    await expect(page).toHaveURL(/.*\/reports/);
    await expect(page.getByRole('heading', { name: /Reports/i })).toBeVisible();

    // 6. Activity Log
    await sidebar.getByRole('link', { name: 'Activity Log', exact: true }).click();
    await expect(page).toHaveURL(/.*\/activity/);
    await expect(page.getByRole('heading', { name: 'Activity Log' })).toBeVisible();

    // 7. Admin: Settings
    await sidebar.getByRole('link', { name: 'Settings', exact: true }).click();
    await expect(page).toHaveURL(/.*\/settings/);
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();

    // 8. Admin: Integrations
    await sidebar.getByRole('link', { name: 'Integrations', exact: true }).click();
    await expect(page).toHaveURL(/.*\/integrations/);
    await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();

    // 9. Return to Dashboard
    await sidebar.getByRole('link', { name: 'Dashboard', exact: true }).click();
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
  });

  test('Logout button logs out and redirects user to /login', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Click logout button in user profile area
    const logoutBtn = page.locator('aside.hidden.md\\:flex button[title="Log Out"]');
    await expect(logoutBtn).toBeVisible();
    await logoutBtn.click();

    // Should redirect to /login
    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  });
});
