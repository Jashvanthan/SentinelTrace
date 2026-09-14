import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo, mockUser } from './helpers/mock-api';

test.describe('Navigation and AppShell Component Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Sidebar collapse and expand buttons work correctly', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Initially sidebar is expanded
    await expect(page.locator('aside').getByText('SentinelTrace')).toBeVisible();
    await expect(page.getByText(mockUser.full_name)).toBeVisible();

    // Find the toggle button on the aside element (has chevron icon)
    const toggleButton = page.locator('aside button.absolute');
    await expect(toggleButton).toBeVisible();

    // Click to collapse
    await toggleButton.click();
    await expect(page.locator('aside').getByText('SentinelTrace')).not.toBeVisible();
    await expect(page.getByText(mockUser.full_name)).not.toBeVisible();

    // Click to expand
    await toggleButton.click();
    await expect(page.locator('aside').getByText('SentinelTrace')).toBeVisible();
    await expect(page.getByText(mockUser.full_name)).toBeVisible();
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

    // 1. Email Analysis
    await page.getByRole('link', { name: 'Email Analysis', exact: true }).click();
    await expect(page).toHaveURL(/.*\/emails/);
    await expect(page.getByRole('heading', { name: 'Email Analysis' })).toBeVisible();

    // 2. Threat Intel
    await page.getByRole('link', { name: 'Threat Intel', exact: true }).click();
    await expect(page).toHaveURL(/.*\/intel/);
    await expect(page.getByRole('heading', { name: 'Threat Intelligence' })).toBeVisible();

    // 3. Campaign Graph
    await page.getByRole('link', { name: 'Campaign Graph', exact: true }).click();
    await expect(page).toHaveURL(/.*\/graph/);
    await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible();

    // 4. Placeholders: Forensics
    await page.getByRole('link', { name: 'Forensics', exact: true }).click();
    await expect(page).toHaveURL(/.*\/forensics/);
    await expect(page.getByRole('heading', { name: 'Digital Forensics' })).toBeVisible();

    // 5. Geolocation
    await page.getByRole('link', { name: 'Geolocation', exact: true }).click();
    await expect(page).toHaveURL(/.*\/geo/);
    await expect(page.getByRole('heading', { name: 'Infrastructure Geolocation' })).toBeVisible();

    // 6. Reports
    await page.getByRole('link', { name: 'Reports', exact: true }).click();
    await expect(page).toHaveURL(/.*\/reports/);
    await expect(page.getByRole('heading', { name: 'Evidence Reports' })).toBeVisible();

    // 7. Activity Log
    await page.getByRole('link', { name: 'Activity Log', exact: true }).click();
    await expect(page).toHaveURL(/.*\/activity/);
    await expect(page.getByRole('heading', { name: 'Activity Log' })).toBeVisible();

    // 8. Admin: Settings
    await page.getByRole('link', { name: 'Settings', exact: true }).click();
    await expect(page).toHaveURL(/.*\/settings/);
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();

    // 9. Admin: Integrations
    await page.getByRole('link', { name: 'Integrations', exact: true }).click();
    await expect(page).toHaveURL(/.*\/integrations/);
    await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();

    // 10. Return to Dashboard
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
  });

  test('Logout button logs out and redirects user to /login', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Click logout button in user profile area
    const logoutBtn = page.getByRole('button', { name: 'Logout' });
    await expect(logoutBtn).toBeVisible();
    await logoutBtn.click();

    // Should redirect to /login
    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.getByRole('heading', { name: /SentinelTrace/i })).toBeVisible();
  });
});
