import { test, expect } from '@playwright/test';
import { setupStandardApiMocks } from './helpers/mock-api';

test.describe('SentinelTrace E2E Smoke Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('successfully login and view dashboard', async ({ page }) => {
    await page.goto('/login');

    // Check that we are on the login page
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

    // Fill in login form
    await page.getByLabel('Email').fill('analyst@sentineltrace.io');
    await page.getByLabel(/Password/i).fill('StrongPassword123!');
    await page.locator('form button[type="submit"]').click();

    // Verify we reach the dashboard
    await expect(page).toHaveURL(/.*dashboard|\//);
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
    await expect(page.getByText('1,248')).toBeVisible();
  });
});
