import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Dashboard UI & Button Functionality Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Renders security overview metrics, score ring, and live feeds', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Header
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();

    // Verify stat cards
    await expect(page.getByText('EMAILS ANALYZED')).toBeVisible();
    await expect(page.getByText('1,248')).toBeVisible();

    await expect(page.getByText('THREATS DETECTED')).toBeVisible();
    await expect(page.getByText('42', { exact: true })).toBeVisible();

    await expect(page.getByText('CRITICAL CASES')).toBeVisible();
    await expect(page.getByText('AVG RISK SCORE')).toBeVisible();

    // Verify Active Investigations Table
    await expect(page.getByRole('heading', { name: 'Active Investigations' })).toBeVisible();
    await expect(page.getByText('URGENT: Payroll Account Verification Required').first()).toBeVisible();

    // Risk Distribution
    await expect(page.getByRole('heading', { name: 'Risk Distribution' })).toBeVisible();
    await expect(page.getByText('CRITICAL', { exact: true })).toBeVisible();
  });

  test('New Investigation CTA button navigates to email analysis upload page', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const investigateBtn = page.locator('aside.hidden.md\\:flex button', { hasText: 'New Investigation' });
    await expect(investigateBtn).toBeVisible();
    await investigateBtn.click();

    await expect(page).toHaveURL(/.*\/investigate/);
    await expect(page.getByRole('heading', { name: /Email Analysis/i })).toBeVisible();
  });

  test('Live email feed item click navigates to analysis details', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const feedItem = page.getByText('URGENT: Payroll Account Verification Required').first();
    await expect(feedItem).toBeVisible();
    await feedItem.click();

    await expect(page).toHaveURL(/.*\/emails\/analysis-001/);
    await expect(page.getByRole('heading', { name: 'URGENT: Payroll Account Verification Required' })).toBeVisible();
  });
});
