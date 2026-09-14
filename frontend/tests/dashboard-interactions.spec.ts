import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Dashboard UI & Button Functionality Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Renders security overview metrics, score ring, and live feeds', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Header & workspace name
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
    await expect(page.locator('main').getByText(/Primary SOC Team/)).toBeVisible();

    // Verify stat cards
    await expect(page.getByText('Emails Scanned')).toBeVisible();
    await expect(page.getByText('1248')).toBeVisible();

    await expect(page.getByText('Threats Detected')).toBeVisible();
    await expect(page.getByText('42', { exact: true })).toBeVisible();

    await expect(page.getByText('Active Campaigns').first()).toBeVisible();
    await expect(page.getByText('4', { exact: true })).toBeVisible();

    await expect(page.getByText('Avg Threat Score')).toBeVisible();
    await expect(page.getByText('76.4')).toBeVisible();

    await expect(page.getByText('Workspace Risk', { exact: true })).toBeVisible();
    await expect(page.getByText('82.0')).toBeVisible();

    await expect(page.getByText('High/Critical IOCs')).toBeVisible();
    await expect(page.getByText('19').first()).toBeVisible();

    // Verify Recent Analyses Feed and Active Campaigns section
    await expect(page.getByRole('heading', { name: 'Recent Analyses' })).toBeVisible();
    await expect(page.getByText('URGENT: Payroll Account Verification Required').first()).toBeVisible();
    await expect(page.getByText('Q3 Financial Spoofing Cluster')).toBeVisible();

    // Threat Category Distribution
    await expect(page.getByText('Threat Category Distribution')).toBeVisible();
    await expect(page.getByText('Credential Harvesting', { exact: true })).toBeVisible();
  });

  test('Analyze Email CTA button navigates to email analysis upload page', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const analyzeBtn = page.getByRole('link', { name: 'Analyze Email' });
    await expect(analyzeBtn).toBeVisible();
    await analyzeBtn.click();

    await expect(page).toHaveURL(/.*\/emails/);
    await expect(page.getByRole('heading', { name: 'Email Analysis' })).toBeVisible();
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
