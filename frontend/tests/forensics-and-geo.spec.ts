import { test, expect } from '@playwright/test';
import { loginAndNavigateTo } from './helpers/mock-api';

test.describe('Forensics, Geolocation, and Campaign Graph Verification', () => {
  test('Geolocation page opens with full interactive telemetry and not coming soon', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Click Geolocation link in sidebar
    await page.getByRole('link', { name: 'Geolocation', exact: true }).click();

    // Verify heading and content are visible
    await expect(page.getByRole('heading', { name: /Infrastructure Geolocation/i })).toBeVisible();
    await expect(page.getByText('Coming soon')).not.toBeVisible();

    // Verify search input and preset buttons
    const searchInput = page.getByPlaceholder(/Enter IPv4 or IPv6 address/i);
    await expect(searchInput).toBeVisible();
    await expect(page.getByRole('button', { name: /Trace IP Telemetry/i })).toBeVisible();
    await expect(page.getByText('Quick Reference Targets:')).toBeVisible();

    // Test clicking a quick lookup chip
    await page.getByRole('button', { name: /1.1.1.1/i }).click();
    await expect(searchInput).toHaveValue('1.1.1.1');
  });

  test('Digital Forensics page opens with full workbench and not coming soon', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Click Evidence / Forensics link in sidebar
    await page.getByRole('link', { name: 'Evidence', exact: true }).click();

    // Verify heading and content are visible
    await expect(page.getByRole('heading', { name: /Forensic Evidence/i })).toBeVisible();
    await expect(page.getByText('Coming soon')).not.toBeVisible();

    // Verify sections
    await expect(page.getByRole('heading', { name: 'Risk Assessment' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Ledger Anchoring Status' })).toBeVisible();
  });

  test('Campaign Graph loads cleanly without Campaign Data Error', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Click Campaigns link in sidebar
    await page.getByRole('link', { name: 'Campaigns', exact: true }).click();

    // Verify heading
    await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible();

    // Ensure Campaign Data Error is NOT present
    await expect(page.getByText('Campaign Data Error')).not.toBeVisible();

    // Depth controls are active
    await expect(page.getByText('Depth:')).toBeVisible();
    await expect(page.getByRole('button', { name: '1', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '4', exact: true })).toBeVisible();
  });
});
