import { test, expect } from '@playwright/test';
import { setupStandardApiMocks } from './helpers/mock-api';

test('Live E2E: Login, Dashboard, Forensics, Geolocation, and Campaign Graph', async ({ page }) => {
  await setupStandardApiMocks(page);

  // 1. Visit live login page
  await page.goto('http://localhost:5173/login');
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();

  // 2. Fill in login form
  await page.getByLabel('Email').fill('analyst@sentineltrace.io');
  await page.getByLabel(/Password/i).fill('StrongPassword123!');

  // 3. Click Sign In
  const submitBtn = page.locator('form button[type="submit"]');
  await submitBtn.click();

  // 4. Verify landing on Dashboard
  await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible({ timeout: 10000 });

  // 5. Navigate to Geolocation page
  await page.getByRole('link', { name: 'Geolocation', exact: true }).click();
  await expect(page).toHaveURL(/.*geo/);
  await expect(page.getByRole('heading', { name: 'Infrastructure Geolocation' })).toBeVisible();
  await expect(page.getByText('Coming soon')).not.toBeVisible();
  await expect(page.getByRole('button', { name: /Trace IP Telemetry/i })).toBeVisible();

  // 6. Navigate to Evidence / Forensics page
  await page.getByRole('link', { name: 'Evidence', exact: true }).click();
  await expect(page).toHaveURL(/.*(evidence|forensics)/);
  await expect(page.getByRole('heading', { name: /Forensic Evidence/i })).toBeVisible();
  await expect(page.getByText('Coming soon')).not.toBeVisible();

  // 7. Navigate to Campaigns / Graph page
  await page.getByRole('link', { name: 'Campaigns', exact: true }).click();
  await expect(page).toHaveURL(/.*(campaigns|graph)/);
  await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible({ timeout: 15000 });
  await expect(page.getByText('Campaign Data Error')).not.toBeVisible();
});
