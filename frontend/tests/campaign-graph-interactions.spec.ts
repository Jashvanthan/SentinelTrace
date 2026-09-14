import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Campaign Graph & Investigation Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Campaign graph depth controls, refresh button, and legend render properly', async ({ page }) => {
    await loginAndNavigateTo(page, '/graph');

    await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible();

    // Depth buttons (1, 2, 3, 4)
    const depth3Btn = page.getByRole('button', { name: '3', exact: true });
    await expect(depth3Btn).toBeVisible();
    await depth3Btn.click();
    await expect(depth3Btn).toHaveClass(/bg-\[hsl\(var\(--accent\)\)\]/);

    const depth1Btn = page.getByRole('button', { name: '1', exact: true });
    await expect(depth1Btn).toBeVisible();
    await depth1Btn.click();
    await expect(depth1Btn).toHaveClass(/bg-\[hsl\(var\(--accent\)\)\]/);

    // Refresh button
    const refreshBtn = page.locator('main button:has(svg.lucide-refresh-cw)');
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Investigation Panel container is visible
    await expect(page.getByText('Investigation Panel')).toBeVisible();

    // Legend items
    await expect(page.getByText('Email', { exact: true })).toBeVisible();
    await expect(page.getByText('Sender', { exact: true })).toBeVisible();
    await expect(page.getByText('Domain', { exact: true })).toBeVisible();
  });
});
