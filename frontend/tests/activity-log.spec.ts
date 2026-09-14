import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Activity & Audit Log Page Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Navigate to Activity Log page and verify telemetry cards, filters, and records', async ({ page }) => {
    await loginAndNavigateTo(page, '/activity');
    await expect(page).toHaveURL(/.*\/activity/);

    // Verify main header
    await expect(page.getByRole('heading', { name: /Security & Activity Log/i })).toBeVisible();
    await expect(page.getByText(/Live Audit Stream/i)).toBeVisible();

    // Verify KPI summary cards
    await expect(page.getByText(/Total Audited Events/i)).toBeVisible();
    await expect(page.getByText(/Successful Actions/i)).toBeVisible();
    await expect(page.getByText(/Errors \/ Denials/i)).toBeVisible();
    await expect(page.getByText(/Distinct Operators/i)).toBeVisible();

    // Verify Refresh and Export buttons exist
    const refreshBtn = page.getByRole('button', { name: /Refresh/i });
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    const exportBtn = page.getByRole('button', { name: /Export JSON/i });
    await expect(exportBtn).toBeVisible();

    // Verify search input
    const searchInput = page.getByPlaceholder(/Search action, actor, IP, or resource/i);
    await expect(searchInput).toBeVisible();
    await searchInput.fill('LOGIN');

    // Verify page filters (within main content area)
    const pageSelects = page.locator('main select');
    await expect(pageSelects).toHaveCount(2);

    // Filter by outcome
    await pageSelects.first().selectOption('SUCCESS');

    // Filter by category
    await pageSelects.nth(1).selectOption('LOGIN');

    // Verify details button works if rows exist
    const detailsButtons = page.getByRole('button', { name: /Details/i });
    const count = await detailsButtons.count();
    if (count > 0) {
      await detailsButtons.first().click();
      await expect(page.getByText(/Telemetry & Forensic Details/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /Copy JSON/i })).toBeVisible();
    }
  });
});
