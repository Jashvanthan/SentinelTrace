import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Threat Intelligence Page & Investigation Panel Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Overview metrics and indicator table render correctly', async ({ page }) => {
    await loginAndNavigateTo(page, '/intel');

    await expect(page.getByRole('heading', { name: 'Threat Intelligence' })).toBeVisible();

    // Metric cards
    await expect(page.getByText('Total IOCs')).toBeVisible();
    await expect(page.getByText('High/Critical Risk')).toBeVisible();

    // Table rows
    await expect(page.getByText('update-portal-spoof.com', { exact: true })).toBeVisible();
    await expect(page.getByText('198.51.100.24', { exact: true })).toBeVisible();
    await expect(page.getByText('https://update-portal-spoof.com/sso/login.php', { exact: true })).toBeVisible();
  });

  test('Search and Type dropdown filters work interactively', async ({ page }) => {
    await loginAndNavigateTo(page, '/intel');

    // Filter by type (scoped to main content area)
    const typeSelect = page.locator('main select').last();
    await typeSelect.selectOption('DOMAIN');
    await expect(typeSelect).toHaveValue('DOMAIN');

    // Search input
    const searchInput = page.getByPlaceholder(/Search IOC/i);
    await searchInput.fill('spoof');
    await expect(searchInput).toHaveValue('spoof');
  });

  test('Clicking indicator row opens Investigation Detail Panel and X button closes it', async ({ page }) => {
    await loginAndNavigateTo(page, '/intel');

    // Panel is initially closed
    await expect(page.getByRole('heading', { name: 'Indicator Details' })).not.toBeVisible();

    // Click on the domain IOC row
    await page.getByText('update-portal-spoof.com', { exact: true }).click();

    // Side panel opens
    const detailPanel = page.locator('div.w-full.lg\\:w-96');
    await expect(detailPanel.getByRole('heading', { name: 'Indicator Details' })).toBeVisible();
    await expect(detailPanel.getByText(/98\s*\/\s*100/).first()).toBeVisible();
    await expect(detailPanel.getByText('95%')).toBeVisible(); // Confidence
    await expect(detailPanel.getByText('credential-stealer')).toBeVisible(); // Tag
    await expect(detailPanel.getByText('phish-kit')).toBeVisible(); // Tag

    // Click X button to close
    const closeBtn = detailPanel.locator('button:has(svg.lucide-x)');
    await expect(closeBtn).toBeVisible();
    await closeBtn.click();

    // Side panel should be closed
    await expect(page.getByRole('heading', { name: 'Indicator Details' })).not.toBeVisible();
  });
});
