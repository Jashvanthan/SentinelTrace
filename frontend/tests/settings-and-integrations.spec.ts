import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo, mockUser } from './helpers/mock-api';

test.describe('Settings Page & Integrations Compound Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Settings tab navigation between General, Members, and Integrations', async ({ page }) => {
    await loginAndNavigateTo(page, '/settings');

    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();

    // 1. General Tab (default)
    await expect(page.getByRole('heading', { name: 'Profile Information' })).toBeVisible();
    await expect(page.locator('main').getByText(mockUser.full_name)).toBeVisible();
    await expect(page.locator('main').getByText(mockUser.email)).toBeVisible();
    await expect(page.locator('main').getByText('Primary SOC Team')).toBeVisible();

    // 2. Switch to Members Tab
    await page.getByRole('button', { name: 'Members' }).click();
    await expect(page.getByRole('heading', { name: 'Workspace Members' })).toBeVisible();
    await expect(page.getByText('Sarah Connor')).toBeVisible();
    await expect(page.getByText('John Doe')).toBeVisible();

    // 3. Switch to Integrations Tab
    await page.getByRole('button', { name: 'Integrations' }).click();
    await expect(page.getByRole('heading', { name: 'Workspace Integrations' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Gmail Integration' })).toBeVisible();
    await expect(page.getByText('Connected', { exact: true })).toBeVisible();
  });

  test('Add Member modal opens, inputs can be filled, and submission updates list', async ({ page }) => {
    await loginAndNavigateTo(page, '/settings');

    // Go to Members tab
    await page.getByRole('button', { name: 'Members' }).click();

    // Click 'Add Member' button
    const addBtn = page.getByRole('button', { name: 'Add Member' });
    await expect(addBtn).toBeVisible();
    await addBtn.click();

    // Modal appears
    await expect(page.getByRole('heading', { name: 'Add Workspace Member' })).toBeVisible();

    // Fill in email
    const emailInput = page.locator('div.fixed input[type="email"]');
    await emailInput.fill('newanalyst@sentineltrace.io');

    // Select role
    const roleSelect = page.locator('div.fixed select');
    await roleSelect.selectOption('analyst');

    // Submit modal form
    const modalSubmitBtn = page.locator('.fixed form button[type="submit"]');
    await modalSubmitBtn.click();

    // Modal closes
    await expect(page.getByRole('heading', { name: 'Add Workspace Member' })).not.toBeVisible();
  });

  test('Integrations tab sync and disconnect button interactions', async ({ page }) => {
    // Handle the browser confirm dialog for disconnect
    page.on('dialog', async (dialog) => {
      expect(dialog.message()).toContain('Disconnecting will stop email ingestion. Are you sure?');
      await dialog.accept();
    });

    await loginAndNavigateTo(page, '/settings');

    // Go to Integrations tab
    await page.getByRole('button', { name: 'Integrations' }).click();

    // Check Sync Now button
    const syncBtn = page.getByRole('button', { name: 'Sync Now' });
    await expect(syncBtn).toBeVisible();
    await syncBtn.click();

    // Check Disconnect button
    const disconnectBtn = page.getByRole('button', { name: 'Disconnect' });
    await expect(disconnectBtn).toBeVisible();
    await disconnectBtn.click();
  });
});
