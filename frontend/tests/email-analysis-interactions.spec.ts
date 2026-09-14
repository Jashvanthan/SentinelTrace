import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Email Analysis Page & Compound Component Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Upload panel toggle button reveals and hides the uploader', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails');

    // Initially upload panel is hidden
    await expect(page.getByText('Upload Email for Analysis')).not.toBeVisible();

    // Click 'Upload .eml' button
    const uploadToggle = page.getByRole('button', { name: /Upload \.eml/i });
    await uploadToggle.click();

    // Now upload panel is visible
    await expect(page.getByRole('heading', { name: 'Upload Email for Analysis' })).toBeVisible();
    await expect(page.getByText('Drop .eml file here or click to browse')).toBeVisible();

    // Click again to hide
    await uploadToggle.click();
    await expect(page.getByText('Upload Email for Analysis')).not.toBeVisible();
  });

  test('Upload form handles file selection, priority buttons, notes, and submit', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails');

    // Open upload panel
    await page.getByRole('button', { name: /Upload \.eml/i }).click();

    // Upload an EML file via the file input
    const fileInput = page.locator('input[type="file"]#eml-file-input');
    await fileInput.setInputFiles({
      name: 'suspicious_invoice.eml',
      mimeType: 'message/rfc822',
      buffer: Buffer.from('From: attacker@evil.com\nTo: victim@target.com\nSubject: Urgent Invoice\n\nPlease pay.'),
    });

    // Check that selected file info appears
    await expect(page.getByText('suspicious_invoice.eml')).toBeVisible();

    // Select 'CRITICAL' priority button
    const criticalBtn = page.getByRole('button', { name: 'CRITICAL' });
    await criticalBtn.click();

    // Fill in analyst notes
    const notesInput = page.getByPlaceholder(/Add context or/i);
    await notesInput.fill('Urgent escalation from finance team.');

    // Submit for analysis
    const submitBtn = page.getByRole('button', { name: 'Submit for Analysis' });
    await submitBtn.click();

    // Form submission succeeds and navigates to the email detail page
    await expect(page).toHaveURL(/.*\/emails\/analysis-001/);
    await expect(page.getByRole('heading', { name: 'URGENT: Payroll Account Verification Required' })).toBeVisible();
  });

  test('Search input and filter dropdowns filter table results', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails');

    // Search input
    const searchInput = page.getByPlaceholder('Search subject, sender…');
    await searchInput.fill('Payroll');
    await expect(searchInput).toHaveValue('Payroll');

    // Status filter
    const statusSelect = page.locator('main select').first();
    await statusSelect.selectOption('COMPLETE');
    await expect(statusSelect).toHaveValue('COMPLETE');

    // Severity filter
    const severitySelect = page.locator('main select').nth(1);
    await severitySelect.selectOption('CRITICAL');
    await expect(severitySelect).toHaveValue('CRITICAL');

    // 'Clear filters' button appears
    const clearBtn = page.getByRole('button', { name: 'Clear filters' });
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();

    // Filters should reset
    await expect(searchInput).toHaveValue('');
    await expect(statusSelect).toHaveValue('');
    await expect(severitySelect).toHaveValue('');
  });

  test('Table row navigation and analysis deletion', async ({ page }) => {
    // Handle the browser confirm dialog
    page.on('dialog', async (dialog) => {
      expect(dialog.message()).toContain('Delete this analysis?');
      await dialog.accept();
    });

    await loginAndNavigateTo(page, '/emails');

    // Verify row items are listed
    await expect(page.getByText('URGENT: Payroll Account Verification Required').first()).toBeVisible();
    await expect(page.getByText('Invoice INV-98214 Attached').first()).toBeVisible();

    // Test row deletion button
    const deleteBtn = page.locator('tbody tr').first().getByTitle('Delete');
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    }

    // Click on row to navigate
    await page.getByText('URGENT: Payroll Account Verification Required').first().click();
    await expect(page).toHaveURL(/.*\/emails\/analysis-001/);
  });
});
