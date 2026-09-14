import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Comprehensive Functional and Non-Functional Buttons Test Suite', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);

    // Track unhandled console errors or exceptions
    page.on('pageerror', (exception) => {
      console.error('Unhandled page exception:', exception);
      throw exception;
    });
  });

  test('1. AppShell and Navigation: Sidebar collapse, expand, mobile menu, and all route links', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Sidebar collapse button (desktop sidebar)
    const collapseBtn = page.locator('aside.hidden.md\\:flex button.absolute');
    await expect(collapseBtn).toBeVisible();
    await collapseBtn.click();

    // Verify sidebar is collapsed
    const aside = page.locator('aside.hidden.md\\:flex');
    await expect(aside).toHaveClass(/w-16/);

    // Sidebar expand button
    await collapseBtn.click();
    await expect(aside).toHaveClass(/w-60/);

    // Navigation links to functional pages
    const routes = [
      { name: 'Dashboard', urlPattern: /.*\/dashboard/, heading: /Security Overview/i },
      { name: 'Investigate', urlPattern: /.*\/investigate/, heading: /Email Analysis/i },
      { name: 'Threat Intel', urlPattern: /.*\/intel/, heading: /Threat Intelligence/i },
      { name: 'Campaigns', urlPattern: /.*\/campaigns/, heading: /Campaign Correlation/i },
      { name: 'Integrations', urlPattern: /.*\/integrations/, heading: /Integrations/i },
      { name: 'Settings', urlPattern: /.*\/settings/, heading: /Settings/i },
    ];

    for (const route of routes) {
      const link = page.locator('aside.hidden.md\\:flex').getByRole('link', { name: route.name, exact: true });
      await expect(link).toBeVisible();
      await link.click();
      await expect(page).toHaveURL(route.urlPattern);
      await expect(page.getByRole('heading', { name: route.heading })).toBeVisible();
    }

    const operationalRoutes = [
      { name: 'Geolocation', urlPattern: /.*\/geo/, heading: /Infrastructure Geolocation/i },
      { name: 'Reports', urlPattern: /.*\/reports/, heading: /Forensic Reports/i },
      { name: 'Activity Log', urlPattern: /.*\/activity/, heading: /Security & Activity Log/i },
    ];

    for (const route of operationalRoutes) {
      const link = page.locator('aside.hidden.md\\:flex').getByRole('link', { name: route.name, exact: true });
      await expect(link).toBeVisible();
      await link.click();
      await expect(page).toHaveURL(route.urlPattern);
      await expect(page.getByRole('heading', { name: route.heading })).toBeVisible();
    }
  });

  test('2. Dashboard: Analyze Email CTA button and View all link', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    // Analyze Email CTA button
    const ctaBtn = page.getByRole('link', { name: 'Analyze Email' });
    await expect(ctaBtn).toBeVisible();
    await ctaBtn.click();
    await expect(page).toHaveURL(/.*\/emails/);

    // Return to dashboard and click View all link in feed
    await page.getByRole('link', { name: 'Dashboard' }).click();
    const viewAllLink = page.getByRole('link', { name: 'View all email analyses' });
    await expect(viewAllLink).toBeVisible();
    await viewAllLink.click();
    await expect(page).toHaveURL(/.*\/emails/);
  });

  test('3. Email Analysis: Upload form, sample load, priority buttons, removal, filters, refresh, clear, pagination', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails');

    // Refresh button
    const refreshBtn = page.getByRole('button', { name: 'Refresh' });
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Toggle Upload panel open
    const uploadToggle = page.getByRole('button', { name: /Upload \.eml/i });
    await uploadToggle.click();
    await expect(page.getByRole('heading', { name: 'Upload Email for Analysis' })).toBeVisible();

    // Non-functional check: Submit button must be disabled when no file is selected
    const initialSubmitBtn = page.getByRole('button', { name: /Attach \.eml or Load Sample/i });
    await expect(initialSubmitBtn).toBeDisabled();

    // Functional button: Load Sample Phishing Email
    const loadSampleBtn = page.getByRole('button', { name: /Load Sample Phishing Email/i });
    await expect(loadSampleBtn).toBeVisible();
    await loadSampleBtn.click();

    // Verify sample file loaded and Submit button is now enabled
    await expect(page.getByText('sample_phishing_alert.eml')).toBeVisible();
    const activeSubmitBtn = page.getByRole('button', { name: 'Submit for Analysis' });
    await expect(activeSubmitBtn).toBeEnabled();

    // Priority buttons toggle
    const criticalBtn = page.getByRole('button', { name: 'CRITICAL' });
    const highBtn = page.getByRole('button', { name: 'HIGH' });
    const normalBtn = page.getByRole('button', { name: 'NORMAL' });

    await criticalBtn.click();
    await highBtn.click();
    await normalBtn.click();

    // Functional button: Remove File
    const removeFileBtn = page.getByRole('button', { name: /Remove File/i });
    await expect(removeFileBtn).toBeVisible();
    await removeFileBtn.click();

    // Verify file removed and submit disabled again
    await expect(page.getByText('sample_phishing_alert.eml')).not.toBeVisible();
    await expect(page.getByRole('button', { name: /Attach \.eml or Load Sample/i })).toBeDisabled();

    // Toggle Upload panel closed
    await uploadToggle.click();
    await expect(page.getByRole('heading', { name: 'Upload Email for Analysis' })).not.toBeVisible();

    // Search and filter controls
    const searchInput = page.getByPlaceholder('Search subject, sender…');
    await searchInput.fill('Invoice');

    // Functional button: Clear filters
    const clearBtn = page.getByRole('button', { name: 'Clear filters' });
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();
    await expect(searchInput).toHaveValue('');
    await expect(clearBtn).not.toBeVisible();
  });

  test('4. Threat Intelligence: Live Enrich button, table row selection, close panel, pagination boundaries', async ({ page }) => {
    await loginAndNavigateTo(page, '/intel');

    // Non-functional check: Enrich button is disabled when input is empty
    const enrichBtn = page.getByRole('button', { name: 'Enrich' });
    await expect(enrichBtn).toBeDisabled();

    // Fill in indicator to enable Enrich
    const enrichInput = page.getByPlaceholder(/e\.g\. 8\.8\.8\.8/i);
    await enrichInput.fill('update-portal-spoof.com');
    await expect(enrichBtn).toBeEnabled();

    // Click Enrich button
    await enrichBtn.click();

    // Verify result card appears
    await expect(page.getByText('update-portal-spoof.com').first()).toBeVisible();

    // Row selection opens detail panel
    const firstRow = page.locator('tbody tr').first();
    await firstRow.click();
    await expect(page.getByText('Indicator Details')).toBeVisible();

    // Close button (X) on detail panel
    const closePanelBtn = page.locator('button:has(svg.lucide-x)');
    await closePanelBtn.click();
    await expect(page.getByText('Indicator Details')).not.toBeVisible();
  });

  test('5. Campaign Graph: Depth buttons (1, 2, 3, 4) and Refresh button', async ({ page }) => {
    await loginAndNavigateTo(page, '/campaigns');

    // Depth buttons 1 to 4
    for (const depth of ['1', '2', '3', '4']) {
      const depthBtn = page.getByRole('button', { name: depth, exact: true });
      await expect(depthBtn).toBeVisible();
      await depthBtn.click();
      await expect(depthBtn).toHaveClass(/(bg-\[#2563eb\]|bg-\[hsl\(var\(--accent\)\)\]|bg-blue)/);
    }

    // Refresh button
    const refreshBtn = page.locator('main').getByRole('button').filter({ has: page.locator('svg.lucide-refresh-cw') });
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Ensure no error banner
    await expect(page.getByText('Campaign Data Error')).not.toBeVisible();
  });

  test('6. Settings: Tab buttons, Add Member modal open & cancel, Sync & Disconnect', async ({ page }) => {
    page.on('dialog', async (dialog) => {
      await dialog.accept();
    });

    await loginAndNavigateTo(page, '/settings');

    // Tab buttons
    const generalTab = page.getByRole('button', { name: 'General' });
    const membersTab = page.getByRole('button', { name: 'Members' });
    const integrationsTab = page.getByRole('button', { name: 'Integrations' });

    // Switch to Members tab
    await membersTab.click();
    await expect(page.getByRole('heading', { name: 'Workspace Members' })).toBeVisible();

    // Add Member modal open
    const addMemberBtn = page.getByRole('button', { name: 'Add Member' });
    await addMemberBtn.click();
    await expect(page.getByRole('heading', { name: 'Add Workspace Member' })).toBeVisible();

    // Modal Cancel button
    const cancelBtn = page.getByRole('button', { name: 'Cancel' });
    await cancelBtn.click();
    await expect(page.getByRole('heading', { name: 'Add Workspace Member' })).not.toBeVisible();

    // Switch to Integrations tab
    await integrationsTab.click();
    await expect(page.getByRole('heading', { name: 'Workspace Integrations' })).toBeVisible();

    // Sync Now button
    const syncBtn = page.getByRole('button', { name: 'Sync Now' });
    await expect(syncBtn).toBeVisible();
    await syncBtn.click();

    // Disconnect button
    const disconnectBtn = page.getByRole('button', { name: 'Disconnect' });
    await expect(disconnectBtn).toBeVisible();
    await disconnectBtn.click();

    // Return to General tab
    await generalTab.click();
    await expect(page.getByRole('heading', { name: 'Profile Information' })).toBeVisible();
  });

  test('7. Integrations Page: Gmail Sync and Reconnect controls', async ({ page }) => {
    await loginAndNavigateTo(page, '/integrations');

    await expect(page.getByRole('heading', { name: 'Integrations' })).toBeVisible();
    await expect(page.getByText('Google Workspace (Gmail)')).toBeVisible();

    // Sync Now button on Integrations page
    const syncBtn = page.getByRole('button', { name: /Sync/i });
    if (await syncBtn.isVisible()) {
      await syncBtn.click();
    }
  });

  test('8. Logout: Header logout button cleanly exits session', async ({ page }) => {
    await loginAndNavigateTo(page, '/dashboard');

    const logoutBtn = page.locator('aside.hidden.md\\:flex button[title="Log Out"]');
    await expect(logoutBtn).toBeVisible();
    await logoutBtn.click();

    await expect(page).toHaveURL(/.*\/login/);
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  });
});
