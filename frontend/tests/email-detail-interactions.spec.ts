import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, loginAndNavigateTo } from './helpers/mock-api';

test.describe('Email Detail Page & Analysis Insights Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('Renders comprehensive threat analysis verdict, AI findings, and authentication pills', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails/analysis-001');

    // Header & Subject
    await expect(page.getByRole('heading', { name: 'URGENT: Payroll Account Verification Required' })).toBeVisible();
    await expect(page.getByText('payroll@update-portal-spoof.com')).toBeVisible();

    // Analysis Pipeline & Status
    await expect(page.getByRole('heading', { name: /Analysis Pipeline/i })).toBeVisible();
    await expect(page.getByText('COMPLETE').first()).toBeVisible();

    // AI Executive Forensic Assessment
    await expect(page.getByRole('heading', { name: /AI Executive Forensic Assessment/i })).toBeVisible();
    await expect(page.getByText(/Critical threat detected/).first()).toBeVisible();

    // Pipeline Steps & Sender Validation
    await expect(page.getByText('Sender Identity Validation')).toBeVisible();
    await expect(page.getByText(/SPF/).first()).toBeVisible();

    // Observed IOCs Table
    await expect(page.getByRole('heading', { name: /Observed Indicators of Compromise/i })).toBeVisible();
    await expect(page.getByText('update-portal-spoof.com').first()).toBeVisible();

    // Analyst Assistant Drawer
    await expect(page.getByRole('heading', { name: /Analyst Assistant/i })).toBeVisible();
    await expect(page.getByText(/Threat Intelligence Assessment/i)).toBeVisible();
  });

  test('Campaign graph CTA button navigates to Campaign Graph investigation', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails/analysis-001');

    const graphBtn = page.getByRole('link', { name: 'View Campaign Graph' });
    await expect(graphBtn).toBeVisible();
    await graphBtn.click();

    await expect(page).toHaveURL(/.*\/graph\?campaign_id=camp-fin-01/);
    await expect(page.getByRole('heading', { name: /Campaign Correlation/i })).toBeVisible();
  });

  test('Back to analyses link returns to emails table', async ({ page }) => {
    await loginAndNavigateTo(page, '/emails/analysis-001');

    const backLink = page.getByRole('link', { name: 'Back to analyses' });
    await expect(backLink).toBeVisible();
    await backLink.click();

    await expect(page).toHaveURL(/.*\/emails/);
    await expect(page.getByRole('heading', { name: /Email Analysis/i })).toBeVisible();
  });
});
