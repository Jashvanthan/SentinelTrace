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

    // Threat Verdict
    await expect(page.getByRole('heading', { name: 'Threat Verdict' })).toBeVisible();
    await expect(page.getByText('COMPLETE').first()).toBeVisible();
    await expect(page.getByText('Credential Harvesting', { exact: true })).toBeVisible();
    await expect(page.getByText('98%')).toBeVisible(); // Confidence

    // AI Agent Findings
    await expect(page.getByRole('heading', { name: 'AI Agent Findings' })).toBeVisible();
    await expect(page.getByText(/Critical threat detected/)).toBeVisible();
    await expect(page.getByText('Model: Sentinel-AI-v4.2-Pro')).toBeVisible();
    await expect(page.getByText('Domain spoofing targeting internal HR portal')).toBeVisible();

    // Email Authentication
    await expect(page.getByRole('heading', { name: 'Email Authentication' })).toBeVisible();
    await expect(page.getByText('SPF', { exact: true })).toBeVisible();
    await expect(page.getByText('DKIM', { exact: true })).toBeVisible();
    await expect(page.getByText('DMARC', { exact: true })).toBeVisible();

    // Sender & IP Intel
    await expect(page.getByRole('heading', { name: 'Sender & IP Intelligence' })).toBeVisible();
    await expect(page.getByText('Frankfurt, Germany')).toBeVisible();
    await expect(page.getByText('HostEurope Gmbh')).toBeVisible();
    await expect(page.getByText('14 / 72')).toBeVisible(); // VirusTotal
    await expect(page.getByText('88%')).toBeVisible(); // AbuseIPDB

    // IOCs
    await expect(page.getByRole('heading', { name: /Indicators of Compromise/ })).toBeVisible();
    await expect(page.getByText('update-portal-spoof.com').first()).toBeVisible();

    // Attachments
    await expect(page.getByRole('heading', { name: /Attachments/ })).toBeVisible();
    await expect(page.getByText('employee_benefits_guide.pdf')).toBeVisible();
    await expect(page.getByText('Malicious').first()).toBeVisible();
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
    await expect(page.getByRole('heading', { name: 'Email Analysis' })).toBeVisible();
  });
});
