import { test, expect } from '@playwright/test';
import { setupStandardApiMocks, mockUser } from './helpers/mock-api';

test.describe('LoginPage Complete Functional & Google Sign-In Tests', () => {
  test.beforeEach(async ({ page }) => {
    await setupStandardApiMocks(page);
  });

  test('1. Initial layout, elements, and password show/hide toggle', async ({ page }) => {
    await page.goto('/login');

    // Branding and Heading
    await expect(page.getByRole('heading', { name: /Sign in/i })).toBeVisible();
    await expect(page.getByText(/AI-Assisted Threat Intelligence Platform/i)).toBeVisible();

    // Mode tabs
    const existingTab = page.getByRole('tab', { name: /Existing Account/i });
    const newAccountTab = page.getByRole('tab', { name: /New Account/i });
    await expect(existingTab).toBeVisible();
    await expect(newAccountTab).toBeVisible();
    await expect(existingTab).toHaveAttribute('aria-selected', 'true');

    // Inputs
    const emailInput = page.getByLabel('Email');
    const passwordInput = page.getByLabel(/Password/i);
    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
    await expect(passwordInput).toHaveAttribute('type', 'password');

    // Password visibility toggle
    await passwordInput.fill('SecretPass123!');
    const eyeBtn = page.locator('button[type="button"]').filter({ has: page.locator('svg.lucide-eye, svg.lucide-eye-off') });
    await expect(eyeBtn).toBeVisible();

    // Toggle to visible
    await eyeBtn.click();
    await expect(passwordInput).toHaveAttribute('type', 'text');

    // Toggle back to hidden
    await eyeBtn.click();
    await expect(passwordInput).toHaveAttribute('type', 'password');

    // Submit button & Google button
    const submitBtn = page.locator('form button[type="submit"]');
    await expect(submitBtn).toHaveText('Sign In');

    const googleBtn = page.getByRole('button', { name: /Sign in with Google/i });
    await expect(googleBtn).toBeVisible();
  });

  test('2. Form validation for empty inputs', async ({ page }) => {
    await page.goto('/login');

    const emailInput = page.getByLabel('Email');
    const submitBtn = page.locator('form button[type="submit"]');

    // Trigger validation
    await emailInput.fill('');
    await submitBtn.click();

    // Built-in or form error message
    await expect(page.getByText(/Please fill in both email and password/i).or(page.locator(':invalid'))).toBeDefined();
  });

  test('3. Mode tab switching (Login <-> Register)', async ({ page }) => {
    await page.goto('/login');

    const newAccountTab = page.getByRole('tab', { name: /New Account/i });
    const existingTab = page.getByRole('tab', { name: /Existing Account/i });

    // Switch to Register mode
    await newAccountTab.click();
    await expect(newAccountTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: /Create an account/i })).toBeVisible();
    await expect(page.getByLabel(/Full Name/i)).toBeVisible();
    await expect(page.locator('form button[type="submit"]')).toHaveText('Create Account');
    await expect(page.getByRole('button', { name: /Register with Google/i })).toBeVisible();

    // Switch back to Login mode
    await existingTab.click();
    await expect(existingTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: /Sign in/i })).toBeVisible();
    await expect(page.getByLabel(/Full Name/i)).not.toBeVisible();
    await expect(page.locator('form button[type="submit"]')).toHaveText('Sign In');
    await expect(page.getByRole('button', { name: /Sign in with Google/i })).toBeVisible();
  });

  test('4. Successful Email & Password Login redirects to Dashboard', async ({ page }) => {
    await page.goto('/login');

    await page.getByLabel('Email').fill('analyst@sentineltrace.io');
    await page.getByLabel(/Password/i).fill('SentinelQAPass123!');
    await page.locator('form button[type="submit"]').click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/.*dashboard|\//);
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
  });

  test('5. Invalid login credentials error display', async ({ page }) => {
    // Override login endpoint with 401 Unauthorized
    await page.route('**/api/**/auth/login', async (route) => {
      await route.fulfill({
        status: 401,
        json: { detail: 'Invalid email or password.' },
      });
    });

    await page.goto('/login');

    await page.getByLabel('Email').fill('wrong@user.com');
    await page.getByLabel(/Password/i).fill('WrongPassword!');
    await page.locator('form button[type="submit"]').click();

    // Error alert should be visible
    await expect(page.getByText('Invalid email or password.')).toBeVisible();
  });

  test('6. Successful Registration Flow', async ({ page }) => {
    // Mock register endpoint
    await page.route('**/api/**/auth/register', async (route) => {
      await route.fulfill({
        status: 201,
        json: {
          id: 'new-user-01',
          email: 'newanalyst@sentineltrace.io',
          full_name: 'Jane Security',
          role: 'ANALYST',
        },
      });
    });

    await page.goto('/login');

    // Switch to Register mode
    await page.getByRole('tab', { name: /New Account/i }).click();

    await page.getByLabel(/Full Name/i).fill('Jane Security');
    await page.getByLabel('Email').fill('newanalyst@sentineltrace.io');
    await page.getByLabel(/Password/i).fill('SuperSecretPass123!');
    await page.locator('form button[type="submit"]').click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/.*dashboard|\//);
    await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible();
  });

  test('7. Registration account collision error with quick switch to login', async ({ page }) => {
    // Mock register endpoint collision
    await page.route('**/api/**/auth/register', async (route) => {
      await route.fulfill({
        status: 409,
        json: { detail: 'The email is already registered.' },
      });
    });

    await page.goto('/login');

    // Switch to Register mode
    await page.getByRole('tab', { name: /New Account/i }).click();
    await page.getByLabel(/Full Name/i).fill('Existing User');
    await page.getByLabel('Email').fill('analyst@sentineltrace.io');
    await page.getByLabel(/Password/i).fill('SuperSecretPass123!');
    await page.locator('form button[type="submit"]').click();

    // Verify error and quick switch link
    await expect(page.getByText(/already registered/i)).toBeVisible();
    const goToLoginBtn = page.getByRole('button', { name: /→ Go to Login/i });
    await expect(goToLoginBtn).toBeVisible();

    // Clicking Go to Login switches tab to login mode
    await goToLoginBtn.click();
    await expect(page.getByRole('heading', { name: /Sign in/i })).toBeVisible();
  });

  test('8. Google OAuth button initiates OAuth redirect flow', async ({ page }) => {
    let oauthRequested = false;
    let requestedIntent = '';

    await page.route('**/api/**/auth/google?**', async (route) => {
      oauthRequested = true;
      const url = new URL(route.request().url());
      requestedIntent = url.searchParams.get('intent') || '';
      await route.fulfill({
        json: {
          authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth?mock=true',
          state: 'mock-state-xyz',
        },
      });
    });

    await page.goto('/login');

    const googleBtn = page.getByRole('button', { name: /Sign in with Google/i });
    await expect(googleBtn).toBeVisible();

    // Click Google OAuth
    await googleBtn.click();
    expect(oauthRequested).toBe(true);
    expect(requestedIntent).toBe('login');
  });

  test('9. Google Pending Registration banner and completion flow', async ({ page }) => {
    let completeRegCalled = false;

    await page.route('**/api/**/auth/google/complete-registration', async (route) => {
      completeRegCalled = true;
      await route.fulfill({
        json: {
          access_token: 'google-oauth-access-token',
          token_type: 'bearer',
          user: {
            id: 'google-user-01',
            email: 'soc.google.analyst@gmail.com',
            full_name: 'Google SOC Lead',
            role: 'ANALYST',
          },
        },
      });
    });

    // Visit login with google_pending query param
    await page.goto('/login?google_pending=test-pending-token-999&email=soc.google.analyst%40gmail.com&name=Google%20SOC%20Lead');

    // Google Verified banner should be visible
    await expect(page.getByText('Google Account Verified')).toBeVisible();
    await expect(page.getByText('soc.google.analyst@gmail.com')).toBeVisible();

    const continueBtn = page.getByRole('button', { name: /Continue with Google as Google SOC Lead/i });
    await expect(continueBtn).toBeVisible();

    // Complete Google registration
    await continueBtn.click();
    expect(completeRegCalled).toBe(true);

    // Navigates to dashboard
    await expect(page).toHaveURL(/.*dashboard|\//);
  });

  test('10. Google Pending Registration cancellation button', async ({ page }) => {
    await page.goto('/login?google_pending=test-pending-token-999&email=test%40gmail.com&name=Test');

    await expect(page.getByText('Google Account Verified')).toBeVisible();

    // Click Cancel
    const cancelBtn = page.getByRole('button', { name: /Cancel — use email & password instead/i });
    await cancelBtn.click();

    // Banner removed, email/password form visible again
    await expect(page.getByText('Google Account Verified')).not.toBeVisible();
    await expect(page.getByLabel('Email')).toBeVisible();
  });

  test('11. Google OAuth Error Callbacks handle redirects smoothly', async ({ page }) => {
    // 1. Google account not registered -> redirects to register mode with message
    await page.goto('/login?error=google_not_registered&email=unregistered%40gmail.com');
    await expect(page.getByRole('heading', { name: /Create an account/i })).toBeVisible();
    await expect(page.getByText(/Your Google account \(unregistered@gmail.com\) is not registered/i)).toBeVisible();

    // 2. Google account exists collision -> redirects to login mode with message
    await page.goto('/login?error=account_exists&email=registered%40gmail.com');
    await expect(page.getByRole('heading', { name: /Sign in/i })).toBeVisible();
    await expect(page.getByText(/already registered with SentinelTrace/i)).toBeVisible();
  });
});
