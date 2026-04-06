import { expect, test, type Page } from '@playwright/test';

const FRONTEND_URL = process.env.PHISH_FRONTEND_URL ?? 'http://127.0.0.1:5173';
const BACKEND_URL = process.env.PHISH_BACKEND_URL ?? 'http://127.0.0.1:8000';

type Verdict = 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK';

async function ensureServices(page: Page) {
  const health = await page.request.get(`${BACKEND_URL}/health`);
  expect(health.ok(), 'Backend health endpoint should be reachable before UI tests run').toBeTruthy();
}

async function openAnalyze(page: Page) {
  await page.goto(FRONTEND_URL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: /PhishShield AI/i })).toBeVisible();
  await page.getByRole('button', { name: /^Analyze$/i }).click();
  await page.waitForTimeout(150);
  const realMode = page.getByRole('button', { name: /^real$/i });
  if (await realMode.count()) {
    await realMode.click();
    await page.waitForTimeout(150);
  }
}

async function openDashboard(page: Page) {
  const dashboardButton = page.getByRole('button', { name: /Dashboard/i }).first();
  await expect(dashboardButton).toBeVisible();
  await dashboardButton.click();
  await page.waitForTimeout(500);
}

async function resetSession(page: Page) {
  await page.goto(FRONTEND_URL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: /PhishShield AI/i })).toBeVisible();
  await openDashboard(page);
  const resetButton = page.getByRole('button', { name: /Reset session/i });
  if (await resetButton.count()) {
    await resetButton.click();
    await page.waitForTimeout(700);
  }
}

async function openDetailsIfAvailable(page: Page) {
  const detailsButton = page.getByRole('button', { name: /View detailed analysis|Hide detailed analysis/i });
  if (await detailsButton.count()) {
    await detailsButton.first().click();
    await page.waitForTimeout(250);
  }
}

async function scanEmail(page: Page, email: string) {
  await openAnalyze(page);
  const textarea = page.locator('textarea').first();
  await textarea.fill(email);

  const scanButton = page.getByRole('button', { name: /Scan Email/i });
  await scanButton.click();

  await expect(page.getByText(/Final verdict/i)).toBeVisible({ timeout: 45_000 });
  await expect(scanButton).toBeEnabled({ timeout: 45_000 });
  await openDetailsIfAvailable(page);

  const text = (await page.locator('main').textContent()) ?? '';
  const verdict = /Final verdict[\s\S]{0,120}?(SAFE|SUSPICIOUS|HIGH RISK)/i.exec(text)?.[1]?.toUpperCase() as Verdict | undefined;
  const risk = Number(/Risk score\s*(\d+)\/100/i.exec(text)?.[1] ?? '-1');
  const confidence = Number(/Confidence:?\s*(\d+)%/i.exec(text)?.[1] ?? '-1');

  return {
    text,
    verdict: verdict ?? 'SAFE',
    risk,
    confidence,
  };
}

function readMetric(text: string, label: string, tail: string) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const escapedTail = tail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return Number(new RegExp(`${escaped}\\s*(\\d+)\\s*${escapedTail}`, 'i').exec(text)?.[1] ?? '-1');
}

test.describe('PhishShield AI standalone UI QA', () => {
  test.beforeEach(async ({ page }) => {
    await ensureServices(page);
  });

  test('trusted safe email stays safe with the correct domain label', async ({ page }) => {
    await resetSession(page);
    const result = await scanEmail(
      page,
      'From: Amazon <order-update@amazon.in>\nSubject: Your Amazon order has shipped\n\nYour Amazon order #402-8837291 has been shipped. Expected delivery: March 18. Track your package at https://amazon.in/orders. Thank you for shopping with Amazon.',
    );

    expect(result.verdict).toBe('SAFE');
    expect(result.risk).toBeLessThanOrEqual(25);
    expect(result.text).toContain('Trusted domain');
    expect(result.text).not.toContain('Unverified / Suspicious domain');
  });

  test('header spoofing email is blocked as high risk with clear explanation', async ({ page }) => {
    await resetSession(page);
    const result = await scanEmail(
      page,
      'From: HDFC Bank <alerts@hdfcbank.com>\nReturn-Path: attacker@spoofed-alert.xyz\nReply-To: attacker@spoofed-alert.xyz\nSubject: Account locked\n\nPlease verify immediately to restore access.',
    );

    expect(result.verdict).toBe('HIGH RISK');
    expect(result.risk).toBeGreaterThanOrEqual(70);
    expect(result.text).toContain('Header Spoofing');
    expect(result.text).toContain('Primary Risk Indicators');
    expect(result.text).not.toContain('Why riskyWhy risky');
  });

  test('dashboard counters stay consistent after mixed scans', async ({ page }) => {
    await resetSession(page);

    await scanEmail(
      page,
      'From: Google <no-reply@accounts.google.com>\nSubject: Security alert for your account\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email.',
    );
    await scanEmail(
      page,
      'From: Billing Desk <alerts@billing-check.info>\nSubject: Payment issue notice\n\nWe noticed a problem processing your recent payment. Please review your billing details at http://billing-check.info/review when convenient.',
    );
    await scanEmail(
      page,
      'From: SBI Alert <support@sbi-security-alert.xyz>\nSubject: OTP verification required\n\nShare OTP immediately and verify your account now at http://sbi-secure-login.xyz/otp.',
    );

    await openDashboard(page);
    const text = (await page.locator('main').textContent()) ?? '';
    const total = readMetric(text, 'Total Scanned', 'emails this session');
    const phishing = readMetric(text, 'Phishing', 'high-risk detected');
    const suspicious = readMetric(text, 'Suspicious', 'need caution');
    const safe = readMetric(text, 'Safe', 'clean emails');

    expect(total).toBeGreaterThanOrEqual(3);
    expect(total).toBe(phishing + suspicious + safe);
    expect(text).not.toContain('Why riskyWhy risky');
    await expect(page.getByRole('button', { name: /Dashboard/i })).toContainText(String(total));
  });
});
