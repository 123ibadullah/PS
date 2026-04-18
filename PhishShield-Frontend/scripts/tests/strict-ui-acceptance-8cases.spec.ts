import { expect, test, type Page } from '@playwright/test';

const FRONTEND_URL = process.env.PHISH_FRONTEND_URL ?? 'http://127.0.0.1:5173';
const BACKEND_URL = process.env.PHISH_BACKEND_URL ?? 'http://127.0.0.1:8000';

type UiCase = {
  id: string;
  email: string;
  headers?: string;
  assertions: (page: Page) => Promise<void>;
};

async function ensureServices(page: Page) {
  const health = await page.request.get(`${BACKEND_URL}/health`);
  expect(health.ok(), 'Backend /health must be reachable before UI validation').toBeTruthy();
}

async function openAnalyze(page: Page) {
  await page.goto(FRONTEND_URL, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { name: /PhishShield AI/i })).toBeVisible();
  await page.getByRole('button', { name: /^Analyze$/i }).click();
  const realMode = page.getByRole('button', { name: /^real$/i });
  if (await realMode.count()) {
    await realMode.click();
  }
}

async function runScan(page: Page, email: string, headers?: string) {
  const textareas = page.locator('textarea');
  await textareas.first().fill(email);

  const advancedButton = page.getByRole('button', { name: /Advanced \(Headers\)/i });
  if (headers !== undefined) {
    const headerArea = page.getByPlaceholder(/Paste raw email headers here/i);
    if (!(await headerArea.isVisible().catch(() => false))) {
      await advancedButton.click();
    }
    await headerArea.fill(headers);
  } else {
    const headerArea = page.getByPlaceholder(/Paste raw email headers here/i);
    if (await headerArea.isVisible().catch(() => false)) {
      await headerArea.fill('');
    }
  }

  const scanButton = page.getByRole('button', { name: /Scan Email/i });
  await scanButton.click();
  await expect(page.getByText(/Final verdict/i)).toBeVisible({ timeout: 45_000 });
  await expect(scanButton).toBeEnabled({ timeout: 45_000 });
}

async function ensureDetailsOpen(page: Page) {
  const openButton = page.getByRole('button', { name: /View detailed analysis/i });
  if (await openButton.count()) {
    await openButton.first().click();
  }
  await expect(page.getByText(/Score components/i)).toBeVisible({ timeout: 20_000 });
}

async function expectNoHeadersBadge(page: Page) {
  await expect(page.getByText(/No headers provided.*sender unverified/i).first()).toBeVisible();
}

async function expectZeroScoreBreakdown(page: Page) {
  await ensureDetailsOpen(page);
  const text = (await page.locator('main').textContent()) ?? '';
  const normalized = text.replace(/\s+/g, '').toLowerCase();
  expect(normalized).toContain('languagemodel0');
  expect(normalized).toContain('patternmatching0');
  expect(normalized).toContain('linkrisk0');
  expect(normalized).toContain('headerspoofing0');
}

const CASES: UiCase[] = [
  {
    id: 'Test 1',
    email:
      'From: Support Team <support@company-helpdesk.com>\n\nPlease review your account profile details.',
    assertions: async (page) => {
      await expectNoHeadersBadge(page);
      await ensureDetailsOpen(page);
      await expect(page.getByText(/Header coverage/i)).toBeVisible();
      await expect(page.getByText(/From line only/i)).toBeVisible();
    },
  },
  {
    id: 'Test 2',
    email:
      'URGENT: Your bank account will be suspended in 30 minutes. Reply with your OTP and password immediately and verify at http://secure-bank-verify-login.xyz/auth now.',
    assertions: async (page) => {
      await expectNoHeadersBadge(page);
    },
  },
  {
    id: 'Test 3',
    email:
      'Your package is delayed. Pay INR 49 now to release delivery at http://parcel-release-fee-track.top/pay.',
    assertions: async (page) => {
      await expectNoHeadersBadge(page);
      await ensureDetailsOpen(page);
      const row = page.locator('tr', { hasText: 'parcel-release-fee-track.top' }).first();
      await expect(row).toBeVisible();
      await expect(row).toContainText(/Suspicious TLD/i);
      await expect(row).not.toContainText(/Low risk/i);
      await expect(row).toContainText(/flagged by local TLD heuristic/i);
    },
  },
  {
    id: 'Test 4',
    email:
      'From: Amazon Billing <billing@amaz0n-security-support.com>\n\nPlease verify your recent account activity by reviewing your account details.',
    assertions: async (page) => {
      await expect(page.getByText(/Final verdict/i)).toBeVisible();
    },
  },
  {
    id: 'Test 5',
    email:
      'From: LinkedIn News <news@linkedin.com>\nSubject: Weekly digest\n\nHere is your weekly professional digest. Manage notification settings or unsubscribe anytime.',
    assertions: async (page) => {
      await expectZeroScoreBreakdown(page);
    },
  },
  {
    id: 'Test 6',
    email:
      'Please review your account profile details. Sender metadata is provided separately.',
    headers:
      [
        'From: HDFC Bank <alerts@hdfcbank.com>',
        'Reply-To: assist@random-mailer.net',
        'Return-Path: <bounce@mailer-random.net>',
        'Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail',
        'Received: from [10.0.0.12] by mx.example.com with ESMTP id 7781',
      ].join('\n'),
    assertions: async (page) => {
      await expect(page.getByText(/Sender authenticity not verified/i).first()).toBeVisible();
      await expect(page.getByText(/No headers provided.*sender unverified/i)).toHaveCount(0);
      await ensureDetailsOpen(page);
      const headerSection = page.locator('div', { hasText: 'Email Header Analysis' }).first();
      await expect(headerSection).toBeVisible();
      await expect(headerSection).toContainText(/high risk/i);
    },
  },
  {
    id: 'Test 7',
    email:
      'Hello team, sharing this week\'s project status summary. No action required.',
    assertions: async (page) => {
      await expectZeroScoreBreakdown(page);
    },
  },
  {
    id: 'Test 8',
    email:
      'Hi Finance Team, process this urgent vendor payment now. Keep this confidential and do not call me. Transfer funds to the beneficiary in the attached invoice and confirm immediately.',
    assertions: async (page) => {
      await expect(page.getByText(/Final verdict/i)).toBeVisible();
    },
  },
];

test.describe('Strict UI acceptance (8 cases)', () => {
  test.beforeEach(async ({ page }) => {
    await ensureServices(page);
    await openAnalyze(page);
  });

  for (const scenario of CASES) {
    test(scenario.id, async ({ page }) => {
      await test.step(`${scenario.id} assertions`, async () => {
        await runScan(page, scenario.email, scenario.headers);
        await scenario.assertions(page);
      });
    });
  }
});
