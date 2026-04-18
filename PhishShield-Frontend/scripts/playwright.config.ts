import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

const frontendUrl = process.env.PHISH_FRONTEND_URL ?? 'http://127.0.0.1:5173';

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  fullyParallel: false,
  reporter: [
    ['list'],
    ['html', { outputFolder: resolve(process.cwd(), '..', 'artifacts', 'reports', 'qa', 'playwright-report'), open: 'never' }],
  ],
  use: {
    baseURL: frontendUrl,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
});
