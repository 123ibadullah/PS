type Classification = 'safe' | 'uncertain' | 'phishing';

type Scenario = {
  id: string;
  title: string;
  expected: Classification | Classification[];
  emailText: string;
  requireSignals?: boolean;
  checkFallback?: boolean;
};

type BackendResponse = {
  risk_score?: number;
  confidence?: number;
  verdict?: string;
  category?: string;
  signals?: string[];
  explanation?: Record<string, unknown>;
  model_used?: string;
};

type FallbackResponse = {
  riskScore?: number;
  classification?: string;
  attackType?: string;
  reasons?: Array<{ description?: string }>;
  suspiciousSpans?: Array<{ text?: string }>;
  warnings?: string[];
  headerAnalysis?: Record<string, unknown>;
};

const DEFAULT_BACKEND_URL = process.env.PHISH_BACKEND_URL ?? 'http://127.0.0.1:8000';
const DEFAULT_FRONTEND_URL = process.env.PHISH_FRONTEND_URL ?? 'http://127.0.0.1:5173';
const BACKEND_CANDIDATES = [...new Set([DEFAULT_BACKEND_URL, 'http://127.0.0.1:8000', 'http://localhost:8000'])];
const FRONTEND_CANDIDATES = [...new Set([DEFAULT_FRONTEND_URL, 'http://127.0.0.1:5173', 'http://localhost:5173', 'http://127.0.0.1:5174', 'http://localhost:5174'])];
let BACKEND_URL = DEFAULT_BACKEND_URL;
let FRONTEND_URL = DEFAULT_FRONTEND_URL;
const DEV_AUTH = 'Bearer dev-sandbox-key';

const scenarios: Scenario[] = [
  {
    id: 'S1',
    title: 'Google security alert',
    expected: 'safe',
    checkFallback: true,
    emailText:
      'From: Google <no-reply@accounts.google.com>\nSubject: Security alert for your account\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email. If this was not you, please secure your account.',
  },
  {
    id: 'S2',
    title: 'Amazon order update',
    expected: 'safe',
    emailText:
      'From: Amazon <order-update@amazon.in>\nSubject: Your Amazon order has shipped\n\nYour Amazon order #402-8837291 has been shipped. Expected delivery: March 18. Track your package at https://amazon.in/orders. Thank you for shopping with Amazon.',
  },
  {
    id: 'S3',
    title: 'LinkedIn newsletter',
    expected: 'safe',
    emailText:
      'From: LinkedIn News <news@linkedin.com>\nList-Unsubscribe: <https://linkedin.com/unsubscribe>\n\nTop stories from your network this week. Manage notification settings or unsubscribe here.',
  },
  {
    id: 'P1',
    title: 'Amazon fake domain',
    expected: 'phishing',
    requireSignals: true,
    checkFallback: true,
    emailText:
      'From: Amazon Support <support@amazon-update-help.xyz>\nSubject: Urgent account verification required\n\nYour Amazon account will be suspended within 24 hours. Verify immediately at http://amazon-update-help.xyz/login to avoid permanent closure.',
  },
  {
    id: 'P2',
    title: 'HDFC spoofing',
    expected: 'phishing',
    requireSignals: true,
    checkFallback: true,
    emailText:
      'From: HDFC Bank <support@hdfc-secure.tk>\nReply-To: unlock@fast-help-alert.xyz\nSubject: Critical Alert: Your account is locked\n\nDear customer, we detected unusual login attempts on your HDFC account. Please click here to verify and unlock immediately: http://hdfc-verify.xyz/login.',
  },
  {
    id: 'P3',
    title: 'SBI OTP scam',
    expected: 'phishing',
    requireSignals: true,
    checkFallback: true,
    emailText:
      'From: SBI Alert <support@sbi-security-alert.xyz>\nSubject: OTP verification required\n\nShare OTP immediately to avoid account suspension. Complete KYC now at http://sbi-secure-login.xyz/otp.',
  },
  {
    id: 'P4',
    title: 'Government refund scam',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'From: Income Tax Refund <refund@incometax-gov.co>\nSubject: Refund pending for your PAN\n\nYour refund has been approved. Update bank details and verify your PAN within 24 hours at http://incometax-gov.co/refund to receive the payment.',
  },
  {
    id: 'B1',
    title: 'Legit Paytm KYC reminder',
    expected: ['safe', 'uncertain'],
    emailText:
      'From: Paytm Care <care@paytm.com>\nSubject: Reminder to complete KYC in the app\n\nThis is a reminder to complete your KYC in the official Paytm app to continue wallet services. No action is needed if already completed.',
  },
  {
    id: 'B2',
    title: 'Payment issue low urgency',
    expected: ['uncertain', 'phishing'],
    emailText:
      'From: Billing Desk <alerts@billing-check.info>\nSubject: Payment issue notice\n\nWe noticed a problem processing your recent payment. Please review your billing details at http://billing-check.info/review when convenient to avoid future interruptions.',
  },
  {
    id: 'A1',
    title: 'Lookalike Microsoft domain',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'From: Microsoft Support <security@micr0soft-support.com>\nSubject: Password reset required\n\nYour Office 365 account will be disabled today unless you confirm your password reset immediately at http://micr0soft-support.com/secure-login.',
  },
  {
    id: 'A2',
    title: 'Delivery fee scam',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'From: FedEx Billing <notify@fedex-delivery-fee.xyz>\nSubject: Parcel delivery fee pending\n\nYour parcel could not be delivered. Pay the customs fee of Rs. 99 now at http://fedex-delivery-fee.xyz/pay to release the shipment.',
  },
  {
    id: 'A3',
    title: 'BEC no-link transfer scam',
    expected: 'phishing',
    requireSignals: true,
    checkFallback: true,
    emailText:
      'From: CEO Office <ceo-finance@vendor-payments.co>\nSubject: Confidential transfer request\n\nI am in a meeting. Process the vendor payment today, keep this confidential, and do not call back until the transfer is done. Update the beneficiary and confirm once released.',
  },
  {
    id: 'M1',
    title: 'Hinglish OTP scam',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'SBI alert: OTP bhejo warna account band ho jayega. Turant verify karo: http://sbi-verify.xyz/otp',
  },
  {
    id: 'M2',
    title: 'Hindi banking scam',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'आपका बैंक खाता बंद हो जाएगा। तुरंत सत्यापन करें और OTP साझा करें: http://sbi-verify.xyz/kyc',
  },
  {
    id: 'M3',
    title: 'Telugu phishing scam',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'SBI ఖాతా నిలిపివేయబడుతుంది. వెంటనే OTP పంపండి మరియు ఈ లింక్ ద్వారా ధృవీకరించండి: http://sbi-verify.xyz/login',
  },
  {
    id: 'D1',
    title: 'Official SBI domain',
    expected: ['safe', 'uncertain'],
    emailText:
      'From: SBI Support <noreply@sbi.co.in>\nSubject: Account notice\n\nPlease review the latest notice in your official SBI portal. This is an informational update only.',
  },
  {
    id: 'D2',
    title: 'Suspicious SBI domain',
    expected: 'phishing',
    requireSignals: true,
    emailText:
      'From: SBI Login <noreply@sbi-secure-login.xyz>\nSubject: Verify now\n\nYour SBI access will be suspended unless you login and confirm immediately at http://sbi-secure-login.xyz/verify.',
  },
];

function expectedList(expected: Scenario['expected']): Classification[] {
  return Array.isArray(expected) ? expected : [expected];
}

function classify(score: number): Classification {
  if (score <= 25) return 'safe';
  if (score <= 60) return 'uncertain';
  return 'phishing';
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`${response.status} ${response.statusText} ${body}`.trim());
  }
  return (await response.json()) as T;
}

async function resolveReachableBaseUrl(candidates: string[], path: string): Promise<string> {
  for (const candidate of candidates) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    try {
      const response = await fetch(`${candidate}${path}`, {
        method: 'GET',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      if (response.ok) {
        return candidate;
      }
    } catch {
      clearTimeout(timeoutId);
    }
  }

  throw new Error(`No reachable service found for ${path} from: ${candidates.join(', ')}`);
}

function hasExplainability(payload: BackendResponse): boolean {
  const explanation = payload.explanation;
  if (!explanation || typeof explanation !== 'object') return false;
  return Object.keys(explanation).length > 0;
}

async function runBackendSuite() {
  const rows: Array<Record<string, string | number>> = [];
  let pass = 0;

  for (const scenario of scenarios) {
    const result = await fetchJson<BackendResponse>(`${BACKEND_URL}/scan-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: scenario.emailText }),
    });

    const score = Number(result.risk_score ?? 0);
    const actual = classify(score);
    const allowed = expectedList(scenario.expected);
    const signals = Array.isArray(result.signals) ? result.signals : [];
    const ok =
      allowed.includes(actual) &&
      Boolean(result.category) &&
      hasExplainability(result) &&
      (!scenario.requireSignals || signals.length > 0);

    if (ok) pass += 1;

    rows.push({
      Suite: 'backend',
      Case: scenario.id,
      Title: scenario.title,
      Expected: allowed.join('|'),
      Got: actual,
      Score: score,
      Verdict: result.verdict ?? 'n/a',
      Category: result.category ?? 'n/a',
      Signals: signals.length,
      Status: ok ? 'PASS' : 'FAIL',
    });
  }

  return { pass, total: scenarios.length, rows };
}

async function runFallbackSuite() {
  const subset = scenarios.filter((scenario) => scenario.checkFallback);
  const rows: Array<Record<string, string | number>> = [];
  let pass = 0;

  for (const scenario of subset) {
    const result = await fetchJson<FallbackResponse>(`${FRONTEND_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: DEV_AUTH,
      },
      body: JSON.stringify({ emailText: scenario.emailText, headers: '' }),
    });

    const score = Number(result.riskScore ?? 0);
    const actual = typeof result.classification === 'string'
      ? (result.classification.toLowerCase() as Classification)
      : classify(score);
    const allowed = expectedList(scenario.expected);
    const reasons = Array.isArray(result.reasons) ? result.reasons : [];
    const ok = allowed.includes(actual) && reasons.length > 0 && Boolean(result.attackType);

    if (ok) pass += 1;

    rows.push({
      Suite: 'fallback',
      Case: scenario.id,
      Title: scenario.title,
      Expected: allowed.join('|'),
      Got: actual,
      Score: score,
      AttackType: result.attackType ?? 'n/a',
      Reasons: reasons.length,
      Status: ok ? 'PASS' : 'FAIL',
    });
  }

  return { pass, total: subset.length, rows };
}

async function runConsistencyCheck() {
  const sample = scenarios.filter((scenario) => ['P2', 'A3', 'S1'].includes(scenario.id));
  const rows: Array<Record<string, string | number>> = [];
  let pass = 0;

  for (const scenario of sample) {
    const first = await fetchJson<BackendResponse>(`${BACKEND_URL}/scan-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: scenario.emailText }),
    });
    const second = await fetchJson<BackendResponse>(`${BACKEND_URL}/scan-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_text: scenario.emailText }),
    });

    const firstClass = classify(Number(first.risk_score ?? 0));
    const secondClass = classify(Number(second.risk_score ?? 0));
    const stable = firstClass === secondClass && (first.category ?? '') === (second.category ?? '');
    if (stable) pass += 1;

    rows.push({
      Suite: 'consistency',
      Case: scenario.id,
      First: `${firstClass} / ${first.category ?? 'n/a'}`,
      Second: `${secondClass} / ${second.category ?? 'n/a'}`,
      Status: stable ? 'PASS' : 'FAIL',
    });
  }

  return { pass, total: sample.length, rows };
}

async function checkHealth() {
  const backendHealth = await fetchJson<Record<string, unknown>>(`${BACKEND_URL}/health`);
  return {
    backendStatus: String(backendHealth.status ?? 'unknown'),
    model: String(backendHealth.model_used ?? 'unknown'),
    device: String(backendHealth.device ?? 'unknown'),
  };
}

async function main() {
  BACKEND_URL = await resolveReachableBaseUrl(BACKEND_CANDIDATES, '/health');
  FRONTEND_URL = await resolveReachableBaseUrl(FRONTEND_CANDIDATES, '/');

  console.log('\n🧪 PhishShield Final Validation Runner');
  console.log(`Backend:  ${BACKEND_URL}`);
  console.log(`Frontend: ${FRONTEND_URL}`);

  const health = await checkHealth();
  console.log(`\nHealth: ${health.backendStatus} | Model: ${health.model} | Device: ${health.device}`);

  const backend = await runBackendSuite();
  const fallback = await runFallbackSuite();
  const consistency = await runConsistencyCheck();

  const allRows = [...backend.rows, ...fallback.rows, ...consistency.rows];
  console.table(allRows);

  const overallPass = backend.pass + fallback.pass + consistency.pass;
  const overallTotal = backend.total + fallback.total + consistency.total;

  const distinctScores = new Set(
    backend.rows.map((row) => Number(row.Score)).filter((value) => Number.isFinite(value)),
  );
  const realisticConfidence = distinctScores.size > 3;

  console.log(`\nBackend:     ${backend.pass}/${backend.total}`);
  console.log(`Fallback:    ${fallback.pass}/${fallback.total}`);
  console.log(`Consistency: ${consistency.pass}/${consistency.total}`);
  console.log(`Confidence realism check: ${realisticConfidence ? 'PASS' : 'FAIL'}`);
  console.log(`\nFINAL RESULT: ${overallPass}/${overallTotal}`);

  if (overallPass !== overallTotal || !realisticConfidence) {
    process.exitCode = 1;
    console.error('\n❌ Validation suite found one or more failures.');
    return;
  }

  console.log('\n✅ All validation checks passed. System is interview-ready.');
  console.log('SYSTEM VERIFIED: 0 CRITICAL ERRORS');
}

main().catch((error) => {
  console.error('\n❌ Validation runner crashed:', error instanceof Error ? error.message : error);
  process.exit(1);
});
