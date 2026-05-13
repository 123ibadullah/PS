/**
 * Email header parser.
 *
 * Detects whether the input is a full RFC 5322 email (headers + body) or
 * just the body, extracts header fields, and runs a spoofing risk analysis.
 */

export type HeaderAnalysis = {
  hasHeaders: boolean;
  senderEmail?: string;
  senderDomain?: string;
  displayName?: string;
  replyToEmail?: string;
  replyToDomain?: string;
  mismatch: boolean;
  spoofingRisk: "none" | "low" | "medium" | "high";
  issues: string[];
  headerScore: number;
};

const SUSPICIOUS_SENDER_TLDS = [
  ".xyz",
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".pw",
  ".top",
  ".club",
  ".online",
  ".site",
  ".icu",
];

const FREEMAIL_DOMAINS = [
  "gmail.com",
  "yahoo.com",
  "yahoo.in",
  "hotmail.com",
  "outlook.com",
  "rediffmail.com",
  "yandex.com",
  "protonmail.com",
];

const NEWSLETTER_INFRA_DOMAINS = [
  "beehiiv.com",
  "mailchimp.com",
  "sendgrid.net",
  "sendgrid.com",
  "amazonses.com",
  "mailgun.org",
  "mailgun.net",
  "hubspotemail.net",
  "mktomail.com",
  "mandrillapp.com",
  "convertkit-mail.com",
  "substack.com",
  "mailerlite.com",
  "constantcontact.com",
  "getresponse.com",
];

const CORPORATE_CLAIMANTS = [
  "sbi",
  "hdfc",
  "icici",
  "axis",
  "paytm",
  "phonepe",
  "gpay",
  "irctc",
  "uidai",
  "incometax",
  "epfo",
  "amazon",
  "flipkart",
];

function extractEmail(
  raw: string,
): { email: string; displayName: string; domain: string } | null {
  // Match "Display Name <email@domain.com>" or bare "email@domain.com"
  const angleMatch = raw.match(/<([^>]+@[^>]+)>/);
  const email = angleMatch
    ? angleMatch[1].trim()
    : (raw
        .trim()
        .split(/\s+/)
        .find((s) => s.includes("@")) ?? "");
  if (!email.includes("@")) return null;

  const domain = email.split("@")[1]?.toLowerCase() ?? "";
  const displayMatch = raw.match(/^([^<]+)</);
  const displayName = displayMatch
    ? displayMatch[1].trim().replace(/^["']|["']$/g, "")
    : "";

  return { email: email.toLowerCase(), displayName, domain };
}

function parseHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  // Headers are everything before the first blank line
  const blankLine = text.search(/\r?\n\r?\n/);
  const headerSection =
    blankLine !== -1 ? text.slice(0, blankLine) : text.slice(0, 1000);

  // Unfold headers (continuation lines start with whitespace)
  const unfolded = headerSection.replace(/\r?\n[ \t]+/g, " ");

  for (const line of unfolded.split(/\r?\n/)) {
    const colonIdx = line.indexOf(":");
    if (colonIdx < 1) continue;
    const name = line.slice(0, colonIdx).toLowerCase().trim();
    const value = line.slice(colonIdx + 1).trim();
    // Keep first occurrence (some headers repeat; From/Reply-To we care about first)
    if (!headers[name]) headers[name] = value;
  }

  return headers;
}

function isSuspiciousDomain(domain: string): boolean {
  return SUSPICIOUS_SENDER_TLDS.some((tld) => domain.endsWith(tld));
}

function isFreeMail(domain: string): boolean {
  return FREEMAIL_DOMAINS.includes(domain);
}

function isKnownNewsletterInfrastructure(domain: string): boolean {
  return NEWSLETTER_INFRA_DOMAINS.some(
    (provider) => domain === provider || domain.endsWith(`.${provider}`),
  );
}

function isLikelyLegitimateReplyRouting(fromDomain: string, replyToDomain: string): boolean {
  return (
    !!fromDomain &&
    !!replyToDomain &&
    fromDomain !== replyToDomain &&
    isKnownNewsletterInfrastructure(fromDomain) &&
    !isFreeMail(replyToDomain) &&
    !isSuspiciousDomain(replyToDomain)
  );
}

function claimsKnownBrand(displayName: string, domain: string): string | null {
  const combined = (displayName + " " + domain).toLowerCase();
  for (const brand of CORPORATE_CLAIMANTS) {
    if (combined.includes(brand)) return brand;
  }
  return null;
}

function hasHeaderPatterns(text: string): boolean {
  // Look for at least two of the classic header fields within the first 500 chars
  const sample = text.slice(0, 800);
  const headerFields = [
    "From:",
    "To:",
    "Subject:",
    "Date:",
    "Received:",
    "MIME-Version:",
    "Return-Path:",
    "Reply-To:",
  ];
  let found = 0;
  for (const f of headerFields) {
    if (new RegExp(`^${f}`, "im").test(sample)) found++;
    if (found >= 2) return true;
  }
  return false;
}

export function analyzeEmailHeaders(text: string): HeaderAnalysis {
  if (!hasHeaderPatterns(text)) {
    return {
      hasHeaders: false,
      mismatch: false,
      spoofingRisk: "none",
      issues: [],
      headerScore: 0,
    };
  }

  const headers = parseHeaders(text);

  const fromRaw = headers["from"] ?? "";
  const replyToRaw = headers["reply-to"] ?? headers["replyto"] ?? "";
  const returnPathRaw = headers["return-path"] ?? "";
  const subjectRaw = headers["subject"] ?? "";
  const xSpamStatus = headers["x-spam-status"] ?? "";
  const xSpamScore = headers["x-spam-score"] ?? "";

  const fromParsed = extractEmail(fromRaw);
  const replyToParsed = replyToRaw ? extractEmail(replyToRaw) : null;
  const returnPathParsed = returnPathRaw ? extractEmail(returnPathRaw) : null;

  const issues: string[] = [];
  let score = 0;

  // ── From/Reply-To domain mismatch ────────────────────────────────────────
  const fromDomain = fromParsed?.domain ?? "";
  const replyToDomain = replyToParsed?.domain ?? "";
  const hasLegitimateReplyRouting = isLikelyLegitimateReplyRouting(
    fromDomain,
    replyToDomain,
  );
  const mismatch = !!(
    replyToDomain &&
    fromDomain &&
    fromDomain !== replyToDomain &&
    !hasLegitimateReplyRouting
  );

  if (mismatch) {
    issues.push(
      `Reply-To domain (${replyToDomain}) differs from sender domain (${fromDomain}) — replies go to a different address than the sender`,
    );
    score += 35;
  }

  // ── Suspicious TLD in sender domain ──────────────────────────────────────
  if (fromDomain && isSuspiciousDomain(fromDomain)) {
    issues.push(
      `Sender domain uses a high-risk TLD (${fromDomain}) — commonly used for disposable phishing addresses`,
    );
    score += 30;
  }

  // ── Freemail impersonating a brand ───────────────────────────────────────
  if (fromParsed && isFreeMail(fromDomain)) {
    const brand = claimsKnownBrand(fromParsed.displayName, fromDomain);
    if (brand) {
      issues.push(
        `Display name suggests "${brand.toUpperCase()}" but email is sent from a free personal account (${fromDomain}) — not an official domain`,
      );
      score += 40;
    }
  }

  // ── Display name vs domain mismatch ──────────────────────────────────────
  if (fromParsed?.displayName) {
    const brand = claimsKnownBrand(fromParsed.displayName, "");
    if (brand && fromDomain && !fromDomain.includes(brand)) {
      const alreadyReported = issues.some((i) =>
        i.includes(brand.toUpperCase()),
      );
      if (!alreadyReported) {
        issues.push(
          `The name "${fromParsed.displayName}" claims to be from ${brand.toUpperCase()} but the actual sending address (${fromDomain}) is unrelated`,
        );
        score += 35;
      }
    }
  }

  // ── Return-Path domain different from From ────────────────────────────────
  const returnDomain = returnPathParsed?.domain ?? "";
  if (returnDomain && fromDomain && returnDomain !== fromDomain && !mismatch) {
    issues.push(
      `Bounce path (${returnDomain}) differs from sender (${fromDomain}) — a sign of email spoofing infrastructure`,
    );
    score += 20;
  }

  // ── X-Spam headers flagged by mail server ────────────────────────────────
  if (xSpamStatus.toLowerCase().startsWith("yes")) {
    issues.push(
      "This email was already flagged as spam by the receiving mail server",
    );
    score += 25;
  }
  if (xSpamScore) {
    const numScore = parseFloat(xSpamScore);
    if (!isNaN(numScore) && numScore > 5) {
      issues.push(
        `Mail server spam score is ${numScore.toFixed(1)} — above the typical safe threshold of 5.0`,
      );
      score += 15;
    }
  }

  // ── Suspicious subject patterns ───────────────────────────────────────────
  const urgentSubject =
    /urgent|immediate|action required|account|suspended|verify|kyc|otp/i.test(
      subjectRaw,
    );
  const allCapsSubject =
    subjectRaw.length > 5 && subjectRaw === subjectRaw.toUpperCase();
  if (urgentSubject && allCapsSubject) {
    issues.push(
      "Subject line is written in all capitals with urgency keywords — a common phishing tactic",
    );
    score += 15;
  }

  const finalScore = Math.min(score, 100);

  let spoofingRisk: "none" | "low" | "medium" | "high";
  if (finalScore >= 60) spoofingRisk = "high";
  else if (finalScore >= 35) spoofingRisk = "medium";
  else if (finalScore > 0) spoofingRisk = "low";
  else spoofingRisk = "none";

  return {
    hasHeaders: true,
    senderEmail: fromParsed?.email,
    senderDomain: fromDomain || undefined,
    displayName: fromParsed?.displayName || undefined,
    replyToEmail: replyToParsed?.email,
    replyToDomain: replyToDomain || undefined,
    mismatch,
    spoofingRisk,
    issues,
    headerScore: finalScore,
  };
}
