/**
 * DOMAIN INTELLIGENCE ENGINE — URL & domain risk analysis
 *
 * Analyzes URLs for lookalike domains, suspicious patterns,
 * phishing keywords in domain names, and TLD risk.
 */

import {
  areDomainsSameFamily,
  detectBrandFromText,
  isDomainTrustedForBrand,
  normalizeDomainForComparison,
} from "./brandTrust";

export type DomainRiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface DomainIntelResult {
  riskLevel: DomainRiskLevel;
  riskScore: number; // 0–100
  hasAnyLink: boolean;
  hasSuspiciousLink: boolean;
  hasLookalikePatterns: boolean;
  hasPhishingKeywords: boolean;
  hasHighRiskTLD: boolean;
  hasShortener: boolean;
  hasPunycodeOrIdn: boolean;
  hasEncodedRedirect: boolean;
  hasIpLiteral: boolean;
  detectedBrand: string | null;
  hasTrustedBrandMismatch: boolean;
  hasSenderLinkMismatch: boolean;
  findings: string[];
}

// Lookalike patterns — character substitutions attackers use
const LOOKALIKE_PATTERNS = [
  { pattern: /amaz[o0]n|arnazon/i, brand: "Amazon" },
  { pattern: /g[o0]{2}gle|goog1e/i, brand: "Google" },
  { pattern: /netfl[i1]x/i, brand: "Netflix" },
  { pattern: /payt[m][\-_]?secure/i, brand: "Paytm" },
  { pattern: /paypa[l1]/i, brand: "PayPal" },
  { pattern: /coinbase-|co1nbase|coinb[a4]se/i, brand: "Coinbase" },
  { pattern: /[i1]c[i1]c[i1]/i, brand: "ICICI" },
  { pattern: /h[d]fc[\-_]?bank/i, brand: "HDFC" },
  { pattern: /m[i1]crosoft/i, brand: "Microsoft" },
  { pattern: /fl[i1]pkart/i, brand: "Flipkart" },
  { pattern: /sb[i1][\-_]?on/i, brand: "SBI" },
  { pattern: /d0cusign|docu[s5]ign/i, brand: "DocuSign" },
  { pattern: /0utl00k|outl[o0]{2}k/i, brand: "Outlook" },
  { pattern: /dr[o0]pbox/i, brand: "Dropbox" },
];

// Phishing keywords in domain names
const DOMAIN_PHISHING_KEYWORDS = [
  "login",
  "signin",
  "verify",
  "update",
  "secure",
  "account",
  "confirm",
  "banking",
  "auth",
  "validate",
  "recover",
  "restore",
  "unlock",
  "alert",
  "notification",
  "billing",
  "payment",
  "parcel",
  "delivery",
  "shipment",
  "tracking",
  "credit",
  "loan",
  "subscription",
  "renew",
  "cancel",
  "beneficiary",
];

// Suspicious URL path patterns
const SUSPICIOUS_PATH_PATTERNS = [
  /\/login\b/i,
  /\/verify\b/i,
  /\/update[\-_]?account/i,
  /\/secure[\-_]?login/i,
  /\/confirm[\-_]?identity/i,
  /\/(?:apply|renew|cancel|billing|payment|delivery|reschedule|tracking|parcel)\b/i,
  /\.php\?.*=(token|id|user|session|redirect)/i,
  /\/redirect\?/i,
];

const HIGH_RISK_TLDS = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".xyz",
  ".top",
  ".work",
  ".click",
  ".buzz",
  ".gq",
  ".sbs",
  ".cfd",
  ".monster",
  ".bond",
  ".su",
  ".cc",
  ".site",
  ".online",
  ".icu",
  ".vip",
];

const NEUTRAL_HOSTING_DOMAINS = [
  "web.app",
  "firebaseapp.com",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "github.io",
  "appspot.com",
  "onrender.com",
  "notion.site",
];

const TRUSTED_BRAND_FAMILY_DOMAINS = [
  "amazon.com",
  "amazon.in",
  "amazon.co.uk",
  "amazonaws.com",
  "amazonses.com",
  "aws.amazon.com",
  "google.com",
  "googleapis.com",
  "accounts.google.com",
  "microsoft.com",
  "microsoftonline.com",
  "office.com",
  "sharepoint.com",
  "live.com",
  "outlook.com",
  "paypal.com",
  "openai.com",
  "tm.openai.com",
  "stripe.com",
  "cursor.com",
  "cursor.sh",
  "notion.so",
  "github.com",
  "gitlab.com",
  "slack.com",
  "discord.com",
  "linkedin.com",
  "huggingface.co",
  "hf.co",
  "quora.com",
  "beehiiv.com",
  "sns.amazonaws.com",
];

function isTrustedBrandFamilyDomain(domain: string): boolean {
  return TRUSTED_BRAND_FAMILY_DOMAINS.some(
    (trusted) => domain === trusted || domain.endsWith(`.${trusted}`),
  );
}

function looksLikeIpHost(domain: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain);
}

function countKeywordHits(domain: string): number {
  return DOMAIN_PHISHING_KEYWORDS.filter((keyword) => domain.includes(keyword)).length;
}

export function analyzeDomainIntel(
  urls: { domain: string; fullUrl: string; isSuspicious: boolean }[],
  context: { senderDomain?: string; emailText?: string } = {},
): DomainIntelResult {
  const findings: string[] = [];
  let riskScore = 0;
  let hasLookalikePatterns = false;
  let hasPhishingKeywords = false;
  let hasHighRiskTLD = false;
  let hasSuspiciousLink = false;
  let hasShortener = false;
  let hasPunycodeOrIdn = false;
  let hasEncodedRedirect = false;
  let hasIpLiteral = false;
  let hasTrustedBrandMismatch = false;
  let hasSenderLinkMismatch = false;

  const senderDomain = normalizeDomainForComparison(context.senderDomain ?? "");
  const detectedBrand = detectBrandFromText(context.emailText ?? "", [
    senderDomain,
    ...urls.map((url) => url.domain),
  ]);
  const hasRiskyKeywordContext = /\b(verify|update|login|payment|refund)\b/i.test(context.emailText ?? "");

  if (urls.length === 0) {
    return {
      riskLevel: "safe",
      riskScore: 0,
      hasAnyLink: false,
      hasSuspiciousLink: false,
      hasLookalikePatterns: false,
      hasPhishingKeywords: false,
      hasHighRiskTLD: false,
      hasShortener: false,
      hasPunycodeOrIdn: false,
      hasEncodedRedirect: false,
      hasIpLiteral: false,
      detectedBrand,
      hasTrustedBrandMismatch: false,
      hasSenderLinkMismatch: false,
      findings: ["No URLs found in email"],
    };
  }

  for (const url of urls) {
    const domainLower = url.domain.toLowerCase();
    const fullUrlLower = url.fullUrl.toLowerCase();
    const isTrustedBrandFamily = isTrustedBrandFamilyDomain(domainLower);
    const normalizedDomain = domainLower
      .replace(/0/g, "o")
      .replace(/[1i|!]/g, "l")
      .replace(/5/g, "s")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/8/g, "b")
      .replace(/_/g, "-");
    const keywordHits = countKeywordHits(domainLower);
    const hyphenCount = (domainLower.match(/-/g) ?? []).length;
    const hasSensitivePath = SUSPICIOUS_PATH_PATTERNS.some((pattern) => pattern.test(fullUrlLower));
    const hasTrustedOAuthConsentPattern =
      /(?:accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com)$/i.test(domainLower) &&
      /(oauth|authorize|consent|permissions?)/i.test(fullUrlLower) &&
      /(client_id=|scope=|prompt=consent|response_type=|access_type=|redirect_uri=)/i.test(fullUrlLower);

    if (url.isSuspicious) {
      hasSuspiciousLink = true;
      riskScore += 20;
      findings.push(`Suspicious URL detected: ${url.domain}`);
    }

    if (fullUrlLower.includes("@") && fullUrlLower.match(/https?:\/\/[^@]+@/)) {
      hasLookalikePatterns = true;
      hasSuspiciousLink = true;
      riskScore += 50;
      findings.push(`URL auth spoofing detected: ${url.domain}`);
    }

    if (domainLower.startsWith("xn--")) {
      hasPunycodeOrIdn = true;
      hasSuspiciousLink = true;
      riskScore += 35;
      findings.push(`Punycode or IDN domain detected: ${url.domain}`);
    }

    if (looksLikeIpHost(domainLower)) {
      hasIpLiteral = true;
      hasSuspiciousLink = true;
      riskScore += 35;
      findings.push(`IP-literal host detected instead of a branded domain: ${url.domain}`);
    }

    if (hasTrustedOAuthConsentPattern) {
      hasSuspiciousLink = true;
      riskScore += 28;
      findings.push(`Legitimate OAuth or app-consent flow detected — these pages can still be abused to request mailbox or file access`);
    }

    if (
      !isTrustedBrandFamily &&
      NEUTRAL_HOSTING_DOMAINS.some((host) => domainLower === host || domainLower.endsWith(`.${host}`)) &&
      (hasSensitivePath || /(login|verify|secure|auth|review|consent|oauth)/i.test(fullUrlLower))
    ) {
      hasSuspiciousLink = true;
      riskScore += 18;
      findings.push(`Cloud-hosted or user-controlled site is presenting a login or review flow: ${url.domain}`);
    }

    if (!isTrustedBrandFamily) {
      for (const { pattern, brand } of LOOKALIKE_PATTERNS) {
        const brandLower = brand.toLowerCase();
        if (
          (pattern.test(domainLower) || normalizedDomain.includes(brandLower)) &&
          !domainLower.includes(`${brandLower}.`) &&
          domainLower !== `${brandLower}.com` &&
          domainLower !== `${brandLower}.in`
        ) {
          hasLookalikePatterns = true;
          hasSuspiciousLink = true;
          riskScore += 50;
          findings.push(`Adversarial lookalike domain detected for ${brand}: ${url.domain}`);
          break;
        }
      }
    }

    if (
      detectedBrand &&
      !isDomainTrustedForBrand(domainLower, detectedBrand) &&
      (normalizedDomain.includes(detectedBrand) || domainLower.includes(detectedBrand) || keywordHits > 0 || url.isSuspicious)
    ) {
      hasTrustedBrandMismatch = true;
      hasSuspiciousLink = true;
      riskScore += 60;
      findings.push(`Brand/domain mismatch detected: ${detectedBrand} is mentioned, but ${url.domain} is not an official ${detectedBrand} domain`);
    }

    if (senderDomain && !areDomainsSameFamily(senderDomain, domainLower)) {
      const sameTrustedBrandFamily =
        detectedBrand &&
        isDomainTrustedForBrand(senderDomain, detectedBrand) &&
        isDomainTrustedForBrand(domainLower, detectedBrand);

      if (!sameTrustedBrandFamily) {
        hasSenderLinkMismatch = true;
        riskScore += 40;
        findings.push(`Sender and link domains do not match: ${senderDomain} → ${url.domain}`);
      }
    }

    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "ow.ly", "cutt.ly", "is.gd", "v.gd", "rb.gy"];
    const officialShorteners = ["c.gle", "lnkd.in"];

    if (shorteners.some((s) => domainLower === s)) {
      hasShortener = true;
      hasSuspiciousLink = true;
      riskScore += 15;
      findings.push(`URL shortener hides the final destination: ${url.domain}`);
    } else if (officialShorteners.some((s) => domainLower === s)) {
      hasShortener = true;
      findings.push(`Official brand shortener detected: ${url.domain}`);
    }

    if (!isTrustedBrandFamily && keywordHits > 0) {
      hasPhishingKeywords = true;
      riskScore += keywordHits >= 2 ? 18 : 10;
      findings.push(
        keywordHits >= 2
          ? `Multiple phishing-style keywords appear in the domain: ${url.domain}`
          : `Phishing-style keyword found in the domain: ${url.domain}`,
      );
    }

    if (HIGH_RISK_TLDS.some((tld) => domainLower.endsWith(tld))) {
      hasHighRiskTLD = true;
      hasSuspiciousLink = true;
      riskScore += 25;
      findings.push(`High-risk TLD detected: ${url.domain}`);
    }

    if (!isTrustedBrandFamily && domainLower.split(".").length > 3) {
      riskScore += 12;
      findings.push(`Deep subdomain chain detected: ${url.domain}`);
    }

    if (!isTrustedBrandFamily && hyphenCount >= 2 && keywordHits > 0) {
      riskScore += 12;
      findings.push(`Low-trust multi-hyphen domain pattern detected: ${url.domain}`);
    }

    if (!isTrustedBrandFamily && /(?:redirect|return|target|next|dest|continue)=https?/i.test(fullUrlLower)) {
      hasEncodedRedirect = true;
      hasSuspiciousLink = true;
      riskScore += 18;
      findings.push(`Redirect-style URL parameters detected: ${url.domain}`);
    }

    if (!isTrustedBrandFamily && hasSensitivePath) {
      hasSuspiciousLink = true;
      riskScore += 12;
      findings.push(`Suspicious URL path pattern detected`);
    }

    if (
      !isTrustedBrandFamily &&
      /(credit|loan|payment|billing|subscription|parcel|delivery|tracking)/i.test(domainLower) &&
      /(apply|cancel|renew|reschedule|track|confirm|review)/i.test(fullUrlLower)
    ) {
      hasSuspiciousLink = true;
      riskScore += 16;
      findings.push(`Low-trust finance or delivery landing page pattern detected: ${url.domain}`);
    }
  }

  if (hasTrustedBrandMismatch && urls.length > 0) {
    riskScore = Math.max(riskScore, 85);
  }

  if (
    hasRiskyKeywordContext &&
    (hasTrustedBrandMismatch || hasHighRiskTLD || hasSuspiciousLink || hasLookalikePatterns)
  ) {
    hasSuspiciousLink = true;
    riskScore = Math.max(riskScore, 80);
    findings.push("Keyword + suspicious domain combination detected (verify/update/login/payment/refund)");
  }

  riskScore = Math.min(100, riskScore);

  let riskLevel: DomainRiskLevel;
  if (riskScore >= 70) riskLevel = "critical";
  else if (riskScore >= 50) riskLevel = "high";
  else if (riskScore >= 30) riskLevel = "medium";
  else if (riskScore >= 10) riskLevel = "low";
  else riskLevel = "safe";

  return {
    riskLevel,
    riskScore,
    hasAnyLink: urls.length > 0,
    hasSuspiciousLink,
    hasLookalikePatterns,
    hasPhishingKeywords,
    hasHighRiskTLD,
    hasShortener,
    hasPunycodeOrIdn,
    hasEncodedRedirect,
    hasIpLiteral,
    detectedBrand,
    hasTrustedBrandMismatch,
    hasSenderLinkMismatch,
    findings,
  };
}
