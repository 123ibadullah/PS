/**
 * TRUST ENGINE — Domain reputation & header integrity
 *
 * Calculates how much to trust the sender based on structural signals.
 * NOT content-based. Purely structural/header analysis.
 */

import { detectBrandFromText, isDomainTrustedForBrand } from "./brandTrust";

export interface TrustResult {
  trustScore: number; // 0 (untrusted) to 100 (fully trusted)
  isTrustedDomain: boolean;
  isKnownSender: boolean;
  hasHeaderSpoof: boolean;
  senderHasRiskyTLD: boolean;
  limitedHeaderAnalysis: boolean;
  senderLinkMismatch: boolean;
  spoofingScore: number;
  detectedBrand: string | null;
  trustFactors: string[]; // Human-readable factors
}

// Trusted domains — real services that send legitimate OTPs and notifications
const TRUSTED_DOMAINS = [
  "amazon.com",
  "amazon.in",
  "amazon.co.uk",
  "amazonaws.com",
  "amazonses.com",
  "aws.amazon.com",
  "google.com",
  "accounts.google.com",
  "googleapis.com",
  "zoom.us",
  "docusign.net",
  "dropbox.com",
  "okta.com",
  "teams.microsoft.com",
  "netflix.com",
  "mailer.netflix.com",
  "icicibank.com",
  "hdfcbank.com",
  "sbi.co.in",
  "flipkart.com",
  "paypal.com",
  "microsoft.com",
  "outlook.com",
  "apple.com",
  "cursor.sh",
  "cursor.com",
  "notion.so",
  "github.com",
  "gitlab.com",
  "razorpay.com",
  "paytm.com",
  "phonepe.com",
  "zomato.com",
  "mailers.zomato.com",
  "swiggy.in",
  "openai.com",
  "tm.openai.com",
  "mandrillapp.com",
  "stripe.com",
  "sns.amazonaws.com",
  "huggingface.co",
  "hf.co",
  "quora.com",
  "beehiiv.com",
  "mail.beehiiv.com",
  "slack.com",
  "discord.com",
  "linkedin.com",
  "medium.com",
  "substack.com",
  "irctc.co.in",
  "noreply.github.com",
  "twitter.com",
  "x.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "spotify.com",
  "uber.com",
  "ola.in",
  "myntra.com",
  "nykaa.com",
  "zerodha.com",
  "groww.in",
  "cred.club",
  "axisbank.com",
  "c.gle",
];

// High-risk TLDs — commonly used by attackers
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
];

export function analyzeTrust(
  senderDomain: string,
  spoofingRisk: string,
  hasHeaders: boolean,
  urlDomains: string[],
  context: { emailText?: string; detectedBrand?: string | null } = {},
): TrustResult {
  const domain = senderDomain.toLowerCase();
  const trustFactors: string[] = [];
  let trustScore = 50; // Neutral baseline
  let spoofingScore = 0;
  let senderLinkMismatch = false;
  const limitedHeaderAnalysis = !hasHeaders;
  const detectedBrand =
    context.detectedBrand ??
    detectBrandFromText(context.emailText ?? "", [domain, ...urlDomains]);

  // Check if sender is from a trusted domain
  const isKnownSender = TRUSTED_DOMAINS.some(
    (t) => domain === t || domain.endsWith("." + t),
  );

  if (isKnownSender) {
    trustScore += 35;
    trustFactors.push("Sender matches a known trusted domain");
  }

  if (limitedHeaderAnalysis) {
    trustFactors.push("Limited header analysis (no raw headers provided)");
  }

  // Check all URLs in the email for trusted domains
  const allUrlsTrusted =
    urlDomains.length > 0 &&
    urlDomains.every((d) => {
      const dl = d.toLowerCase();
      return TRUSTED_DOMAINS.some((t) => dl === t || dl.endsWith("." + t));
    });

  if (allUrlsTrusted) {
    trustScore += 10;
    trustFactors.push("All links point to trusted domains");
  }

  // Check header spoofing
  let hasHeaderSpoof = hasHeaders && spoofingRisk !== "none";
  if (hasHeaderSpoof) {
    trustScore -= 40;
    spoofingScore = Math.max(
      spoofingScore,
      spoofingRisk === "high" ? 80 : spoofingRisk === "medium" ? 60 : 40,
    );
    trustFactors.push("Email headers show signs of spoofing");
  }

  if (detectedBrand && domain && !isDomainTrustedForBrand(domain, detectedBrand)) {
    hasHeaderSpoof = true;
    spoofingScore = Math.max(spoofingScore, 50);
    trustScore -= 50;
    trustFactors.push(`Sender domain does not match the trusted ${detectedBrand} domain family`);
  }

  // Check risky TLDs
  const senderHasRiskyTLD = HIGH_RISK_TLDS.some((tld) => domain.endsWith(tld));
  if (senderHasRiskyTLD) {
    trustScore -= 35;
    trustFactors.push("Sender uses a high-risk disposable domain TLD");
  }

  // Check if URLs use risky TLDs
  const urlsHaveRiskyTLD = urlDomains.some((d) =>
    HIGH_RISK_TLDS.some((tld) => d.toLowerCase().endsWith(tld)),
  );
  if (urlsHaveRiskyTLD) {
    trustScore -= 20;
    trustFactors.push("Links point to high-risk domain TLDs");
  }

  const mismatchedUrlDomains = urlDomains.filter((candidate) => {
    const normalized = candidate.toLowerCase();
    return normalized && normalized !== domain && !normalized.endsWith(`.${domain}`) && !domain.endsWith(`.${normalized}`);
  });

  if (domain && mismatchedUrlDomains.length > 0 && !allUrlsTrusted) {
    senderLinkMismatch = true;
    spoofingScore = Math.max(spoofingScore, 40);
    trustScore -= 15;
    trustFactors.push("Sender domain and linked domains do not match");
  }

  // Clamp
  trustScore = Math.max(0, Math.min(100, trustScore));

  return {
    trustScore,
    isTrustedDomain: isKnownSender || allUrlsTrusted,
    isKnownSender,
    hasHeaderSpoof,
    senderHasRiskyTLD,
    limitedHeaderAnalysis,
    senderLinkMismatch,
    spoofingScore,
    detectedBrand,
    trustFactors,
  };
}
