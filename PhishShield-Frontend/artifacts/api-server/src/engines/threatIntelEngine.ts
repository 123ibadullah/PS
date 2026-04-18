import type { UrlAnalysis } from "@workspace/api-zod";

export interface ThreatIntelResult {
  reputationScore: number;
  hasKnownBadInfrastructure: boolean;
  maliciousDomains: string[];
  matchedIndicators: string[];
  recommendedAction: "allow" | "review" | "block";
}

const BUILT_IN_BLOCKED_DOMAINS = new Set([
  "secure-access-reset.xyz",
  "evil-site.xyz",
  "amaz0n-secure.net",
  "paypa1-secure.xyz",
  "hdfc-verify.xyz",
  "sbi-verify.xyz",
  "amazon-claim.ml",
]);

const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.ly", "rebrand.ly", "shorturl.at", "cutt.ly"];
const RISKY_TLDS = [".xyz", ".top", ".click", ".site", ".icu", ".shop", ".vip"];
const NEUTRAL_HOSTING_DOMAINS = ["web.app", "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io", "appspot.com", "onrender.com", "notion.site"];

function dedupe(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function readEnvBlocklist(): Set<string> {
  const raw = process.env.PHISHSHIELD_BLOCKED_DOMAINS || process.env.PHISHSHIELD_IOC_DOMAINS || "";
  return new Set(
    raw
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

export function analyzeThreatIntel(
  urlAnalyses: Array<Pick<UrlAnalysis, "url" | "domain" | "riskScore" | "flags" | "isSuspicious">>,
  senderDomain: string,
  emailText: string,
): ThreatIntelResult {
  const envBlocklist = readEnvBlocklist();
  const maliciousDomains: string[] = [];
  const matchedIndicators: string[] = [];
  let reputationScore = 0;

  for (const item of urlAnalyses) {
    const domain = String(item.domain || "").toLowerCase();
    const fullUrl = String(item.url || "").toLowerCase();

    if (!domain) continue;

    if (BUILT_IN_BLOCKED_DOMAINS.has(domain) || envBlocklist.has(domain)) {
      maliciousDomains.push(domain);
      matchedIndicators.push(`Known bad infrastructure match: ${domain}`);
      reputationScore = Math.max(reputationScore, 95);
    }

    if (domain.startsWith("xn--")) {
      matchedIndicators.push(`Punycode / IDN domain detected: ${domain}`);
      reputationScore = Math.max(reputationScore, 72);
    }

    if (URL_SHORTENERS.includes(domain)) {
      matchedIndicators.push(`URL shortener hides the final destination: ${domain}`);
      reputationScore = Math.max(reputationScore, 48);
    }

    if (RISKY_TLDS.some((tld) => domain.endsWith(tld))) {
      matchedIndicators.push(`High-risk TLD observed: ${domain}`);
      reputationScore = Math.max(reputationScore, 55);
    }

    if (
      NEUTRAL_HOSTING_DOMAINS.some((host) => domain === host || domain.endsWith(`.${host}`)) &&
      /\/(?:login|signin|verify|secure|auth|unlock|wallet|recovery|reset|payroll|invoice|beneficiary|review|consent|oauth)/i.test(fullUrl)
    ) {
      matchedIndicators.push(`Cloud-hosted or user-controlled app page is presenting a login or review flow: ${domain}`);
      reputationScore = Math.max(reputationScore, 62);
    }

    if (
      /(?:accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com)/i.test(domain) &&
      /(oauth|authorize|consent|scope=|client_id=|prompt=consent)/i.test(fullUrl)
    ) {
      matchedIndicators.push(`OAuth consent or app-permission flow detected on a legitimate identity provider domain`);
      reputationScore = Math.max(reputationScore, 68);
    }

    if (/\/(?:login|signin|verify|secure|auth|unlock|wallet|recovery|reset|payroll|invoice|beneficiary)/i.test(fullUrl) && !domain.endsWith(senderDomain.toLowerCase())) {
      matchedIndicators.push(`High-risk path pattern detected: ${domain}`);
      reputationScore = Math.max(reputationScore, 64);
    }

    if (item.isSuspicious || (item.flags || []).length > 0) {
      reputationScore = Math.max(reputationScore, item.riskScore || 0);
    }
  }

  if (/seed phrase|wallet|private key|authorize app|grant consent|scan the qr|password protected/i.test(emailText.toLowerCase())) {
    matchedIndicators.push("Message matches modern credential or wallet-theft lure patterns");
    reputationScore = Math.max(reputationScore, 60);
  }

  const hasKnownBadInfrastructure = maliciousDomains.length > 0;
  const recommendedAction: ThreatIntelResult["recommendedAction"] = hasKnownBadInfrastructure
    ? "block"
    : reputationScore >= 50
      ? "review"
      : "allow";

  return {
    reputationScore: Math.max(0, Math.min(100, reputationScore)),
    hasKnownBadInfrastructure,
    maliciousDomains: dedupe(maliciousDomains),
    matchedIndicators: dedupe(matchedIndicators).slice(0, 8),
    recommendedAction,
  };
}
