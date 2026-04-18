import { AnalyzeEmailResponse } from "@workspace/api-zod";
import type {
  AnalyzeResult,
  UrlAnalysis,
  DetectionReason,
  SuspiciousSpan,
} from "@workspace/api-zod";
import { hybridScore, type FeatureContribution } from "./transformerModel.js";
import { analyzeEmailHeaders, type HeaderAnalysis } from "./emailHeaderParser";
import { detectAdversarialAttacks } from "./adversarialDetector.js";
import { reviewWithFrontierModel } from "./frontierModel.js";
import { analyzePolymorphicCampaign } from "./polymorphicDetector.js";
import { analyzeIndiaThreatHeuristics } from "./indiaThreatHeuristics.js";

// ─── Modular Engine Imports ───────────────────────────────────────────────────
import { analyzeIntent } from "../engines/intentEngine";
import { analyzeTrust } from "../engines/trustEngine";
import { analyzeDomainIntel } from "../engines/domainEngine";
import { analyzeBehavior } from "../engines/behaviorEngine";
import { analyzeContext } from "../engines/contextEngine";
import { makeDecision } from "../engines/decisionEngine";
import { generateExplanation } from "../engines/explanationEngine";
import { detectBrandFromText } from "../engines/brandTrust";
import {
  computeConfidenceScore,
  mapConfidenceValueToLevel,
  mapRiskScoreToConfidenceLevel,
  scoreToDeterministicConfidence,
} from "../engines/confidenceEngine";
import {
  analyzeAttachments,
  type AttachmentContext,
} from "../engines/attachmentEngine";
import { analyzeThreatIntel } from "../engines/threatIntelEngine";
import { buildPreventionPlan } from "../engines/preventionEngine";

// ─── Language detection ───────────────────────────────────────────────────────
// We check for Devanagari (Hindi) and Telugu Unicode ranges.
// If both appear in the same email it's a mixed-language message.
function detectLanguage(text: string): string {
  const hasHindi = /[\u0900-\u097F]/.test(text);
  const hasTelugu = /[\u0C00-\u0C7F]/.test(text);
  if (hasHindi && hasTelugu) return "mixed";
  if (hasHindi) return "hi";
  if (hasTelugu) return "te";
  return "en";
}

function shouldUseFrontierReview(localScore: number): boolean {
  const hasLlmFallback = Boolean(
    process.env.PHISHSHIELD_LLM_API_URL ||
      process.env.PHISHSHIELD_FRONTIER_URL ||
      process.env.PHISHSHIELD_LOCAL_MODEL_URL,
  );

  if (!hasLlmFallback) {
    return false;
  }

  const mode = (process.env.PHISHSHIELD_FRONTIER_MODE ?? "smart").toLowerCase();
  if (mode === "off" || mode === "disabled") {
    return false;
  }

  if (mode === "always") {
    return true;
  }

  return localScore >= 30 && localScore <= 70;
}

// ─── Keyword lists ────────────────────────────────────────────────────────────
// These feed both the rule-based scorer and the highlighted span finder.

const URGENCY_WORDS = [
  "urgent",
  "urgently",
  "immediate",
  "immediately",
  "asap",
  "now",
  "act now",
  "right away",
  "right now",
  "limited time",
  "24h",
  "24 hours",
  "48 hours",
  "hours left",
  "deadline",
  "final notice",
  "last chance",
  "today",
  "tonight",
  "next hour",
  "before noon",
  "before end of day",
  "end of day",
  "quickly",
  // Hindi / Hinglish / Telugu urgency words
  "तुरंत",
  "तत्काल",
  "जल्दी",
  "अभी",
  "jaldi",
  "abhi",
  "turant",
  "వెంటనే",
  "త్వరగా",
  "ఇప్పుడే",
];

const FINANCIAL_SCAM_WORDS = [
  "prize",
  "winner",
  "won",
  "reward",
  "cash prize",
  "lottery",
  "jackpot",
  "congratulations",
  "selected",
  "lucky draw",
  "free money",
  "claim",
  "refund",
  "refund available",
  "claim refund",
  "rs.",
  "rs ",
  "rupees",
  "lakh",
  "crore",
  "₹",
  "upi",
  "paytm",
  "phonepe",
  "gpay",
  "google pay",
  "bhim",
  "neft",
  "rtgs",
  "wallet",
  "cashback",
  "refund pending",
  "kyc",
  "know your customer",
  "pan card",
  "aadhaar",
  "income tax",
  "tax notice",
  "penalty",
  "bank account",
  "credit card",
  "debit card",
  "card details",
  "billing details",
  "otp",
  "one time password",
  "transaction failed",
  "payment pending",
  "payment failed",
  "transfer",
  // Hindi financial words
  "इनाम",
  "जीत",
  "पैसे",
  "बधाई",
  "रुपये",
];

const SOCIAL_ENGINEERING_WORDS = [
  "dear customer",
  "dear user",
  "dear member",
  "dear account holder",
  "your account",
  "your profile",
  "login credentials",
  "password",
  "click here",
  "click the link",
  "visit the link",
  "follow the link",
  "do not share",
  "do not disclose",
  "confidential",
  "security alert",
  "unauthorized access",
  "suspicious activity",
  "login attempt",
  "confirm your identity",
  "verify your identity",
  "prove your identity",
  "provide your",
  "enter your",
  "submit your",
  "update your",
  "failure to comply",
  "legal action",
  "court action",
  "police complaint",
];

const CREDENTIAL_REQUEST_WORDS = [
  "otp",
  "one time password",
  "password",
  "pin",
  "passcode",
  "cvv",
  "credentials",
  "bank details",
  "billing details",
  "card details",
  "verify your identity",
  "confirm your identity",
  "verify your account",
  "verify your profile",
  "sign-in details",
  "identity information",
  "identity details",
  "mailbox credentials",
  "mailbox ownership",
  "reactivate mailbox",
  "enter your",
  "reset password",
  "secure your account",
];

const CRYPTO_SCAM_WORDS = [
  "btc",
  "bitcoin",
  "crypto",
  "wallet",
  "double money",
  "double your btc",
  "instant return",
  "guaranteed return",
  "send 0.1 btc",
  "get 0.2 btc",
];

const JOB_SCAM_WORDS = [
  "candidate",
  "job selection",
  "offer letter",
  "interview",
  "recruitment",
  "joining",
  "registration fee",
  "processing fee",
  "security deposit",
  "confirm your job selection",
];

const SHORT_SCAM_PHRASES = [
  "verify now",
  "verify your account",
  "verify your profile",
  "act now",
  "send otp",
  "urgent",
  "immediately",
  "immediate verification required",
  "verification required",
  "confirm now",
  "confirm your sign-in details",
  "update now",
  "update required",
  "reply now",
  "reset password",
  "secure your account",
  "secure login",
  "secure login required",
  "login required",
  "reactivate mailbox",
  "important update",
  "update account",
  "confirm credentials",
  "submit details",
  "submit identity information",
  "action required",
  "bank alert",
];

// Indian banks and payment services — used for impersonation detection
const INDIA_SPECIFIC_BANKS = [
  "sbi",
  "state bank",
  "hdfc",
  "icici",
  "axis bank",
  "punjab national",
  "pnb",
  "bank of baroda",
  "bob",
  "canara bank",
  "union bank",
  "indian bank",
  "uco bank",
  "kotak",
  "yes bank",
  "indusind",
  "rbl bank",
  "idfc",
  "federal bank",
  "karnataka bank",
];

const INDIA_SPECIFIC_SERVICES = [
  "paytm",
  "phonepe",
  "phone pe",
  "gpay",
  "google pay",
  "bhim upi",
  "amazon pay",
  "mobikwik",
  "freecharge",
  "airtel payments",
  "jio payments",
  "ippb",
  "india post",
  "irctc",
  "uidai",
  "aadhaar",
  "pan",
  "epfo",
  "income tax",
  "gst",
  "eway bill",
  "itr",
  "form 16",
];

// TLDs that are free/abused and show up constantly in phishing campaigns
const SUSPICIOUS_TLDS = [
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
  ".work",
  ".loan",
  ".click",
  ".link",
  ".info",
  ".biz",
  ".sbs",
  ".cfd",
  ".monster",
  ".bond",
  ".su",
  ".cc",
];

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "goo.su",
  "ow.ly",
  "short.io",
  "rebrand.ly",
  "cutt.ly",
  "tiny.cc",
  "bl.ink",
  "clk.sh",
  "is.gd",
  "v.gd",
  "rb.gy",
  "c.gle",
  "lnkd.in",
];

// Regex patterns for lookalike domains (e.g. "sbi-secure-login.xyz")
const LOOKALIKE_PATTERNS: [RegExp, string][] = [
  [/paypa[l1]|payp4l/i, "PayPal lookalike domain"],
  [/coinbase-|co1nbase|coinb[a4]se/i, "Coinbase lookalike domain"],
  [/g00gle|g0ogle|gooogle|goog1e/i, "Google lookalike domain"],
  [/amaz0n|am4zon|amazzon|arnazon/i, "Amazon lookalike domain"],
  [/faceb00k|f4cebook|faceb0ok/i, "Facebook lookalike domain"],
  [/sb[i1]-|sb[i1]\.|sbi-online|sbi_online/i, "SBI lookalike domain"],
  [/hdf[c0]-|hdfcbank-/i, "HDFC lookalike domain"],
  [/icic[i1]-|icicibankk/i, "ICICI lookalike domain"],
  [/payt[m0]-|paytrn/i, "Paytm lookalike domain"],
  [/ph0nepe|phonep3/i, "PhonePe lookalike domain"],
  [/d0cusign|docu[s5]ign/i, "DocuSign lookalike domain"],
  [/0utl00k|outl[o0]{2}k/i, "Outlook lookalike domain"],
  [/dr[o0]pbox/i, "Dropbox lookalike domain"],
  [/[a-z]+-secure-|secure-[a-z]+\./i, "Fake 'secure' domain pattern"],
  [/[a-z]+-update\./i, "Fake 'update' domain pattern"],
  [/[a-z]+-verify\./i, "Fake 'verify' domain pattern"],
  [/[a-z]+-alert\./i, "Fake 'alert' domain pattern"],
  [/[a-z]+-kyc\./i, "Fake 'KYC' domain pattern"],
  [/[a-z]+-reward\./i, "Fake 'reward' domain pattern"],
  [/[a-z]+-claim\./i, "Fake 'claim' domain pattern"],
];

function matchesKeyword(text: string, keyword: string): boolean {
  const normalized = String(keyword || '').trim();
  if (!normalized) return false;
  if (normalized === '₹') return text.includes(normalized);

  const escaped = normalized
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\s+/g, "\\s+");

  if (/[a-z0-9]/i.test(normalized)) {
    return new RegExp(`(?:^|\\b)${escaped}(?:\\b|$)`, 'i').test(text);
  }

  return new RegExp(escaped, 'i').test(text);
}

function stripMailboxChromeArtifacts(text: string): string {
  const cleaned = text
    .split(/\r?\n/)
    .filter((line) => {
      const normalized = line.trim().toLowerCase();
      if (!normalized) return true;

      return !(
        normalized === "skip to content" ||
        normalized === "using gmail with screen readers" ||
        normalized === "enable desktop notifications for gmail." ||
        normalized === "ok" ||
        normalized === "no, thanks" ||
        normalized === "report as not spam" ||
        normalized === "none selected" ||
        /^(?:spam|inbox)$/i.test(normalized) ||
        /^in:(?:spam|inbox|drafts?|sent|important|starred)\b/i.test(normalized) ||
        /^\d+\s+of\s+\d+$/i.test(normalized) ||
        /^why is this message in spam\?/i.test(normalized) ||
        /^this message is similar to messages that were identified as spam in the past\.?$/i.test(normalized)
      );
    })
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return cleaned || text;
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

function extractUrls(text: string): string[] {
  const collectMatches = (regex: RegExp, skipEmailDomains = false): string[] => {
    const matches: string[] = [];
    for (const match of text.matchAll(regex)) {
      const value = match[0];
      const index = match.index ?? -1;
      const prevChar = index > 0 ? text[index - 1] : "";

      if (skipEmailDomains && prevChar === "@") {
        continue;
      }

      matches.push(value);
    }
    return matches;
  };

  const urlRegex =
    /https?:\/\/[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+/gi;
  const standardMatches = collectMatches(urlRegex);

  const suspiciousTldPattern = SUSPICIOUS_TLDS.map((tld) => tld.replace(/^\./, "")).join("|");
  const bareDomainRegex = new RegExp(
    "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:" +
      suspiciousTldPattern +
      ")(?:\\/[^\\s<>\"{}|\\\\^`\\[\\]]*)?\\b",
    "gi",
  );
  const bareMatches = collectMatches(bareDomainRegex, true);

  const shortenerPattern = URL_SHORTENERS.map((domain) => domain.replace(/\./g, "\\.")).join("|");
  const shortenerRegex = new RegExp(
    "\\b(?:" + shortenerPattern + ")(?:\\/[^\\s<>\"{}|\\\\^`\\[\\]]*)?\\b",
    "gi",
  );
  const shortenerMatches = collectMatches(shortenerRegex, true);

  const riskyKeywordDomainRegex = /\b(?:[a-z0-9-]*?(?:google|amazon|paypal|microsoft|dropbox|docusign|outlook|coinbase|binance|metamask|sbi|hdfc|icici|paytm|phonepe|login|verify|secure|account|update|support|alert|review|payroll|wallet|beneficiary|reward)[a-z0-9-]*\.)+[a-z]{2,}(?:\.[a-z]{2,})*(?:\/[^\s<>"{}|\\^`\[\]]*)?\b/gi;
  const riskyKeywordMatches = collectMatches(riskyKeywordDomainRegex, true);

  return [...new Set([...standardMatches, ...bareMatches, ...shortenerMatches, ...riskyKeywordMatches])];
}

function extractDomain(url: string): string {
  try {
    const normalized = url.startsWith("www.") ? "http://" + url : url;
    const parsed = new URL(normalized);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    // If URL parsing fails, pull the hostname out manually
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase().replace(/[.,;:!?]+$/, "") : url;
  }
}

function analyzeUrl(url: string): UrlAnalysis {
  const domain = extractDomain(url);
  const flags: string[] = [];
  let score = 0;
  const isTrustedServiceDomain =
    /(?:^|\.)(amazonaws\.com|amazonses\.com|aws\.amazon\.com|amazon\.com|amazon\.in|google\.com|accounts\.google\.com|meet\.google\.com|huggingface\.co|hf\.co|quora\.com|dropbox\.com|docusign\.net|zoom\.us|openai\.com|onedrive\.com|microsoft\.com|microsoftonline\.com|office\.com|sharepoint\.com|live\.com)$/i.test(
      domain,
    );

  const tld = "." + domain.split(".").pop();
  const domainKeywordHits =
    domain.match(/login|verify|secure|account|update|confirm|kyc|claim|reward|billing|payment|parcel|delivery|shipment|tracking|credit|loan|subscription|cancel|beneficiary/gi)?.length ?? 0;
  const hyphenCount = (domain.match(/-/g) ?? []).length;
  const hasTrustedOauthConsentPattern =
    /(?:accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com)$/i.test(domain) &&
    /(oauth|authorize|consent|scope=|client_id=|prompt=consent|response_type=|redirect_uri=)/i.test(url);

  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push(`Suspicious TLD: ${tld}`);
    score += 30;
  }

  if (domain.startsWith("xn--")) {
    flags.push("Punycode or IDN domain detected");
    score += 35;
  }

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
    flags.push("IP-based URL detected");
    score += 35;
  }

  if (hasTrustedOauthConsentPattern) {
    flags.push("OAuth or app-consent flow on a legitimate identity provider can still be abused");
    score += 28;
  }

  if (URL_SHORTENERS.some((s) => domain.includes(s))) {
    flags.push("URL shortener detected");
    score += 25;
  }

  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain)) {
      flags.push(label);
      score += 40;
      break;
    }
  }

  if (domain.split(".").length > 3 && !isTrustedServiceDomain) {
    flags.push("Suspicious subdomain structure");
    score += 15;
  }

  if (/[0-9]/.test(domain.split(".")[0]) && !isTrustedServiceDomain) {
    flags.push("Domain contains numbers (suspicious)");
    score += 10;
  }

  if (!isTrustedServiceDomain && domainKeywordHits > 0) {
    flags.push(
      domainKeywordHits >= 2
        ? "Multiple high-risk keywords in domain name"
        : "Suspicious keyword in domain name",
    );
    score += domainKeywordHits >= 2 ? 18 : 12;
  }

  if (!isTrustedServiceDomain && hyphenCount >= 2 && domainKeywordHits > 0) {
    flags.push("Low-trust multi-hyphen domain pattern");
    score += 12;
  }

  if (url.length > 100 && !isTrustedServiceDomain) {
    flags.push("Unusually long URL");
    score += 10;
  }

  if (/token=|session=|verify=|otp=|password=|pin=|redirect=|return=|continue=/i.test(url) && !isTrustedServiceDomain) {
    flags.push("Sensitive or redirect parameters in URL");
    score += 20;
  }

  if (/\/(?:apply|renew|cancel|billing|payment|delivery|reschedule|tracking|parcel|confirm|review)\b/i.test(url) && !isTrustedServiceDomain) {
    flags.push("Suspicious action-oriented URL path");
    score += 12;
  }

  if (
    !isTrustedServiceDomain &&
    /(credit|loan|payment|billing|subscription|parcel|delivery|tracking)/i.test(domain) &&
    /\/(?:apply|renew|cancel|delivery|reschedule|track|billing|payment|review)/i.test(url)
  ) {
    flags.push("Low-trust finance or delivery landing page");
    score += 16;
  }

  if (
    isTrustedServiceDomain &&
    /unsubscribe|support|help|email_confirmation|confirm(?:ation)?/i.test(url)
  ) {
    score = Math.min(score, 5);
  }

  score = Math.min(score, 100);

  return {
    url,
    domain,
    riskScore: score,
    flags,
    isSuspicious: score >= 30,
  };
}

// ─── Suspicious span finder ───────────────────────────────────────────────────
// Finds character positions of matched keywords and URLs so the frontend
// can highlight them in the original email text.

function findSuspiciousSpans(
  text: string,
  matchedTerms: string[],
): SuspiciousSpan[] {
  const spans: SuspiciousSpan[] = [];
  const lowerText = text.toLowerCase();

  for (const term of matchedTerms) {
    const lowerTerm = term.toLowerCase();
    let idx = 0;
    while (idx < lowerText.length) {
      const pos = lowerText.indexOf(lowerTerm, idx);
      if (pos === -1) break;
      spans.push({
        start: pos,
        end: pos + term.length,
        text: text.slice(pos, pos + term.length),
        reason: `Suspicious term: "${term}"`,
      });
      idx = pos + 1;
    }
  }

  // Also mark every URL found in the email
  for (const url of extractUrls(text)) {
    const pos = text.indexOf(url);
    if (pos !== -1) {
      spans.push({
        start: pos,
        end: pos + url.length,
        text: url,
        reason: "URL detected",
      });
    }
  }

  // Sort and merge overlapping spans so we don't get double-highlights
  spans.sort((a, b) => a.start - b.start);
  const merged: SuspiciousSpan[] = [];
  for (const span of spans) {
    if (merged.length === 0 || span.start > merged[merged.length - 1].end) {
      merged.push(span);
    } else {
      const last = merged[merged.length - 1];
      if (span.end > last.end) {
        last.end = span.end;
        last.text = text.slice(last.start, last.end);
        last.reason = last.reason + "; " + span.reason;
      }
    }
  }

  return merged;
}

function getReasonSignalKey(reason: DetectionReason): string {
  const description = reason.description.toLowerCase();

  if (reason.category === "ml_score") {
    if (/llm fallback/.test(description)) {
      return "ml_score:llm_fallback";
    }
    if (/semantic phishing pattern|transformer semantics/.test(description)) {
      return "ml_score:semantic";
    }
    if (/legitimate otp/i.test(description)) {
      return "ml_score:safe_otp";
    }
    if (/transactional alert|payment notification|standard communication/i.test(description)) {
      return "ml_score:safe_transactional";
    }
  }

  return reason.category;
}

function mergeDetectionReasons(...reasonSets: DetectionReason[][]): DetectionReason[] {
  const severityRank = { low: 1, medium: 2, high: 3 } as const;
  const merged = new Map<string, DetectionReason>();

  for (const set of reasonSets) {
    for (const reason of set) {
      const key = getReasonSignalKey(reason);
      const existing = merged.get(key);

      if (existing) {
        existing.matchedTerms = [
          ...new Set([...existing.matchedTerms, ...reason.matchedTerms]),
        ].slice(0, 8);

        const existingRank = severityRank[existing.severity];
        const incomingRank = severityRank[reason.severity];
        if (
          incomingRank > existingRank ||
          (incomingRank === existingRank && reason.description.length > existing.description.length)
        ) {
          existing.description = reason.description;
          existing.severity = reason.severity;
        }
      } else {
        merged.set(key, {
          ...reason,
          matchedTerms: [...new Set(reason.matchedTerms)].slice(0, 8),
        });
      }
    }
  }

  return [...merged.values()];
}

function isWeakGenericReason(reason: DetectionReason): boolean {
  const description = reason.description.toLowerCase().trim();
  return [
    "general analysis inference detected potential risk patterns.",
    "general analysis suggests potential risk patterns.",
    "no threatening intent detected. this appears to be a standard communication.",
  ].includes(description);
}

function isConcreteModelReason(reason: DetectionReason): boolean {
  return reason.category === "ml_score" && /llm fallback|semantic phishing pattern|transformer semantics/i.test(reason.description);
}

function getReasonPriority(reason: DetectionReason): number {
  const description = reason.description.toLowerCase();

  if (/password|otp|pin\b|cvv|credential|identity|sensitive/i.test(description)) return 100;
  if (reason.category === "url") return 90;
  if (reason.category === "urgency") return 80;
  if (reason.category === "header" || reason.category === "domain" || reason.category === "india_specific") return 70;
  if (reason.category === "financial") return /payment|invoice|transfer|refund|fee|wallet|crypto|reward|prize|cashback/i.test(description) ? 60 : 35;
  if (reason.category === "social_engineering") return /business email compromise|bec|attachment|qr/i.test(description) ? 65 : 25;
  if (reason.category === "ml_score") return 15;
  return 10;
}

function sanitizeDisplayMatchedTerms(matchedTerms: string[]): string[] {
  return [...new Set(matchedTerms.filter(Boolean).map((term) => term.trim()))]
    .filter((term) => !/^(leet-|homoglyph-|mixed-script|zero-width-chars|invisible-separators|bidi-control-chars|html-entity-|numeric-html-entities|base64-encoded|noise-injection|excessive-benign-content)/i.test(term))
    .slice(0, 3);
}

function normalizeDisplayReason(reason: DetectionReason): DetectionReason {
  const description = reason.description.toLowerCase();
  const matchedTerms = sanitizeDisplayMatchedTerms(reason.matchedTerms);

  if (reason.category === "urgency") {
    return {
      ...reason,
      description: "Uses explicit urgency to push quick action.",
      matchedTerms,
    };
  }

  if (reason.category === "url") {
    return {
      ...reason,
      description: /lookalike|brand/i.test(description)
        ? "Contains a suspicious or lookalike link."
        : "Contains a suspicious link or risky destination.",
      matchedTerms,
    };
  }

  if (reason.category === "header" || reason.category === "domain" || reason.category === "india_specific") {
    return {
      ...reason,
      description:
        reason.category === "india_specific" && /kyc|upi|aadhaar|pan|regional/i.test(description)
          ? "Matches a common KYC, UPI, or regional phishing pattern."
          : "Shows signs of sender or brand impersonation.",
      matchedTerms,
    };
  }

  if (reason.category === "financial") {
    if (matchedTerms.some((term) => /delivery fee scam|customs release fee/i.test(term))) {
      return {
        ...reason,
        description: "Uses a fake delivery or customs fee pretext.",
        matchedTerms,
      };
    }

    if (matchedTerms.some((term) => /subscription renewal bait|cancel-now billing lure/i.test(term))) {
      return {
        ...reason,
        description: "Uses a subscription renewal or cancellation lure with a payment-style action.",
        matchedTerms,
      };
    }

    if (matchedTerms.some((term) => /credit offer lure|loan bait/i.test(term))) {
      return {
        ...reason,
        description: "Promises easy credit or low-interest financing to push a risky click.",
        matchedTerms,
      };
    }

    const hasConcreteMoneyTerm = matchedTerms.some((term) =>
      /invoice|payment|transfer|refund|fee|billing|wallet|crypto|cashback|reward|prize|beneficiary/i.test(term),
    );

    return {
      ...reason,
      description: hasConcreteMoneyTerm
        ? "Pushes a payment or money-related request."
        : "Uses a financial lure to pressure a response.",
      matchedTerms,
    };
  }

  if (reason.category === "social_engineering") {
    if (/password|otp|pin\b|cvv|credential|identity|sensitive/i.test(description)) {
      const keySensitiveTerms = matchedTerms
        .flatMap((term) => term.split(/[\/,]/).map((part) => part.trim()))
        .filter((term) => /otp|password|pin\b|cvv|credential|aadhaar|pan|bank details|card details|billing details|identity/i.test(term))
        .map((term) => {
          if (/^otp$/i.test(term)) return "OTP";
          if (/^pin$/i.test(term)) return "PIN";
          if (/^cvv$/i.test(term)) return "CVV";
          if (/^aadhaar$/i.test(term)) return "Aadhaar";
          if (/^pan$/i.test(term)) return "PAN";
          return term.toLowerCase();
        })
        .filter((term, index, array) => array.indexOf(term) === index)
        .slice(0, 2);
      const detail = keySensitiveTerms.length > 0 ? ` such as your ${keySensitiveTerms.join(" or ")}` : "";
      return {
        ...reason,
        description: `Requests sensitive information${detail}.`,
        matchedTerms: keySensitiveTerms.length > 0 ? keySensitiveTerms : matchedTerms,
      };
    }

    if (/telegram|whatsapp|off-platform|job scam|employment scam|refundable deposit/i.test(description)) {
      return {
        ...reason,
        description: "Moves the conversation off-platform and follows a job-scam style pretext.",
        matchedTerms,
      };
    }

    if (/business email compromise|bec|executive|invoice fraud/i.test(description)) {
      return {
        ...reason,
        description: "Uses an impersonation or executive-style pretext to push action.",
        matchedTerms,
      };
    }

    if (/attachment|qr/i.test(description)) {
      return {
        ...reason,
        description: "Pushes you to open an attachment or scan a QR code.",
        matchedTerms,
      };
    }

    return {
      ...reason,
      description: "Uses a suspicious account or action prompt.",
      matchedTerms,
    };
  }

  return {
    ...reason,
    matchedTerms,
  };
}

function finalizeDisplayReasons(
  reasons: DetectionReason[],
  classification: "safe" | "uncertain" | "phishing",
): DetectionReason[] {
  const deduped = mergeDetectionReasons(reasons)
    .filter((reason) => reason.description.trim().length > 0)
    .map(normalizeDisplayReason);
  const hasConcreteNonModelReason = deduped.some(
    (reason) => reason.category !== "ml_score" && reason.category !== "informational",
  );
  const hasHighImpactReason = deduped.some((reason) => getReasonPriority(reason) >= 70);

  const filtered = deduped.filter((reason) => {
    if (isWeakGenericReason(reason)) {
      return classification === "safe" && !hasConcreteNonModelReason;
    }

    if (/obfuscation detected|hidden characters|encoded text|qr tricks/i.test(reason.description)) {
      return false;
    }

    if (reason.category === "ml_score" && hasConcreteNonModelReason && !isConcreteModelReason(reason)) {
      return false;
    }

    if (
      hasHighImpactReason &&
      reason.category === "social_engineering" &&
      getReasonPriority(reason) < 30
    ) {
      return false;
    }

    if (
      hasHighImpactReason &&
      reason.category === "financial" &&
      !reason.matchedTerms.some((term) => /invoice|payment|transfer|refund|fee|billing|wallet|crypto|cashback|reward|prize|beneficiary/i.test(term))
    ) {
      return false;
    }

    return true;
  });

  const prioritized = [...filtered].sort((a, b) => getReasonPriority(b) - getReasonPriority(a));

  if (classification === "safe") {
    return deduped.filter((reason) => reason.category === "informational").slice(0, 1);
  }

  if (prioritized.length > 0) {
    return prioritized.slice(0, 3);
  }

  return [{
    category: "social_engineering",
    description:
      "The message contains a suspicious request or account-related prompt that should be verified through an official channel.",
    severity: classification === "phishing" ? "high" : "medium",
    matchedTerms: [],
  }];
}

function toHumanConfidenceLabel(level: "LOW" | "MEDIUM" | "HIGH"): "Low" | "Medium" | "High" {
  if (level === "HIGH") return "High";
  if (level === "LOW") return "Low";
  return "Medium";
}

function toReadableConfidencePhrase(
  score: number,
  level: "LOW" | "MEDIUM" | "HIGH",
): string {
  if (score <= 25) return "low-risk indicators";
  if (level === "HIGH") return "strong confidence";
  if (level === "LOW") return "limited confidence";
  return "moderate confidence";
}

function buildDisplayLabel(
  riskScore: number,
  confidenceLevel: "LOW" | "MEDIUM" | "HIGH",
): string {
  const score = Math.max(0, Math.min(100, Math.round(riskScore)));
  const confidencePhrase = toReadableConfidencePhrase(score, confidenceLevel);

  if (score <= 14) return `🟢 ${score}% · Safe with ${confidencePhrase}`;
  if (score <= 25) return `🟡 ${score}% · Likely Safe with ${confidencePhrase}`;
  if (score <= 60) return `🟠 ${score}% · Suspicious with ${confidencePhrase}`;
  return `🔴 ${score}% · High Risk with ${confidencePhrase}`;
}

function buildDetectedSignals(
  classification: "safe" | "uncertain" | "phishing",
  reasons: DetectionReason[],
  attackType: string,
): string[] {
  if (classification === "safe") {
    return ["No strong phishing signals detected"];
  }

  const signals = new Map<string, number>();
  const addSignal = (signal: string, priority: number) => {
    if (!signal) return;
    const existing = signals.get(signal);
    if (existing === undefined || priority > existing) {
      signals.set(signal, priority);
    }
  };

  for (const reason of reasons) {
    switch (reason.category) {
      case "urgency":
        addSignal("Urgent or pressuring language", 80);
        break;
      case "financial":
        if (reason.matchedTerms.some((term) => /invoice|payment|transfer|beneficiary|refund|fee|pay|wallet|crypto/i.test(term))) {
          addSignal("Payment or money request", 60);
        }
        break;
      case "social_engineering":
        if (/otp|password|credential|identity|sensitive/i.test(reason.description)) {
          addSignal("Request for sensitive information", 100);
        } else if (/telegram|whatsapp|off-platform|job-scam/i.test(reason.description)) {
          addSignal("Off-platform move or recruiter-style scam", 75);
        } else if (/business email compromise|bec|executive/i.test(reason.description)) {
          addSignal("Possible sender impersonation", 70);
        } else {
          addSignal("Suspicious wording or unusual request", 15);
        }
        break;
      case "url":
        addSignal("Link to a suspicious website", 90);
        break;
      case "domain":
      case "header":
      case "india_specific":
        addSignal("Possible sender impersonation", 70);
        break;
      case "language":
        addSignal("Unusual language or script pattern", 20);
        break;
      case "ml_score":
        if (/llm fallback|semantic phishing pattern|transformer semantics/i.test(reason.description)) {
          addSignal("High-risk phishing pattern detected", 30);
        }
        break;
      case "informational":
        break;
    }
  }

  const rankedSignals = [...signals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([signal]) => signal)
    .slice(0, 3);

  if (rankedSignals.length === 0) {
    if (/OTP|Credential/i.test(attackType)) {
      return ["Request for sensitive information"];
    }
    if (/Reward Scam|Financial Scam/i.test(attackType)) {
      return ["Payment or money request"];
    }
    return ["Suspicious wording or unusual request"];
  }

  return rankedSignals;
}

function buildFriendlyExplanation(
  classification: "safe" | "uncertain" | "phishing",
  attackType: string,
  detectedSignals: string[],
  fallbackStory: string,
  reasons: DetectionReason[],
): string {
  const matchedTerms = reasons.flatMap((reason) => reason.matchedTerms.map((term) => term.toLowerCase()));
  const sensitivePriority = [
    "otp",
    "password",
    "pin",
    "cvv",
    "credentials",
    "bank details",
    "card details",
    "billing details",
    "aadhaar",
    "pan",
  ];
  const primarySensitiveTerm = sensitivePriority.find((term) => matchedTerms.includes(term));
  const readableSensitiveTerm = primarySensitiveTerm === "otp"
    ? "OTP"
    : primarySensitiveTerm === "pin"
      ? "PIN"
      : primarySensitiveTerm === "cvv"
        ? "CVV"
        : primarySensitiveTerm === "aadhaar"
          ? "Aadhaar"
          : primarySensitiveTerm === "pan"
            ? "PAN"
            : primarySensitiveTerm;

  if (classification === "safe") {
    return "This message looks routine and does not show the usual phishing signs.";
  }

  if (classification === "uncertain") {
    if (detectedSignals.includes("Link to a suspicious website")) {
      return "This message includes a suspicious link. Verify the sender before you click or reply.";
    }
    return "This message has a few warning signs, but not enough to confirm phishing. Verify it through an official channel before acting.";
  }

  if (
    detectedSignals.includes("Request for sensitive information") &&
    readableSensitiveTerm
  ) {
    if (detectedSignals.includes("Urgent or pressuring language")) {
      return `This message asks for your ${readableSensitiveTerm} and uses urgency, which is a strong sign of phishing.`;
    }
    return `This message asks for your ${readableSensitiveTerm}, which is a strong sign of a phishing attempt.`;
  }

  if (
    detectedSignals.includes("Possible business email compromise pattern") ||
    /business email compromise|bec/i.test(fallbackStory)
  ) {
    return "This message fits a possible business email compromise pattern and pushes for action without normal verification.";
  }

  if (
    detectedSignals.includes("Urgent or pressuring language") &&
    detectedSignals.includes("Payment or money request")
  ) {
    return "This message pressures you to make or confirm a payment quickly, which is common in phishing and invoice scams.";
  }

  if (detectedSignals.includes("Link to a suspicious website")) {
    return "This message includes a suspicious link that may lead to a fake sign-in or payment page.";
  }

  if (/Safe/.test(attackType)) {
    return "This message appears informational and does not show strong phishing signs.";
  }

  const conciseFallback = fallbackStory.trim();
  if (conciseFallback && conciseFallback.length <= 160) {
    return conciseFallback;
  }

  return "This message shows clear phishing signs and should not be trusted.";
}

function alignExplanationWithClassification(
  explanation: string,
  classification: "safe" | "uncertain" | "phishing",
): string {
  const normalized = explanation.toLowerCase();

  if (
    classification === "phishing" &&
    !/(phishing|scam|risky|danger|high risk|suspicious|do not trust|warning)/i.test(normalized)
  ) {
    return "⚠️ This may be a phishing attempt. It contains high-risk signals and should not be trusted.";
  }

  if (
    classification === "safe" &&
    /(phishing|scam|danger|high risk)/i.test(normalized) &&
    !/(does not show|no strong phishing signs|looks routine)/i.test(normalized)
  ) {
    return "This message looks routine and does not show the usual phishing signs.";
  }

  if (
    classification === "uncertain" &&
    /(looks routine|completely safe|no phishing signs)/i.test(normalized)
  ) {
    return "This message has a few warning signs, so verify it through an official channel before acting.";
  }

  return explanation;
}

// ─── Rule-based scorer ────────────────────────────────────────────────────────
// Pattern matching against known phishing indicators.
// Returns a score (0–100), the human-readable reasons, and all matched terms.

function computeRuleScore(text: string): {
  score: number;
  reasons: DetectionReason[];
  allTerms: string[];
  isSafeOtp: boolean;
  isSafeTransactional: boolean;
  isSoftTransaction: boolean;
  hasBenignBillingDashboardContext: boolean;
  isNoLinkPhishing: boolean;
  isNoLinkSocialEngineering: boolean;
  isRewardScam: boolean;
  isFinancialScam: boolean;
  isCryptoScam: boolean;
  isJobScam: boolean;
  isRegionalBankThreatPhishing: boolean;
  hasCredentialRequest: boolean;
  isSensitiveDataOverride: boolean;
  isShortScam: boolean;
  isPhoneScam: boolean;
  isCalmScam: boolean;
  isTrustedSafeLink: boolean;
  isAccountAlert: boolean;
  isHindiPhishing: boolean;
  isUrgencyPhishing: boolean;
} {
  const lower = text.toLowerCase();
  const proseLower = lower
    .replace(/(?:from|reply-to|return-path|subject):[^\n]+/gi, " ")
    .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const reasons: DetectionReason[] = [];
  const allTerms: string[] = [];
  let total = 0;

  const extractedUrls = extractUrls(text);
  const hasLinks = extractedUrls.length > 0;
  const rawHasStrongUrgency =
    /\burgent(?:ly)?\b|\bimmediate(?:ly)?\b|\basap\b|\bnow\b|\b(?:act now|right away|right now|final notice|deadline|last chance|limited time|today|tonight|next hour|before noon|before end of day|end of day|24h|24 hours|48 hours|within \d+\s*(?:hours?|hr)|quickly|lockout|locked\s*out)\b|keep\s+(?:\w+\s+){0,2}access|maintain\s+(?:\w+\s+){0,2}access|restore\s+(?:\w+\s+){0,2}access|jaldi|abhi|turant|తురంత|వెంటనే|త్వరగా|ఇప్పుడే|तुरंत|अभी|जल्दी/i.test(
      lower,
    );

  // ─── 1. SAFE OTP DETECTION ───
  const hasOtpOrCode = /otp|verification code|security code|one(?:-|\s)?time(?: password| code)?/i.test(lower);
  const hasSafeOtpPhrase = /do not share|don'?t share|never share|will never ask|किसी के साथ साझा न करें|साझा न करें|मत साझा करें|share mat karo|share मत करें/i.test(lower);
  const hasPassiveOtpSafetyContext =
    /if this was not you|if this wasn't you|did(?:n't| not) request (?:this|the)? ?(?:code|otp)|ignore this (?:message|email|notice)|can safely ignore|code will expire|expires? in \d+\s*(?:minutes?|mins?)|agar ye aap nahi the|koi action required nahi hai|कोई (?:कार्रवाई|action) (?:required|आवश्यक) नहीं है/i.test(
      lower,
    );
  const hasBenignBillingDashboardContext =
    /(subscription payment|billing (?:&|and) invoices|billing issue|could(?:n't| not) process payment|in your dashboard|official dashboard)/i.test(
      lower,
    ) &&
    /(dashboard|billing (?:&|and) invoices|reply to this email|reach out to us|support@|help@|hi@)/i.test(
      lower,
    ) &&
    !/(update billing details|update payment details|re-?enter (?:your )?(?:card|bank|payment|billing) details|provide.*(?:card|bank)|wire transfer|bank transfer|confirm payment|urgent|immediately|final notice|avoid suspension|within \d+ ?hours?)/i.test(
      lower,
    );
  const hasProtectiveSafeContext =
    hasSafeOtpPhrase ||
    hasPassiveOtpSafetyContext ||
    /if this was you|if this was not you|if this wasn't you|if you do not recognize (?:this device|it)|if you don't recognize (?:this device|it)|ignore if not you|ignore this (?:message|notice)|no action required|no action is required|can safely ignore|check (?:your )?account activity|check your account for any unauthorized activity|review (?:this )?activity|sign out of (?:this|the) device|official (?:website|site|app)|official app|agar ye aap the|agar ye aap nahi the|koi action required nahi hai|कोई (?:कार्रवाई|action) (?:required|आवश्यक) नहीं है|आधिकारिक (?:app|ऐप|site|website)|official app me review|official app se review/i.test(
      lower,
    );
  const hasSecurityNotificationContext =
    /(new sign(?:-|\s)?in|sign(?:-|\s)?in was detected|signed in to your account|new device|recognized device|new device(?: .*?)? signed in|unauthorized activity|security alert|sign out of this device|review this activity|login alert|naya login detect)/i.test(
      lower,
    ) &&
    /(if this was you|if this was not you|if this wasn't you|if you do not recognize (?:this device|it)|if you don't recognize (?:this device|it)|check (?:your )?account activity|check your account for any unauthorized activity|review (?:this )?activity|sign out of (?:this|the) device|no action required|can safely ignore|ignore this (?:message|notice)|agar ye aap the|agar ye aap nahi the|koi action required nahi hai|official app me review|official app se review)/i.test(
      lower,
    );
  const hasTrustedLinks = extractedUrls.every((u) =>
    /amazon\.(com|in|co\.uk|de|fr|ca|jp)|google\.com|c\.gle|cursor\.(?:sh|com)|\.cursor\.(?:sh|com)|flipkart\.com|netflix\.com|apple\.com|openai\.com|mandrillapp\.com|stripe\.com|hdfcbank\.com|icicibank\.com|axisbank\.com|sbi\.co\.in|paytm\.com|phonepe\.com|zomato\.com|swiggy\.in|cred\.club/i.test(u)
  );
  const hasOnlyLowRiskUrls = extractedUrls.every((u) => !analyzeUrl(u).isSuspicious);
  const protectiveContextStripped = proseLower
    .replace(/(?:do not|don'?t|never)\s+(?:share|disclose)\b[^.!?\n]*/gi, " ")
    .replace(/(?:किसी के साथ साझा न करें|साझा न करें|मत साझा करें|share mat karo|share मत करें)\b[^.!?\n]*/gi, " ")
    .replace(/will never ask\b[^.!?\n]*/gi, " ")
    .replace(/if (?:this was(?: not)? you|you do not recognize (?:this device|it)|you don't recognize (?:this device|it))\b[^.!?\n]*/gi, " ")
    .replace(/ignore (?:if not you|this (?:message|email|notice))\b[^.!?\n]*/gi, " ")
    .replace(/no action (?:is )?required\b[^.!?\n]*/gi, " ")
    .replace(/if you receive a suspicious e-?mail\b[^.!?\n]*/gi, " ")
    .replace(/do not click (?:on )?(?:the )?link\b[^.!?\n]*/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  const hasActionWordsForOtp = /\b(?:send|share|reply|provide|call)\b/i.test(
    protectiveContextStripped,
  );
  const isSafeOtp =
    hasOtpOrCode &&
    (hasSafeOtpPhrase || hasPassiveOtpSafetyContext) &&
    (hasTrustedLinks || !hasLinks || hasOnlyLowRiskUrls) &&
    !hasActionWordsForOtp;

  // ─── 2. LEGIT TRANSACTIONAL / PROMO EMAIL ───
  const isPromoMarketing =
    /apply now|introducing|unveiling|get your|exclusive offer|claim benefit|try\s+[a-z0-9'’\- ]{1,40}\s+for free|included in your .* plan|now in your .* plan|product update|feature update|newsletter|special offer|logging and training policies|privacy update|data retention/i.test(
      lower,
    );
  const hasNewsletterFooter =
    /unsubscribe|privacy\s*[·•|]\s*terms|privacy\b|terms\b|all rights reserved|©\s*20\d{2}|zero data retention|privacy dashboard/i.test(lower);
  const hasLegitPromotionalFooter =
    /(you(?:'re| are) getting this email because|change your notification settings|manage notification settings|update your email preferences|unsubscribe here|have questions\??\s*visit the help center|visit the help center|mailing list:|signed by:\s*[a-z0-9.-]+\.[a-z]{2,}|issued in partnership with|google india digital services private limited|powered by beehiiv)/i.test(
      lower,
    );
  const isTrustedPromotionalFinanceOffer =
    (isPromoMarketing || hasNewsletterFooter) &&
    hasLegitPromotionalFooter &&
    /(google pay|amazon|openai|chatgpt|cursor|rupay|axis bank|help center|product update|newsletter|promo|offer)/i.test(
      lower,
    ) &&
    !/(reply with|\bsend\b|\bshare\b|\bprovide\b|\benter\b|\bsubmit\b|otp|password|pin\b|passcode|credentials?|bank details|billing details|card details|cvv|wire transfer|bank transfer|beneficiary|crypto|wallet|reset password|secure your account|verify your identity|confirm payment)/i.test(
      lower,
    ) &&
    !/(avoid suspension|within \d+\s*(?:hours?|hr)|final notice|service disruption|account (?:will be )?closed|maintain access|restore access|lockout|unauthorized activity)/i.test(
      lower,
    );
  const isPolicyOrPrivacyUpdate =
    /(logging and training policies|data retention|zero data retention|\bzdr\b|privacy dashboard|train on your data|prompt logging|usage discount|paid requests never route|provider.*data retention|privacy settings)/i.test(
      lower,
    ) &&
    (hasNewsletterFooter || /privacy|policy|data retention|logging|training/i.test(lower)) &&
    !/(reply with|\bsend\b|\bshare\b|\bprovide\b|\benter\b|\bsubmit\b|otp|password|pin\b|passcode|credentials?|update billing details|update payment details|re-?enter (?:your )?(?:card|bank|payment|billing) details|wire transfer|bank transfer|confirm payment|urgent|immediately|avoid suspension|within \d+\s*(?:hours?|hr))/i.test(
      lower,
    );
  const isTransactional =
    isPolicyOrPrivacyUpdate ||
    /debited|credited|txn|transaction alert|subscri(?:bed|ption)|your new plan|payment method|order (?:number|date|placed|confirmation)|order has been shipped|shipment (?:is )?dispatched|tracking details|being processed|successfully (?:subscribed|signed up|placed)|thank you for your (?:purchase|order)/i.test(
      lower,
    );

  const hasBenignEditorialTimeContext =
    (isPromoMarketing || hasNewsletterFooter) &&
    /(past 24 hours|today(?:'s|’s)? newsletter|read online|update your email preferences|unsubscribe here|powered by beehiiv|welcome to .* recap|ai recap)/i.test(lower) &&
    !/urgent|immediate(?:ly)?|asap|final notice|avoid suspension|reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|otp|password|pin\b|credentials?|bank details|card details|billing details|wire transfer|bank transfer/i.test(lower);
  const hasStrongUrgency = rawHasStrongUrgency && !hasBenignEditorialTimeContext;
  const hasTransactionalActionRequest =
    !isPolicyOrPrivacyUpdate &&
    !hasBenignEditorialTimeContext &&
    ((/\b(?:update|verify|reset|secure|enter|submit|pay|transfer|approve)\b/i.test(proseLower) &&
      /(account|billing|bank|card|payment|invoice|security|identity|credentials?|profile|mailbox|service|details?)/i.test(proseLower)) ||
      /confirm (?:your|identity|details|payment)|update (?:card|billing|bank|account) details|card details|billing details|bank details|account details|claim now|refund available|pending invoice|service disruption/i.test(
        proseLower,
      ));
  const hasPromotionalUrgencyOnly =
    ((isPromoMarketing || hasNewsletterFooter) &&
      /(limited time|for a limited time|limited period|launch week|welcome benefits)/i.test(lower) &&
      !/urgent|immediate(?:ly)?|asap|final notice|avoid suspension|within \d+\s*(?:hours?|hr)|account (?:will be )?closed|service disruption/i.test(
        lower,
      ) &&
      !hasTransactionalActionRequest &&
      !/otp|one time password|password|passcode|billing details|card details|pin\b|cvv|credentials?|bank details|security code|pan\b|aadhaar|beneficiary|wallet details?|sign(?:-|\s)?in details?|identity (?:information|details?|documents?)|mailbox (?:credentials|ownership)|account verification|profile verification/i.test(
        lower,
      )) ||
    hasBenignEditorialTimeContext;
  const isSafeTransactional =
    (isTransactional || ((isPromoMarketing || hasNewsletterFooter) && (hasTrustedLinks || !hasLinks || hasOnlyLowRiskUrls))) &&
    (hasTrustedLinks || !hasLinks || hasOnlyLowRiskUrls) &&
    (!hasStrongUrgency || hasPromotionalUrgencyOnly) &&
    !/pending invoice|pay(?:ment)? immediately|process (?:a )?payment|transfer funds?|service disruption|jaldi|warna|band ho jayegi|block ho jayega/i.test(lower) &&
    !hasTransactionalActionRequest;

  // ─── 3. SOFT URGENCY TRANSACTION ───
  const hasMildUrgency =
    /contact immediately|call support|contact cus|helpdesk|reach out/i.test(
      lower,
    );
  const hasStrongPhishingWords =
    /verify\b|blocked|suspended|password|otp|click here|login/i.test(lower);
  const isSoftTransaction =
    isTransactional && !hasLinks && hasMildUrgency && !hasStrongPhishingWords;

  // ─── 4. HIGH-RISK REQUEST / NO-LINK PHISHING BOOST ───
  const hasActionRequest =
    /\b(?:call|contact|reply|send|share|provide|enter|confirm|verify|submit|update|claim|redeem|pay|transfer|approve|process|reset|secure|unlock|continue|proceed|check|review|click|bhej|batao|batana)\b|confirm payment|transfer funds?|send money|click link|\b\d{10}\b/i.test(
      proseLower,
    );
  const requestsSensitiveInfo =
    /otp|one time password|password|passcode|billing details|card details|pin\b|cvv|credentials?|bank details|security code|pan\b|aadhaar|beneficiary|wallet details?|login details|sign(?:-|\s)?in details?|identity (?:information|details?|documents?)|mailbox (?:credentials|ownership)|account verification|profile verification/i.test(
      proseLower,
    );
  const safeLower = protectiveContextStripped;
  const hasBenignEditorialEscalationContext =
    hasBenignEditorialTimeContext || hasPromotionalUrgencyOnly || (isSafeTransactional && hasNewsletterFooter);
  const hasActionContextCombo =
    !hasBenignEditorialEscalationContext &&
    /\b(?:update|updating|confirm|confirming|review|reviewing|check|checking|verify|verifying|process|processing|submit|submitting|handle|handling|secure|reset|reactivate|restore|take action)\b/i.test(
      safeLower,
    ) &&
    /(account|profile|service|payment|invoice|payroll|bank|security|details|information|status|activity|identity|access|mailbox|sign(?:-|\s)?in)/i.test(
      lower,
    );
  const hasRiskEscalatingConsequence =
    !hasBenignEditorialEscalationContext &&
    /urgent|immediate(?:ly)?|asap|now|today|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|next hour|time sensitive|avoid (?:disruption|closure|suspension|penalty|action)|avoid penalties|restore\s+(?:\w+\s+){0,2}access|maintain\s+(?:\w+\s+){0,2}access|keep\s+(?:\w+\s+){0,2}access|lockout|locked\s*out|maintain uninterrupted service|service disruption|payroll closes(?: today)?|i(?:'m| am) unavailable|i(?:'m| am) in a meeting|will explain later|jaldi|warna|band ho jayega|block ho jayega/i.test(
      lower,
    );
  const hasDocumentVerificationPrompt =
    /\b(?:submit|review|check)\b.*\b(?:documents?|forms?)\b.*\b(?:verification|security|review)\b/i.test(
      lower,
    );
  const hasGenericInfoRequest =
    !hasProtectiveSafeContext &&
    (hasActionContextCombo ||
      /\b(?:update|confirm|review|check|verify)\b/i.test(safeLower)) &&
    (/(details|information|info|email address|account status|account information|account info|profile|service|status|identity|mailbox|sign(?:-|\s)?in)/i.test(
      lower,
    ) || hasDocumentVerificationPrompt);
  const hasStrictActionIntent =
    /\b(?:send|share|reply|provide|enter|confirm|submit|update|authenticate|type|fill|pay|transfer|approve|process|reset|secure|unlock|reactivate|restore|continue|proceed|check|review|click|bhej|batao)\b|confirm your identity|verify your identity|confirm payment|transfer funds?|reset password|secure your account/i.test(
      safeLower,
    );
  const hasRequestIntent =
    /\b(?:send|share|reply|provide|request|enter|confirm|submit|update|claim|redeem|pay|transfer|approve|process|reset|secure|unlock|reactivate|restore|continue|proceed|check|review|click|bhej|batao)\b|confirm your identity|verify your identity|confirm payment|transfer funds?|reset password|secure your account/i.test(
      safeLower,
    );
  const hasCredentialTheftStyleAccessRequest =
    !hasProtectiveSafeContext &&
    !hasSecurityNotificationContext &&
    /\b(?:verify|confirm|reactivate|restore|unlock|submit|update|open)\b/i.test(safeLower) &&
    /\b(?:account|profile|mailbox|workspace|login|sign(?:-|\s)?in|identity|credentials?|ownership|bank)\b/i.test(lower) &&
    (hasStrongUrgency ||
      /\b(?:discrepancy|compliance|penalt(?:y|ies)|maintain uninterrupted service|avoid penalties|keep\s+(?:\w+\s+){0,2}access)\b/i.test(lower));

  const hasCredentialRequest =
    !hasProtectiveSafeContext &&
    !hasSecurityNotificationContext &&
    ((requestsSensitiveInfo &&
      /\b(?:send|share|reply|provide|enter|submit|update|authenticate|type|fill|reset|secure|unlock|reactivate|restore|continue|proceed|check|review|click)\b|confirm your identity|verify your identity|reset password|secure your account/i.test(
        safeLower,
      )) ||
      hasCredentialTheftStyleAccessRequest);
  const hasCryptoKeywords =
    /btc|bitcoin|crypto|wallet|usdt|ethereum|eth\b|blockchain|binance|coinbase/i.test(
      lower,
    );
  const hasCryptoPromise =
    /double (?:your )?(?:money|btc|bitcoin|crypto)|instant return|guaranteed return|get \d+(?:\.\d+)?\s*(?:btc|eth|usdt)|send \d+(?:\.\d+)?\s*(?:btc|eth|usdt)|wallet verification needed|limited crypto offer|send funds get return|crypto bonus available|claim crypto reward|crypto reward claim now|transfer crypto to receive bonus/i.test(
      lower,
    );
  const isCryptoScam =
    hasCryptoPromise ||
    (hasCryptoKeywords && (hasActionRequest || hasStrongUrgency));

  const isNoLinkPhishing =
    !hasProtectiveSafeContext &&
    !hasLinks &&
    ((hasStrongUrgency &&
      (hasCredentialRequest ||
        hasCryptoKeywords ||
        /reward|cashback|prize|claim|refund|kyc|wallet|billing|card|pan|aadhaar|tax/i.test(lower))) ||
      (hasCredentialRequest && /identity|account|wallet|kyc|security|login|billing|card/i.test(lower)) ||
      (/(reward|cashback|prize|claim|refund|wallet|kyc|billing|card|tax notice|income tax)/i.test(lower) &&
        hasActionRequest &&
        (hasStrongUrgency || lower.trim().length <= 90)) ||
      (/(account|login|identity|password|credentials?|bank alert|verification|wallet|kyc|billing|card|okta|workspace|sign(?:-|\s)?in)/i.test(lower) &&
        hasActionRequest &&
        /required|now|blocked|lockout|locked\s*out|closure|suspension|detected|alert|under review|suspicious login|confirm identity/i.test(lower)) ||
      (hasActionContextCombo && hasRiskEscalatingConsequence));

  // ─── 5. STRONG NO-LINK SOCIAL ENGINEERING ───
  const hasSensitiveIntent =
    /otp|password|bank|aadhaar|account|verify|salary|reward|credited|won|pin\b|btc|bitcoin|crypto|wallet/i.test(
      lower,
    );
  const hasSocialPressure =
    /urgent|immediately|suspended|blocked|to proceed|failure to act|limited slots|act now|verify now/i.test(
      lower,
    );
  const isNoLinkSocialEngineering =
    !hasLinks && hasActionRequest && hasSensitiveIntent && hasSocialPressure;

  // ─── 6. REWARD / CASHBACK / FINANCIAL SCAM ───
  const hasRewardLure =
    /cashback|congratulations|prize|gift|bonus|selected winner|refund|lottery|claim refund|claim now|redeem now|reward credited/i.test(
      lower,
    ) ||
    (/\bwon\b/i.test(lower) && /(prize|cashback|lottery|reward|gift|bonus|claim|selected)/i.test(lower)) ||
    (/\boffer\b/i.test(lower) &&
      /(cashback|reward|gift|bonus|prize|refund|claim|redeem|winner|lottery|free money)/i.test(
        lower,
      ));
  const hasRewardSensitiveRequest =
    /otp|bank|account number|aadhaar|bank details|account details|card details|personal details|send|reply|provide|enter|claim now|redeem|verify/i.test(
      lower,
    );
  const isRewardScam =
    !isTrustedPromotionalFinanceOffer &&
    hasRewardLure &&
    (hasRewardSensitiveRequest || hasActionRequest || hasStrongUrgency);
  const hasJobKeyword =
    /candidate|job|selection|selected candidate|offer letter|interview|recruitment|joining/i.test(
      lower,
    );
  const hasAdvanceFeeRequest =
    /\bpay\b|payment|deposit|registration fee|processing fee|application fee|security deposit|confirm your job selection/i.test(
      lower,
    );
  const mentionsMoneyAmount = /₹|\brs\.?\b|rupees|\b\d{2,6}\b/i.test(lower);
  const isJobScam =
    hasJobKeyword &&
    hasAdvanceFeeRequest &&
    (mentionsMoneyAmount || /confirm|selection|onboarding|offer/i.test(lower));
  const hasInvoiceOrTransferRequest =
    /attached invoice|invoice attached|confirm payment|payment confirmation|transfer funds?|wire transfer|bank transfer|remittance advice|vendor payment|payment details updated/i.test(
      lower,
    );
  const hasSecretivePretext =
    /i(?:'m| am) in a meeting|will explain later|small help|confidential|quietly|asap/i.test(
      lower,
    );
  const hasBusinessPaymentFraud =
    !hasProtectiveSafeContext &&
    hasInvoiceOrTransferRequest &&
    (hasStrongUrgency || hasActionRequest || hasSecretivePretext) &&
    !/payment successful|invoice paid|receipt|transaction id/i.test(lower);

  const hasHindiBankThreat =
    /(बैंक|खाता|खाते)/.test(text) &&
    /(बंद|सत्यापन|सत्यापित|तुरंत|निलंबित|सस्पेंड)/.test(text);
  const hasTeluguBankThreat =
    /(బ్యాంక్|ఖాతా)/.test(text) &&
    /(నిలిపివేయబడింది|ధృవీకరించండి|వెంటనే|బ్లాక్)/.test(text);
  const hasHinglishBankThreat =
    /(khata|account)\s+(?:band|block)(?:\s+h(?:one|o)\s+wala)?/i.test(lower) ||
    /khata band hone wala hai|aapka khata band|account band ho jayega|access band ho jayega/i.test(lower);
  const isRegionalBankThreatPhishing =
    !hasLinks && (hasHindiBankThreat || hasTeluguBankThreat || hasHinglishBankThreat);

  const isBenignFinancialNotice =
    (((isSafeOtp || isTransactional || isSafeTransactional || isPolicyOrPrivacyUpdate) &&
      (hasProtectiveSafeContext || isPolicyOrPrivacyUpdate)) ||
      hasBenignBillingDashboardContext ||
      isTrustedPromotionalFinanceOffer);

  const isFinancialScam =
    !isBenignFinancialNotice &&
    (isRewardScam ||
      isCryptoScam ||
      isJobScam ||
      hasBusinessPaymentFraud ||
      (/(paytm|phonepe|gpay|google pay|upi|wallet|kyc|cashback|reward|prize|claim|refund|billing|card|payment failed|income tax|tax notice)/i.test(
        lower,
      ) &&
        (hasActionRequest || hasStrongUrgency)));

  // ─── 7. UNIVERSAL SENSITIVE DATA OVERRIDE ───
  const hasSensitiveSubmissionIntent =
    /\b(?:send|share|reply|provide|enter|submit|type|fill|confirm|update|authenticate|reset|secure|unlock|reactivate|restore|continue|proceed|click)\b|confirm your identity|verify your identity|reset password|secure your account/i.test(
      safeLower,
    );
  const isOtpScam =
    !hasProtectiveSafeContext &&
    hasSensitiveSubmissionIntent &&
    /otp|verification code/i.test(safeLower);
  const isPasswordScam =
    !hasProtectiveSafeContext &&
    hasSensitiveSubmissionIntent &&
    /password|pin\b|credentials/i.test(safeLower);
  const isBankScam =
    !hasProtectiveSafeContext &&
    hasRequestIntent &&
    /bank details|account details|card details|aadhaar|pan\b|account number/i.test(
      safeLower,
    );

  const isSensitiveDataOverride =
    isOtpScam || isPasswordScam || isBankScam || hasCredentialRequest;

  // ─── 8. SHORT SCAM DETECTION ───
  const hasShortUrgencyPhrase = SHORT_SCAM_PHRASES.some((phrase) =>
    lower.includes(phrase),
  );
  const isShortScam =
    lower.trim().length <= 80 &&
    (hasCredentialRequest ||
      hasShortUrgencyPhrase ||
      (hasActionRequest && hasStrongUrgency) ||
      isFinancialScam);

  // ─── 9. PHONE SCAM DETECTION ───
  const hasPhoneNumber = /\b\d{10}\b/.test(lower);
  const hasPhoneAction = /call|contact/i.test(lower);
  const hasAccountSecurityContext =
    /account|security|bank|aadhaar|pan\b|blocked|suspended|unauthorized/i.test(
      lower,
    );
  const hasPhoneSensitiveIntent =
    /otp|password|verify|restore|reactivate|kyc|blocked|suspended/i.test(lower);
  const isPhoneScam =
    hasPhoneNumber &&
    hasPhoneAction &&
    hasAccountSecurityContext &&
    hasPhoneSensitiveIntent;

  // ─── 10. CALM SCAM DETECTION ───
  const isCalmScam = !hasStrongUrgency && isSensitiveDataOverride;

  // ─── 11. TRUSTED DOMAIN WHITELIST BOOST ───
  const hasTrustedDomain = extractUrls(text).some((u) =>
    /icicibank\.com|hdfcbank\.com|sbi\.co\.in|amazon\.in|flipkart\.com|paytm\.com|phonepe\.com|google\.com|cursor\.(?:com|sh)/i.test(
      u,
    ),
  );
  const hasSensitiveData =
    /otp|password|pin\b|send|share|reply|provide|account number|aadhaar|pan\b/i.test(
      lower,
    );
  const hasNeutralTone = /view|access|track|check|download/i.test(lower);
  const isTrustedSafeLink =
    hasLinks && hasTrustedDomain && !hasSensitiveData && hasNeutralTone;

  // ─── 12. ACCOUNT ALERT DETECTION ───
  const hasAccountAlertPhrase =
    /unusual activity|suspicious activity|unusual login detected|login attempt|login activity detected|sign-?in attempt|security alert|security update required|security check required|account activity|account notice|account update recommended|review recent activity|review security settings|mailbox alert|unusual sign-?in|update your account information|review(?:ing)? your account information|confirm your details|update account information to continue|ensure uninterrupted service|continue services?|update required|please check your account|check your account status|activity alert|please take action regarding your account|account may require attention|immediate review is suggested|update might be needed|verify details if necessary|security might be affected|action could be required|review may help avoid issues|kindly check once|submit documents for verification/i.test(
      lower,
    );
  const hasAlertSensitiveData = /otp|password|bank|aadhaar|send|share/i.test(
    lower,
  );
  const isAccountAlert =
    (hasAccountAlertPhrase || hasGenericInfoRequest) && !hasAlertSensitiveData && !hasLinks;

  // New Detection Hardening Flags
  const hasHindiUrgency = /बंद|तुरंत|अभी|सस्पेंड|रोक दिया|जल्दी/i.test(text);
  const hasHindiAction = /भेजें|भेजो|सेंड|उत्तर दें|reply/i.test(text);
  const hasHinglishUrgency = /jaldi|abhi|turant|warna|nahi toh|block ho jayega|band ho jayega|band hone wala hai|service ruk jayegi|account block/i.test(lower);
  const hasHinglishAction = /\bbhej(?:na|do|de|dena)?\b|share kar|reply|verify karo|confirm karo|complete karo|details bhejo/i.test(lower);
  const hasOtpOrSensitive = /otp|पासवर्ड|password|pin|account|details|bank/i.test(lower);
  const hasHinglishSensitiveTask =
    /\b(?:details\s+bhejo|otp\s+bhejo|verify\s+karo|confirm\s+karo|payment\s+karo|complete\s+karo|task\s+complete\s+karo)\b/i.test(lower);
  const isHindiPhishing =
    (hasHindiUrgency && hasHindiAction && hasOtpOrSensitive) ||
    (hasHinglishUrgency && hasHinglishAction && hasOtpOrSensitive) ||
    (hasHinglishUrgency && hasHinglishSensitiveTask) ||
    hasHindiBankThreat ||
    hasHinglishBankThreat;

  const hasStrongUrgencyWords =
    /\burgent(?:ly)?\b|\bimmediate(?:ly)?\b|\basap\b|\b(?:act now|right away|right now|today|tonight|next hour|before noon|24h|24 hours|48 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|quickly)\b|jaldi|abhi|turant|వెంటనే|తక్షణం|तुरंत|अभी|जल्दी/i.test(
      proseLower,
    );
  const hasEscalationUrgencyWords =
    /\burgent(?:ly)?\b|\bimmediate(?:ly)?\b|\basap\b|\b(?:act now|right away|right now|final notice|deadline|last chance|limited time|today|tonight|before noon|before end of day|end of day|next hour|24h|24 hours|48 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|quickly)\b|jaldi|abhi|turant|వెంటనే|తక్షణం|तुरंत|अभी|जल्दी/i.test(
      proseLower,
    );
  const hasVerifyIntent =
    /verify|confirm|update|reset|secure|unlock|review|check|continue|proceed|ensure|maintain|secure account|confirm payment|transfer funds?/i.test(
      lower,
    );
  const hasSensitiveUrgencyContext =
    hasBusinessPaymentFraud ||
    /otp|password|pin|account|credentials?|billing|card|bank|identity|wallet|kyc|beneficiary/i.test(lower) ||
    (hasVerifyIntent && /(account|login|identity|credentials?|billing|card|bank|wallet|kyc|beneficiary)/i.test(lower));
  const isUrgencyPhishing =
    !hasProtectiveSafeContext &&
    !isSafeTransactional &&
    !isSafeOtp &&
    hasSensitiveUrgencyContext &&
    (hasEscalationUrgencyWords || ((hasCredentialRequest || isFinancialScam) && hasStrongUrgencyWords));

  // Track standard hits
  const urgencyHits = URGENCY_WORDS.filter((term) =>
    new RegExp(
      `(?:^|\\b)${term.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&").replace(/\\s+/g, "\\\\s+")}(?:\\b|$)`,
      "i",
    ).test(proseLower),
  );
  const hasOnlyMarketingUrgencyHits =
    urgencyHits.length > 0 &&
    (hasBenignEditorialTimeContext ||
      (hasPromotionalUrgencyOnly &&
        urgencyHits.every((term) => ["limited time", "now", "today", "24 hours"].includes(term.toLowerCase()))));
  if (urgencyHits.length > 0 && !hasOnlyMarketingUrgencyHits) {
    allTerms.push(...urgencyHits);
    const sev =
      urgencyHits.length >= 3
        ? "high"
        : urgencyHits.length >= 2
          ? "medium"
          : "low";
    reasons.push({
      category: "urgency",
      description: `This email is trying to rush you into action. Words like "urgent", "blocked", or "verify now" are a common tactic used to prevent you from pausing to check whether the message is genuine.`,
      severity: sev,
      matchedTerms: urgencyHits.slice(0, 6),
    });
    total += Math.min(15 + (urgencyHits.length - 1) * 10, 45);
  }

  const financialHits = FINANCIAL_SCAM_WORDS.filter((w) => matchesKeyword(lower, w));
  const shouldSuppressBenignMarketingFinancialHits =
    isTrustedPromotionalFinanceOffer &&
    !hasCredentialRequest &&
    !hasStrongUrgency &&
    !hasTransactionalActionRequest;
  if (financialHits.length > 0 && !shouldSuppressBenignMarketingFinancialHits) {
    allTerms.push(...financialHits);
    const sev =
      financialHits.length >= 4
        ? "high"
        : financialHits.length >= 2
          ? "medium"
          : "low";
    reasons.push({
      category: "financial",
      description: `The email references money, bank accounts, or digital payments. Scammers use financial language to grab your attention and exploit concerns about your account or wallet.`,
      severity: sev,
      matchedTerms: financialHits.slice(0, 6),
    });
    total += Math.min(15 + (financialHits.length - 1) * 8, 35);
  }

  const credentialHits = CREDENTIAL_REQUEST_WORDS.filter((w) => matchesKeyword(lower, w));
  const shouldTreatCredentialHitsAsRisk =
    hasCredentialRequest || (credentialHits.length > 0 && !isSafeOtp && !hasProtectiveSafeContext);

  if (shouldTreatCredentialHitsAsRisk) {
    allTerms.push(...credentialHits);
    reasons.push({
      category: "social_engineering",
      description:
        "The email is requesting sensitive credentials or identity data. Real organizations do not ask you to enter or send OTPs, PINs, or passwords over email.",
      severity: hasCredentialRequest ? "high" : "medium",
      matchedTerms: credentialHits.slice(0, 6),
    });
    total += hasCredentialRequest ? 35 : 12;
  } else if (isSafeOtp) {
    total = Math.max(0, total - 10);
  }

  const cryptoHits = CRYPTO_SCAM_WORDS.filter((w) => matchesKeyword(lower, w));
  if (isCryptoScam || cryptoHits.length > 0) {
    allTerms.push(...cryptoHits);
    reasons.push({
      category: "financial",
      description:
        "This message matches a crypto-investment or wallet scam pattern, such as promising instant returns or asking for a crypto transfer.",
      severity: isCryptoScam ? "high" : "medium",
      matchedTerms: cryptoHits.slice(0, 6),
    });
    total += isCryptoScam ? 40 : 18;
  }

  const jobHits = JOB_SCAM_WORDS.filter((w) => matchesKeyword(lower, w));
  if (isJobScam || jobHits.length > 0) {
    allTerms.push(...jobHits);
    reasons.push({
      category: "financial",
      description:
        "This email matches an advance-fee job scam pattern. Real employers do not ask candidates to pay money to confirm selection or release an offer.",
      severity: isJobScam ? "high" : "medium",
      matchedTerms: [...new Set([...jobHits, "pay", "fee"])].slice(0, 6),
    });
    total += isJobScam ? 42 : 14;
  }

  if (hasBusinessPaymentFraud) {
    allTerms.push("invoice", "payment", "transfer");
    reasons.push({
      category: "financial",
      description:
        "This message resembles business email compromise or invoice fraud: it pressures you to confirm payment or move funds quickly, often using a meeting or secrecy pretext.",
      severity: "high",
      matchedTerms: ["invoice/payment request", "urgent transfer", "meeting pretext"],
    });
    total += 40;
  }

  if (isRegionalBankThreatPhishing) {
    const regionalTerms = [
      ...(hasHindiBankThreat ? ["बैंक", "खाता", "सत्यापन"] : []),
      ...(hasTeluguBankThreat ? ["బ్యాంక్", "ఖాతా", "ధృవీకరించండి"] : []),
    ];
    allTerms.push(...regionalTerms);
    reasons.push({
      category: "social_engineering",
      description:
        "This regional-language bank warning pressures the user to verify or act quickly after claiming the account will be blocked or closed — a common phishing pattern.",
      severity: "high",
      matchedTerms: regionalTerms.slice(0, 6),
    });
    total += 38;
  }

  if (isShortScam) {
    const shortHits = SHORT_SCAM_PHRASES.filter((phrase) => lower.includes(phrase));
    const hasExplicitShortUrgency = urgencyHits.length > 0;
    allTerms.push(...shortHits);
    reasons.push({
      category: hasExplicitShortUrgency ? "urgency" : "social_engineering",
      description: hasExplicitShortUrgency
        ? "Very short, high-pressure commands with explicit urgency words are commonly used in phishing and should be treated cautiously."
        : "Short command-style phishing text is risky even without overt urgency wording, especially when it asks for action or sensitive information.",
      severity: hasCredentialRequest || isFinancialScam ? "high" : "medium",
      matchedTerms: shortHits.slice(0, 4),
    });
    total = Math.max(total, hasCredentialRequest || isFinancialScam ? 45 : 30);
  }

  // FIX 1 & FIX 4: SOCIAL ENGINEERING STRICT MODE & CTA NORMALIZATION
  const socialHits = SOCIAL_ENGINEERING_WORDS.filter((w) => matchesKeyword(lower, w));

  if (socialHits.length > 0) {
    const hasUrgencyAction =
      /immediately verify|account blocked|act now|verify now/i.test(lower);
    const hasAuthorityReq =
      /(bank|rbi|gov|income tax|police).*?(verify|provide|share|update)/i.test(
        lower,
      );
    const hasFear =
      /account suspended|legal action|court action|police complaint/i.test(
        lower,
      );

    const isInformationalAlert =
      /statement|newsletter|login notification/i.test(lower);
    const hasGenericCta =
      /apply now|get started|claim offer|claim reward/i.test(lower);

    // Only flag social engineering if strict urgency, requests, or fear apply, without being informational
    // If it's just a "click here" or "Apply now" (CTA), we ignore unless sensitive data override is active
    const isStrictSocialEngineering =
      hasUrgencyAction ||
      hasAuthorityReq ||
      hasFear ||
      (isSensitiveDataOverride && !hasGenericCta);

    if (isStrictSocialEngineering && !isInformationalAlert) {
      allTerms.push(...socialHits);
      reasons.push({
        category: "social_engineering",
        description: `This email uses high-pressure psychological tactics to build false authority, urgency, or fear. Scammers use this so you rush your decision without verifying.`,
        severity: socialHits.length >= 3 ? "high" : "medium",
        matchedTerms: socialHits.slice(0, 6),
      });
      total += Math.min(10 + (socialHits.length - 1) * 7, 30);
    }
  }

  const bankHits = INDIA_SPECIFIC_BANKS.filter((b) => matchesKeyword(lower, b));
  const serviceHits = INDIA_SPECIFIC_SERVICES.filter((s) => matchesKeyword(lower, s));
  if (bankHits.length > 0 || serviceHits.length > 0) {
    const terms = [...bankHits, ...serviceHits];
    allTerms.push(...terms);

    // Lower brand impersonation risk if it's a legit transactional or OTP mail or Trusted Link
    if (
      total > 8 &&
      !isSafeOtp &&
      !isSafeTransactional &&
      !isSoftTransaction &&
      !isTrustedSafeLink
    ) {
      reasons.push({
        category: "india_specific",
        description: `The sender appears to be impersonating a well-known Indian bank or payment platform. Scammers frequently clone real brands to appear legitimate — your actual bank will never ask for credentials over email.`,
        severity: "high",
        matchedTerms: terms.slice(0, 6),
      });
      total += 25;
    }
  }

  const hindiScamWords = [
    "तुरंत",
    "जल्दी",
    "अभी",
    "बंद",
    "इनाम",
    "बधाई",
    "रुपये",
    "पैसे",
    "खाता",
    "सत्यापन",
  ];
  const hindiHits = hindiScamWords.filter((w) => text.includes(w));
  if (hindiHits.length > 0) {
    allTerms.push(...hindiHits);
    reasons.push({
      category: "language",
      description: `This message contains Hindi words that commonly appear in regionally targeted phishing. Scammers use local language to make the email feel more familiar and trustworthy to Indian readers.`,
      severity: "medium",
      matchedTerms: hindiHits,
    });
    total += hindiHits.length * 8;
  }

  const teluguScamWords = [
    "వెంటనే",
    "త్వరగా",
    "బ్లాక్",
    "నిలిపివేయబడింది",
    "బహుమతి",
    "రివార్డ్",
    "అభినందనలు",
    "రూపాయలు",
    "డబ్బు",
    "ఖాతా",
    "ధృవీకరణ",
  ];
  const teluguHits = teluguScamWords.filter((w) => text.includes(w));
  if (teluguHits.length > 0) {
    allTerms.push(...teluguHits);
    reasons.push({
      category: "language",
      description: `This message contains Telugu words that commonly appear in regionally targeted phishing. Scammers use local languages to make the email feel more familiar and trustworthy to Indian readers.`,
      severity: "medium",
      matchedTerms: teluguHits,
    });
    total += teluguHits.length * 8;
  }

  // ─── APPLY EDGE CASE ADJUSTMENTS ───
  if (isSafeOtp) {
    total = 0; // FORCE ruleScore = 0
    reasons.push({
      category: "ml_score",
      description: "Legitimate OTP notification (no action required).",
      severity: "low",
      matchedTerms: ["otp", "do not share"],
    });
  } else if (isSafeTransactional || isSoftTransaction) {
    total = Math.max(0, total - 40); // Reduce near 0
    reasons.push({
      category: "ml_score",
      description:
        "Appears to be a standard transactional alert or payment notification. No suspicious links or urgent actions were detected.",
      severity: "low",
      matchedTerms: ["transaction", "payment"],
    });
  } else if (isSensitiveDataOverride || isPhoneScam || isCalmScam || isCryptoScam || isJobScam) {
    total += isCryptoScam || isJobScam ? 70 : 60; // Huge boost for direct sensitive, crypto, or advance-fee job scams
    reasons.push({
      category: "social_engineering",
      description:
        isJobScam
          ? "This message requests payment to confirm a job or candidate selection — a classic advance-fee scam pattern."
          : "Sensitive information or a high-risk money transfer is being requested — a strong phishing signal. Legitimate organizations never ask you to send or enter credentials or crypto funds in this manner.",
      severity: "high",
      matchedTerms: isCryptoScam
        ? ["btc/crypto", "wallet", "instant return"]
        : isJobScam
          ? ["job selection", "pay", "fee"]
          : ["password/otp", "enter/verify/send"],
    });
  } else if (isRewardScam || isRegionalBankThreatPhishing) {
    total += isRegionalBankThreatPhishing ? 62 : 55; // Boost aggressively for reward or regional bank-threat scams
    reasons.push({
      category: "social_engineering",
      description: isRegionalBankThreatPhishing
        ? "High-risk no-link bank impersonation warning. The message claims the account will be blocked or closed unless you verify immediately."
        : "High-risk reward scam. The sender claims you have won a prize or cashback but requests sensitive details or a direct reply without providing a verifiable link.",
      severity: "high",
      matchedTerms: isRegionalBankThreatPhishing
        ? ["bank account", "blocked/closed", "verify now"]
        : ["prize", "bank details"],
    });
  } else if (isNoLinkSocialEngineering) {
    total += 55; // Boost aggressively for social engineering
    reasons.push({
      category: "social_engineering",
      description:
        "High-risk social engineering attack (no-link phishing). The sender is pressuring you to take action regarding sensitive information without providing verifiable links.",
      severity: "high",
      matchedTerms: ["action required", "sensitive intent"],
    });
  } else if (isNoLinkPhishing) {
    total += 50; // Boost aggressively
    reasons.push({
      category: "social_engineering",
      description:
        "Extremely suspicious no-link phishing attempt. The email uses high-pressure urgency to demand sensitive information or exploit a financial lure directly.",
      severity: "high",
      matchedTerms: ["urgent", "verify/claim", "password/otp"],
    });
  } else if (isShortScam) {
    total = Math.max(total, 35);
    reasons.push({
      category: "urgency",
      description:
        "Short, command-style text with pressure language should never be trusted without verification.",
      severity: "medium",
      matchedTerms: SHORT_SCAM_PHRASES.filter((phrase) => lower.includes(phrase)).slice(0, 4),
    });
  } else if (isAccountAlert) {
    total = Math.max(35, total); // Ensure base score supports suspicious classification
    reasons.push({
      category: "social_engineering",
      description:
        "Account activity alert — verify authenticity before taking action.",
      severity: "medium",
      matchedTerms: ["account alert"],
    });
  }

  return {
    score: Math.min(total, 100),
    reasons,
    allTerms: [...new Set(allTerms)],
    isSafeOtp,
    isSafeTransactional,
    isSoftTransaction,
    hasBenignBillingDashboardContext,
    isNoLinkPhishing,
    isNoLinkSocialEngineering,
    isRewardScam,
    isFinancialScam,
    isCryptoScam,
    isJobScam,
    isRegionalBankThreatPhishing,
    hasCredentialRequest,
    isSensitiveDataOverride,
    isShortScam,
    isPhoneScam,
    isCalmScam,
    isTrustedSafeLink,
    isAccountAlert,
    isHindiPhishing,
    isUrgencyPhishing,
  };
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function analyzeEmail(
  emailText: string,
  headersText?: string,
  id: string = "untracked",
  attachments: AttachmentContext[] = [],
): Promise<AnalyzeResult> {
  // Empty input — return a neutral safe result
  if (!emailText || emailText.trim().length === 0) {
    return AnalyzeEmailResponse.parse({
      id,
      riskScore: 0,
      risk_score: 0,
      classification: "safe",
      confidence: 0.95,
      confidenceLevel: "HIGH",
      confidenceLabel: "High",
      confidence_level: "High",
      displayLabel: "🟢 Safe (0%)",
      display_label: "🟢 Safe (0%)",
      explanation:
        "No readable email content was provided, and no strong phishing signs could be evaluated.",
      detectedSignals: ["No strong phishing signals detected"],
      detected_signals: ["No strong phishing signals detected"],
      signals: ["No strong phishing signals detected"],
      detectedLanguage: "en",
      reasons: [],
      suspiciousSpans: [],
      urlAnalyses: [],
      safetyTips: [
        "Always verify sender email addresses before clicking any links.",
      ],
      warnings: [],
      recommendedDisposition: "allow",
      autoBlockRecommended: false,
      preventionActions: [
        "No blocking action is needed because no readable content was available to analyze.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 0,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "allow",
      },
      mlScore: 0,
      ruleScore: 0,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [],
      attackType: "Safe / Informational",
      scamStory:
        "No readable email content was provided, so there are no phishing signs to evaluate.",
    });
  }

  const preparedEmailText = stripMailboxChromeArtifacts(emailText);
  const explicitAwsSnsUtilityNotice =
    /(aws notifications\s*<no-reply@sns\.amazonaws\.com>|from:\s*aws notifications\s*<no-reply@sns\.amazonaws\.com>)/i.test(
      preparedEmailText,
    ) &&
    /(this is sns test|stop receiving notifications from this topic|please do not reply directly to this email)/i.test(
      preparedEmailText,
    ) &&
    /(sns\.[a-z0-9-]+\.amazonaws\.com\/unsubscribe|aws\.amazon\.com\/support)/i.test(
      preparedEmailText,
    );

  if (explicitAwsSnsUtilityNotice) {
    const utilityUrlAnalyses = extractUrls(preparedEmailText).map(analyzeUrl);
    return AnalyzeEmailResponse.parse({
      id,
      riskScore: 18,
      risk_score: 18,
      classification: "safe",
      confidence: 0.9,
      confidenceLevel: "HIGH",
      confidenceLabel: "High",
      confidence_level: "High",
      displayLabel: buildDisplayLabel(18, "HIGH"),
      display_label: buildDisplayLabel(18, "HIGH"),
      explanation:
        "This looks like a legitimate AWS notification or unsubscribe notice from official Amazon infrastructure.",
      detectedSignals: ["Trusted service notification"],
      detected_signals: ["Trusted service notification"],
      signals: ["Trusted service notification"],
      detectedLanguage: detectLanguage(emailText),
      reasons: [
        {
          category: "informational",
          description:
            "This appears to be an official AWS SNS notification with standard unsubscribe and support links, not a credential-harvesting email.",
          severity: "low",
          matchedTerms: ["aws sns notification"],
        },
      ],
      suspiciousSpans: findSuspiciousSpans(emailText, ["unsubscribe", "aws", "support"]),
      urlAnalyses: utilityUrlAnalyses,
      safetyTips: [
        "If you expected this notification, no blocking action is needed.",
        "Use the AWS console directly if you want to verify the topic or change notification settings.",
      ],
      warnings: [],
      recommendedDisposition: "allow",
      autoBlockRecommended: false,
      preventionActions: [
        "No automatic blocking is recommended for this message based on the current signals.",
        "Use the official AWS console if you want to verify the notification or unsubscribe settings.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 0,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "allow",
      },
      mlScore: 0,
      ruleScore: 18,
      urlScore: 0,
      headerScore: 0,
      featureImportance: [
        {
          feature: "Trusted AWS SNS notification",
          contribution: 2.1,
          direction: "safe",
        },
      ],
      attackType: "Safe / Informational",
      scamStory:
        "This looks like a legitimate AWS notification or unsubscribe notice from official Amazon infrastructure.",
      headerAnalysis: analyzeEmailHeaders(preparedEmailText),
    });
  }

  const headerAnalysis: HeaderAnalysis = analyzeEmailHeaders(
    headersText?.trim() ? headersText : preparedEmailText,
  );

  const indiaHeuristics = analyzeIndiaThreatHeuristics(preparedEmailText, {
    senderDomain: headerAnalysis.senderDomain,
    existingUrls: extractUrls(preparedEmailText),
  });

  const adversarial = detectAdversarialAttacks(indiaHeuristics.normalizedText);
  const analysisText = adversarial.normalizedText || indiaHeuristics.normalizedText;
  let {
    score: ruleScore,
    reasons,
    allTerms,
    isSafeOtp,
    isSafeTransactional,
    hasBenignBillingDashboardContext,
    isSoftTransaction,
    isNoLinkPhishing,
    isNoLinkSocialEngineering,
    isRewardScam,
    isFinancialScam,
    isCryptoScam,
    isJobScam,
    isRegionalBankThreatPhishing,
    hasCredentialRequest,
    isSensitiveDataOverride,
    isShortScam,
    isPhoneScam,
    isCalmScam,
    isTrustedSafeLink,
    isAccountAlert,
    isHindiPhishing,
    isUrgencyPhishing,
  } = computeRuleScore(analysisText);

  ruleScore = Math.min(100, Math.max(0, ruleScore + indiaHeuristics.scoreDelta));
  if (indiaHeuristics.scoreFloor > 0) {
    ruleScore = Math.max(ruleScore, indiaHeuristics.scoreFloor);
  }
  if (indiaHeuristics.scoreCap !== undefined) {
    ruleScore = Math.min(ruleScore, indiaHeuristics.scoreCap);
  }

  reasons = mergeDetectionReasons(reasons, indiaHeuristics.reasons);
  allTerms = [...new Set([...allTerms, ...indiaHeuristics.matchedTerms])];
  isSafeTransactional = isSafeTransactional || indiaHeuristics.flags.newsletterContext;
  isFinancialScam =
    isFinancialScam ||
    indiaHeuristics.flags.deliveryScam ||
    indiaHeuristics.flags.gstScam ||
    indiaHeuristics.flags.phoneLure ||
    indiaHeuristics.flags.bec;
  isUrgencyPhishing = isUrgencyPhishing || indiaHeuristics.flags.smsSpoofing;
  isShortScam = isShortScam || indiaHeuristics.flags.shortFinancialUrl;

  let ruleReasons = [...reasons];

  // URL analysis — score is weighted max+avg to avoid one bad link dominating
  const urls = extractUrls(analysisText);
  const urlAnalyses = urls.map(analyzeUrl);

  let urlScore = 0;
  if (urlAnalyses.length > 0) {
    const maxScore = Math.max(...urlAnalyses.map((u) => u.riskScore));
    const avgScore =
      urlAnalyses.reduce((s, u) => s + u.riskScore, 0) / urlAnalyses.length;
    urlScore = Math.round(maxScore * 0.7 + avgScore * 0.3);
  }

  const suspiciousUrls = urlAnalyses.filter((u) => u.isSuspicious);
  const headerScore = headerAnalysis.headerScore;

  if (adversarial.detected) {
    ruleScore = Math.min(
      100,
      ruleScore + Math.max(8, Math.round(adversarial.confidence * 0.22)),
    );
  }

  const detectedLanguage = detectLanguage(emailText);

  // ═══════════════════════════════════════════════════════════════
  // MODULAR ENGINE PIPELINE
  // ═══════════════════════════════════════════════════════════════

  // 1. INTENT ENGINE — What does the email ask the user to do?
  const intent = analyzeIntent(analysisText);
  const detectedBrand = detectBrandFromText(analysisText, [
    headerAnalysis.senderDomain || "",
    ...urlAnalyses.map((u) => u.domain),
  ]);

  // 2. TRUST ENGINE — Can we trust the sender?
  const trust = analyzeTrust(
    headerAnalysis.senderDomain || "",
    headerAnalysis.spoofingRisk || "none",
    headerAnalysis.hasHeaders,
    urlAnalyses.map((u) => u.domain),
    {
      emailText: analysisText,
      detectedBrand,
    },
  );

  // 3. DOMAIN INTELLIGENCE — Are the URLs dangerous?
  const domainIntel = analyzeDomainIntel(
    urlAnalyses.map((u) => ({
      domain: u.domain,
      fullUrl: u.url,
      isSuspicious: u.isSuspicious,
    })),
    {
      senderDomain: headerAnalysis.senderDomain || "",
      emailText: analysisText,
    },
  );

  const attachmentIntel = analyzeAttachments(
    attachments,
    analysisText,
    trust.isTrustedDomain && !trust.hasHeaderSpoof,
  );

  const threatIntel = analyzeThreatIntel(
    urlAnalyses.map((u) => ({
      url: u.url,
      domain: u.domain,
      riskScore: u.riskScore,
      flags: u.flags,
      isSuspicious: u.isSuspicious,
    })),
    headerAnalysis.senderDomain || "",
    analysisText,
  );

  if (attachmentIntel.hasHighRiskAttachment) {
    ruleScore = Math.max(ruleScore, Math.max(72, attachmentIntel.score));
    reasons.unshift({
      category: "social_engineering",
      description:
        "This message includes a high-risk attachment pattern such as an executable, macro-enabled file, HTML lure, QR prompt, or password-protected archive.",
      severity: "high",
      matchedTerms: attachmentIntel.summarySignals.slice(0, 4),
    });
  } else if (attachmentIntel.suspiciousAttachmentCount > 0) {
    ruleScore = Math.max(ruleScore, Math.max(38, attachmentIntel.score));
    reasons.unshift({
      category: "social_engineering",
      description:
        "This message includes one or more suspicious attachments that should be manually verified before opening.",
      severity: "medium",
      matchedTerms: attachmentIntel.summarySignals.slice(0, 4),
    });
  }

  if (threatIntel.recommendedAction === "block") {
    ruleScore = Math.max(ruleScore, Math.max(82, threatIntel.reputationScore));
    reasons.unshift({
      category: "url",
      description:
        "Threat-intel heuristics matched known bad or highly suspicious infrastructure associated with phishing delivery.",
      severity: "high",
      matchedTerms: [...threatIntel.maliciousDomains, ...threatIntel.matchedIndicators].slice(0, 4),
    });
  } else if (threatIntel.recommendedAction === "review") {
    ruleScore = Math.max(ruleScore, Math.max(40, threatIntel.reputationScore));
    reasons.unshift({
      category: "url",
      description:
        "Link infrastructure shows risky patterns such as shorteners, punycode, suspicious paths, or high-risk TLDs.",
      severity: "medium",
      matchedTerms: threatIntel.matchedIndicators.slice(0, 4),
    });
  }

  allTerms = [
    ...new Set([
      ...allTerms,
      ...attachmentIntel.summarySignals,
      ...threatIntel.maliciousDomains,
      ...threatIntel.matchedIndicators,
    ]),
  ];
  ruleReasons = [...reasons];

  const lowerAnalysisTextEarly = analysisText.toLowerCase();
  const earlyTrustedBillingSafeNotice =
    trust.isTrustedDomain &&
    !trust.hasHeaderSpoof &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    (((/(payment method(?: associated with .* account)?|could(?:n't| not) process payment|billing issue|billing notice|authorization (?:might fail|failed|declined))/i.test(
      lowerAnalysisTextEarly,
    ) ||
      (/amazon web services account alert/i.test(lowerAnalysisTextEarly) && /payment method/i.test(lowerAnalysisTextEarly))) &&
      /(console\.aws\.amazon\.com|aws\.amazon\.com\/support|billing (?:&|and) invoices|billing home|dashboard|support center|customer service|contact your bank|paymentmethods|aws-account-and-billing)/i.test(
        lowerAnalysisTextEarly,
      )) ||
      (headerAnalysis.senderDomain === "amazonaws.com" &&
        /amazon web services account alert/i.test(lowerAnalysisTextEarly) &&
        /payment method/i.test(lowerAnalysisTextEarly))) &&
    !/(reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your|the)|submit (?:your|the)|re-?enter (?:your )?(?:card|bank|payment|billing) details|confirm your credentials|validate your credentials|confirm your identity|validate your identity|wire transfer|bank transfer|gift cards?|crypto|wallet)/i.test(
      lowerAnalysisTextEarly,
    );

  if (earlyTrustedBillingSafeNotice) {
    return AnalyzeEmailResponse.parse({
      id,
      riskScore: 18,
      risk_score: 18,
      classification: "safe",
      confidence: 0.78,
      confidenceLevel: "MEDIUM",
      confidenceLabel: "Medium",
      confidence_level: "Medium",
      displayLabel: buildDisplayLabel(18, "LOW"),
      display_label: buildDisplayLabel(18, "LOW"),
      explanation: "This looks like a legitimate billing or account notice from an official service and does not ask you to send credentials or sensitive data.",
      detectedSignals: ["Trusted billing notice"],
      detected_signals: ["Trusted billing notice"],
      signals: ["Trusted billing notice"],
      detectedLanguage: detectLanguage(emailText),
      reasons: [{
        category: "informational",
        description: "This appears to be an official billing or account-maintenance notice from a trusted sender and does not ask you to send sensitive information.",
        severity: "low",
        matchedTerms: ["trusted billing notice"],
      }],
      suspiciousSpans: findSuspiciousSpans(emailText, ["payment method", "support center", "billing"]),
      urlAnalyses,
      safetyTips: [
        "Always verify billing alerts through the provider's official dashboard.",
        "Do not share OTP, PIN, password, or banking credentials by email.",
        "If unsure, navigate to the service manually instead of using the email links.",
      ],
      warnings: [],
      recommendedDisposition: "allow",
      autoBlockRecommended: false,
      preventionActions: [
        "Use the provider's official dashboard if you want to verify the billing notice.",
        "No automatic blocking is recommended for this message based on the current signals.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 0,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "allow",
      },
      mlScore: 0,
      ruleScore: 18,
      urlScore,
      headerScore,
      attackType: "Safe / Informational",
      scamStory: "This looks like a legitimate billing or account notice from an official service and does not ask you to send credentials or sensitive data.",
      featureImportance: [{
        feature: "Trusted billing notice",
        contribution: 2.2,
        direction: "safe",
      }],
      headerAnalysis,
    });
  }

  const hasExplicitOfficialInfraSignals =
    /aws notifications\s*<no-reply@sns\.amazonaws\.com>|huggingface\s*<website@huggingface\.co>|quora digest\s*<english-quora-digest@quora\.com>|signed by:\s*(?:sns\.amazonaws\.com|huggingface\.co|quora\.com)|mailed-by:\s*(?:amazonses\.com|quora\.com)|from:\s*.*@(?:sns\.amazonaws\.com|huggingface\.co|quora\.com)/i.test(
      lowerAnalysisTextEarly,
    );
  const earlyTrustedServiceUtilitySafeNotice =
    (trust.isTrustedDomain || hasExplicitOfficialInfraSignals) &&
    !trust.hasHeaderSpoof &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    !threatIntel.hasKnownBadInfrastructure &&
    ((/(aws notifications|this is sns test|stop receiving notifications from this topic|please do not reply directly to this email)/i.test(
      lowerAnalysisTextEarly,
    ) &&
      /(unsubscribe|aws\.amazon\.com\/support|sns\.[a-z0-9-]+\.amazonaws\.com)/i.test(
        lowerAnalysisTextEarly,
      )) ||
      (/(confirm your email address|email confirmation|verify your email address)/i.test(
        lowerAnalysisTextEarly,
      ) &&
        /(if you did(?:n't| not) create (?:a |an )?.{0,40}account|you can ignore this email|ignore this email)/i.test(
          lowerAnalysisTextEarly,
        ))) &&
    !/(reply with|send (?:your|the)|share (?:your|the)|provide (?:your|the)|enter (?:your )?(?:otp|password|pin|passcode|credentials?)|re-?enter|update billing|update payment details|confirm your identity|validate your identity|wire transfer|bank transfer)/i.test(
      lowerAnalysisTextEarly,
    );

  if (earlyTrustedServiceUtilitySafeNotice) {
    return AnalyzeEmailResponse.parse({
      id,
      riskScore: 20,
      risk_score: 20,
      classification: "safe",
      confidence: 0.9,
      confidenceLevel: "HIGH",
      confidenceLabel: "High",
      confidence_level: "High",
      displayLabel: buildDisplayLabel(20, "HIGH"),
      display_label: buildDisplayLabel(20, "HIGH"),
      explanation:
        "This looks like a legitimate service notification or account-confirmation email from an official sender. It does not ask you to send sensitive information.",
      detectedSignals: ["Trusted service notification"],
      detected_signals: ["Trusted service notification"],
      signals: ["Trusted service notification"],
      detectedLanguage: detectLanguage(emailText),
      reasons: [
        {
          category: "informational",
          description:
            "This appears to be an official service utility or email-confirmation notice from a trusted sender and does not request credentials or payment details.",
          severity: "low",
          matchedTerms: ["trusted service notification"],
        },
      ],
      suspiciousSpans: findSuspiciousSpans(emailText, ["unsubscribe", "support", "confirm your email address"]),
      urlAnalyses,
      safetyTips: [
        "If you expected this notification, no blocking action is needed.",
        "If the sign-up or notification was unexpected, verify it from the official site instead of using the email links.",
        "Never share passwords, OTPs, or payment details over email.",
      ],
      warnings: [],
      recommendedDisposition: "allow",
      autoBlockRecommended: false,
      preventionActions: [
        "Use the official site or app if you want to verify the notification.",
        "No automatic blocking is recommended for this message based on the current signals.",
      ],
      attachmentFindings: [],
      threatIntel: {
        reputationScore: 0,
        hasKnownBadInfrastructure: false,
        maliciousDomains: [],
        matchedIndicators: [],
        recommendedAction: "allow",
      },
      mlScore: 0,
      ruleScore: 20,
      urlScore,
      headerScore,
      attackType: "Safe / Informational",
      scamStory:
        "This looks like a legitimate service notification or email-confirmation email from an official sender.",
      featureImportance: [
        {
          feature: "Trusted service utility notice",
          contribution: 2.1,
          direction: "safe",
        },
      ],
      headerAnalysis,
    });
  }

  // 4. BEHAVIOR ENGINE — What signal combinations exist?
  const behavior = analyzeBehavior(analysisText, intent, trust, domainIntel);

  // 4.5 CONTEXT ENGINE — Does the message break the normal business workflow?
  const context = analyzeContext(analysisText);
  const polymorphic = analyzePolymorphicCampaign(analysisText);

  if (context.hasWorkflowMismatch || context.hasThreadHijackStyleShift) {
    const isHighRiskContext =
      context.contextRiskScore >= 45 ||
      (context.hasWorkflowMismatch && context.hasUrgentWorkflowPressure);

    ruleScore = Math.max(ruleScore, isHighRiskContext ? 72 : 44);
    reasons.unshift({
      category: "social_engineering",
      description: context.hasThreadHijackStyleShift
        ? "This message shifts an existing business thread into a payment or beneficiary-change request, which is a common thread-hijack or BEC tactic."
        : "This message breaks the normal workflow by turning a delivery or collaboration notice into a payment, access, or approval request. That mismatch is strongly associated with phishing.",
      severity: isHighRiskContext ? "high" : "medium",
      matchedTerms: context.riskMarkers.slice(0, 4),
    });

    if (context.category === "shipping" && context.hasWorkflowMismatch) {
      isFinancialScam = true;
      isUrgencyPhishing = isUrgencyPhishing || context.hasUrgentWorkflowPressure;
    }
  } else if (
    context.isRoutineOperationalMessage &&
    context.safeMarkers.length > 0 &&
    !hasCredentialRequest &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    threatIntel.recommendedAction === "allow"
  ) {
    ruleScore = Math.max(0, ruleScore - 6);
  }

  if (
    polymorphic.hasActiveCampaign &&
    (hasCredentialRequest || isFinancialScam || behavior.hasExecutiveFraud || context.hasWorkflowMismatch || domainIntel.hasSuspiciousLink)
  ) {
    const campaignEscalation = polymorphic.recentVariantCount >= 2 ? 78 : 46;
    ruleScore = Math.max(ruleScore, campaignEscalation);
    reasons.unshift({
      category: "ml_score",
      description:
        polymorphic.recentVariantCount >= 2
          ? `This message matches an active phishing family (${polymorphic.theme}) seen in multiple recent variants, which raises confidence that it is part of a campaign.`
          : `This message matches a known high-risk phishing pattern family (${polymorphic.theme}), which strengthens the suspicious verdict.`,
      severity: polymorphic.recentVariantCount >= 2 ? "high" : "medium",
      matchedTerms: polymorphic.indicators.slice(0, 4),
    });
  }

  allTerms = [
    ...new Set([
      ...allTerms,
      ...context.safeMarkers,
      ...context.riskMarkers,
    ]),
  ];
  ruleReasons = [...reasons];

  // 5. CONFIDENCE ENGINE — Deterministic signal scoring
  const confidenceArchitecture = computeConfidenceScore({
    text: analysisText,
    detectedLanguage,
    intent,
    trust,
    domainIntel,
    behavior,
    hasCredentialRequest,
    isFinancialScam,
    isNoLinkPhishing,
    isShortScam,
    isHindiPhishing,
    isRegionalBankThreatPhishing,
    isUrgencyPhishing,
    isSafeOtp,
    isSafeTransactional,
  });

  ruleScore = confidenceArchitecture.ruleScore;

  const {
    score: hybridRiskScore,
    mlScore,
    transformerScore,
    classification: hybridClassification,
    confidence: hybridConfidence,
    topFeatures,
  } = await hybridScore(analysisText, ruleScore);

  // 6. DECISION ENGINE — Final classification
  const mlBaseScore = Math.round(
    0.6 * ruleScore + 0.2 * mlScore + 0.2 * transformerScore,
  );
  const decision = makeDecision(
    intent,
    trust,
    domainIntel,
    behavior,
    mlBaseScore,
  );

  // 6. EXPLANATION ENGINE — Human-readable output
  const explanation = generateExplanation(
    decision.classification,
    decision.attackType,
    intent,
    trust,
    domainIntel,
    behavior,
  );

  const frontierReview = shouldUseFrontierReview(hybridRiskScore)
    ? await reviewWithFrontierModel(analysisText, {
      localScore: hybridRiskScore,
      urlScore,
      headerScore,
      suspiciousUrlCount: suspiciousUrls.length,
      spoofingRisk: headerAnalysis.spoofingRisk,
      detectedSignals: allTerms.slice(0, 20),
      classification: hybridClassification,
    })
    : null;

  // ─── Map engine outputs to API response format ───
  let classification: "safe" | "uncertain" | "phishing" = hybridClassification;
  let finalScore = hybridRiskScore;
  let confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
  let confidence = Math.max(hybridConfidence, scoreToDeterministicConfidence(finalScore));
  let decisionAttackType = decision.attackType;
  reasons = mergeDetectionReasons(ruleReasons, explanation.reasons);

  const warnings = [...explanation.warnings];
  const safetyTips = [...explanation.safetyTips];

  if (indiaHeuristics.warnings.length > 0) {
    warnings.unshift(...indiaHeuristics.warnings);
  }

  if (indiaHeuristics.flags.bec) {
    safetyTips.unshift(
      "Do NOT transfer funds. Call the sender directly on a known, verified phone number before any action.",
    );
  }
  if (indiaHeuristics.flags.deliveryScam) {
    safetyTips.unshift(
      "Check the official courier website yourself before paying any redelivery or customs fee.",
    );
  }
  if (indiaHeuristics.flags.phoneLure) {
    safetyTips.unshift(
      "Do not move the conversation to WhatsApp or a callback number in the email. Use an official support number instead.",
    );
  }

  if (attachmentIntel.suspiciousAttachmentCount > 0) {
    warnings.unshift(
      `${attachmentIntel.suspiciousAttachmentCount} suspicious attachment${attachmentIntel.suspiciousAttachmentCount === 1 ? "" : "s"} detected.`,
    );
    safetyTips.unshift(...attachmentIntel.recommendedActions.slice(0, 2));
  }

  if (polymorphic.hasActiveCampaign) {
    warnings.unshift(
      polymorphic.recentVariantCount >= 2
        ? `Multiple recent variants of the same phishing family (${polymorphic.theme}) were detected.`
        : `This message resembles a recent phishing variant family (${polymorphic.theme}).`,
    );
  }

  if (threatIntel.matchedIndicators.length > 0) {
    warnings.unshift(...threatIntel.matchedIndicators.slice(0, 2));
  }

  if (adversarial.detected) {
    const uniqueTechniques = [...new Set(adversarial.techniques)].slice(0, 4);
    reasons.unshift({
      category: "social_engineering",
      description: `Obfuscation detected (${uniqueTechniques.join(", ")}). Attackers often use hidden characters or encoding to bypass filters.`,
      severity: adversarial.confidence >= 45 ? "high" : "medium",
      matchedTerms: uniqueTechniques,
    });
    warnings.unshift(`Obfuscation detected: ${uniqueTechniques.join(", ")}`);
    safetyTips.unshift(
      "Treat emails using hidden characters, encoded text, or QR tricks as high risk until verified through an official channel.",
    );
  }

  if (frontierReview) {
    const normalizedAttackType = frontierReview.attackType.toLowerCase();
    if (/otp/.test(normalizedAttackType)) {
      decisionAttackType = "OTP Scam";
    } else if (/credential|password|wallet|oauth|login/.test(normalizedAttackType)) {
      decisionAttackType = "Credential Theft";
    } else if (/invoice|vendor|payment|bec|gift/.test(normalizedAttackType)) {
      decisionAttackType = "Financial Scam";
    } else if (/brand|spoof/.test(normalizedAttackType)) {
      decisionAttackType = "Brand Impersonation";
    } else if (/lookalike|domain/.test(normalizedAttackType)) {
      decisionAttackType = "Lookalike Domain Phishing";
    }

    reasons.unshift({
      category: "ml_score",
      description:
        `LLM fallback (${frontierReview.model}) returned ${frontierReview.finalLabel} with ${frontierReview.riskLevel} risk. ${frontierReview.explanation}`.trim(),
      severity:
        frontierReview.finalLabel === "phishing"
          ? "high"
          : frontierReview.finalLabel === "uncertain"
            ? "medium"
            : "low",
      matchedTerms: frontierReview.reasons,
    });
  }

  if (finalScore >= 61) {
    classification = "phishing";
  } else if (finalScore <= 25) {
    classification = "safe";
  } else {
    classification = "uncertain";
  }
  confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
  confidence = scoreToDeterministicConfidence(finalScore);

  if (frontierReview) {
    classification = frontierReview.finalLabel;

    if (frontierReview.finalLabel === "phishing") {
      finalScore = Math.max(61, Math.round(frontierReview.score));
    } else if (frontierReview.finalLabel === "safe") {
      finalScore = Math.min(25, Math.round(frontierReview.score));
    } else {
      finalScore = Math.min(60, Math.max(26, Math.round(frontierReview.score)));
    }

    confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
    confidence = Math.max(scoreToDeterministicConfidence(finalScore), frontierReview.confidence);
  }

  const lowerAnalysisText = analysisText.toLowerCase();
  const isSafeStatusNotification =
    /password changed successfully|your password has been changed|order has been shipped|order has shipped|subscription renewed|appointment confirmed|thank you for your purchase/i.test(
      lowerAnalysisText,
    );
  const isSafeSignInNotice =
    /(new sign(?:-|\s)?in|sign(?:-|\s)?in was detected|signed in to your account|recognized device|login alert|new device(?: .*?)? signed in|unauthorized activity|naya login detect)/i.test(lowerAnalysisText) &&
    /(if this was you|if this was not you|if this wasn't you|if you do not recognize (?:this device|it)|if you don't recognize (?:this device|it)|no action required|no action is required|can safely ignore|ignore this (?:message|notice)|check (?:your )?account activity|check your account for any unauthorized activity|review (?:this )?activity|sign out of (?:this|the) device|agar ye aap the|agar ye aap nahi the|koi action required nahi hai|official app me review|official app se review)/i.test(lowerAnalysisText) &&
    !/(reply with|send|share|provide|enter (?:your )?(?:otp|password|pin|passcode|credentials?)|confirm your credentials|submit (?:your )?(?:otp|password|pin|passcode|credentials?)|re-?enter|update billing|update payment details|reset password now)/i.test(lowerAnalysisText);
  const isSafePassiveNotice =
    /(if this was you|if this was not you|if this wasn't you|if you do not recognize (?:this device|it)|if you don't recognize (?:this device|it)|no action required|no action is required|can safely ignore|ignore this (?:message|notice)|check (?:your )?account activity|review (?:this )?activity|sign out of (?:this|the) device|agar ye aap the|agar ye aap nahi the|koi action required nahi hai)/i.test(
      lowerAnalysisText,
    ) &&
    !/(reply with|send|share|provide|enter|click|tap|open the secure link|confirm your credentials|update billing|update account|reset password now|otp|password|pin\b|passcode|credentials?|billing details|bank details|card details|mailbox credentials|verification link)/i.test(
      lowerAnalysisText,
    );
  const isSafeEmailConfirmationNotice =
    trust.isTrustedDomain &&
    !trust.hasHeaderSpoof &&
    /(confirm your email address|email confirmation|verify your email address)/i.test(lowerAnalysisText) &&
    /(if you did(?:n't| not) create (?:a |an )?.{0,40}account|you can ignore this email|ignore this email)/i.test(lowerAnalysisText) &&
    !/(reply with|send|share|provide|enter (?:your )?(?:otp|password|pin|passcode|credentials?)|re-?enter|update billing|update payment details|wire transfer|bank transfer)/i.test(lowerAnalysisText);
  const isSafeServiceUtilityNotification =
    trust.isTrustedDomain &&
    !trust.hasHeaderSpoof &&
    /(aws notifications|this is sns test|stop receiving notifications from this topic|please do not reply directly to this email)/i.test(lowerAnalysisText) &&
    /(unsubscribe|aws\.amazon\.com\/support|sns\.[a-z0-9-]+\.amazonaws\.com)/i.test(lowerAnalysisText) &&
    !/(reply with|send|share|provide|enter (?:your )?(?:otp|password|pin|passcode|credentials?)|confirm your identity|update billing|update payment details|wire transfer|bank transfer)/i.test(lowerAnalysisText);
  // Another manual-review fix: plain document review mail was getting nudged into
  // the suspicious bucket even when nothing risky was present.
  const isSafeDocumentReview =
    /please review the (?:attached )?document\b|review the (?:attached )?document\b|review (?:the )?document\b|review (?:the )?report\b|document attached for review|for discussion only|informational only|thanks for the update/i.test(
      lowerAnalysisText,
    ) &&
    !/(account|security|invoice|payment|payroll|bank|login|verify|confirm)/i.test(
      lowerAnalysisText,
    ) &&
    !/\bupdate (?:billing|account|profile|bank|payment)\b|zip file|docm|xlsm|enable macros|enable content|scan (?:the )?qr code|shared document|grant consent|authorize app/i.test(
      lowerAnalysisText,
    );
  const isSafeCollaborationNotice =
    /(shared a (?:file|folder) with you|open in dropbox|open in google drive|view event in google calendar|you are receiving this email because a file was shared with you|you were invited to a meeting|manage notification settings anytime)/i.test(
      lowerAnalysisText,
    ) &&
    !/(confirm your (?:identity|credentials|login details)|verify your identity|keep (?:workspace )?access|maintain access|grant consent|authorize app|approve sign(?:-|\s)?in|password|otp|re-?enter|secure thread)/i.test(
      lowerAnalysisText,
    );
  const isSafeNewsletter =
    /(unsubscribe|privacy\s*[·•|]\s*terms|official blog|release notes|newsletter|product update|launch week|included in your .* plan|logging and training policies|data retention|privacy dashboard|zero data retention|prompt logging|usage discount|paid requests never route)/i.test(
      lowerAnalysisText,
    ) &&
    !/(reply with|\bsend\b|\bshare\b|\bprovide\b|\benter\b|\bsubmit\b|otp|password|pin\b|passcode|credentials?|billing details|bank details|card details|wire transfer|bank transfer|confirm payment|claim refund|urgent(?:ly)?|immediate(?:ly)?|avoid suspension|deadline)/i.test(
      lowerAnalysisText,
    );
  const hasBenignBillingDashboardContextFinal =
    /(subscription payment|billing (?:&|and) invoices|billing issue|could(?:n't| not) process payment|in your dashboard|official dashboard)/i.test(
      lowerAnalysisText,
    ) &&
    /(dashboard|billing (?:&|and) invoices|reply to this email|reach out to us|support@|help@|hi@)/i.test(
      lowerAnalysisText,
    ) &&
    !/(update billing details|update payment details|re-?enter (?:your )?(?:card|bank|payment|billing) details|provide.*(?:card|bank)|wire transfer|bank transfer|confirm payment|urgent|immediately|final notice|avoid suspension|within \d+ ?hours?)/i.test(
      lowerAnalysisText,
    );
  const hasBareLinkOnlyText = /^(?:(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/\S*)?)$/i.test(lowerAnalysisText.trim());
  const linkOnlyResidualText = lowerAnalysisText
    .replace(/https?:\/\/[^\s]+|www\.[^\s]+/gi, " ")
    .replace(/[^a-z\u0900-\u097f]+/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
  const hasShortSuspiciousLinkLure =
    urlAnalyses.length > 0 &&
    lowerAnalysisText.length <= 160 &&
    (linkOnlyResidualText.length === 0 ||
      /^(?:(?:verify|click|open|review|visit|check|login|secure|confirm)(?:\s+(?:here|now|link|portal|access))?|access|keep access(?: active)?|maintain access|restore access|open to keep access active)$/.test(
        linkOnlyResidualText,
      ));
  const hasBareLinkOnlySuspicious =
    (hasBareLinkOnlyText || hasShortSuspiciousLinkLure) &&
    (domainIntel.hasSuspiciousLink || domainIntel.hasLookalikePatterns);
  const isBareLinkOnlySafeCandidate =
    (hasBareLinkOnlyText || hasShortSuspiciousLinkLure) &&
    !hasBareLinkOnlySuspicious &&
    (isTrustedSafeLink || urlAnalyses.every((url) => url.isSuspicious === false)) &&
    !hasCredentialRequest &&
    !isFinancialScam &&
    !behavior.hasUrgency &&
    !isNoLinkPhishing;
  const canHonorSafeContextDespiteCredentialTerms =
    !hasCredentialRequest ||
    isSafeOtp ||
    isSafeTransactional ||
    isSafeSignInNotice ||
    isSafePassiveNotice;
  const canRelaxHeaderNoiseForSafeContext =
    (isSafeOtp || isSafeTransactional || isSafeNewsletter || isSafeSignInNotice || isSafePassiveNotice) &&
    headerAnalysis.spoofingRisk !== "high";
  const safeContextExemptFromFinancialBlock =
    isSafeOtp || isSafeTransactional || isSafeNewsletter || isSafeSignInNotice || isSafePassiveNotice;
  const hasSafeDeterministicOverride =
    (isSafeOtp ||
      isSafeTransactional ||
      isTrustedSafeLink ||
      trust.isTrustedDomain ||
      isSafeStatusNotification ||
      isSafeSignInNotice ||
      isSafePassiveNotice ||
      isSafeEmailConfirmationNotice ||
      isSafeServiceUtilityNotification ||
      isSafeDocumentReview ||
      isSafeCollaborationNotice ||
      isSafeNewsletter ||
      isBareLinkOnlySafeCandidate) &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    (!trust.hasHeaderSpoof || canRelaxHeaderNoiseForSafeContext) &&
    attachmentIntel.suspiciousAttachmentCount === 0 &&
    threatIntel.recommendedAction === "allow" &&
    canHonorSafeContextDespiteCredentialTerms &&
    !isNoLinkPhishing &&
    (!isFinancialScam || safeContextExemptFromFinancialBlock);

  if (hasSafeDeterministicOverride) {
    finalScore = Math.min(finalScore, isSafeOtp ? 18 : 24);
    classification = "safe";
    confidenceLevel = "LOW";
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
    decisionAttackType = "Safe / Informational";
  }

  if (!hasSafeDeterministicOverride && hasBareLinkOnlySuspicious) {
    const shouldEscalateLinkOnlyToPhishing =
      hasShortSuspiciousLinkLure ||
      domainIntel.hasLookalikePatterns ||
      suspiciousUrls.some((item) => /verify|login|secure|update|portal|review/i.test(item.url));

    finalScore = Math.max(finalScore, shouldEscalateLinkOnlyToPhishing ? 75 : 36);
    classification = shouldEscalateLinkOnlyToPhishing ? "phishing" : "uncertain";
    confidenceLevel = shouldEscalateLinkOnlyToPhishing ? "HIGH" : "MEDIUM";
    confidence = scoreToDeterministicConfidence(finalScore);
    decisionAttackType = domainIntel.hasLookalikePatterns
      ? "Lookalike Domain Phishing"
      : "Link Phishing";
    reasons.unshift({
      category: "url",
      description: shouldEscalateLinkOnlyToPhishing
        ? "This message is a minimal link lure that points to a risky domain pattern. Short prompts like 'verify here' that lead to low-trust URLs should be treated as phishing."
        : "This message is mostly just a link, and the destination uses a risky or low-trust domain pattern. Treat standalone links like this as suspicious unless you expected them from an official source.",
      severity: shouldEscalateLinkOnlyToPhishing ? "high" : "medium",
      matchedTerms: suspiciousUrls.map((item) => item.domain).slice(0, 3),
    });
  }

  const isGenericAccountAlert =
    isAccountAlert &&
    !isSafeOtp &&
    !isSafeTransactional &&
    !headerAnalysis.senderDomain &&
    !headerAnalysis.hasHeaders;

  if (classification === "safe" && isGenericAccountAlert && !hasSafeDeterministicOverride && !isSafeSignInNotice) {
    finalScore = Math.max(35, finalScore);
    classification = "uncertain";
    confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
    decisionAttackType = "Account Alert / Social Engineering";
    reasons.unshift({
      category: "social_engineering",
      description:
        "This message uses generic account-alert language without a verifiable sender or official destination. Treat it cautiously until confirmed through a trusted channel.",
      severity: "medium",
      matchedTerms: ["unusual activity", "account alert"],
    });
  }

  const hasProtectiveFallbackContext =
    /do not share|don'?t share|never share|will never ask|if this was you|if this was not you|if this wasn't you|ignore if not you|ignore this message|no action required|no action is required|can safely ignore|official (?:website|site|app)|official app|share mat karo|share मत करें|किसी के साथ साझा न करें|साझा न करें|मत साझा करें|koi action required nahi hai|agar ye aap the|agar ye aap nahi the|official app me review|official app se review/i.test(
      lowerAnalysisText,
    );
  const hasHighRiskShortDirective =
    !hasProtectiveFallbackContext &&
    lowerAnalysisText.length <= 160 &&
    /verify now|verify your (?:account|profile|mailbox|bank(?:ing)? profile)|verification required|secure your account|secure login(?: required)?|login required|login alert|click (?:login|to login)|reset password|bank alert|account under review|account verification form|expense reimbursement is on hold|unauthorized login detected|unusual login attempt|unusual login detected|login attempt|update billing details|re-?enter (?:your )?(?:card|bank(?:ing)? details|billing details)|claim refund|refund available|otp required|otp .*?(?:send|reply|share|పంపండి)|confirm credentials|confirm your sign(?:-|\s)?in details?|submit details|submit (?:the )?(?:required )?identity (?:information|details?|documents?)|submit documents immediately|payment failed|update account to continue|update account|important update|click link|avoid (?:suspension|closure|penalt(?:y|ies))|account block(?:ed)?|account (?:will be )?closed|closed in 24h|disabled tonight|unless updated|account restriction|service will be terminated|failure to respond|profile confirmation required|secure account review pending|documents required to keep (?:service|access)|reactivate (?:your )?(?:mailbox|account|profile)|otp bhej|access band ho jayega|block ho jayega|band hone wala hai|khata band|confirm (?:your )?identity|verify identity to keep access|suspicious login|confirm details to avoid closure|verify your profile|update account details|process (?:this )?invoice|pay(?:ment)? reminder|validate your mailbox (?:credentials|ownership)|mailbox credentials|verification link|handle this task urgently|take care of this task immediately|do this quickly|for security purposes|ensure uninterrupted service|review your account activity at your convenience|government alert|government review pending|official notice|legal notice|failure to comply may result in penalty|compliance update required|pan verification required|aadhaar verification required|wallet verification needed|limited crypto offer|send funds get return|crypto bonus available|respond immediately|avoid action/i.test(
      lowerAnalysisText,
    );
  const hasBenignEditorialEscalationExemption =
    (isSafeNewsletter || isSafeTransactional) &&
    !hasCredentialRequest &&
    !isFinancialScam &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    attachmentIntel.suspiciousAttachmentCount === 0 &&
    threatIntel.recommendedAction === "allow";
  const hasActionContextComboFinal =
    !hasBenignEditorialEscalationExemption &&
    /\b(?:update|updating|confirm|confirming|review|reviewing|check|checking|verify|verifying|process|processing|submit|submitting|handle|handling|complete|transfer|finish|sort|secure|reset|take action|ensure|maintain|open|opening|visit|visiting|login|logging\s+in)\b/i.test(
      lowerAnalysisText,
    ) &&
    /(account|profile|service|payment|invoice|payroll|bank|security|details|information|status|activity|identity|access)/i.test(
      lowerAnalysisText,
    );
  const hasRiskEscalatingConsequenceFinal =
    !hasBenignEditorialEscalationExemption &&
    /urgent|immediate(?:ly)?|asap|today|tonight|before noon|before end of day|end of day|24h|24 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|next hour|time sensitive|avoid (?:disruption|closure|suspension|penalty|action)|account (?:will be )?closed|closed in 24h|disabled|restriction|restricted|terminated|unless updated|failure to respond|restore access|keep access|service disruption|payroll closes(?: today)?|i(?:'m| am) unavailable|i(?:'m| am) in a meeting|will explain later|quickly|very important|jaldi|warna|band ho jayega|block ho jayega|band hone wala hai|khata band|issue hoga|problem hogi/i.test(
      lowerAnalysisText,
    );
  const hasCleanLookingPhishPatternFinal =
    lowerAnalysisText.length <= 160 &&
    /for security purposes|ensure uninterrupted service|maintain access|avoid disruption/i.test(
      lowerAnalysisText,
    );

  const hasGenericAccountInfoPrompt =
    ((/\b(?:update|updating|confirm|confirming|review|reviewing|check|checking|verify|verifying|take action|refresh)\b/i.test(lowerAnalysisText) &&
      /(details|information|info|email address|account status|account information|account info|security|account|profile|service|status|activity|employee profile)/i.test(
        lowerAnalysisText,
      )) ||
      /\bsecurity (?:update|check) required\b/i.test(lowerAnalysisText) ||
      /please take action regarding your account|account may require attention|immediate review is suggested|update might be needed|verify details if necessary|security might be affected|action could be required|review may help avoid issues|kindly check once|submit documents for verification|security refresh is suggested|refresh is suggested for your employee profile/i.test(
        lowerAnalysisText,
      )) &&
    !hasRiskEscalatingConsequenceFinal &&
    !hasCleanLookingPhishPatternFinal;
  const hasProfessionalCredentialLure =
    /(expense reimbursement|payroll notice|audit continuity|document access exception|secure document|reimbursement|compliance review|tax discrepancy|account record discrepancy)[\s\S]{0,140}(account verification form|validate your mailbox|mailbox (?:credentials|ownership)|re-?enter (?:your )?(?:bank(?:ing)? details|card)|verification link|sign(?:-|\s)?in details?|identity (?:information|details?|documents?))/i.test(
      lowerAnalysisText,
    ) ||
    /(account verification form|validate your mailbox (?:credentials|ownership)|mailbox (?:credentials|ownership)|re-?enter (?:your )?(?:bank(?:ing)? details|card)|verification link|sign(?:-|\s)?in details?|identity (?:information|details?|documents?))/i.test(
      lowerAnalysisText,
    );
  const hasUrgentActionContextThreat =
    hasActionContextComboFinal &&
    (hasRiskEscalatingConsequenceFinal || hasCleanLookingPhishPatternFinal || isUrgencyPhishing || behavior.hasExecutiveFraud);
  const hasPolymorphicCampaignThreat =
    polymorphic.hasActiveCampaign &&
    (hasCredentialRequest ||
      isFinancialScam ||
      behavior.hasExecutiveFraud ||
      behavior.hasAttachmentLure ||
      context.hasWorkflowMismatch ||
      domainIntel.hasSuspiciousLink ||
      hasHighRiskShortDirective ||
      isUrgencyPhishing);
  const shouldCapAtUncertain =
    !context.hasWorkflowMismatch &&
    !context.hasThreadHijackStyleShift &&
    !hasPolymorphicCampaignThreat &&
    !hasCredentialRequest &&
    !isFinancialScam &&
    !domainIntel.hasSuspiciousLink &&
    !domainIntel.hasLookalikePatterns &&
    attachmentIntel.suspiciousAttachmentCount === 0 &&
    threatIntel.recommendedAction === "allow" &&
    !hasUrgentActionContextThreat &&
    (isAccountAlert || hasGenericAccountInfoPrompt || hasBenignBillingDashboardContextFinal);

  const mustNotBeSafe =
    confidenceArchitecture.shouldNeverBeSafe ||
    hasPolymorphicCampaignThreat ||
    hasCredentialRequest ||
    isFinancialScam ||
    behavior.hasSubscriptionTrap ||
    behavior.hasCallbackScam ||
    behavior.hasOAuthConsentLure ||
    behavior.hasLoanOrCreditBait ||
    behavior.hasJobScamPattern ||
    behavior.hasOffPlatformRedirect ||
    context.hasThreadHijackStyleShift ||
    (context.hasWorkflowMismatch && context.hasUrgentWorkflowPressure) ||
    isCryptoScam ||
    isJobScam ||
    isNoLinkPhishing ||
    isRegionalBankThreatPhishing ||
    isUrgencyPhishing ||
    hasHighRiskShortDirective ||
    hasActionContextComboFinal ||
    hasGenericAccountInfoPrompt ||
    hasProfessionalCredentialLure ||
    attachmentIntel.hasHighRiskAttachment ||
    attachmentIntel.suspiciousAttachmentCount > 0 ||
    threatIntel.recommendedAction !== "allow";
  const shouldForcePhishing =
    decision.classification === "phishing" ||
    hasPolymorphicCampaignThreat ||
    isCryptoScam ||
    isJobScam ||
    behavior.hasJobScamPattern ||
    behavior.hasSubscriptionTrap ||
    behavior.hasCallbackScam ||
    behavior.hasOAuthConsentLure ||
    (behavior.hasLoanOrCreditBait && (domainIntel.hasPhishingKeywords || behavior.hasUrgency || domainIntel.hasSuspiciousLink)) ||
    context.hasThreadHijackStyleShift ||
    (context.hasWorkflowMismatch && context.hasUrgentWorkflowPressure) ||
    isRegionalBankThreatPhishing ||
    isHindiPhishing ||
    hasHighRiskShortDirective ||
    hasProfessionalCredentialLure ||
    hasUrgentActionContextThreat ||
    behavior.hasExecutiveFraud ||
    attachmentIntel.hasHighRiskAttachment ||
    threatIntel.recommendedAction === "block" ||
    (domainIntel.hasLookalikePatterns &&
      /(payment|wallet|refund|reimbursement|account|login|verify|secure|portal|credentials?|bank|mailbox|access)/i.test(
        lowerAnalysisText,
      )) ||
    (hasCredentialRequest && (isNoLinkPhishing || isUrgencyPhishing || isShortScam)) ||
    (hasCredentialRequest && /\botp\b/i.test(lowerAnalysisText) && (detectedLanguage !== "en" || lowerAnalysisText.length <= 160)) ||
    (isFinancialScam && (isRewardScam || isNoLinkPhishing || isUrgencyPhishing || isJobScam || hasRiskEscalatingConsequenceFinal || behavior.hasExecutiveFraud)) ||
    (isUrgencyPhishing &&
      /(account|login|password|credentials?|billing|card|refund|bank|otp|pin|tax|pan|aadhaar|identity|wallet|kyc|service|profile)/i.test(lowerAnalysisText) &&
      !hasGenericAccountInfoPrompt);
  if (shouldCapAtUncertain && classification === "phishing" && finalScore < 85) {
    finalScore = Math.min(Math.max(finalScore, 35), 58);
    classification = "uncertain";
    confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
    confidence = scoreToDeterministicConfidence(finalScore);
    decisionAttackType = "Account Alert / Social Engineering";
  }

  if (hasPolymorphicCampaignThreat && polymorphic.recentVariantCount >= 2) {
    finalScore = Math.max(finalScore, 82);
    classification = "phishing";
    confidenceLevel = "HIGH";
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
  }

  if (!hasSafeDeterministicOverride && shouldForcePhishing && classification !== "phishing") {
    finalScore = Math.max(finalScore, decision.riskScore, transformerScore >= 61 ? 78 : 72);
    classification = "phishing";
    confidenceLevel = "HIGH";
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));

    if (behavior.hasCallbackScam) {
      decisionAttackType = "Financial Scam";
    } else if (behavior.hasOAuthConsentLure) {
      decisionAttackType = "Social Engineering";
    } else if (isCryptoScam || /btc|bitcoin|crypto|wallet/i.test(analysisText.toLowerCase())) {
      decisionAttackType = "Financial Scam";
    } else if (hasCredentialRequest) {
      decisionAttackType = /otp/i.test(analysisText) ? "OTP Scam" : "Credential Theft";
    } else if (isFinancialScam) {
      decisionAttackType = "Financial Scam";
    }
  } else if (!hasSafeDeterministicOverride && (decision.classification === "uncertain" || mustNotBeSafe || isShortScam) && classification === "safe") {
    finalScore = Math.max(finalScore, decision.riskScore, isShortScam ? 35 : 45);
    classification = "uncertain";
    confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
  }

  const transformerSuggestsEscalation =
    transformerScore >= 78 &&
    (hasCredentialRequest || isFinancialScam || isCryptoScam || isNoLinkPhishing || isShortScam);

  if (transformerSuggestsEscalation && classification !== "phishing") {
    finalScore = Math.max(finalScore, 74);
    classification =
      hasCredentialRequest || isCryptoScam || isRewardScam ? "phishing" : "uncertain";
    confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
    reasons.unshift({
      category: "ml_score",
      description:
        "Transformer semantics detected a high-risk phishing pattern even though the email relies on short or low-context wording.",
      severity: "high",
      matchedTerms: ["semantic phishing pattern"],
    });
  }

  if (indiaHeuristics.weightedScore > 0) {
    const blendedScore = Math.round(finalScore * 0.65 + indiaHeuristics.weightedScore * 0.35);
    finalScore = indiaHeuristics.flags.newsletterContext
      ? Math.min(finalScore, Math.max(0, blendedScore))
      : Math.max(finalScore, blendedScore);
  }

  if (indiaHeuristics.flags.shortFinancialUrl) {
    finalScore = Math.min(100, Math.round(finalScore * 1.2));
  }

  if (indiaHeuristics.scoreCap !== undefined) {
    finalScore = Math.min(finalScore, indiaHeuristics.scoreCap);
  }

  const shouldGuaranteeHighPhishingScore =
    classification === "phishing" &&
    (confidenceArchitecture.shouldNeverBeSafe ||
      hasCredentialRequest ||
      isFinancialScam ||
      isCryptoScam ||
      isJobScam ||
      isNoLinkPhishing ||
      behavior.hasExecutiveFraud ||
      hasHighRiskShortDirective ||
      attachmentIntel.hasHighRiskAttachment ||
      threatIntel.recommendedAction === "block");

  if (shouldGuaranteeHighPhishingScore) {
    finalScore = Math.max(finalScore, 72);
    confidenceLevel = "HIGH";
    confidence = Math.max(confidence, scoreToDeterministicConfidence(finalScore));
  }

  if ((classification === "phishing" || classification === "uncertain") && decisionAttackType === "Safe / Informational") {
    if (isCryptoScam || isFinancialScam || isRewardScam) {
      decisionAttackType = "Financial Scam";
    } else if (
      hasCredentialRequest ||
      isSensitiveDataOverride ||
      /verify|verification|login|account|bank|profile|credentials?|identity|mailbox ownership|sign-?in details/i.test(lowerAnalysisText)
    ) {
      decisionAttackType = /otp/i.test(analysisText) ? "OTP Scam" : "Credential Theft";
    } else if (domainIntel.hasLookalikePatterns) {
      decisionAttackType = "Lookalike Domain Phishing";
    } else if (
      isNoLinkPhishing ||
      isNoLinkSocialEngineering ||
      isShortScam ||
      isRegionalBankThreatPhishing ||
      adversarial.detected ||
      hasHighRiskShortDirective ||
      hasActionContextComboFinal ||
      hasUrgentActionContextThreat ||
      hasGenericAccountInfoPrompt
    ) {
      decisionAttackType = "Social Engineering";
    }
  }

  if (
    classification !== "safe" &&
    reasons.every((reason) => reason.category === "ml_score") &&
    (isShortScam || hasHighRiskShortDirective || hasUrgentActionContextThreat)
  ) {
    const shortMatchedTerms = [
      ...new Set([
        ...SHORT_SCAM_PHRASES.filter((phrase) => lowerAnalysisText.includes(phrase)),
        ...URGENCY_WORDS.filter((term) => lowerAnalysisText.includes(term)),
      ]),
    ].slice(0, 4);
    const fallbackShortTerms = [
      ...new Set(
        (analysisText.match(
          /\b(?:click|link|suspension|closure|urgent|immediately|now|24h|reply|verify|update|account|otp|password|login|confirm|review)\b/gi,
        ) ?? []).map((term) => term.toLowerCase()),
      ),
    ].slice(0, 4);
    const finalShortMatchedTerms = shortMatchedTerms.length > 0 ? shortMatchedTerms : fallbackShortTerms;
    const explicitUrgencyTermsFinal = finalShortMatchedTerms.filter((term) => URGENCY_WORDS.includes(term));

    reasons.unshift({
      category: explicitUrgencyTermsFinal.length > 0 ? "urgency" : "social_engineering",
      description:
        explicitUrgencyTermsFinal.length > 0
          ? "The email uses explicit urgency words to push a quick action without proper verification context."
          : "The email uses a short command-style phishing prompt to push a risky action without proper context or verification.",
      severity: classification === "phishing" ? "high" : "medium",
      matchedTerms: finalShortMatchedTerms,
    });
  }

  finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));
  if (finalScore >= 61) {
    classification = "phishing";
  } else if (finalScore <= 25 && !mustNotBeSafe) {
    classification = "safe";
  } else if (classification !== "safe") {
    classification = "uncertain";
  }
  confidenceLevel = mapRiskScoreToConfidenceLevel(finalScore);

  reasons = finalizeDisplayReasons(reasons, classification);

  const highlightTerms = [
    ...new Set([
      ...allTerms,
      ...reasons.flatMap((reason) => reason.matchedTerms),
    ]),
  ].slice(0, 30);
  const suspiciousSpans = findSuspiciousSpans(emailText, highlightTerms);

  const featureImportance = topFeatures.map((f: FeatureContribution) => ({
    feature: f.feature,
    contribution: f.contribution,
    direction: f.direction,
  }));

  if (adversarial.detected) {
    featureImportance.unshift({
      feature: "Adversarial obfuscation detected",
      contribution: Math.max(1.8, adversarial.confidence / 30),
      direction: "phishing",
    });
  }

  if (frontierReview) {
    featureImportance.unshift({
      feature: `LLM fallback (${frontierReview.model})`,
      contribution: Math.max(1.2, frontierReview.score / 35),
      direction: frontierReview.finalLabel === "safe" ? "safe" : "phishing",
    });
  }

  // Map engine attack types to legacy API enum
  let attackType:
    | "Credential Harvesting"
    | "Reward Scam"
    | "Bank Impersonation"
    | "OTP Scam"
    | "Social Engineering"
    | "Safe / Informational"
    | "Account Alert / Social Engineering"
    | "Lookalike Domain Phishing"
    | "Business Email Compromise"
    | "Delivery Fee Scam"
    | "Newsletter / Digest"
    | "GST Compliance Scam"
    | "SMS Spoofing Attack" = "Safe / Informational";

  switch (decisionAttackType) {
    case "Credential Theft":
      attackType = "Credential Harvesting";
      break;
    case "Brand Impersonation":
      attackType = "Bank Impersonation";
      break;
    case "Financial Scam":
      attackType = "Reward Scam";
      break;
    case "Link Phishing":
      attackType = "Credential Harvesting"; // or leave as Social Engineering
      break;
    case "Social Engineering":
      attackType = "Social Engineering";
      break;
    case "Safe / Informational":
      attackType = "Safe / Informational";
      break;
    case "Account Alert / Social Engineering":
      attackType = "Account Alert / Social Engineering";
      break;
    case "Lookalike Domain Phishing":
      attackType = "Lookalike Domain Phishing";
      break;
    case "OTP Scam":
      attackType = "OTP Scam";
      break;
  }

  if (indiaHeuristics.attackTypeOverride) {
    attackType = indiaHeuristics.attackTypeOverride as typeof attackType;
  }

  // Scam story from explanation engine
  let scamStory = explanation.whatIsHappening;
  if (frontierReview) {
    scamStory = `${scamStory} LLM fallback assessment: ${frontierReview.explanation}`;
  }

  if (classification === "safe") {
    const hasTrustedSafeOutcome =
      hasSafeDeterministicOverride ||
      isSafeOtp ||
      isSafeTransactional ||
      isSafeNewsletter ||
      isSafeCollaborationNotice ||
      isSafeSignInNotice ||
      isSafePassiveNotice ||
      isSafeEmailConfirmationNotice ||
      isSafeServiceUtilityNotification ||
      trust.isTrustedDomain;
    const safeFloor = hasTrustedSafeOutcome ? 0.88 : 0.8;
    confidence = Math.min(
      0.96,
      Math.max(confidence, scoreToDeterministicConfidence(finalScore), safeFloor),
    );
  } else if (classification === "phishing") {
    confidence = Math.min(
      0.99,
      Math.max(confidence, 0.89, scoreToDeterministicConfidence(finalScore)),
    );
  } else {
    confidence = Math.min(0.79, Math.max(0.55, confidence));
  }

  confidence = Number(Math.max(0.05, Math.min(0.95, confidence)).toFixed(2));
  confidenceLevel = mapConfidenceValueToLevel(confidence);

  const preventionPlan = buildPreventionPlan({
    classification,
    attackType,
    suspiciousUrlCount: suspiciousUrls.length,
    attachmentIntel,
    threatIntel,
  });

  if (polymorphic.hasActiveCampaign) {
    preventionPlan.preventionActions.unshift(
      polymorphic.recentVariantCount >= 2
        ? "Treat this as part of an active phishing campaign and quarantine similar variants automatically."
        : "Watch for near-duplicate variants of this message because it matches a known phishing family.",
    );

    if (polymorphic.recentVariantCount >= 2) {
      preventionPlan.recommendedDisposition = "block";
      preventionPlan.autoBlockRecommended = true;
    }
  }

  const detectedSignals = [
    ...new Set([
      ...buildDetectedSignals(classification, reasons, attackType),
      ...indiaHeuristics.signals,
      ...attachmentIntel.summarySignals.slice(0, 2),
      ...threatIntel.matchedIndicators.slice(0, 2),
    ]),
  ].slice(0, 6);
  const humanConfidenceLabel = toHumanConfidenceLabel(confidenceLevel);
  const displayLabel = buildDisplayLabel(finalScore, confidenceLevel);
  const explanationText = alignExplanationWithClassification(
    buildFriendlyExplanation(
      classification,
      attackType,
      detectedSignals,
      scamStory,
      reasons,
    ),
    classification,
  );
  scamStory = explanationText;

  return AnalyzeEmailResponse.parse({
    id,
    riskScore: finalScore,
    risk_score: finalScore,
    classification,
    confidence,
    confidenceLevel,
    confidenceLabel: humanConfidenceLabel,
    confidence_level: humanConfidenceLabel,
    displayLabel,
    display_label: displayLabel,
    explanation: explanationText,
    detectedSignals,
    detected_signals: detectedSignals,
    signals: detectedSignals,
    detectedLanguage,
    reasons,
    suspiciousSpans,
    urlAnalyses,
    safetyTips,
    warnings,
    recommendedDisposition: preventionPlan.recommendedDisposition,
    autoBlockRecommended: preventionPlan.autoBlockRecommended,
    preventionActions: preventionPlan.preventionActions,
    attachmentFindings: attachmentIntel.findings,
    threatIntel,
    mlScore,
    ruleScore,
    urlScore,
    headerScore,
    featureImportance,
    headerAnalysis: headerAnalysis.hasHeaders
      ? {
        hasHeaders: true,
        senderEmail: headerAnalysis.senderEmail,
        senderDomain: headerAnalysis.senderDomain,
        displayName: headerAnalysis.displayName,
        replyToEmail: headerAnalysis.replyToEmail,
        replyToDomain: headerAnalysis.replyToDomain,
        mismatch: headerAnalysis.mismatch,
        spoofingRisk: headerAnalysis.spoofingRisk,
        issues: headerAnalysis.issues,
        headerScore: headerAnalysis.headerScore,
      }
      : undefined,
    attackType,
    scamStory,
  });
}
