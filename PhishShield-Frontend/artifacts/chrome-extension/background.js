// PhishShield Guardian — Background Service Worker
// Coordinates deterministic URL protection, Gmail/email state, and final badge + popup sync.
// URL risk checks stay local and deterministic; page/email verdicts are merged consistently.

// ─── Detection rules (mirrored from the PhishShield backend) ─────────────────

const SUSPICIOUS_TLDS = [
  ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
  ".top", ".club", ".online", ".site", ".icu", ".work",
  ".loan", ".click", ".link", ".biz",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "short.io", "rebrand.ly", "cutt.ly", "tiny.cc", "bl.ink",
  "clk.sh", "is.gd", "v.gd",
];

const BRAND_SHORTENERS = ["c.gle", "lnkd.in"];

const LOOKALIKE_PATTERNS = [
  [/paypa[l1]|payp4l/i,                          "PayPal lookalike domain"],
  [/g00gle|g0ogle|gooogle/i,                     "Google lookalike domain"],
  [/amaz0n|am4zon|amazzon/i,                     "Amazon lookalike domain"],
  [/faceb00k|f4cebook|faceb0ok/i,                "Facebook lookalike domain"],
  [/sb[i1]-|sb[i1]\.|sbi-online|sbi_online/i,   "SBI lookalike domain"],
  [/hdf[c0]-|hdfcbank-/i,                        "HDFC lookalike domain"],
  [/icic[i1]-|icicibankk/i,                      "ICICI lookalike domain"],
  [/payt[m0]-|paytrn/i,                          "Paytm lookalike domain"],
  [/ph0nepe|phonep3/i,                           "PhonePe lookalike domain"],
  [/[a-z]+-secure-|secure-[a-z]+\./i,           "Fake 'secure' domain pattern"],
  [/[a-z]+-update\./i,                           "Fake 'update' domain pattern"],
  [/[a-z]+-verify\./i,                           "Fake 'verify' domain pattern"],
  [/[a-z]+-alert\./i,                            "Fake 'alert' domain pattern"],
  [/[a-z]+-kyc\./i,                              "Fake 'KYC' domain pattern"],
  [/[a-z]+-reward\./i,                           "Fake 'reward' domain pattern"],
  [/[a-z]+-claim\./i,                            "Fake 'claim' domain pattern"],
];

const INDIA_BANKS = [
  "sbi", "hdfc", "icici", "axisbank", "pnb", "kotak",
  "yesbank", "indusind", "bankofbaroda", "canarabank", "unionbank",
];

const INDIA_SERVICES = [
  "paytm", "phonepe", "gpay", "bhimupi", "irctc", "uidai",
  "aadhaar", "incometax", "epfo", "nsdl", "cibil",
];

const TRUSTED_DOMAIN_GROUPS = {
  Google: ["google.com", "googlemail.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "c.gle"],
  Amazon: ["amazon.com", "amazon.in", "amazonaws.com", "amazonses.com"],
  Microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"],
  GitHub: ["github.com", "githubassets.com", "githubusercontent.com", "github.io"],
  Overleaf: ["overleaf.com"],
  OpenAI: ["openai.com", "chatgpt.com", "oaistatic.com"],
  LinkedIn: ["linkedin.com", "lnkd.in"],
  Apple: ["apple.com", "icloud.com"],
  Banking: ["sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "bankofbaroda.in", "canarabank.in", "unionbankofindia.co.in"],
  Payments: ["paytm.com", "paytm.in", "phonepe.com", "bhimupi.org.in"],
};

function getBaseDomain(value) {
  const normalized = String(value || "").toLowerCase().replace(/^www\./, "").trim();
  const parts = normalized.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");

  const compoundSuffixes = new Set(["co.uk", "co.in", "com.au", "com.br", "co.jp", "com.mx"]);
  const lastTwo = parts.slice(-2).join(".");
  if (compoundSuffixes.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

function sameDomainFamily(left, right) {
  const a = getBaseDomain(left);
  const b = getBaseDomain(right);
  return Boolean(a && b && a === b);
}

function formatDomainBrandLabel(brand, domain = "") {
  const brandLabels = {
    Google: "Google",
    Amazon: "Amazon",
    Microsoft: "Microsoft",
    GitHub: "GitHub",
    Overleaf: "Overleaf",
    OpenAI: "OpenAI",
    LinkedIn: "LinkedIn",
    Apple: "Apple",
    Banking: "banking",
    Payments: "payment",
    Government: "government",
  };

  if (brand && brandLabels[brand]) {
    return brandLabels[brand];
  }

  return getBaseDomain(domain || "") || "sender";
}

function isTrustedDomainStatus(value) {
  return ["trusted", "verified"].includes(String(value || "").toLowerCase());
}

function getKnownDomainProfile(domain) {
  const normalized = getBaseDomain(domain);
  if (!normalized) return null;

  for (const [brand, domains] of Object.entries(TRUSTED_DOMAIN_GROUPS)) {
    if (domains.some((entry) => sameDomainFamily(normalized, entry) || normalized === entry || normalized.endsWith(`.${entry}`))) {
      const brandLabel = formatDomainBrandLabel(brand, normalized);
      return {
        trust: "Trusted",
        status: "trusted",
        brand: brandLabel,
        domain: normalized,
        label: `Verified ${brandLabel} domain`,
        source: "backend",
      };
    }
  }

  if (/gov\.in$|nic\.in$/i.test(normalized)) {
    return {
      trust: "Trusted",
      status: "trusted",
      brand: "government",
      domain: normalized,
      label: "Verified government domain",
      source: "backend",
    };
  }

  return null;
}

function hasPassingHeaderAuth(headerAnalysis) {
  return ["spf", "dkim", "dmarc"].some((key) => String(headerAnalysis?.[key] || "").toLowerCase() === "pass");
}

function buildDomainTrustInfo(payload = {}) {
  const explicit = payload?.domainTrust || {};
  const senderDomain = getBaseDomain(payload?.headerAnalysis?.senderDomain || payload?.headerAnalysis?.replyToDomain || payload?.senderDomain || "");
  const pageDomain = getBaseDomain(payload?.domain || extractDomain(payload?.url || ""));
  const linkDomains = dedupeStrings(
    (payload?.urlAnalyses || [])
      .map((item) => getBaseDomain(item?.domain || extractDomain(item?.url || "")))
      .filter(Boolean)
  );
  const primaryDomain = getBaseDomain(explicit.domain || senderDomain || pageDomain || linkDomains[0] || "");
  const knownProfile = getKnownDomainProfile(primaryDomain || senderDomain || pageDomain || linkDomains[0] || "");
  const explicitTrust = String(explicit.trust || explicit.domainTrust || explicit.status || "").toLowerCase();
  const spoofingRisk = String(payload?.headerAnalysis?.spoofingRisk || "").toLowerCase();
  const hasSpoofing = Boolean(
    spoofingRisk === "high"
    || payload?.headerAnalysis?.mismatch
    || payload?.headerAnalysis?.returnPathMismatch
    || payload?.headerAnalysis?.replyToMismatch
    || (Array.isArray(payload?.headerAnalysis?.issues) && payload.headerAnalysis.issues.some((issue) => /mismatch|spoof/i.test(String(issue))))
  );
  const suspiciousLinks = Boolean((payload?.urlAnalyses || []).some((item) => item?.isSuspicious));
  const alignedDomains = !senderDomain || !linkDomains.length || linkDomains.every((domain) => sameDomainFamily(domain, senderDomain));
  const hasRiskyTld = Boolean(primaryDomain) && SUSPICIOUS_TLDS.some((tld) => primaryDomain.endsWith(tld));
  const hasLookalikePattern = Boolean(primaryDomain) && LOOKALIKE_PATTERNS.some(([pattern]) => pattern.test(primaryDomain));
  const dynamicTrust = Boolean(
    senderDomain
    && alignedDomains
    && !hasSpoofing
    && !suspiciousLinks
    && !hasRiskyTld
    && !hasLookalikePattern
    && (hasPassingHeaderAuth(payload?.headerAnalysis) || linkDomains.length === 0 || linkDomains.every((domain) => sameDomainFamily(domain, senderDomain)))
  );
  const brandLabel = formatDomainBrandLabel(knownProfile?.brand, primaryDomain || senderDomain || pageDomain || "");
  const source = explicit.source || payload?.source || "backend";

  if (explicitTrust === "suspicious" || hasSpoofing || (!alignedDomains && suspiciousLinks) || (!knownProfile && (hasRiskyTld || hasLookalikePattern) && (suspiciousLinks || String(payload?.classification || "").toLowerCase() !== "safe"))) {
    return {
      trust: "Suspicious",
      status: "suspicious",
      brand: brandLabel,
      domain: primaryDomain || senderDomain || pageDomain || "",
      label: "Domain mismatch or spoofing detected",
      source,
    };
  }

  if (explicitTrust === "trusted" || explicitTrust === "verified" || isTrustedDomainStatus(explicit.status) || knownProfile || dynamicTrust) {
    return {
      trust: "Trusted",
      status: "trusted",
      brand: brandLabel,
      domain: primaryDomain || senderDomain || pageDomain || "",
      label: explicit.label || `Verified ${brandLabel} domain`,
      source,
    };
  }

  return {
    trust: "Unknown",
    status: "unknown",
    brand: brandLabel === "sender" ? "Unknown" : brandLabel,
    domain: primaryDomain || senderDomain || pageDomain || "",
    label: explicit.label || "This domain is not widely recognized — verify if unsure.",
    source,
  };
}

function getTrustedDomainInfo(domain) {
  return buildDomainTrustInfo({ domain, source: "backend" });
}

function mapLanguageLabel(code) {
  switch (String(code || "EN").toUpperCase()) {
    case "HI":
      return "Hindi";
    case "TE":
      return "Telugu";
    case "MX":
      return "Mixed";
    default:
      return "English";
  }
}

function inferIntent(payload, classification) {
  const blob = [
    payload?.category,
    payload?.attackType,
    payload?.explanation,
    payload?.scamStory,
    ...(payload?.reasons || []).map(normalizeReasonText),
    ...(payload?.signals || []),
    ...(payload?.flags || []),
  ].join(" ").toLowerCase();

  if (/password reset|account recovery/.test(blob)) return "Password reset flow";
  if (/security alert|account activity|new sign-?in|login attempt|verification code|otp/.test(blob)) return "OTP / account verification";
  if (/payment|refund|invoice|bank transfer|upi|billing/.test(blob)) return "Payment or banking request";
  if (/newsletter|digest|product update|terms update|policy update|welcome/.test(blob)) return "Routine notification";
  if (classification === "phishing") return "Credential or payment theft attempt";
  if (classification === "uncertain") return "Request needs independent verification";
  return "Normal browsing activity";
}

function extractDomain(url) {
  try {
    const normalized = url.startsWith("http") ? url : "https://" + url;
    return new URL(normalized).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase() : url;
  }
}

function checkUrl(url) {
  if (!url || !url.startsWith("http")) return null;

  const domain = extractDomain(url);
  const trustInfo = getTrustedDomainInfo(domain);
  const flags = [];
  const reasons = [];
  const scoreBreakdown = [];
  let score = 0;

  const addImpact = (label, impact, detail, flag) => {
    score += impact;
    scoreBreakdown.push({ label, impact, detail });
    if (flag) {
      flags.push(flag);
    }
  };

  if (isTrustedDomainStatus(trustInfo?.status) || trustInfo?.trust === "Trusted") {
    addImpact("Trusted domain verification", -45, trustInfo.label, "Trusted domain verified");
    reasons.push(`This destination resolves to a ${trustInfo.label.toLowerCase()}, which strongly reduces phishing risk.`);
  }

  const tld = "." + domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld) && !isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Suspicious top-level domain", 30, tld, `Suspicious TLD: ${tld}`);
    reasons.push(`This site uses the "${tld}" domain, which is commonly abused in phishing campaigns.`);
  }

  if (URL_SHORTENERS.some((entry) => domain.includes(entry))) {
    addImpact("URL shortener hides destination", 25, domain, "URL shortener detected");
    reasons.push("A link shortener can hide the real destination, so the final landing page needs closer review.");
  } else if (BRAND_SHORTENERS.some((entry) => domain.includes(entry))) {
    addImpact("Official brand shortener", -15, domain, "Official brand shortener detected");
    reasons.push("This is an official shortener used by a trusted brand.");
  }

  let lookalikMatched = false;
  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain) && !isTrustedDomainStatus(trustInfo?.status)) {
      addImpact("Lookalike or impersonation domain", 45, domain, label);
      reasons.push(`"${domain}" appears to imitate a trusted brand (${label}). This is a classic phishing tactic.`);
      lookalikMatched = true;
      break;
    }
  }

  if (domain.split(".").length > 3 && !isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Complex subdomain structure", 12, domain, "Complex subdomain structure");
    reasons.push("Deep subdomain chains are often used to make phishing pages look legitimate.");
  }

  if (/[0-9]/.test(domain.split(".")[0]) && !isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Numbers in domain label", 10, domain.split(".")[0], "Numbers in domain name");
    reasons.push("Legitimate brands rarely use numbers in the visible domain label.");
  }

  if (url.length > 100 && !isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Long URL footprint", 8, `${url.length} characters`, "Unusually long URL");
    reasons.push("Phishing links are often deliberately long to discourage manual inspection.");
  }

  if (/token=|session=|verify=|otp=|password=|pin=/i.test(url)) {
    addImpact("Sensitive query parameters", 18, "Query string contains credential or session terms", "Sensitive parameters in URL");
    reasons.push("The URL exposes credential or session-related parameters in the address bar.");
  }

  if (/secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(domain) && !isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Deceptive trust wording in domain", 15, domain, "Deceptive keyword in domain");
    reasons.push("The domain uses trust-building words such as “secure”, “login”, or “verify” to appear legitimate.");
  }

  const domainStripped = domain.toLowerCase().replace(/[-_.]/g, "");
  const matchedBank = INDIA_BANKS.find((entry) => domainStripped.includes(entry));
  const matchedService = INDIA_SERVICES.find((entry) => domainStripped.includes(entry));
  const isIndianBankingRelated = !!(matchedBank || matchedService);

  if (isIndianBankingRelated && isTrustedDomainStatus(trustInfo?.status)) {
    addImpact("Verified banking or payment brand", -20, (matchedBank || matchedService || "service").toUpperCase(), "Verified institution domain");
    reasons.push("The destination matches the official banking or payment domain family.");
  } else if (isIndianBankingRelated && score > 10) {
    const brandName = (matchedBank || matchedService || "service").toUpperCase();
    addImpact("Banking impersonation risk", 18, brandName, "Banking brand mismatch");
    reasons.push(
      matchedBank
        ? `This looks like a fake ${brandName} banking page. Real banks will NEVER ask for your OTP or PIN through a link.`
        : `This appears to impersonate ${brandName}. Never enter your UPI PIN or Aadhaar details on suspicious sites.`
    );
  }

  const finalScore = clamp(score, 0, 100);
  const classification = finalScore >= 71 ? "phishing" : finalScore >= 31 ? "suspicious" : "safe";
  const suspiciousParts = [];
  if (SUSPICIOUS_TLDS.includes(tld) && !isTrustedDomainStatus(trustInfo?.status)) suspiciousParts.push({ part: tld, reason: "Suspicious TLD" });
  if (lookalikMatched) suspiciousParts.push({ part: domain, reason: "Lookalike domain" });

  const domainTrust = buildDomainTrustInfo({
    domain,
    url,
    classification,
    urlAnalyses: [{ domain, url, isSuspicious: classification !== "safe" }],
    source: "backend",
  });

  return {
    url,
    domain: domainTrust.domain || domain,
    riskScore: finalScore,
    classification,
    flags: dedupeStrings(flags),
    reasons: dedupeStrings(reasons),
    isIndianBankingRelated,
    suspiciousParts,
    scoreBreakdown,
    domainTrust,
    linkAnalysis: {
      status: classification === "phishing" ? "risky" : classification === "suspicious" ? "review" : "clean",
      label: classification === "safe"
        ? "No suspicious link behavior detected"
        : classification === "phishing"
          ? "Link pattern matches phishing indicators"
          : "Link should be verified before opening",
    },
    category: classification === "safe" ? "Trusted website" : classification === "phishing" ? "Suspicious link" : "Link needs review",
    intent: "Open website",
    detectedLanguage: "EN",
  };
}

// ─── Internal pages we never check ───────────────────────────────────────────

const SKIP_PREFIXES = ["chrome:", "chrome-extension:", "edge:", "about:", "data:", "file:"];

function shouldSkip(url) {
  return !url || SKIP_PREFIXES.some(p => url.startsWith(p));
}

// ─── Per-tab result cache ─────────────────────────────────────────────────────

const tabState = new Map(); // tabId → { url, urlResult, contentState, emailResult, finalResult }
const urlCache = new Map(); // URL → deterministic URL analysis result
const allowedUrls = new Set(); // URLs the user has explicitly approved (allow once)
const EMAIL_API_BASE_CANDIDATES = ["http://127.0.0.1:8000", "http://localhost:8000"];
const EMAIL_API_RETRY_COOLDOWN_MS = 30000;
const EMAIL_API_LOG_THROTTLE_MS = 60000;
let emailApiOfflineUntil = 0;
let lastEmailApiLogAt = 0;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function dedupeStrings(values) {
  return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
}

function normalizeClassification(value, riskScore) {
  if (value === "suspicious") return "uncertain";
  if (value === "safe" || value === "uncertain" || value === "phishing") return value;
  if (riskScore >= 71) return "phishing";
  if (riskScore >= 31) return "uncertain";
  return "safe";
}

function normalizeReasonText(reason) {
  if (!reason) return "";
  if (typeof reason === "string") return reason;
  return reason.description || reason.label || reason.category || "Suspicious activity detected";
}

function normalizeExplanationText(value) {
  if (!value) return "";
  const normalized = typeof value === "string"
    ? value
    : typeof value === "number" || typeof value === "boolean"
      ? String(value)
      : String(
          value.why_risky
          || value.scamStory
          || value.summary
          || value.reason
          || value.message
          || value.description
          || value.text
          || ""
        ).trim();

  if (/^top words driving this verdict$/i.test(normalized) || /^ai analysis completed$/i.test(normalized)) {
    return "";
  }

  return normalized;
}

function canonicalizeSignal(value) {
  const raw = String(value || "").trim();
  const lower = raw.toLowerCase();
  if (!raw) return "";

  if (/otp \/ account verification|account activity|password reset flow|verification flow/.test(lower)) return "OTP / account verification";
  if (/credential|password|otp|pin|passcode|identity/.test(lower)) return "Credential request";
  if (/suspicious link|lookalike|shortener|spoof|fake .*domain|deceptive/.test(lower)) return "Suspicious link";
  if (/urgent|deadline|final notice|pressure|suspension|blocked/.test(lower)) return "Urgency pressure";
  if (/impersonat|trusted brand|brand|bank/.test(lower)) return "Impersonation risk";
  if (/known sender|trusted sender/.test(lower)) return "Trusted sender";
  if (/routine|newsletter|product-update|informational/.test(lower)) return "Routine communication";
  if (/no credential|no password|no otp|no payment/.test(lower)) return "No sensitive request";
  return raw;
}

function buildKeySignals(payload) {
  const classification = normalizeClassification(payload.classification ?? payload.visualClassification, Number(payload.riskScore ?? 0));
  const rawSignalText = [
    ...(payload.flags || []),
    ...(payload.keySignals || []),
    ...(payload.detectedSignals || []),
    ...(payload.detected_signals || []),
    ...(payload.signals || []),
  ].join(" ").toLowerCase();

  const reasonBlob = [
    ...(payload.reasons || []).map(normalizeReasonText),
    normalizeExplanationText(payload.explanation),
  ].join(" ").toLowerCase();

  const negatesCredential = /no credential|does not ask for passwords|does not request|no password request|no otp request/.test(reasonBlob);
  const negatesLink = /no spoofed domain|no suspicious phishing pattern|known sender domain|known sender context|trusted sender|verified destination/.test(reasonBlob);
  const negatesUrgency = /no urgency|no strong urgency|routine language|routine communication|routine product-update|routine message/.test(reasonBlob);
  const safeOtpContext = classification === "safe" && /(trusted sender|verified .*domain|protective security wording|account activity notification|password reset flow|otp \/ account verification)/i.test(`${rawSignalText} ${reasonBlob} ${payload.intent || ""} ${payload.category || ""}`);

  const signals = [];
  if (safeOtpContext && /(otp|verification code|security code|sign-?in|password reset|account activity)/i.test(`${rawSignalText} ${reasonBlob} ${payload.intent || ""}`)) {
    signals.push("OTP / account verification");
  } else if (!negatesCredential && /(credential|password|pin\b|otp|passcode|identity|sign-?in details|send your otp|reply with.*otp)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
    signals.push("Credential request");
  }
  if (!negatesLink && /(suspicious link|lookalike|shortener|deceptive keyword|fake .*domain|spoof|impersonat)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
    signals.push("Suspicious link");
  }
  if (!negatesUrgency && /(urgent|immediate|immediately|act now|deadline|final notice|suspension|blocked|pressure)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
    signals.push("Urgency pressure");
  }
  if (classification !== "safe" && /(impersonat|spoof|trusted brand|bank|brand)/i.test(`${rawSignalText} ${reasonBlob}`)) {
    signals.push("Impersonation risk");
  }

  return dedupeStrings(signals.map(canonicalizeSignal)).slice(0, 3);
}

async function scanEmailWithLocalApi(payload) {
  if (!payload?.email_text) {
    return null;
  }

  if (Date.now() < emailApiOfflineUntil) {
    return null;
  }

  let lastError = null;
  const requestVariants = [
    {
      endpoint: "/api/analyze",
      body: {
        emailText: String(payload.email_text || ""),
        headers: String(payload.headers || ""),
      },
    },
    {
      endpoint: "/scan-email",
      body: {
        email_text: String(payload.email_text || ""),
      },
    },
  ];

  for (const baseUrl of EMAIL_API_BASE_CANDIDATES) {
    for (const variant of requestVariants) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const response = await fetch(`${baseUrl}${variant.endpoint}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(variant.body),
          signal: controller.signal,
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        emailApiOfflineUntil = 0;
        return await response.json();
      } catch (error) {
        clearTimeout(timeoutId);
        lastError = error;
      }
    }
  }

  const isExpectedConnectivityFailure =
    lastError && (
      lastError.name === "AbortError" ||
      /Failed to fetch|NetworkError|Load failed/i.test(String(lastError?.message || lastError))
    );

  if (isExpectedConnectivityFailure) {
    emailApiOfflineUntil = Date.now() + EMAIL_API_RETRY_COOLDOWN_MS;
    if (Date.now() - lastEmailApiLogAt > EMAIL_API_LOG_THROTTLE_MS) {
      lastEmailApiLogAt = Date.now();
      console.info("PhishShield local email API is unavailable from the extension background.");
    }
  } else if (lastError) {
    console.warn("PhishShield background email analysis failed.", lastError);
  }

  return null;
}

function buildExplanation(classification, signals, reasons, source) {
  if (classification === "safe") {
    if (signals.includes("OTP / account verification")) {
      return "This is a legitimate account verification message. Only use the OTP on the official website.";
    }

    return source === "gmail-email"
      ? "No risky behavior detected. This is a trusted message."
      : "No risky behavior detected. This page looks trustworthy.";
  }

  if (classification === "phishing") {
    if (signals.includes("Credential request")) {
      return "This page or email asks for sensitive information, which is a strong phishing indicator.";
    }
    if (signals.includes("Suspicious link")) {
      return "This destination uses a suspicious link pattern commonly seen in phishing attacks.";
    }
    return "This page or email shows strong phishing indicators and should not be trusted.";
  }

  if (signals.includes("Urgency pressure") || signals.includes("Real urgency")) {
    return "This content uses pressure or urgency, so verify it through an official channel before acting.";
  }

  return "This content shows suspicious signals and should be verified before you click, reply, or sign in.";
}

function normalizeResult(result, fallback = {}) {
  const initialRiskScore = clamp(Number(result?.riskScore ?? result?.risk_score ?? fallback.riskScore ?? 0), 0, 100);
  const initialClassification = normalizeClassification(result?.classification ?? fallback.classification, initialRiskScore);
  const reasons = dedupeStrings([
    ...((result?.reasons || fallback.reasons || []).map(normalizeReasonText)),
  ]).slice(0, 4);
  const flags = dedupeStrings([
    ...(result?.flags || fallback.flags || []),
    ...(result?.detectedSignals || []),
    ...(result?.detected_signals || []),
    ...(result?.signals || []),
  ]);
  const normalizedExplanation = normalizeExplanationText(result?.explanation ?? result?.scamStory ?? fallback.explanation);
  const headerAnalysis = result?.headerAnalysis || fallback.headerAnalysis || null;
  const initialKeySignals = buildKeySignals({ ...result, ...fallback, classification: initialClassification, riskScore: initialRiskScore, reasons, flags, explanation: normalizedExplanation }).slice(0, 4);
  const resolvedDomain = getBaseDomain(result?.domain || fallback.domain || extractDomain(result?.url || fallback.url || ""));
  const urlAnalyses = Array.isArray(result?.urlAnalyses) ? result.urlAnalyses : Array.isArray(fallback.urlAnalyses) ? fallback.urlAnalyses : [];
  const domainTrust = buildDomainTrustInfo({
    ...fallback,
    ...result,
    domain: resolvedDomain,
    headerAnalysis,
    urlAnalyses,
  });
  const signalBlob = [result?.category, result?.attackType, fallback.category, fallback.attackType, result?.intent, fallback.intent, normalizedExplanation, ...reasons, ...initialKeySignals, ...flags].join(" ").toLowerCase();
  const hasTrustedDomain = domainTrust?.trust === "Trusted" || isTrustedDomainStatus(domainTrust?.status);
  const hasOtpContext = /otp|verification code|security code|authentication code|sign-?in|account activity|two[- ]?factor|2fa/.test(signalBlob);
  const hasSuspiciousLinks = urlAnalyses.some((item) => item?.isSuspicious) || initialKeySignals.includes("Suspicious link");
  const hasUrgencySignal = initialKeySignals.includes("Urgency pressure") || /urgent|immediately|act now|final notice|blocked|respond now|avoid suspension/.test(signalBlob);
  const hasSpoofingRisk = Boolean((headerAnalysis?.spoofingRisk && headerAnalysis.spoofingRisk !== "none") || headerAnalysis?.mismatch || headerAnalysis?.replyToMismatch || headerAnalysis?.returnPathMismatch);
  const hasCredentialTrap = /send your otp|reply with.*otp|share.*otp|provide.*otp|enter.*password|send.*password|send.*pin|confirm your credentials|re-?enter .*details/.test(signalBlob);
  const hasTrustedOtpContext = hasTrustedDomain && hasOtpContext && !hasSuspiciousLinks && !hasSpoofingRisk && !hasCredentialTrap;
  const riskScore = hasTrustedOtpContext ? Math.min(28, Math.max(initialRiskScore, 25)) : initialRiskScore;
  const classification = hasTrustedOtpContext ? "safe" : initialClassification;
  const keySignals = hasTrustedOtpContext
    ? dedupeStrings(["OTP / account verification", ...initialKeySignals.filter((item) => !/credential request|urgency pressure|suspicious link/i.test(String(item)))]).slice(0, 3)
    : initialKeySignals;
  const displayReasons = hasTrustedOtpContext
    ? (dedupeStrings(reasons.filter((item) => !/urgent|urgency|pressure|blocked|final notice|act now/i.test(String(item)))).slice(0, 3).length
        ? dedupeStrings(reasons.filter((item) => !/urgent|urgency|pressure|blocked|final notice|act now/i.test(String(item)))).slice(0, 3)
        : [domainTrust.label, "Protective security wording", "No sensitive request"])
    : reasons;
  const visualClassification = classification === "uncertain" ? "suspicious" : classification;

  const derivedBreakdown = [];
  if (domainTrust?.trust === "Trusted" || isTrustedDomainStatus(domainTrust?.status)) {
    derivedBreakdown.push({ label: "Trusted domain verification", impact: -45, detail: domainTrust.label });
  }
  if ((result?.urlAnalyses || []).some((item) => item?.isSuspicious)) {
    derivedBreakdown.push({ label: "Suspicious link analysis", impact: 25, detail: "Email contains at least one untrusted link" });
  }
  if (headerAnalysis?.spoofingRisk && headerAnalysis.spoofingRisk !== "none") {
    derivedBreakdown.push({ label: "Header spoofing signal", impact: headerAnalysis.spoofingRisk === "high" ? 28 : 14, detail: headerAnalysis.spoofingRisk });
  }
  if (keySignals.includes("Credential request")) {
    derivedBreakdown.push({ label: "Sensitive request detected", impact: 30, detail: "OTP, password, or credential prompt" });
  }
  if (keySignals.includes("Suspicious link")) {
    derivedBreakdown.push({ label: "Suspicious link pattern", impact: 25, detail: "Domain mismatch or deceptive URL" });
  }
  if (keySignals.includes("Urgency pressure")) {
    derivedBreakdown.push({ label: "Urgency pressure", impact: 18, detail: "Pressure to act quickly" });
  }
  if (!derivedBreakdown.length && classification === "safe") {
    derivedBreakdown.push({ label: "No risky behavior detected", impact: -12, detail: "No phishing cues found in the latest scan" });
  }

  return {
    ...fallback,
    ...result,
    url: result?.url || fallback.url || "",
    domain: domainTrust.domain || resolvedDomain,
    riskScore,
    classification,
    visualClassification,
    explanation: hasTrustedOtpContext
      ? "This is a legitimate account verification message. Only use the OTP on the official website."
      : (normalizedExplanation || buildExplanation(classification, keySignals, displayReasons, result?.source || fallback.source)),
    reasons: displayReasons,
    flags: keySignals.length > 0 ? keySignals : flags.slice(0, 4),
    keySignals,
    source: result?.source || fallback.source || "url",
    suspiciousParts: result?.suspiciousParts || fallback.suspiciousParts || [],
    isIndianBankingRelated: Boolean(result?.isIndianBankingRelated ?? fallback.isIndianBankingRelated),
    contentAnalyzed: Boolean(result?.contentAnalyzed ?? fallback.contentAnalyzed),
    fingerprint: result?.fingerprint || fallback.fingerprint || "",
    category: hasTrustedOtpContext
      ? (/password reset/.test(signalBlob) ? "Password reset flow" : "Account activity notification")
      : (result?.category || result?.attackType || fallback.category || fallback.attackType || ""),
    attackType: hasTrustedOtpContext
      ? (/password reset/.test(signalBlob) ? "Password reset flow" : "Account activity notification")
      : (result?.attackType || result?.category || fallback.attackType || fallback.category || ""),
    detectedLanguage: result?.detectedLanguage || result?.language || fallback.detectedLanguage || fallback.language || "EN",
    language: result?.language || result?.detectedLanguage || fallback.language || fallback.detectedLanguage || "EN",
    languageLabel: mapLanguageLabel(result?.detectedLanguage || result?.language || fallback.detectedLanguage || fallback.language || "EN"),
    confidence: result?.confidence ?? fallback.confidence ?? riskScore,
    recommendation: result?.recommendation || fallback.recommendation || "",
    modelUsed: result?.modelUsed || result?.model_used || fallback.modelUsed || fallback.model_used || "",
    headerAnalysis,
    urlAnalyses,
    featureImportance: Array.isArray(result?.featureImportance) ? result.featureImportance : Array.isArray(fallback.featureImportance) ? fallback.featureImportance : [],
    scoreBreakdown: Array.isArray(result?.scoreBreakdown) && result.scoreBreakdown.length ? result.scoreBreakdown : Array.isArray(fallback.scoreBreakdown) && fallback.scoreBreakdown.length ? fallback.scoreBreakdown : derivedBreakdown,
    domainTrust,
    intent: hasTrustedOtpContext ? "OTP / account verification" : (result?.intent || fallback.intent || inferIntent({ ...fallback, ...result, reasons, flags }, classification)),
    analysisSources: dedupeStrings([
      ...(result?.analysisSources || []),
      ...(fallback.analysisSources || []),
      result?.source || fallback.source || "url",
    ]),
  };
}

function isWarningPage(url) {
  return Boolean(url && url.startsWith(chrome.runtime.getURL("warning.html")));
}

function getTabState(tabId, url = "") {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, {
      url,
      urlResult: null,
      contentState: null,
      emailResult: null,
      finalResult: null,
    });
  }

  const state = tabState.get(tabId);
  if (url && state.url && state.url !== url) {
    state.urlResult = null;
    state.contentState = null;
    state.emailResult = null;
    state.finalResult = null;
  }
  if (url) state.url = url;
  return state;
}

function getUrlResult(url) {
  if (!url || shouldSkip(url) || isWarningPage(url)) {
    return null;
  }

  if (urlCache.has(url)) {
    return normalizeResult(urlCache.get(url), { url });
  }

  const result = normalizeResult(checkUrl(url), { url, source: "url" });
  urlCache.set(url, result);
  return normalizeResult(result, { url });
}

function combineUrlAndContent(baseResult, contentState, url) {
  const base = normalizeResult(baseResult || {}, { url, source: "url" });
  if (!contentState) {
    return base;
  }

  const contentScore = clamp(Number(contentState.contentScore || 0), 0, 60);
  const contentReasons = dedupeStrings(contentState.contentReasons || []).slice(0, 3);
  let combinedScore = Math.max(base.riskScore, Math.round(base.riskScore * 0.45 + contentScore * 0.9));

  if (contentState.forcePhishing) {
    combinedScore = Math.max(combinedScore, 75);
  } else if (contentScore >= 45) {
    combinedScore = Math.max(combinedScore, 71);
  }

  const merged = normalizeResult(
    {
      ...base,
      riskScore: combinedScore,
      reasons: dedupeStrings([...(base.reasons || []), ...contentReasons]).slice(0, 3),
      flags: dedupeStrings([...(base.flags || []), ...buildKeySignals({ reasons: contentReasons })]).slice(0, 3),
      source: contentState.source || "page-content",
      contentAnalyzed: true,
    },
    { url, source: "page-content" },
  );

  return merged;
}

function updateBadge(tabId, result) {
  const classification = result?.visualClassification || (result?.classification === "uncertain" ? "suspicious" : result?.classification);

  if (!result || classification === "safe") {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  const color = classification === "phishing" ? "#DC2626" : "#F59E0B";
  const numericScore = Number(result.riskScore || 0);
  const text = classification === "phishing" ? String(numericScore || "!") : "!";
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

function syncTab(tabId) {
  const state = tabState.get(tabId);
  if (!state) return null;

  let finalResult = null;

  if (state.emailResult && /mail\.google\.com/i.test(state.url || "")) {
    finalResult = normalizeResult(state.emailResult, { url: state.url, source: "gmail-email" });
  } else {
    finalResult = combineUrlAndContent(state.urlResult, state.contentState, state.url);
  }

  if (finalResult) {
    finalResult.analysisSources = dedupeStrings([
      ...(finalResult.analysisSources || []),
      state.urlResult?.source,
      state.contentState?.source,
      state.emailResult?.source,
    ]);
  }

  state.finalResult = finalResult;
  updateBadge(tabId, finalResult);

  chrome.tabs.sendMessage(tabId, {
    type: "PHISHSHIELD_RESULT",
    data: finalResult,
    url: state.url,
  }).catch(() => {});

  return finalResult;
}

function analyzeTab(tabId, url) {
  if (!url || shouldSkip(url) || isWarningPage(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    tabState.delete(tabId);
    return null;
  }

  const state = getTabState(tabId, url);
  state.urlResult = getUrlResult(url);

  if (!/mail\.google\.com/i.test(url)) {
    state.emailResult = null;
  }

  return syncTab(tabId);
}

// ─── Extension's own warning page URL prefix ──────────────────────────────────

function getWarningUrl(result, originalUrl) {
  const params = new URLSearchParams({
    url: originalUrl,
    score: String(result.riskScore || 0),
    level: result.visualClassification || result.classification || "safe",
    reasons: JSON.stringify(result.reasons || []),
    india: result.isIndianBankingRelated ? "1" : "0",
    dest: originalUrl,
  });
  return chrome.runtime.getURL("warning.html") + "?" + params.toString();
}

// ─── Event listeners ──────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url && !shouldSkip(changeInfo.url) && !isWarningPage(changeInfo.url)) {
    const url = changeInfo.url;
    const isGmailShell = /https?:\/\/mail\.google\.com\/mail\//i.test(url);
    const result = analyzeTab(tabId, url);
    if (!result) return;

    if (!isGmailShell && (result.visualClassification === "phishing" || result.visualClassification === "suspicious")) {
      if (allowedUrls.has(url)) {
        allowedUrls.delete(url);
        return;
      }

      chrome.tabs.update(tabId, { url: getWarningUrl(result, url) });
      return;
    }
  }

  if (changeInfo.status === "complete" && tab.url && !isWarningPage(tab.url)) {
    analyzeTab(tabId, tab.url);
  }
});

if (chrome.webNavigation?.onHistoryStateUpdated) {
  chrome.webNavigation.onHistoryStateUpdated.addListener(({ tabId, url, frameId }) => {
    if (frameId !== 0 || !url || shouldSkip(url) || isWarningPage(url)) return;
    analyzeTab(tabId, url);
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

// Respond to messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    const tabId = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    if (!tabId) {
      sendResponse(null);
      return true;
    }

    const state = getTabState(tabId, tabUrl || "");
    if (!state.finalResult && tabUrl && !shouldSkip(tabUrl) && !isWarningPage(tabUrl)) {
      analyzeTab(tabId, tabUrl);
    }

    sendResponse(tabState.get(tabId)?.finalResult ?? null);
    return true;
  }

  if (message.type === "GET_TAB_RESULT") {
    sendResponse(tabState.get(message.tabId)?.finalResult ?? null);
    return true;
  }

  if (message.type === "CHECK_URL") {
    const result = getUrlResult(message.url || "");
    sendResponse(result ?? null);
    return true;
  }

  if (message.type === "SCAN_EMAIL_API") {
    scanEmailWithLocalApi(message.payload || {}).then((result) => {
      sendResponse(result ?? null);
    });
    return true;
  }

  if (message.type === "RECHECK_TAB") {
    const { tabId, url } = message;
    const result = analyzeTab(tabId, url);
    chrome.tabs.sendMessage(tabId, { type: "PHISHSHIELD_FORCE_RESCAN" }).catch(() => {});
    sendResponse({ ok: true, result });
    return true;
  }

  if (message.type === "SET_EMAIL_RESULT") {
    const tabId = sender.tab?.id;
    if (!tabId || !message.result) {
      sendResponse(null);
      return true;
    }

    const tabUrl = sender.tab?.url || message.result.url || "";
    const state = getTabState(tabId, tabUrl);
    state.emailResult = normalizeResult(
      {
        ...message.result,
        url: tabUrl,
        source: "gmail-email",
      },
      {
        url: tabUrl,
        source: "gmail-email",
      },
    );

    const finalResult = syncTab(tabId);
    sendResponse({ ok: true, result: finalResult });
    return true;
  }

  if (message.type === "CLEAR_EMAIL_RESULT") {
    const tabId = sender.tab?.id;
    if (!tabId) {
      sendResponse(null);
      return true;
    }

    const state = getTabState(tabId, sender.tab?.url || "");
    state.emailResult = null;
    const finalResult = syncTab(tabId);
    sendResponse({ ok: true, result: finalResult });
    return true;
  }

  if (message.type === "ALLOW_URL") {
    allowedUrls.add(message.url);
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "CONTENT_ANALYSIS") {
    const tabId = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    if (!tabId) {
      sendResponse(null);
      return true;
    }

    const state = getTabState(tabId, tabUrl || "");
    if (!state.urlResult && tabUrl && !shouldSkip(tabUrl) && !isWarningPage(tabUrl)) {
      state.urlResult = getUrlResult(tabUrl);
    }

    state.contentState = {
      contentScore: clamp(Number(message.contentScore || 0), 0, 60),
      contentReasons: dedupeStrings(message.contentReasons || []).slice(0, 3),
      forcePhishing: Boolean(message.forcePhishing),
      source: message.source || "page-content",
    };

    const updated = syncTab(tabId);
    sendResponse(updated);
    return true;
  }
});
