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
  const flags = [];
  const reasons = [];
  let score = 0;

  // Suspicious TLD
  const tld = "." + domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push(`Suspicious TLD: ${tld}`);
    reasons.push(`This site uses the "${tld}" domain, which is commonly used in phishing campaigns.`);
    score += 30;
  }

  // URL shortener
  if (URL_SHORTENERS.some(s => domain.includes(s))) {
    flags.push("URL shortener detected");
    reasons.push("A link shortener hides the real destination — the site you end up at could be anything.");
    score += 25;
  } else if (BRAND_SHORTENERS.some(s => domain.includes(s))) {
    flags.push("Official brand shortener detected");
    reasons.push("This is an official shortener used by a trusted brand.");
    score += 5;
  }

  // Lookalike domain
  let lookalikMatched = false;
  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain)) {
      flags.push(label);
      reasons.push(`"${domain}" appears to impersonate a trusted brand (${label}). This is a classic phishing tactic.`);
      score += 45;
      lookalikMatched = true;
      break;
    }
  }

  // Deep subdomain structure
  if (domain.split(".").length > 3) {
    flags.push("Complex subdomain structure");
    reasons.push("Fake sites often use deep subdomains to look like part of a legitimate website.");
    score += 15;
  }

  // Numbers in primary domain
  if (/[0-9]/.test(domain.split(".")[0])) {
    flags.push("Numbers in domain name");
    reasons.push("Legitimate brands rarely use numbers in their domain name — a common sign of a spoofed site.");
    score += 10;
  }

  // Unusually long URL
  if (url.length > 100) {
    flags.push("Unusually long URL");
    reasons.push("Phishing links are often deliberately long to discourage inspection.");
    score += 10;
  }

  // Sensitive URL parameters
  if (/token=|session=|verify=|otp=|password=|pin=/i.test(url)) {
    flags.push("Sensitive parameters in URL");
    reasons.push("The URL contains sensitive fields (OTP, token, password) in the address — a red flag for credential theft.");
    score += 20;
  }

  // Deceptive keywords in domain
  if (/secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(domain)) {
    flags.push("Deceptive keyword in domain");
    reasons.push(`The domain uses a word like "secure", "login", or "kyc" to appear trustworthy.`);
    score += 15;
  }

  // Indian banking / payment context
  const domainStripped = domain.toLowerCase().replace(/[-_.]/g, "");
  const matchedBank = INDIA_BANKS.find(b => domainStripped.includes(b));
  const matchedService = INDIA_SERVICES.find(s => domainStripped.includes(s));
  const isIndianBankingRelated = !!(matchedBank || matchedService);

  if (isIndianBankingRelated && score > 15) {
    const brandName = (matchedBank || matchedService).toUpperCase();
    reasons.push(
      matchedBank
        ? `This looks like a fake ${brandName} banking page. Real banks will NEVER ask for your OTP or PIN through a link.`
        : `This appears to impersonate ${brandName}. Never enter your UPI PIN or Aadhaar details on suspicious sites.`
    );
    score = Math.min(score + 20, 100);
  }

  const finalScore = Math.min(score, 100);
  const classification = finalScore >= 71 ? "phishing" : finalScore >= 31 ? "suspicious" : "safe";

  // Which parts of the URL to highlight
  const suspiciousParts = [];
  if (SUSPICIOUS_TLDS.includes(tld)) suspiciousParts.push({ part: tld, reason: "Suspicious TLD" });
  if (lookalikMatched) suspiciousParts.push({ part: domain, reason: "Lookalike domain" });

  return { url, domain, riskScore: finalScore, classification, flags, reasons, isIndianBankingRelated, suspiciousParts };
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

function buildKeySignals(payload) {
  const blob = [
    ...(payload.flags || []),
    ...(payload.keySignals || []),
    ...(payload.detectedSignals || []),
    ...(payload.detected_signals || []),
    ...(payload.signals || []),
    ...(payload.reasons || []).map(normalizeReasonText),
    payload.explanation || "",
  ].join(" ").toLowerCase();

  const signals = [];
  if (/(credential|password|pin\b|otp|passcode|identity|sign-?in details|send your otp|reply with.*otp)/i.test(blob)) {
    signals.push("Credential request");
  }
  if (/(suspicious link|lookalike|shortener|deceptive keyword|fake .*domain|domain|url)/i.test(blob)) {
    signals.push("Suspicious link");
  }
  if (/(urgent|immediate|immediately|act now|deadline|final notice|suspension|blocked|pressure)/i.test(blob)) {
    signals.push("Real urgency");
  }
  if (/(impersonat|spoof|trusted brand|bank|google|amazon|microsoft|brand)/i.test(blob)) {
    signals.push("Impersonation");
  }

  return signals.slice(0, 3);
}

function buildExplanation(classification, signals, reasons, source) {
  if (classification === "safe") {
    return source === "gmail-email"
      ? "This Gmail message looks routine and does not show strong phishing signs."
      : "This page currently looks low risk based on the available signals.";
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

  if (signals.includes("Real urgency")) {
    return "This content uses pressure or urgency, so verify it through an official channel before acting.";
  }

  return "This content shows suspicious signals and should be verified before you click, reply, or sign in.";
}

function normalizeResult(result, fallback = {}) {
  const riskScore = clamp(Number(result?.riskScore ?? result?.risk_score ?? fallback.riskScore ?? 0), 0, 100);
  const classification = normalizeClassification(result?.classification ?? fallback.classification, riskScore);
  const reasons = dedupeStrings([
    ...((result?.reasons || fallback.reasons || []).map(normalizeReasonText)),
  ]).slice(0, 3);
  const flags = dedupeStrings([
    ...(result?.flags || fallback.flags || []),
    ...(result?.detectedSignals || []),
    ...(result?.detected_signals || []),
    ...(result?.signals || []),
  ]);
  const keySignals = buildKeySignals({ ...result, reasons, flags }).slice(0, 3);
  const visualClassification = classification === "uncertain" ? "suspicious" : classification;

  return {
    url: result?.url || fallback.url || "",
    domain: result?.domain || fallback.domain || extractDomain(result?.url || fallback.url || ""),
    riskScore,
    classification,
    visualClassification,
    explanation: result?.explanation || fallback.explanation || buildExplanation(classification, keySignals, reasons, result?.source || fallback.source),
    reasons,
    flags: keySignals.length > 0 ? keySignals : flags.slice(0, 3),
    keySignals,
    source: result?.source || fallback.source || "url",
    suspiciousParts: result?.suspiciousParts || fallback.suspiciousParts || [],
    isIndianBankingRelated: Boolean(result?.isIndianBankingRelated ?? fallback.isIndianBankingRelated),
    contentAnalyzed: Boolean(result?.contentAnalyzed ?? fallback.contentAnalyzed),
    fingerprint: result?.fingerprint || fallback.fingerprint || "",
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
