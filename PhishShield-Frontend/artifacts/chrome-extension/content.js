// PhishShield Guardian — Content Script
// Injects a full-screen warning overlay when a phishing site is detected.
// For suspicious (medium-risk) sites, shows a dismissible top banner instead.

(function () {
  "use strict";

  let overlayEl = null;
  let bannerEl = null;
  let gmailBannerEl = null;
  let gmailObserver = null;
  let gmailScanTimer = null;
  let pageScanTimer = null;
  let hoverTooltipEl = null;
  let linkGuardModalEl = null;
  let passwordWarningEl = null;
  let lastGmailFingerprint = "";
  let lastGmailRenderKey = "";
  let lastGmailScanAt = 0;
  let latestGmailScanToken = 0;
  let gmailLoadingGuardTimer = null;
  let currentPageResult = null;
  let lastPageFingerprint = "";
  let allowSensitiveActionUntil = 0;

  const resultCache = new Map();
  const urlRiskCache = new Map();

  const DISMISSED_KEY = `phishshield_dismissed_${location.hostname}`;
  const IS_GMAIL = location.hostname === "mail.google.com";
  const API_BASE_CANDIDATES = ["http://127.0.0.1:8000", "http://localhost:8000"];
  const GMAIL_SCAN_DEBOUNCE_MS = 900;
  const GMAIL_SCAN_MIN_INTERVAL_MS = 1800;
  const MAX_EMAIL_TEXT_CHARS = 50000;
  const API_RETRY_COOLDOWN_MS = 30000;
  const API_LOG_THROTTLE_MS = 60000;

  let apiOfflineUntil = 0;
  let lastApiFallbackLogAt = 0;

  // Don't show anything if the user already dismissed the warning on this page
  function wasDismissed() {
    try { return sessionStorage.getItem(DISMISSED_KEY) === "1"; } catch { return false; }
  }

  function markDismissed() {
    try { sessionStorage.setItem(DISMISSED_KEY, "1"); } catch { /* ignore */ }
  }

  // ─── Utility: highlight suspicious parts of the URL ───────────────────────

  function highlightUrl(url, suspiciousParts) {
    if (!suspiciousParts || suspiciousParts.length === 0) {
      return `<span class="ps-url-text">${escapeHtml(url)}</span>`;
    }
    let highlighted = escapeHtml(url);
    suspiciousParts.forEach(({ part }) => {
      const escaped = escapeHtml(part);
      highlighted = highlighted.replaceAll(
        escaped,
        `<mark class="ps-url-mark">${escaped}</mark>`
      );
    });
    return `<span class="ps-url-text">${highlighted}</span>`;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function dedupeStrings(values) {
    return [...new Set((values || []).map(v => String(v || "").trim()).filter(Boolean))];
  }

  function getReasonText(reason) {
    if (!reason) return "";
    if (typeof reason === "string") return reason;
    return reason.description || reason.label || reason.category || "Suspicious content detected by AI";
  }

  function canonicalizeReason(value) {
    const raw = getReasonText(value);
    const lower = raw.toLowerCase();
    if (!raw) return "";

    if (/known sender|trusted sender/.test(lower)) return "Trusted sender";
    if (/routine|newsletter|product-update|weekly digest|informational|changelog|release notes/.test(lower)) return "Routine communication";
    if (/no credential|no payment|no password|no otp/.test(lower)) return "No sensitive request";
    if (/no strong urgency|no urgency|fear pressure/.test(lower)) return "No urgency pressure";
    if (/no suspicious|no spoofed/.test(lower)) return "No spoofing detected";
    if (/password reset|account recovery/.test(lower)) return "Password reset request";
    if (/verify through the trusted site/.test(lower)) return "Use the official site";
    if (/protective wording|no action required|do not share/.test(lower)) return "Protective security wording";
    return raw;
  }

  function toVisualClassification(classification) {
    if (classification === "phishing") return "phishing";
    if (classification === "uncertain" || classification === "suspicious") return "suspicious";
    return "safe";
  }

  function stableHash(value) {
    const text = String(value || "");
    let hash = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(16);
  }

  function buildGmailMessageKey(meta) {
    return [meta && meta.sender, meta && meta.subject]
      .map((value) => String(value || "").trim().toLowerCase())
      .join("|");
  }

  function cloneResult(result) {
    return result ? JSON.parse(JSON.stringify(result)) : result;
  }

  function flashElementText(element, text) {
    if (!element) return;
    const original = element.dataset.originalLabel || element.textContent || "";
    element.dataset.originalLabel = original;
    element.textContent = text;
    window.setTimeout(() => {
      element.textContent = original;
    }, 1400);
  }

  async function copyText(value) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return false;
    }

    try {
      await navigator.clipboard.writeText(String(value || ""));
      return true;
    } catch {
      return false;
    }
  }

  function buildEnterpriseSummary(result, context = {}) {
    const normalized = normalizeUiResult(result || {}, context || {});
    const signals = (normalized.keySignals || normalized.flags || []).slice(0, 3);
    const reasons = (normalized.reasons || []).slice(0, 3);
    const target = normalized.domain || context.domain || context.url || location.hostname;
    const sourceLabel = normalized.source === "gmail-email" ? "Mail protection" : "Web protection";
    const statusLabel = normalized.visualClassification === "phishing"
      ? "High-risk destination"
      : normalized.visualClassification === "suspicious"
        ? "Review recommended"
        : "Protected communication";

    return [
      `PhishShield Guardian assessment: ${statusLabel}`,
      `Risk score: ${normalized.riskScore}/100`,
      `Category: ${normalized.attackType || normalized.category || "Low-risk communication"}`,
      `Intent: ${normalized.intent || "Routine communication"}`,
      `Domain trust: ${normalized.domainTrust?.label || "Not available"}`,
      `Target: ${target}`,
      `Source: ${sourceLabel}`,
      `Signals: ${(signals.length ? signals : ["No strong signals"]).join(", ")}`,
      `Summary: ${normalized.explanation || "No additional details available."}`,
      reasons.length ? `Decision factors: ${reasons.join(" | ")}` : "",
    ].filter(Boolean).join("\n");
  }

  function isRuntimeAvailable() {
    try {
      return Boolean(globalThis.chrome?.runtime?.id);
    } catch {
      return false;
    }
  }

  function getWarningPageUrl() {
    if (!isRuntimeAvailable()) return "";
    try {
      return chrome.runtime.getURL("warning.html");
    } catch {
      return "";
    }
  }

  function safeSendMessage(message) {
    return new Promise((resolve) => {
      if (!isRuntimeAvailable()) {
        resolve(null);
        return;
      }

      try {
        chrome.runtime.sendMessage(message, (response) => {
          try {
            if (chrome.runtime.lastError) {
              resolve(null);
              return;
            }
          } catch {
            resolve(null);
            return;
          }

          resolve(response || null);
        });
      } catch {
        resolve(null);
      }
    });
  }

  function openIncidentPortal() {
    window.open("https://www.cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx?rnt=5", "_blank", "noopener,noreferrer");
  }

  function extractSenderDomain(sender) {
    const match = String(sender || "").match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
    return match ? match[1].toLowerCase() : "";
  }

  function extractUrls(text) {
    return dedupeStrings(String(text || "").match(/https?:\/\/[^\s<>")']+/gi) || []);
  }

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

  function isTrustedDomainStatus(value) {
    return ["trusted", "verified"].includes(String(value || "").toLowerCase());
  }

  const FALLBACK_TRUSTED_DOMAIN_GROUPS = {
    Google: ["google.com", "googlemail.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "c.gle"],
    Amazon: ["amazon.com", "amazon.in", "amazonaws.com", "amazonses.com"],
    Microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"],
    GitHub: ["github.com", "githubassets.com", "githubusercontent.com", "github.io"],
    Overleaf: ["overleaf.com"],
    OpenAI: ["openai.com", "chatgpt.com", "oaistatic.com"],
    LinkedIn: ["linkedin.com", "lnkd.in"],
  };

  function getTrustedDomainBrand(domain) {
    const normalized = getBaseDomain(domain);
    if (!normalized) return "";

    for (const [brand, domains] of Object.entries(FALLBACK_TRUSTED_DOMAIN_GROUPS)) {
      if (domains.some((entry) => sameDomainFamily(normalized, entry) || normalized === entry || normalized.endsWith(`.${entry}`))) {
        return brand;
      }
    }

    return "";
  }

  function buildNeutralDomainTrust(domain, source = "backend") {
    const normalized = getBaseDomain(domain);
    const trustedBrand = getTrustedDomainBrand(normalized);
    const hasSuspiciousPattern = Boolean(normalized) && (
      /(\.xyz|\.top|\.click|\.tk|\.ml|\.cf|\.gq|\.zip|\.mov)$/.test(normalized)
      || /g00gle|g0ogle|paypa[l1]|amaz0n|am4zon|sb[i1]-|sbi-online|hdf[c0]-|icic[i1]-|payt[m0]-|ph0nepe|phonep3/i.test(normalized)
    );

    if (trustedBrand) {
      return {
        trust: "Trusted",
        status: "trusted",
        brand: trustedBrand,
        domain: normalized,
        label: `Verified ${trustedBrand} domain`,
        source,
      };
    }

    if (hasSuspiciousPattern) {
      return {
        trust: "Suspicious",
        status: "suspicious",
        brand: normalized || "Unknown",
        domain: normalized,
        label: "Domain mismatch or spoofing detected",
        source,
      };
    }

    return {
      trust: "Unknown",
      status: "unknown",
      brand: normalized || "Unknown",
      domain: normalized,
      label: "This domain is not widely recognized — verify if unsure.",
      source,
    };
  }

  function detectLanguageCodeFromText(text) {
    const value = String(text || "");
    const visibleChars = [...value].filter((char) => !/\s/.test(char));
    if (!visibleChars.length) return "EN";

    const hindiChars = visibleChars.filter((char) => char >= "\u0900" && char <= "\u097F").length;
    const teluguChars = visibleChars.filter((char) => char >= "\u0C00" && char <= "\u0C7F").length;

    if (hindiChars / visibleChars.length > 0.15) return "HI";
    if (teluguChars / visibleChars.length > 0.15) return "TE";
    if ((hindiChars + teluguChars) / visibleChars.length > 0.1) return "MX";
    return "EN";
  }

  function getLanguageLabel(code) {
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

  function inferIntentLabel(text, classification = "safe") {
    const blob = String(text || "").toLowerCase();
    if (/password reset|account recovery/.test(blob)) return "Password reset flow";
    if (/otp|verification code|security code|new sign-?in|login alert|account activity/.test(blob)) return "OTP / account verification";
    if (/payment|refund|invoice|billing|bank transfer|upi/.test(blob)) return "Payment or banking request";
    if (/terms|privacy update/.test(blob)) return "Terms update message";
    if (/welcome|getting started|thanks for signing up/.test(blob)) return "Welcome email detected";
    if (/newsletter|digest|release notes|product update|announcement/.test(blob)) return "Routine notification";
    if (classification === "phishing") return "Credential or payment theft attempt";
    if (classification === "suspicious") return "Needs independent verification";
    return "Routine communication";
  }

  function buildHumanSummary(payload, classification, rawExplanation = "") {
    const raw = String(rawExplanation || "").trim();
    const textBlob = [
      payload?.category,
      payload?.attackType,
      payload?.intent,
      raw,
      ...(payload?.reasons || []).map(getReasonText),
      ...(payload?.keySignals || []),
      ...(payload?.flags || []),
    ].join(" ").toLowerCase();

    if (raw && !/no sign of spoofing|no risky behavior detected|trusted sender with no strong phishing signals detected|top words driving this verdict|ai analysis completed/i.test(raw)) {
      return raw;
    }

    if (classification === "safe") {
      if (/welcome/.test(textBlob)) {
        return "Welcome email detected from a known sender. This is a trusted message.";
      }
      if (/terms|policy/.test(textBlob)) {
        return "This looks like a routine terms or policy update from a trusted sender.";
      }
      if (/otp|verification|security alert|account activity|new sign-?in/.test(textBlob)) {
        return "This is a legitimate account verification message. Only use the OTP on the official website.";
      }
      if (/newsletter|digest|product update|routine/.test(textBlob)) {
        return "This looks like a normal newsletter or product update from a trusted source.";
      }
      return "No risky behavior detected. This is a trusted message.";
    }

    if (classification === "phishing") {
      if (/credential|password|otp|pin/.test(textBlob)) {
        return "This message tries to collect sensitive information or approval codes, which is a strong phishing signal.";
      }
      if (/link|domain|spoof|lookalike/.test(textBlob)) {
        return "The links or sender details look deceptive and could redirect you to a fake sign-in or payment page.";
      }
      return "This message shows strong phishing indicators and should not be trusted.";
    }

    if (/password reset/.test(textBlob)) {
      return "This looks like a password reset flow. If you initiated it, open the official site directly instead of relying on the email link.";
    }

    return "This message has mixed signals. Verify it through the official site or support channel before acting.";
  }

  function getExplanationText(value) {
    if (!value) return "";
    const normalized = typeof value === "string"
      ? value
      : typeof value === "number" || typeof value === "boolean"
        ? String(value)
        : typeof value === "object"
          ? String(
              value.why_risky
              || value.scamStory
              || value.summary
              || value.reason
              || value.message
              || value.description
              || value.text
              || ""
            ).trim()
          : "";

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

  function pickTopSignals(payload) {
    const classification = toVisualClassification(payload.classification || payload.visualClassification || "safe");
    const rawSignalText = [
      ...(payload.keySignals || []),
      ...(payload.flags || []),
      ...(payload.detectedSignals || []),
      ...(payload.detected_signals || []),
      ...(payload.signals || []),
    ].join(" ").toLowerCase();

    const reasonBlob = [...(payload.reasons || []).map(getReasonText), getExplanationText(payload.explanation)]
      .join(" ")
      .toLowerCase();

    const negatesCredential = /no credential|does not ask for passwords|does not request|no password request|no otp request/.test(reasonBlob);
    const negatesLink = /no spoofed domain|no suspicious phishing pattern|known sender domain|known sender context|trusted sender|verified destination/.test(reasonBlob);
    const negatesUrgency = /no urgency|no strong urgency|routine language|routine communication|routine product-update|routine message/.test(reasonBlob);
    const safeOtpContext = classification === "safe" && /(trusted sender|verified .*domain|protective security wording|account activity notification|password reset flow|otp \/ account verification)/i.test(`${rawSignalText} ${reasonBlob} ${payload.intent || ""} ${payload.category || ""}`);

    const topSignals = [];
    if (safeOtpContext && /(otp|verification code|security code|sign-?in|password reset|account activity)/i.test(`${rawSignalText} ${reasonBlob} ${payload.intent || ""}`)) {
      topSignals.push("OTP / account verification");
    } else if (!negatesCredential && /(credential|otp|password|pin\b|passcode|identity|send your otp|reply with.*otp|confirm your credentials)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
      topSignals.push("Credential request");
    }
    if (!negatesLink && /(suspicious link|lookalike|shortener|deceptive keyword|fake .*domain|spoof|impersonat)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
      topSignals.push("Suspicious link");
    }
    if (!negatesUrgency && /(urgent|immediately|deadline|final notice|act now|pressure|suspension|blocked)/i.test(`${rawSignalText} ${classification === "safe" ? "" : reasonBlob}`)) {
      topSignals.push("Urgency pressure");
    }
    if (classification !== "safe" && /(impersonat|spoof|bank|brand)/i.test(`${rawSignalText} ${reasonBlob}`)) {
      topSignals.push("Impersonation risk");
    }

    return dedupeStrings(topSignals.map(canonicalizeSignal)).slice(0, 3);
  }

  function normalizeUiResult(result, fallback) {
    const merged = { ...(fallback || {}), ...(result || {}) };
    const source = merged.source || "api";
    const initialRiskScore = Math.max(0, Math.min(100, Number(merged.riskScore ?? merged.risk_score ?? 0)));
    const initialClassification = toVisualClassification(merged.classification || (initialRiskScore >= 71 ? "phishing" : initialRiskScore >= 31 ? "suspicious" : "safe"));
    const reasons = dedupeStrings([
      ...(Array.isArray(merged.reasons) ? merged.reasons : []).map(canonicalizeReason),
    ]).slice(0, initialClassification === "safe" ? 3 : 4);
    const rawExplanation = getExplanationText(merged.explanation || merged.scamStory || (fallback && fallback.explanation));
    const initialKeySignals = pickTopSignals({ ...merged, classification: initialClassification, reasons, explanation: rawExplanation });
    const headerAnalysis = merged.headerAnalysis || null;
    const senderDomain = getBaseDomain(merged?.headerAnalysis?.senderDomain || merged?.headerAnalysis?.replyToDomain || merged?.domain || "");
    const domainTrust = merged.domainTrust || fallback?.domainTrust || buildNeutralDomainTrust(senderDomain || merged.domain || "", merged?.domainTrust?.source || fallback?.domainTrust?.source || "backend");
    const signalBlob = [merged.category, merged.attackType, merged.intent, rawExplanation, ...reasons, ...initialKeySignals, ...(Array.isArray(merged.flags) ? merged.flags : [])].join(" ").toLowerCase();
    const hasTrustedDomain = domainTrust.trust === "Trusted" || isTrustedDomainStatus(domainTrust.status);
    const hasOtpContext = /otp|verification code|security code|authentication code|sign-?in|account activity|two[- ]?factor|2fa/.test(signalBlob);
    const hasSuspiciousLinks = (Array.isArray(merged.urlAnalyses) && merged.urlAnalyses.some((item) => item?.isSuspicious)) || initialKeySignals.includes("Suspicious link");
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
    const category = hasTrustedOtpContext
      ? (/password reset/.test(signalBlob) ? "Password reset flow" : "Account activity notification")
      : (merged.category || merged.attackType || (classification === "safe" ? "Safe Email" : classification === "phishing" ? "Phishing threat" : "Needs review"));
    const intent = hasTrustedOtpContext ? "OTP / account verification" : (merged.intent || inferIntentLabel([category, ...reasons, ...keySignals, rawExplanation].join(" "), classification));

    const derivedBreakdown = [];
    if (domainTrust.trust === "Trusted" || isTrustedDomainStatus(domainTrust.status)) {
      derivedBreakdown.push({ label: "Trusted domain verification", impact: -45, detail: domainTrust.label });
    }
    if ((merged.urlAnalyses || []).some((item) => item?.isSuspicious)) {
      derivedBreakdown.push({ label: "Suspicious link analysis", impact: 25, detail: "At least one link needs review" });
    }
    if (keySignals.includes("Credential request")) {
      derivedBreakdown.push({ label: "Sensitive request detected", impact: 30, detail: "OTP, password, or credential prompt" });
    }
    if (keySignals.includes("Urgency pressure")) {
      derivedBreakdown.push({ label: "Urgency pressure", impact: 18, detail: "Pressure to act quickly" });
    }
    if (!derivedBreakdown.length && classification === "safe") {
      derivedBreakdown.push({ label: "No risky behavior detected", impact: -12, detail: "No phishing cues were found" });
    }

    const explanation = hasTrustedOtpContext
      ? "This is a legitimate account verification message. Only use the OTP on the official website."
      : buildHumanSummary({ ...merged, category, intent, reasons: displayReasons, keySignals }, classification, rawExplanation);

    return {
      ...merged,
      source,
      riskScore,
      classification,
      visualClassification: classification,
      reasons: displayReasons,
      keySignals,
      flags: keySignals.length ? keySignals : (Array.isArray(merged.flags) ? merged.flags : []),
      explanation,
      category,
      attackType: merged.attackType || category,
      intent,
      detectedLanguage: merged.detectedLanguage || merged.language || detectLanguageCodeFromText([merged.subject, merged.bodyText, explanation].join(" ")),
      language: merged.language || merged.detectedLanguage || detectLanguageCodeFromText([merged.subject, merged.bodyText, explanation].join(" ")),
      languageLabel: getLanguageLabel(merged.detectedLanguage || merged.language || detectLanguageCodeFromText([merged.subject, merged.bodyText, explanation].join(" "))),
      confidence: merged.confidence ?? riskScore,
      recommendation: merged.recommendation || "",
      headerAnalysis,
      urlAnalyses: Array.isArray(merged.urlAnalyses) ? merged.urlAnalyses : [],
      featureImportance: Array.isArray(merged.featureImportance) ? merged.featureImportance : [],
      domainTrust,
      scoreBreakdown: Array.isArray(merged.scoreBreakdown) && merged.scoreBreakdown.length ? merged.scoreBreakdown : derivedBreakdown,
    };
  }

  function buildGmailRenderKey(result, meta, options = {}) {
    const messageKey = buildGmailMessageKey(meta);
    if (options.isLoading) {
      return `loading|${messageKey}`;
    }

    const normalized = normalizeUiResult(result || {}, { source: "gmail-email" });
    return [
      messageKey,
      normalized.visualClassification,
      normalized.riskScore,
      getExplanationText(normalized.explanation),
      (normalized.reasons || []).map(canonicalizeReason).join("|"),
      (normalized.keySignals || []).map(canonicalizeSignal).join("|"),
      normalized.domainTrust?.label || "",
    ].join("|");
  }

  function buildLocalFallbackResult(text, senderHint, source) {
    const rawText = String(text || "");
    const lower = rawText.toLowerCase();
    const senderDomain = getBaseDomain(extractSenderDomain(senderHint));
    const neutralDomainTrust = buildNeutralDomainTrust(senderDomain, "fallback");
    const urls = extractUrls(rawText);
    const detectedLanguage = detectLanguageCodeFromText(rawText);
    const hasKnownSenderDomain = Boolean(senderDomain);
    const isTrustedSender = neutralDomainTrust.trust === "Trusted" || isTrustedDomainStatus(neutralDomainTrust.status);
    const hasSuspiciousSenderDomain = neutralDomainTrust.trust === "Suspicious";
    const hasOtp = /\botp\b|one time password|verification code|security code|2fa|two[- ]factor/i.test(lower);
    const hasDoNotShare = /do not share|don't share|never share|will never ask|ignore this message if you didn't request/i.test(lower);
    const hasLoginAlert = /new sign-?in|login alert|new device|recognized device|security alert|account activity/i.test(lower);
    const hasSigninContext = /sign-?in|sign in|log in|login|complete your sign in|complete sign-in|verify it's you|authentication code|verification code|two-step|two factor|2fa/i.test(lower);
    const hasProtectiveLoginContext = /if you don't recognize this device|if you do not recognize this device|if this was you|if this wasn't you|if this was not you|you don.?t need to do anything|unauthorized activity|check your account for any unauthorized activity|review this activity|sign out of this device|no action required|can safely ignore|check activity|security activity/i.test(lower);
    const requestsCredentials = /send your otp|reply with.*otp|share.*otp|provide.*otp|enter.*password|send.*password|send.*pin|confirm your credentials|re-?enter .*details/i.test(lower);
    const hasRiskyLinkHost = urls.some((url) => {
      try {
        const host = new URL(url).hostname.toLowerCase();
        return /(\.xyz|\.top|\.click|\.tk|\.ml|\.cf|\.gq|\.zip|\.mov)$/.test(host) || /bit\.ly|tinyurl\.com|t\.co|rb\.gy/i.test(host);
      } catch {
        return false;
      }
    });
    const hasSenderLinkMismatch = urls.some((url) => {
      try {
        const host = new URL(url).hostname.toLowerCase();
        return Boolean(senderDomain)
          && !sameDomainFamily(host, senderDomain)
          && !/googleapis\.com|gstatic\.com|googleusercontent\.com|doubleclick\.net|amazonaws\.com|mailchimp\.com|mandrillapp\.com|list-manage\.com|sendgrid\.net/i.test(host);
      } catch {
        return false;
      }
    });
    const hasExternalUntrustedLink = urls.some((url) => {
      try {
        const host = new URL(url).hostname.toLowerCase();
        return Boolean(host) && (!senderDomain || !sameDomainFamily(host, senderDomain));
      } catch {
        return false;
      }
    });
    const hasDeceptiveLinkPath = urls.some((url) => /\/(verify|login|secure|update|claim|unlock|kyc|wallet|refund|payment|reset)(?:[/?#-]|$)/i.test(url));
    const hasSuspiciousLink = hasRiskyLinkHost || (hasDeceptiveLinkPath && (hasSenderLinkMismatch || hasExternalUntrustedLink));
    const hasTrustedSecurityLink = urls.some((url) => {
      try {
        const host = new URL(url).hostname.toLowerCase();
        return Boolean(host) && (sameDomainFamily(host, senderDomain) || /myaccount\.google\.com|accounts\.google\.com|appleid\.apple\.com|microsoftonline\.com/i.test(host));
      } catch {
        return false;
      }
    });
    const hasUrgency = /urgent|immediately|act now|within \d+ ?hours?|avoid suspension|account suspended|final notice|blocked|respond now/i.test(lower);
    const hasPromoTone = /try .* free|included in your plan|product update|newsletter|announcement|we can.?t wait to see what you build|best,?\s+the .* team|community benchmarks|premium standard|trial ends soon|welcome to claude|upcoming updates to your .* plan|birdclef|cluster will be automatically paused|weekly digest|changelog|release notes|developer update|welcome to amazon web services|get authentication running|resources|get started|download free app|start watching|free access|continue where you left off|session is still active|plans starting at|limited time offer|returning users/i.test(lower);
    const hasRoutineFooter = /unsubscribe|privacy|terms|all rights reserved|©|san francisco|stockholm|mountain view|support@/i.test(lower);
    const hasPasswordResetContext = /forgot password|reset your password|set a new password|password reset|account recovery/i.test(lower);
    const hasAccountVerificationRequest = /verify your account|confirm your account|confirm your identity|review your account|update your account/i.test(lower);
    const hasWelcomeTone = /welcome|getting started|thanks for signing up|glad you're here/i.test(lower);
    const hasTermsUpdate = /terms update|privacy update|policy update|updated terms|updated privacy/i.test(lower);

    if (hasKnownSenderDomain && (hasPromoTone || hasRoutineFooter || hasWelcomeTone || hasTermsUpdate) && !requestsCredentials && !hasSuspiciousLink && !hasUrgency) {
      const category = hasWelcomeTone ? "Welcome email detected" : hasTermsUpdate ? "Terms update message" : "Newsletter / Digest";
      return {
        source,
        classification: "safe",
        riskScore: hasWelcomeTone ? 6 : 8,
        category,
        attackType: category,
        intent: inferIntentLabel(category, "safe"),
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "Sender and link consistency", impact: -18, detail: senderDomain ? `Sender domain: ${senderDomain}` : "No sender mismatch found" },
          { label: "Routine communication context", impact: -15, detail: "Welcome, update, or digest tone" },
        ],
        explanation: "This looks like a routine update and does not request passwords, OTPs, or payment details.",
        reasons: ["Consistent sender context", "Routine communication", "No sensitive request"],
      };
    }

    const looksLikeTrustedOtpFlow = isTrustedSender
      && hasOtp
      && (hasSigninContext || hasLoginAlert || hasPasswordResetContext)
      && !requestsCredentials
      && !hasSuspiciousLink
      && (!hasExternalUntrustedLink || hasTrustedSecurityLink);

    if (looksLikeTrustedOtpFlow || ((isTrustedSender || /roocode\.com|cursor\.com/i.test(senderDomain)) && hasLoginAlert && (hasProtectiveLoginContext || hasTrustedSecurityLink) && !requestsCredentials && !hasSuspiciousLink)) {
      const category = hasPasswordResetContext ? "Password reset flow" : "Account activity notification";
      return {
        source,
        classification: "safe",
        riskScore: hasPasswordResetContext ? 28 : 25,
        category,
        attackType: category,
        intent: "OTP / account verification",
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "Trusted domain verification", impact: -24, detail: neutralDomainTrust.label },
          { label: "Standard login or security flow", impact: -18, detail: "Normal OTP or account activity wording" },
        ],
        explanation: "This is a legitimate account verification message. Only use the OTP on the official website.",
        reasons: [neutralDomainTrust.label, "Protective security wording", "No sensitive request"],
      };
    }

    if (hasOtp && !isTrustedSender && !hasSuspiciousLink && !requestsCredentials) {
      return {
        source,
        classification: "suspicious",
        riskScore: 34,
        category: "Needs review",
        attackType: "Needs review",
        intent: "OTP / account verification",
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "OTP or verification wording", impact: 16, detail: "Security code or sign-in context detected" },
          { label: "Domain trust check", impact: 8, detail: neutralDomainTrust.label },
        ],
        explanation: "This message contains account-verification wording. This domain is not widely recognized, so verify it through the official site if unsure.",
        reasons: [neutralDomainTrust.label, "OTP / account verification", "Verify through the trusted site"],
      };
    }

    if (hasKnownSenderDomain && hasPasswordResetContext && !hasSuspiciousLink) {
      return {
        source,
        classification: "suspicious",
        riskScore: 32,
        category: "Password reset flow",
        attackType: "Password reset flow",
        intent: "Password reset flow",
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "Sensitive account action", impact: 12, detail: "Password reset or recovery message" },
          { label: "Sender and link consistency", impact: -8, detail: senderDomain ? `Sender domain: ${senderDomain}` : "No sender mismatch found" },
        ],
        explanation: "This looks like a password reset or account recovery message. If you initiated it, open the trusted site directly instead of relying on the email link.",
        reasons: ["Password reset or account recovery request", "Verify through the trusted site", "Sensitive action link detected"],
      };
    }

    const shouldForceHighRisk = Boolean(
      hasSuspiciousSenderDomain
      || (hasOtp && (hasSenderLinkMismatch || hasRiskyLinkHost))
      || (hasOtp && hasUrgency && hasExternalUntrustedLink)
      || (requestsCredentials && (hasSenderLinkMismatch || hasExternalUntrustedLink || hasSuspiciousSenderDomain))
    );

    if (shouldForceHighRisk) {
      return {
        source,
        classification: "phishing",
        riskScore: 72,
        category: hasOtp ? "OTP Scam" : "Credential Harvesting",
        attackType: hasOtp ? "OTP Scam" : "Credential Harvesting",
        intent: "Credential or payment theft attempt",
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "Sensitive request detected", impact: 30, detail: "OTP, password, or credential prompt" },
          { label: "Suspicious link pattern", impact: 28, detail: hasExternalUntrustedLink ? "External untrusted link" : "Deceptive path or domain" },
          { label: "Urgency pressure", impact: hasUrgency ? 16 : 8, detail: hasUrgency ? "Pressure to act immediately" : "Risky request pattern" },
        ],
        explanation: "This content combines a sensitive request with a fake or mismatched domain pattern, which is a strong phishing signal.",
        reasons: ["Credential request", hasSuspiciousLink || hasSuspiciousSenderDomain ? "Suspicious link" : "Urgency pressure"].filter(Boolean),
      };
    }

    if (hasUrgency || hasAccountVerificationRequest) {
      return {
        source,
        classification: "suspicious",
        riskScore: 38,
        category: "Needs review",
        attackType: "Needs review",
        intent: inferIntentLabel(lower, "suspicious"),
        detectedLanguage,
        language: detectedLanguage,
        domainTrust: neutralDomainTrust,
        scoreBreakdown: [
          { label: "Urgency or review pressure", impact: 18, detail: "Account verification or action request" },
          { label: "Sender context unavailable", impact: 10, detail: neutralDomainTrust.label },
        ],
        explanation: "This message asks for account verification or urgent action. Verify it through the official site before acting.",
        reasons: [hasUrgency ? "Urgency pressure" : "Account verification request"],
      };
    }

    return {
      source,
      classification: "safe",
      riskScore: 12,
      category: "Safe Email",
      attackType: "Safe Email",
      intent: inferIntentLabel(lower, "safe"),
      detectedLanguage,
      language: detectedLanguage,
      domainTrust: neutralDomainTrust,
      scoreBreakdown: [
        { label: senderDomain ? "Sender domain available" : "Low-risk message pattern", impact: -12, detail: senderDomain ? `Sender domain: ${senderDomain}` : neutralDomainTrust.label },
      ],
      explanation: "No risky behavior detected. This is a trusted message.",
      reasons: ["No sensitive request", "No urgency pressure", senderDomain ? "Consistent sender context" : "No spoofing detected"],
    };
  }

  function isVisibleNode(node) {
    if (!node) return false;
    const style = window.getComputedStyle(node);
    if (!style || style.display === "none" || style.visibility === "hidden") return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  async function analyzeWithApi(emailText, headersText, cacheKey, context, options) {
    const skipCache = Boolean(options && options.skipCache);
    if (cacheKey && !skipCache && resultCache.has(cacheKey)) {
      return cloneResult(resultCache.get(cacheKey));
    }

    const payload = {
      email_text: String(emailText || "").slice(0, MAX_EMAIL_TEXT_CHARS),
      headers: String(headersText || "").slice(0, 10000),
    };

    const buildFallback = () => {
      const fallback = normalizeUiResult(
        buildLocalFallbackResult(
          payload.email_text,
          (context && context.sender) || "",
          (context && context.source) || "fallback",
        ),
        context || {},
      );
      if (cacheKey) {
        resultCache.set(cacheKey, fallback);
      }
      return cloneResult(fallback);
    };

    payload.email_text = payload.email_text.replace(/\s+/g, " ").trim();
    if (!payload.email_text) {
      return buildFallback();
    }

    if (!skipCache && Date.now() < apiOfflineUntil) {
      return buildFallback();
    }

    const runtimeResult = await safeSendMessage({ type: "SCAN_EMAIL_API", payload });
    if (runtimeResult) {
      apiOfflineUntil = 0;
      const normalized = normalizeUiResult(runtimeResult, context || {});
      if (cacheKey) {
        resultCache.set(cacheKey, normalized);
      }
      return cloneResult(normalized);
    }

    let lastError = null;

    const requestVariants = [
      {
        endpoint: "/api/analyze",
        body: {
          emailText: payload.email_text,
          headers: payload.headers || "",
        },
      },
      {
        endpoint: "/scan-email",
        body: {
          email_text: payload.email_text,
        },
      },
    ];

    for (const baseUrl of API_BASE_CANDIDATES) {
      for (const variant of requestVariants) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);

        try {
          const res = await fetch(`${baseUrl}${variant.endpoint}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(variant.body),
            signal: controller.signal,
          });
          clearTimeout(timeoutId);

          if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
          }

          apiOfflineUntil = 0;
          const normalized = normalizeUiResult(await res.json(), context || {});
          if (cacheKey) {
            resultCache.set(cacheKey, normalized);
          }
          return cloneResult(normalized);
        } catch (error) {
          clearTimeout(timeoutId);
          lastError = error;
        }
      }
    }

    const errorText = String((lastError && lastError.message) || lastError || "");
    const isExpectedConnectivityFailure =
      lastError && (
        lastError.name === "AbortError" ||
        /Failed to fetch|NetworkError|Load failed/i.test(errorText)
      );
    const isExpectedValidationFailure = /HTTP 422/i.test(errorText);

    if (isExpectedConnectivityFailure) {
      apiOfflineUntil = Date.now() + API_RETRY_COOLDOWN_MS;
      if (Date.now() - lastApiFallbackLogAt > API_LOG_THROTTLE_MS) {
        lastApiFallbackLogAt = Date.now();
        console.info("PhishShield local API is unavailable; using built-in fallback protection.");
      }
    } else if (!isExpectedValidationFailure && lastError) {
      console.warn("PhishShield analysis failed; using deterministic local fallback.", lastError);
    }

    return buildFallback();
  }

  function getGmailAnchor() {
    const bodyNodes = Array.from(document.querySelectorAll("div.a3s.aiL, div.a3s, div[data-message-id] .a3s"))
      .filter(isVisibleNode);

    const firstBody = bodyNodes[0];
    if (firstBody) {
      return firstBody.closest("div.adn.ads, div[role='listitem'], .ii.gt") || firstBody.parentElement;
    }

    return document.querySelector("div[role='main']");
  }

  function extractGmailEmailData() {
    const subjectEl = Array.from(document.querySelectorAll("h2.hP, h2[data-thread-perm-id]"))
      .find(isVisibleNode);
    const senderEl = Array.from(document.querySelectorAll("h3.iw span[email], .gD[email]"))
      .find(isVisibleNode);
    const bodyNodes = Array.from(document.querySelectorAll("div.adn.ads div.a3s.aiL, div.adn.ads div.a3s, div[data-message-id] .a3s.aiL"))
      .filter(isVisibleNode);

    const subject = ((subjectEl && subjectEl.innerText) || "").trim();
    const sender = ((senderEl && (senderEl.getAttribute("email") || senderEl.innerText)) || "").trim();
    const bodyParts = dedupeStrings(bodyNodes.map((node) => (node.innerText || "").trim()).filter(Boolean));
    const bodyText = bodyParts.join("\n\n").replace(/\n{3,}/g, "\n\n").trim();

    const isThreadOpen = Boolean(subject) && bodyText.length >= 40;
    if (!isThreadOpen) {
      return null;
    }

    const combinedText = [
      subject ? `Subject: ${subject}` : "",
      sender ? `From: ${sender}` : "",
      bodyText,
    ].filter(Boolean).join("\n\n").slice(0, MAX_EMAIL_TEXT_CHARS);

    if (!combinedText.trim()) {
      return null;
    }

    const stableBody = bodyText
      .replace(/\s+/g, " ")
      .replace(/\b(view in browser|unsubscribe|manage preferences|open discord channel|follow @\w+|facebook|instagram|linkedin|youtube|twitter|discord)\b/gi, " ")
      .trim();

    const fingerprint = [subject, sender, stableBody.slice(0, 2500)]
      .join("|")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();

    return {
      subject,
      sender,
      bodyText,
      combinedText,
      fingerprint,
    };
  }

  function getGmailMailboxContext() {
    const mainText = String(document.querySelector("div[role='main']")?.innerText || "").toLowerCase();
    return {
      isSpamView: location.href.includes("#spam") || /\bin:spam\b/.test(mainText),
      hasSpamWarning: /why is this message in spam|report not spam/.test(mainText),
    };
  }

  function applyGmailMailboxContext(result) {
    if (!IS_GMAIL) return result;

    const mailbox = getGmailMailboxContext();
    if (!mailbox.isSpamView && !mailbox.hasSpamWarning) {
      return result;
    }

    const normalized = normalizeUiResult(result || {}, { source: "gmail-email" });
    if (normalized.visualClassification === "phishing") {
      return normalized;
    }

    const reasons = dedupeStrings([
      "Mailbox provider marked this message as spam or bulk mail",
      ...(normalized.reasons || []),
    ]).slice(0, 3);
    const keySignals = dedupeStrings([
      "Mailbox spam warning",
      ...(normalized.keySignals || []),
    ]).slice(0, 3);

    return {
      ...normalized,
      riskScore: Math.max(normalized.riskScore, 34),
      classification: "suspicious",
      visualClassification: "suspicious",
      reasons,
      keySignals,
      flags: keySignals,
      explanation: "Your mail provider flagged this message as spam or bulk mail. Review it before clicking, replying, or downloading anything.",
    };
  }

  function isPhishShieldNode(node) {
    if (!node || typeof node !== "object") return false;
    const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    return Boolean(element && (element.id === "ps-gmail-banner" || element.closest?.("#ps-gmail-banner, #ps-overlay, #ps-banner, #ps-link-guard-modal")));
  }

  function shouldIgnoreGmailMutations(mutations) {
    return Array.isArray(mutations) && mutations.length > 0 && mutations.every((mutation) => {
      if (!isPhishShieldNode(mutation.target)) {
        return false;
      }

      const addedNodes = Array.from(mutation.addedNodes || []);
      const removedNodes = Array.from(mutation.removedNodes || []);
      return [...addedNodes, ...removedNodes].every((node) => isPhishShieldNode(node));
    });
  }

  async function pushTabResult(result) {
    const response = await safeSendMessage({ type: "SET_EMAIL_RESULT", result });
    return response?.result || null;
  }

  function renderGmailBanner(result, meta) {
    const mountPoint = getGmailAnchor();
    if (!mountPoint || !mountPoint.parentElement) return;

    injectStyles();

    const isLoading = Boolean(result && result.isLoading);
    const normalized = normalizeUiResult(result || {}, {
      source: "gmail-email",
      classification: isLoading ? "safe" : undefined,
      riskScore: isLoading ? 0 : undefined,
    });
    const classification = isLoading ? "loading" : normalized.visualClassification;
    const score = isLoading ? "—" : String(normalized.riskScore);
    const label = isLoading
      ? "Analyzing"
      : classification === "phishing"
        ? "Blocked"
        : classification === "suspicious"
          ? "Review"
          : "Protected";
    const categoryLabel = normalized.attackType || normalized.category || "";
    const bannerTitleBase = isLoading
      ? "Analyzing message..."
      : classification === "phishing"
        ? "High-Risk Message"
        : classification === "suspicious"
          ? "Message Needs Review"
          : "Protected Message";
    const bannerTitle = !isLoading && categoryLabel && !/^safe email$/i.test(categoryLabel)
      ? `${bannerTitleBase} · ${categoryLabel}`
      : bannerTitleBase;
    const reasons = (normalized.reasons || []).slice(0, 3);
    const reasonKeys = new Set(reasons.map((item) => canonicalizeSignal(canonicalizeReason(item)).toLowerCase()));
    const signals = dedupeStrings([
      normalized.domainTrust?.label,
      normalized.intent,
      normalized.languageLabel,
      ...(classification === "safe" ? [] : ((normalized.keySignals && normalized.keySignals.length) ? normalized.keySignals : [])),
    ])
      .map((item) => canonicalizeSignal(item))
      .filter((item) => item && !reasonKeys.has(String(item).toLowerCase()))
      .slice(0, 4);
    const explanation = isLoading
      ? "PhishShield is finalizing the security assessment to avoid contradictory results."
      : normalized.explanation;

    if (!gmailBannerEl) {
      gmailBannerEl = document.createElement("div");
      gmailBannerEl.id = "ps-gmail-banner";
    }

    gmailBannerEl.className = `ps-gmail-banner ps-gmail-banner--${classification}`;
    gmailBannerEl.dataset.messageKey = buildGmailMessageKey(meta);
    gmailBannerEl.innerHTML = `
      <div class="ps-gmail-banner__top">
        <div class="ps-gmail-banner__summary">
          <div class="ps-gmail-banner__label">PhishShield Guardian · Mail Protection</div>
          <div class="ps-gmail-banner__title">${bannerTitle}</div>
          <div class="ps-gmail-banner__meta">${escapeHtml((meta && meta.sender) || "Opened email")} ${meta && meta.subject ? `· ${escapeHtml(meta.subject)}` : ""}</div>
        </div>
        <div class="ps-gmail-banner__status">
          <span class="ps-gmail-banner__pill ps-gmail-banner__pill--${classification === "loading" ? "suspicious" : classification}">${label}</span>
          <div class="ps-gmail-banner__score">${score}<span>/100</span></div>
        </div>
      </div>
      <div class="ps-gmail-banner__body">${escapeHtml(explanation)}</div>
      ${reasons.length ? `<ul class="ps-gmail-banner__list">${reasons.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
      ${signals.length ? `<div class="ps-gmail-banner__signals">${signals.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
      <div class="ps-gmail-banner__actions">
        <button type="button" class="ps-gmail-btn" data-action="rescan">Refresh analysis</button>
        <button type="button" class="ps-gmail-btn ps-gmail-btn--secondary" data-action="copy">Copy summary</button>
        <button type="button" class="ps-gmail-btn ps-gmail-btn--secondary" data-action="report">Report incident</button>
        <button type="button" class="ps-gmail-btn ps-gmail-btn--ghost" data-action="dismiss">Close</button>
      </div>
    `;

    if (gmailBannerEl.parentElement !== mountPoint.parentElement) {
      mountPoint.parentElement.insertBefore(gmailBannerEl, mountPoint);
    }

    const dismissBtn = gmailBannerEl.querySelector("[data-action='dismiss']");
    const rescanBtn = gmailBannerEl.querySelector("[data-action='rescan']");
    const copyBtn = gmailBannerEl.querySelector("[data-action='copy']");
    const reportBtn = gmailBannerEl.querySelector("[data-action='report']");

    if (dismissBtn) {
      dismissBtn.onclick = () => {
        if (gmailBannerEl) {
          gmailBannerEl.remove();
          gmailBannerEl = null;
        }
      };
    }

    if (rescanBtn) {
      rescanBtn.onclick = () => scheduleGmailScan(true);
    }

    if (copyBtn) {
      copyBtn.onclick = async () => {
        const copied = await copyText(buildEnterpriseSummary(normalized, {
          url: location.href,
          domain: (meta && meta.sender) || location.hostname,
          source: "gmail-email",
        }));
        flashElementText(copyBtn, copied ? "Copied" : "Unavailable");
      };
    }

    if (reportBtn) {
      reportBtn.onclick = () => {
        openIncidentPortal();
        flashElementText(reportBtn, "Opened");
      };
    }
  }

  async function scanCurrentGmailEmail(force) {
    if (!IS_GMAIL) return;

    const meta = extractGmailEmailData();
    if (!meta) {
      lastGmailFingerprint = "";
      lastGmailRenderKey = "";
      currentPageResult = null;
      clearTimeout(gmailLoadingGuardTimer);
      gmailLoadingGuardTimer = null;
      if (gmailBannerEl) {
        gmailBannerEl.remove();
        gmailBannerEl = null;
      }
      void safeSendMessage({ type: "CLEAR_EMAIL_RESULT" });
      return;
    }

    const messageKey = buildGmailMessageKey(meta);
    const emailHash = stableHash(meta.fingerprint || `${messageKey}|${meta.bodyText.slice(0, 2500)}`);
    meta.fingerprint = emailHash;
    const cacheKey = `gmail:${emailHash}`;
    const now = Date.now();

    if (!force && emailHash === lastGmailFingerprint && (now - lastGmailScanAt) < GMAIL_SCAN_MIN_INTERVAL_MS) {
      const cached = resultCache.get(cacheKey);
      if (cached) {
        const normalizedCached = applyGmailMailboxContext(normalizeUiResult(cached, {
          domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
          source: "gmail-email",
          fingerprint: emailHash,
        }));
        const cachedRenderKey = buildGmailRenderKey(normalizedCached, meta);
        const syncedCached = await pushTabResult(normalizedCached);
        const authoritativeCached = applyGmailMailboxContext(normalizeUiResult(syncedCached || normalizedCached, {
          domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
          source: "gmail-email",
          fingerprint: emailHash,
        }));
        currentPageResult = authoritativeCached;
        const authoritativeRenderKey = buildGmailRenderKey(authoritativeCached, meta);
        if (authoritativeRenderKey !== lastGmailRenderKey || !gmailBannerEl) {
          renderGmailBanner(authoritativeCached, meta);
          lastGmailRenderKey = authoritativeRenderKey;
        }
      }
      return;
    }

    const emailChanged = emailHash !== lastGmailFingerprint;
    lastGmailFingerprint = emailHash;
    lastGmailScanAt = now;

    if (emailChanged) {
      clearTimeout(gmailLoadingGuardTimer);
      gmailLoadingGuardTimer = null;
    }

    const cachedResult = !force ? resultCache.get(cacheKey) : null;
    if (cachedResult) {
      const normalizedCached = applyGmailMailboxContext(normalizeUiResult(cachedResult, {
        domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
        source: "gmail-email",
        fingerprint: emailHash,
      }));
      const cachedRenderKey = buildGmailRenderKey(normalizedCached, meta);
      const syncedCached = await pushTabResult(normalizedCached);
      const authoritativeCached = applyGmailMailboxContext(normalizeUiResult(syncedCached || normalizedCached, {
        domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
        source: "gmail-email",
        fingerprint: emailHash,
      }));
      currentPageResult = authoritativeCached;
      const authoritativeRenderKey = buildGmailRenderKey(authoritativeCached, meta);
      if (authoritativeRenderKey !== lastGmailRenderKey || !gmailBannerEl) {
        renderGmailBanner(authoritativeCached, meta);
        lastGmailRenderKey = authoritativeRenderKey;
      }
      return;
    }

    const scanToken = ++latestGmailScanToken;
    const shouldShowLoadingState = Boolean(
      force ||
      !gmailBannerEl ||
      !currentPageResult ||
      !lastGmailRenderKey ||
      gmailBannerEl.dataset.messageKey !== messageKey
    );
    if (shouldShowLoadingState) {
      const loadingKey = buildGmailRenderKey({ isLoading: true }, meta, { isLoading: true });
      if (loadingKey !== lastGmailRenderKey || !gmailBannerEl) {
        renderGmailBanner({ isLoading: true }, meta);
        lastGmailRenderKey = loadingKey;
      }
    }
    clearTimeout(gmailLoadingGuardTimer);
    gmailLoadingGuardTimer = window.setTimeout(async () => {
      if (lastGmailFingerprint !== emailHash) return;
      if (!gmailBannerEl || !gmailBannerEl.classList.contains("ps-gmail-banner--loading")) return;

      const fallbackResult = applyGmailMailboxContext(normalizeUiResult(
        buildLocalFallbackResult(meta.combinedText, meta.sender, "gmail-email"),
        {
          domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
          source: "gmail-email",
          fingerprint: emailHash,
        },
      ));
      const fallbackRenderKey = buildGmailRenderKey(fallbackResult, meta);
      if (fallbackRenderKey !== lastGmailRenderKey || !gmailBannerEl) {
        renderGmailBanner(fallbackResult, meta);
        lastGmailRenderKey = fallbackRenderKey;
      }
      const syncedFallback = await pushTabResult({ ...fallbackResult, fingerprint: emailHash });
      const authoritativeFallback = applyGmailMailboxContext(normalizeUiResult(syncedFallback || fallbackResult, {
        domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
        source: "gmail-email",
        fingerprint: emailHash,
      }));
      const authoritativeFallbackKey = buildGmailRenderKey(authoritativeFallback, meta);
      if (authoritativeFallbackKey !== lastGmailRenderKey || !gmailBannerEl) {
        renderGmailBanner(authoritativeFallback, meta);
        lastGmailRenderKey = authoritativeFallbackKey;
      }
      currentPageResult = authoritativeFallback;
    }, 4500);

    const apiResult = await analyzeWithApi(meta.combinedText, "", cacheKey, {
      sender: meta.sender,
      fingerprint: emailHash,
      domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
      source: "gmail-email",
    }, {
      skipCache: force,
    });

    clearTimeout(gmailLoadingGuardTimer);
    gmailLoadingGuardTimer = null;

    if (scanToken !== latestGmailScanToken || lastGmailFingerprint !== emailHash) {
      return;
    }

    const normalized = applyGmailMailboxContext(normalizeUiResult(apiResult, {
      domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
      source: "gmail-email",
      fingerprint: emailHash,
    }));

    const syncedResult = await pushTabResult({ ...normalized, fingerprint: emailHash });
    const authoritativeResult = applyGmailMailboxContext(normalizeUiResult(syncedResult || normalized, {
      domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
      source: "gmail-email",
      fingerprint: emailHash,
    }));

    const renderKey = buildGmailRenderKey(authoritativeResult, meta);
    if (renderKey !== lastGmailRenderKey || !gmailBannerEl) {
      renderGmailBanner(authoritativeResult, meta);
      lastGmailRenderKey = renderKey;
    }

    currentPageResult = authoritativeResult;
  }

  function scheduleGmailScan(force) {
    clearTimeout(gmailScanTimer);
    gmailScanTimer = setTimeout(() => scanCurrentGmailEmail(force), force ? 120 : GMAIL_SCAN_DEBOUNCE_MS);
  }

  function initGmailScanner() {
    if (!document.body) {
      window.addEventListener("DOMContentLoaded", () => initGmailScanner(), { once: true });
      return;
    }

    scheduleGmailScan(true);

    if (!gmailObserver) {
      gmailObserver = new MutationObserver((mutations) => {
        if (shouldIgnoreGmailMutations(mutations)) return;
        scheduleGmailScan(false);
      });
      gmailObserver.observe(document.body, { childList: true, subtree: true });
    }

    window.addEventListener("hashchange", () => scheduleGmailScan(true));
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) scheduleGmailScan(false);
    });
  }

  // ─── Decision summary generator (plain English, rule-based) ───────────────

  function generateSimpleExplanation(reasons, score, isIndian) {
    const r = reasons.join(" ").toLowerCase();
    const lines = [];

    if (score >= 80) {
      lines.push("This destination shows multiple high-confidence phishing indicators and should be treated as unsafe.");
    } else if (score >= 50) {
      lines.push("This destination should be independently verified before any sign-in, reply, payment, or data entry.");
    } else {
      lines.push("This destination shows caution signals that justify a manual review before proceeding.");
    }

    if (/otp/.test(r))
      lines.push("The page appears to request an OTP or verification code, which is commonly used in account takeover attempts.");
    if (/pin|password/.test(r))
      lines.push("A password or PIN request was detected. Trusted organizations should not request these details through an unverified page.");
    if (/cvv/.test(r))
      lines.push("The page appears to request CVV or card information, which should only be entered on the verified trusted site.");
    if (/kyc/.test(r))
      lines.push("KYC-related language was detected. This is frequently used in impersonation and financial fraud campaigns.");
    if (/aadhaar/.test(r))
      lines.push("The page references Aadhaar details, which should never be shared on an unverified destination.");
    if (/pan card|pan number/.test(r))
      lines.push("The page requests PAN information, which should only be shared through a verified official workflow.");
    if (/suspend|block|restrict/.test(r))
      lines.push("The message uses suspension or restriction language to create pressure, which is a common phishing tactic.");
    if (/urgency|act now|immediately|within.*hours/.test(r))
      lines.push("Urgency language was detected, indicating possible pressure to act before the request can be verified.");
    if (/input fields|sensitive input/.test(r))
      lines.push("Sensitive input fields were detected on a risky page, increasing the likelihood of credential or payment theft.");
    if (/prize|reward|lottery|free gift|free offer/.test(r))
      lines.push("Reward or prize language was detected, which is commonly used to lure users into fraud flows.");
    if (/lookalike|impersonat|fake.*domain|spoofed/.test(r))
      lines.push("The destination appears to imitate a trusted brand or service, which is a classic impersonation pattern.");
    if (/sbi|hdfc|icici|paytm|phonepe|upi|bank/.test(r))
      lines.push("The content references banking or payment services, so any request for login, OTP, PIN, or UPI approval should be treated with caution.");
    if (/suspicious.*tld|\.xyz|\.tk|\.ml|\.cf|\.gq/.test(r))
      lines.push("The domain uses a suspicious address pattern that is uncommon for legitimate enterprise or banking services.");

    if (isIndian) {
      lines.push("If this relates to banking or UPI, verify directly in the official app or through the institution's official support channel.");
    } else {
      lines.push("Use the verified trusted site or internal support channel to confirm the request before proceeding.");
    }
    return lines;
  }

  // ─── Full-screen phishing overlay ─────────────────────────────────────────

  function showPhishingOverlay(result) {
    if (overlayEl || wasDismissed()) return;

    const { riskScore, reasons = [], suspiciousParts = [], isIndianBankingRelated } = result;
    const url = location.href;

    const reasonsHtml = reasons.slice(0, 4).map(r =>
      `<li class="ps-reason">${escapeHtml(r)}</li>`
    ).join("");

    const indianWarning = isIndianBankingRelated
      ? `<div class="ps-india-warning">
           🏦 This looks like a fake banking or UPI-related site.<br>
           Real banks like SBI, HDFC, and ICICI will <strong>never</strong> ask for your OTP, PIN, or Aadhaar details through a link.
         </div>`
      : "";

    const html = `
      <div id="ps-backdrop"></div>
      <div id="ps-card" role="alertdialog" aria-modal="true" aria-label="Phishing Warning">
        <div class="ps-header">
          <div class="ps-icon">🛡</div>
          <div>
            <div class="ps-title">High-Risk Destination Blocked</div>
            <div class="ps-score">Risk score: <strong>${riskScore}/100</strong> — Authentication, payment, or sensitive data entry should not be completed on this page.</div>
          </div>
        </div>

        <div class="ps-url-box">
          <div class="ps-url-label">Destination under review:</div>
          ${highlightUrl(url, suspiciousParts)}
        </div>

        ${indianWarning}

        ${reasonsHtml ? `
          <div class="ps-reasons-label">Decision factors:</div>
          <ul class="ps-reasons">${reasonsHtml}</ul>
        ` : ""}

        <button id="ps-explain" class="ps-btn-explain">View analysis details</button>
        <div id="ps-explain-box" class="ps-explain-box" style="display:none"></div>

        <div class="ps-actions">
          <button id="ps-close-tab" class="ps-btn-primary">Return to safety</button>
          <button id="ps-copy-summary" class="ps-btn-secondary">Copy evidence</button>
          <button id="ps-report-incident" class="ps-btn-secondary">Report incident</button>
          <button id="ps-proceed" class="ps-btn-ghost">Proceed with caution</button>
        </div>

        <div class="ps-footer">
          PhishShield Guardian · Enterprise web risk protection
        </div>
      </div>
    `;

    overlayEl = document.createElement("div");
    overlayEl.id = "ps-overlay";
    overlayEl.innerHTML = html;
    injectStyles();
    document.documentElement.appendChild(overlayEl);

    if (document.body) {
      document.body.style.overflow = "hidden";
    }

    overlayEl.querySelector("#ps-close-tab").addEventListener("click", () => {
      window.close();
      setTimeout(() => { location.href = "about:blank"; }, 300);
    });

    overlayEl.querySelector("#ps-copy-summary").addEventListener("click", async (event) => {
      const copied = await copyText(buildEnterpriseSummary(result, {
        url,
        domain: location.hostname,
        source: "page-content",
      }));
      flashElementText(event.currentTarget, copied ? "Copied" : "Unavailable");
    });

    overlayEl.querySelector("#ps-report-incident").addEventListener("click", (event) => {
      openIncidentPortal();
      flashElementText(event.currentTarget, "Opened");
    });

    overlayEl.querySelector("#ps-proceed").addEventListener("click", () => {
      markDismissed();
      removeOverlay();
    });

    // ── Explain button ──
    overlayEl.querySelector("#ps-explain").addEventListener("click", () => {
      const box = overlayEl ? overlayEl.querySelector("#ps-explain-box") : null;
      const btn = overlayEl ? overlayEl.querySelector("#ps-explain") : null;
      if (!box || !btn) return;
      if (box.style.display !== "none") {
        box.style.display = "none";
        btn.textContent = "View analysis details";
        return;
      }
      const lines = generateSimpleExplanation(reasons, riskScore, isIndianBankingRelated);
      box.innerHTML = "<div class='ps-explain-title'>Security summary</div>" +
        lines.map(l => `<div class="ps-explain-line">${escapeHtml(l)}</div>`).join("");
      box.style.display = "block";
      btn.textContent = "Hide analysis details";
    });
  }

  // ─── Top banner for suspicious (medium-risk) sites ────────────────────────

  function showSuspiciousBanner(result) {
    if (bannerEl || overlayEl || wasDismissed()) return;

    const { riskScore } = result;

    bannerEl = document.createElement("div");
    bannerEl.id = "ps-banner";
    bannerEl.innerHTML = `
      <div class="ps-banner-icon">⚠</div>
      <div class="ps-banner-text">
        <strong>Review recommended:</strong> This destination shows warning signs (risk score ${riskScore}/100).
        Verify the domain before any sign-in, reply, or sensitive data entry.
      </div>
      <button id="ps-banner-dismiss" class="ps-banner-close" title="Dismiss">✕</button>
    `;
    injectStyles();
    document.documentElement.appendChild(bannerEl);

    bannerEl.querySelector("#ps-banner-dismiss").addEventListener("click", () => {
      markDismissed();
      removeBanner();
    });
  }

  function removeOverlay() {
    if (overlayEl) { overlayEl.remove(); overlayEl = null; }
    if (!linkGuardModalEl && document.body) {
      document.body.style.overflow = "";
    }
  }

  function removeBanner() {
    if (bannerEl) { bannerEl.remove(); bannerEl = null; }
  }

  function removeHoverTooltip() {
    if (hoverTooltipEl) {
      hoverTooltipEl.remove();
      hoverTooltipEl = null;
    }
  }

  function removeLinkGuardModal() {
    if (linkGuardModalEl) {
      linkGuardModalEl.remove();
      linkGuardModalEl = null;
    }
    if (!overlayEl && document.body) {
      document.body.style.overflow = "";
    }
  }

  function removePasswordWarning() {
    if (passwordWarningEl) {
      passwordWarningEl.remove();
      passwordWarningEl = null;
    }
  }

  function positionHoverTooltip(x, y) {
    if (!hoverTooltipEl) return;
    hoverTooltipEl.style.left = `${Math.min(window.innerWidth - 280, x + 14)}px`;
    hoverTooltipEl.style.top = `${Math.min(window.innerHeight - 120, y + 14)}px`;
  }

  function showHoverTooltip(result, x, y, href) {
    injectStyles();
    const normalized = normalizeUiResult(result, { url: href, domain: new URL(href).hostname, source: "link-hover" });
    const classification = normalized.visualClassification;

    if (!hoverTooltipEl) {
      hoverTooltipEl = document.createElement("div");
      hoverTooltipEl.id = "ps-link-tooltip";
      document.documentElement.appendChild(hoverTooltipEl);
    }

    hoverTooltipEl.className = `ps-link-tooltip ps-link-tooltip--${classification}`;
    hoverTooltipEl.innerHTML = `
      <div class="ps-link-tooltip__title">${classification === "phishing" ? "High Risk Link" : classification === "suspicious" ? "Suspicious Link" : "Safe Link"}</div>
      <div class="ps-link-tooltip__domain">${escapeHtml(normalized.domain || href)}</div>
      <div class="ps-link-tooltip__meta">Trust score: ${100 - normalized.riskScore}/100 · Risk: ${normalized.riskScore}/100</div>
      ${normalized.keySignals && normalized.keySignals.length ? `<div class="ps-link-tooltip__signals">${normalized.keySignals.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
    `;

    positionHoverTooltip(x, y);
  }

  async function getUrlRisk(href) {
    if (!href || !/^https?:/i.test(href)) return null;
    if (urlRiskCache.has(href)) {
      return cloneResult(urlRiskCache.get(href));
    }

    const result = await safeSendMessage({ type: "CHECK_URL", url: href });

    if (result) {
      const normalized = normalizeUiResult(result, { url: href, source: "url" });
      urlRiskCache.set(href, normalized);
      return cloneResult(normalized);
    }

    return null;
  }

  function showLinkInterceptionModal(result, href, options = {}) {
    injectStyles();
    removeLinkGuardModal();

    const normalized = normalizeUiResult(result, { url: href, source: options.source || "url" });
    const classification = normalized.visualClassification;
    const title = options.title || (classification === "phishing" ? "⚠️ This link may be unsafe" : "⚠️ Check this link before opening it");
    const actionText = classification === "phishing"
      ? "This destination shows strong phishing signals."
      : "This destination looks suspicious and should be verified first.";
    const bodyText = options.body || normalized.explanation || actionText;
    const cancelLabel = options.cancelLabel || "Go back";
    const proceedLabel = options.proceedLabel || "Proceed anyway";

    linkGuardModalEl = document.createElement("div");
    linkGuardModalEl.id = "ps-link-guard-modal";
    linkGuardModalEl.innerHTML = `
      <div class="ps-link-guard__backdrop"></div>
      <div class="ps-link-guard__card ps-link-guard__card--${classification}">
        <div class="ps-link-guard__eyebrow">PhishShield Guardian</div>
        <div class="ps-link-guard__title">${escapeHtml(title)}</div>
        <div class="ps-link-guard__url">${escapeHtml(href)}</div>
        <div class="ps-link-guard__body">${escapeHtml(bodyText)}</div>
        ${normalized.keySignals && normalized.keySignals.length ? `<div class="ps-link-guard__signals">${normalized.keySignals.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        <div class="ps-link-guard__actions">
          <button type="button" class="ps-link-guard__btn ps-link-guard__btn--ghost" data-action="cancel">${escapeHtml(cancelLabel)}</button>
          <button type="button" class="ps-link-guard__btn ps-link-guard__btn--primary" data-action="proceed">${escapeHtml(proceedLabel)}</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(linkGuardModalEl);
    if (document.body) {
      document.body.style.overflow = "hidden";
    }

    linkGuardModalEl.querySelector("[data-action='cancel']").onclick = () => {
      removeLinkGuardModal();
      if (typeof options.onCancel === "function") {
        options.onCancel();
      }
    };

    linkGuardModalEl.querySelector("[data-action='proceed']").onclick = () => {
      if (typeof options.onProceed === "function") {
        options.onProceed();
        return;
      }

      void safeSendMessage({ type: "ALLOW_URL", url: href }).then(() => {
        removeLinkGuardModal();
        window.location.href = href;
      });
    };
  }

  function hasSensitiveFormFields(form) {
    if (!form || !form.querySelectorAll) return false;

    return Array.from(form.querySelectorAll("input, textarea, select")).some((field) => {
      const attrs = [field.type, field.name, field.id, field.placeholder, field.autocomplete, field.inputMode]
        .map((value) => String(value || ""))
        .join(" ");
      return field.type === "password" || /otp|pin|password|cvv|card.?number|aadhaar|pan|upi|ifsc|account.?number|net.?banking/i.test(attrs);
    });
  }

  function showPasswordWarning(result) {
    injectStyles();
    const normalized = normalizeUiResult(result || {}, { source: "page-content" });

    removePasswordWarning();
    passwordWarningEl = document.createElement("div");
    passwordWarningEl.id = "ps-password-warning";
    passwordWarningEl.className = `ps-password-warning ps-password-warning--${normalized.visualClassification}`;
    passwordWarningEl.innerHTML = `
      <strong>${normalized.visualClassification === "phishing" ? "Do not enter your password here." : "Be careful before entering credentials."}</strong>
      <span>${escapeHtml(normalized.explanation)}</span>
    `;
    document.documentElement.appendChild(passwordWarningEl);
    setTimeout(() => removePasswordWarning(), 4500);
  }

  function initLiveProtection() {
    document.addEventListener("mousemove", (event) => {
      if (hoverTooltipEl) {
        positionHoverTooltip(event.clientX, event.clientY);
      }
    }, true);

    document.addEventListener("mouseover", async (event) => {
      const link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
      if (!link || !/^https?:/i.test(link.href)) {
        return;
      }

      const result = await getUrlRisk(link.href);
      if (result) {
        showHoverTooltip(result, event.clientX, event.clientY, link.href);
      }
    }, true);

    document.addEventListener("mouseout", (event) => {
      const link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
      if (link) {
        removeHoverTooltip();
      }
    }, true);

    document.addEventListener("click", async (event) => {
      const link = event.target && event.target.closest ? event.target.closest("a[href]") : null;
      if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }

      const href = link.href;
      const warningUrl = getWarningPageUrl();
      if (!/^https?:/i.test(href) || href === location.href || (warningUrl && href.startsWith(warningUrl))) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();

      const result = await getUrlRisk(href);
      if (!result || toVisualClassification(result.classification || result.visualClassification) === "safe") {
        window.location.href = href;
        return;
      }

      showLinkInterceptionModal(result, href);
    }, true);

    document.addEventListener("focusin", (event) => {
      const field = event.target;
      if (!field || !field.matches || !field.matches("input, textarea")) return;

      const attrs = [field.type, field.name, field.id, field.placeholder, field.autocomplete].join(" ");
      const isSensitive = field.type === "password" || /otp|pin|password|cvv|card.?number|aadhaar|pan/i.test(attrs);
      if (!isSensitive || !currentPageResult) return;

      const classification = toVisualClassification(currentPageResult.classification || currentPageResult.visualClassification);
      if (classification === "phishing") {
        showLinkInterceptionModal({
          ...currentPageResult,
          explanation: "This page is risky and contains a password or OTP field. Do not enter credentials here unless you verify the site independently.",
        }, location.href);
      } else if (classification === "suspicious") {
        showPasswordWarning(currentPageResult);
      }
    }, true);

    document.addEventListener("submit", (event) => {
      const form = event.target;
      if (!form || !form.matches || !form.matches("form")) return;
      if (!currentPageResult || Date.now() < allowSensitiveActionUntil || !hasSensitiveFormFields(form)) return;

      const classification = toVisualClassification(currentPageResult.classification || currentPageResult.visualClassification);
      if (classification === "safe") return;

      event.preventDefault();
      event.stopPropagation();

      showLinkInterceptionModal(
        {
          ...currentPageResult,
          explanation: classification === "phishing"
            ? "PhishShield blocked this submission because the page looks like a credential or payment theft attempt."
            : "This site is suspicious. Verify the domain before you submit any password, OTP, PIN, or payment information.",
        },
        location.href,
        {
          source: "page-content",
          title: classification === "phishing" ? "🚫 Sensitive form blocked" : "⚠️ Verify before submitting",
          body: classification === "phishing"
            ? "This form appears on a high-risk page. Only continue if you independently verified the destination through the trusted site or internal security workflow."
            : "This form may collect sensitive data on a suspicious page. Double-check the domain before continuing.",
          cancelLabel: "Cancel submission",
          proceedLabel: "Submit anyway",
          onProceed: () => {
            allowSensitiveActionUntil = Date.now() + 15000;
            removeLinkGuardModal();
            window.setTimeout(() => {
              if (typeof form.requestSubmit === "function") {
                form.requestSubmit();
              } else {
                HTMLFormElement.prototype.submit.call(form);
              }
            }, 0);
          },
        },
      );
    }, true);
  }

  // ─── CSS injected as a <style> tag ────────────────────────────────────────

  function injectStyles() {
    if (document.getElementById("ps-styles")) return;
    const style = document.createElement("style");
    style.id = "ps-styles";
    style.textContent = `
      #ps-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        display: flex; align-items: center; justify-content: center;
        padding: 16px; box-sizing: border-box;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      #ps-backdrop {
        position: absolute; inset: 0;
        background: rgba(0, 0, 0, 0.85);
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
      }
      #ps-card {
        position: relative; z-index: 1;
        background: #0f172a;
        border: 2px solid #DC2626;
        border-radius: 16px;
        padding: 28px 32px;
        max-width: 560px; width: 100%;
        box-shadow: 0 0 60px rgba(220, 38, 38, 0.4), 0 25px 50px rgba(0,0,0,0.6);
        color: #f1f5f9;
      }
      .ps-header {
        display: flex; align-items: flex-start; gap: 16px; margin-bottom: 20px;
      }
      .ps-icon {
        font-size: 36px; line-height: 1; flex-shrink: 0;
      }
      .ps-title {
        font-size: 18px; font-weight: 700; color: #FCA5A5; line-height: 1.3;
        margin-bottom: 4px;
      }
      .ps-score {
        font-size: 13px; color: #94a3b8;
      }
      .ps-url-box {
        background: #1e293b; border: 1px solid #334155;
        border-radius: 8px; padding: 12px 14px; margin-bottom: 16px;
        word-break: break-all;
      }
      .ps-url-label {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #64748b; margin-bottom: 6px; font-weight: 600;
      }
      .ps-url-text { font-size: 12px; font-family: monospace; color: #cbd5e1; }
      .ps-url-mark {
        background: rgba(220, 38, 38, 0.25); color: #FCA5A5;
        border-radius: 3px; padding: 0 2px;
        outline: 1px solid rgba(220, 38, 38, 0.5);
      }
      .ps-india-warning {
        background: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.35);
        border-radius: 8px; padding: 12px 14px;
        color: #FCD34D; font-size: 13px; line-height: 1.5;
        margin-bottom: 16px;
      }
      .ps-reasons-label {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #64748b; margin-bottom: 8px; font-weight: 600;
      }
      .ps-reasons {
        list-style: none; margin: 0 0 20px; padding: 0;
        display: flex; flex-direction: column; gap: 6px;
      }
      .ps-reason {
        font-size: 13px; color: #cbd5e1; line-height: 1.4;
        padding-left: 18px; position: relative;
      }
      .ps-reason::before {
        content: "›"; position: absolute; left: 0;
        color: #DC2626; font-weight: 700;
      }
      .ps-actions {
        display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px;
      }
      .ps-btn-primary {
        flex: 1; min-width: 140px;
        background: #DC2626; color: white; border: none;
        border-radius: 8px; padding: 11px 18px;
        font-size: 14px; font-weight: 600; cursor: pointer;
        transition: background 0.15s;
      }
      .ps-btn-primary:hover { background: #B91C1C; }
      .ps-btn-secondary {
        flex: 1; min-width: 140px;
        background: #0f172a; color: #dbeafe;
        border: 1px solid #1d4ed8; border-radius: 8px;
        padding: 11px 18px; font-size: 13px; font-weight: 600; cursor: pointer;
        transition: background 0.15s, border-color 0.15s, color 0.15s;
      }
      .ps-btn-secondary:hover {
        background: #102040; border-color: #2563eb; color: #eff6ff;
      }
      .ps-btn-ghost {
        flex: 1; min-width: 140px;
        background: transparent; color: #64748b;
        border: 1px solid #334155; border-radius: 8px;
        padding: 11px 18px; font-size: 13px; cursor: pointer;
        transition: color 0.15s, border-color 0.15s;
      }
      .ps-btn-ghost:hover { color: #94a3b8; border-color: #475569; }
      .ps-btn-explain {
        width: 100%; margin-bottom: 12px;
        background: #0f172a; color: #64748b;
        border: 1px dashed #334155; border-radius: 8px;
        padding: 10px 16px; font-size: 13px; font-weight: 600;
        cursor: pointer; transition: background 0.15s, color 0.15s;
        text-align: center;
      }
      .ps-btn-explain:hover { background: #1e293b; color: #94a3b8; }
      .ps-explain-box {
        background: #0a1628; border: 1px solid #1e3a5f;
        border-radius: 10px; padding: 14px 16px; margin-bottom: 14px;
      }
      .ps-explain-title {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #3b82f6; font-weight: 700; margin-bottom: 10px;
      }
      .ps-explain-line {
        font-size: 13px; color: #cbd5e1; line-height: 1.6; margin-bottom: 6px;
      }
      .ps-footer {
        font-size: 11px; color: #475569; text-align: center; padding-top: 4px;
      }

      /* Suspicious banner */
      #ps-banner {
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: #78350f;
        border-bottom: 2px solid #F59E0B;
        display: flex; align-items: center; gap: 10px;
        padding: 10px 16px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 13px; color: #FDE68A;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.3);
      }
      .ps-banner-icon { font-size: 18px; flex-shrink: 0; }
      .ps-banner-text { flex: 1; line-height: 1.4; }
      .ps-banner-close {
        background: none; border: none; color: #FDE68A;
        font-size: 18px; cursor: pointer; padding: 2px 6px;
        border-radius: 4px; flex-shrink: 0; opacity: 0.7;
        transition: opacity 0.15s;
      }
      .ps-banner-close:hover { opacity: 1; }

      /* Gmail inline banner */
      .ps-gmail-banner {
        margin: 12px 0 16px;
        padding: 16px 18px;
        border-radius: 16px;
        border: 2px solid #334155;
        background: #0f172a;
        box-shadow: 0 12px 28px rgba(15, 23, 42, 0.24);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      .ps-gmail-banner--phishing {
        border-color: #dc2626;
        background: #211114;
      }
      .ps-gmail-banner--suspicious {
        border-color: #f59e0b;
        background: #24170a;
      }
      .ps-gmail-banner--safe {
        border-color: #16a34a;
        background: #0d1d12;
      }
      .ps-gmail-banner--loading {
        border-color: #2563eb;
        background: #0c1730;
      }
      .ps-gmail-banner__top {
        display: flex;
        justify-content: space-between;
        gap: 14px;
        margin-bottom: 10px;
      }
      .ps-gmail-banner__summary {
        flex: 1;
        min-width: 0;
      }
      .ps-gmail-banner__label {
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        font-weight: 800;
        margin-bottom: 5px;
      }
      .ps-gmail-banner__title {
        font-size: 17px;
        font-weight: 800;
        color: #f8fafc;
        line-height: 1.25;
      }
      .ps-gmail-banner__meta {
        font-size: 12px;
        color: #cbd5e1;
        margin-top: 4px;
      }
      .ps-gmail-banner__status {
        min-width: 94px;
        text-align: right;
      }
      .ps-gmail-banner__pill {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 10px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 8px;
      }
      .ps-gmail-banner__pill--phishing {
        background: rgba(220, 38, 38, 0.18);
        color: #fca5a5;
        border: 1px solid rgba(248, 113, 113, 0.35);
      }
      .ps-gmail-banner__pill--suspicious {
        background: rgba(245, 158, 11, 0.18);
        color: #fcd34d;
        border: 1px solid rgba(245, 158, 11, 0.35);
      }
      .ps-gmail-banner__pill--safe {
        background: rgba(22, 163, 74, 0.18);
        color: #86efac;
        border: 1px solid rgba(22, 163, 74, 0.35);
      }
      .ps-gmail-banner__score {
        font-size: 24px;
        font-weight: 900;
        color: #f8fafc;
      }
      .ps-gmail-banner__score span {
        font-size: 12px;
        color: #94a3b8;
        margin-left: 2px;
      }
      .ps-gmail-banner__body {
        font-size: 13px;
        color: #e2e8f0;
        line-height: 1.5;
        margin-bottom: 10px;
      }
      .ps-gmail-banner__list {
        margin: 0 0 10px;
        padding-left: 18px;
        color: #e2e8f0;
        font-size: 12px;
        line-height: 1.55;
      }
      .ps-gmail-banner__signals {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-bottom: 10px;
      }
      .ps-gmail-banner__signals span {
        font-size: 10px;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid #475569;
        color: #cbd5e1;
        background: rgba(15, 23, 42, 0.55);
      }
      .ps-gmail-banner__actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }
      .ps-gmail-btn {
        border: none;
        background: #2563eb;
        color: white;
        border-radius: 10px;
        padding: 8px 12px;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
      }
      .ps-gmail-btn--secondary {
        background: #0f172a;
        color: #dbeafe;
        border: 1px solid #1d4ed8;
      }
      .ps-gmail-btn--ghost {
        background: transparent;
        color: #cbd5e1;
        border: 1px solid #475569;
      }

      /* Hover link tooltip */
      #ps-link-tooltip {
        position: fixed;
        z-index: 2147483646;
        width: 260px;
        pointer-events: none;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid #334155;
        background: #0f172a;
        color: #f8fafc;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.28);
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      .ps-link-tooltip--phishing { border-color: #dc2626; }
      .ps-link-tooltip--suspicious { border-color: #f59e0b; }
      .ps-link-tooltip--safe { border-color: #16a34a; }
      .ps-link-tooltip__title {
        font-size: 12px;
        font-weight: 800;
        margin-bottom: 4px;
      }
      .ps-link-tooltip__domain {
        font-size: 12px;
        color: #cbd5e1;
        word-break: break-all;
        margin-bottom: 4px;
      }
      .ps-link-tooltip__meta {
        font-size: 11px;
        color: #94a3b8;
      }
      .ps-link-tooltip__signals {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 8px;
      }
      .ps-link-tooltip__signals span {
        font-size: 10px;
        border-radius: 999px;
        border: 1px solid #334155;
        padding: 3px 7px;
      }

      /* Interception modal */
      #ps-link-guard-modal {
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 16px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      .ps-link-guard__backdrop {
        position: absolute;
        inset: 0;
        background: rgba(2, 6, 23, 0.76);
        backdrop-filter: blur(5px);
      }
      .ps-link-guard__card {
        position: relative;
        z-index: 1;
        width: min(520px, 100%);
        border-radius: 18px;
        border: 2px solid #334155;
        background: #0f172a;
        padding: 22px;
        box-shadow: 0 20px 48px rgba(15, 23, 42, 0.4);
      }
      .ps-link-guard__card--phishing { border-color: #dc2626; }
      .ps-link-guard__card--suspicious { border-color: #f59e0b; }
      .ps-link-guard__card--safe { border-color: #16a34a; }
      .ps-link-guard__eyebrow {
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        font-weight: 800;
        margin-bottom: 8px;
      }
      .ps-link-guard__title {
        font-size: 22px;
        font-weight: 900;
        color: #f8fafc;
        margin-bottom: 8px;
      }
      .ps-link-guard__url {
        font-size: 12px;
        color: #cbd5e1;
        word-break: break-all;
        margin-bottom: 10px;
      }
      .ps-link-guard__body {
        font-size: 14px;
        color: #e2e8f0;
        line-height: 1.55;
        margin-bottom: 12px;
      }
      .ps-link-guard__signals {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-bottom: 14px;
      }
      .ps-link-guard__signals span {
        font-size: 10px;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid #475569;
      }
      .ps-link-guard__actions {
        display: flex;
        gap: 10px;
      }
      .ps-link-guard__btn {
        flex: 1;
        border: none;
        border-radius: 10px;
        padding: 10px 12px;
        font-size: 13px;
        font-weight: 800;
        cursor: pointer;
      }
      .ps-link-guard__btn--primary {
        background: #dc2626;
        color: white;
      }
      .ps-link-guard__btn--ghost {
        background: transparent;
        color: #cbd5e1;
        border: 1px solid #475569;
      }

      /* Password warning */
      #ps-password-warning {
        position: fixed;
        top: 18px;
        right: 18px;
        z-index: 2147483647;
        width: min(360px, calc(100vw - 24px));
        padding: 12px 14px;
        border-radius: 12px;
        border: 1px solid #334155;
        background: #0f172a;
        box-shadow: 0 12px 28px rgba(15, 23, 42, 0.26);
        display: flex;
        flex-direction: column;
        gap: 4px;
        color: #f8fafc;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      .ps-password-warning--phishing { border-color: #dc2626; }
      .ps-password-warning--suspicious { border-color: #f59e0b; }
      .ps-password-warning span {
        font-size: 12px;
        color: #cbd5e1;
        line-height: 1.45;
      }
    `;
    document.documentElement.appendChild(style);
  }

  // ─── Listen for results from the background worker ────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "PHISHSHIELD_FORCE_RESCAN") {
      if (IS_GMAIL) {
        scheduleGmailScan(true);
      } else {
        schedulePageProtectionScan(true);
      }
      return;
    }

    if (message.type !== "PHISHSHIELD_RESULT") return;
    handleResult(message.data);
  });

  function handleResult(result) {
    if (!result) return;

    const normalized = normalizeUiResult(result, {
      url: location.href,
      domain: location.hostname,
      source: IS_GMAIL ? "gmail-email" : "page-content",
    });
    currentPageResult = normalized;

    if (IS_GMAIL) {
      const gmailMeta = extractGmailEmailData();
      if (!gmailMeta) {
        if (gmailBannerEl) {
          gmailBannerEl.remove();
          gmailBannerEl = null;
        }
        return;
      }
      if (normalized.source !== "gmail-email" && !normalized.isLoading) {
        return;
      }
      renderGmailBanner(normalized, gmailMeta);
      return;
    }

    if (normalized.visualClassification === "phishing") {
      removeBanner();
      showPhishingOverlay(normalized);
    } else if (normalized.visualClassification === "suspicious") {
      removeOverlay();
      showSuspiciousBanner(normalized);
    } else {
      removeOverlay();
      removeBanner();
      removeLinkGuardModal();
      removePasswordWarning();
    }
  }

  function requestResult(attempt) {
    void safeSendMessage({ type: "GET_RESULT" }).then((result) => {
      if (result) {
        handleResult(result);
      } else if (attempt < 5) {
        const delay = [200, 400, 800, 1200, 2000][attempt];
        setTimeout(() => requestResult(attempt + 1), delay);
      }
    });
  }

  function schedulePageProtectionScan(force) {
    clearTimeout(pageScanTimer);
    pageScanTimer = setTimeout(() => analyzePageContent(force), force ? 150 : 900);
  }

  if (!IS_GMAIL) {
    requestResult(0);
  }

  // ─── Content-based phishing detection ───────────────────────────────────
  // Runs after the page has rendered, scans visible text and input fields.
  // Sends findings to background which merges them with the URL-based score.

  const SENSITIVE_INPUT_RE = /otp|pin|password|cvv|card.?number|aadhaar|pan/i;

  async function analyzePageContent(force) {
    if (!document.body) return;
    if (location.href.includes("warning.html")) return;
    if (!location.href.startsWith("http")) return;

    const rawText = String(document.body.innerText || document.body.textContent || "").slice(0, 15000);
    const text = rawText.replace(/\s+/g, " ").trim();

    let hasSensitiveInputs = false;
    for (const input of document.querySelectorAll("input")) {
      const attrs = [input.type, input.name, input.id, input.placeholder, input.autocomplete].join(" ");
      if (input.type === "password" || SENSITIVE_INPUT_RE.test(attrs)) {
        hasSensitiveInputs = true;
        break;
      }
    }

    if (!text && !hasSensitiveInputs) {
      return;
    }

    const pageKey = `page:${location.href}|${stableHash(text.slice(0, 8000))}`;

    if (!force && pageKey === lastPageFingerprint) {
      return;
    }
    lastPageFingerprint = pageKey;

    const apiResult = await analyzeWithApi(text, "", pageKey, {
      url: location.href,
      domain: location.hostname,
      source: "page-content",
    }, {
      skipCache: force,
    });
    const normalized = normalizeUiResult(apiResult, {
      url: location.href,
      domain: location.hostname,
      source: "page-content",
    });

    let contentScore = normalized.riskScore;
    const contentReasons = dedupeStrings(normalized.reasons || []).slice(0, 3);

    if (hasSensitiveInputs && normalized.visualClassification !== "safe") {
      contentScore = Math.max(contentScore, 42);
      contentReasons.unshift("Sensitive input field detected on a risky page");
    }

    const forcePhishing = normalized.visualClassification === "phishing" || (hasSensitiveInputs && contentScore >= 45);
    const message = {
      type: "CONTENT_ANALYSIS",
      contentScore: Math.min(contentScore, 60),
      contentReasons: dedupeStrings(contentReasons).slice(0, 3),
      hasSensitiveInputs,
      forcePhishing,
      source: "page-content",
    };

    if (message.contentScore === 0) return;

    void safeSendMessage(message).then((updatedResult) => {
      if (!updatedResult) return;
      handleResult(updatedResult);
      if (hasSensitiveInputs && toVisualClassification(updatedResult.classification || updatedResult.visualClassification) !== "safe") {
        showPasswordWarning(updatedResult);
      }
    });
  }

  initLiveProtection();

  if (IS_GMAIL) {
    initGmailScanner();
  } else {
    schedulePageProtectionScan(true);
    window.addEventListener("hashchange", () => schedulePageProtectionScan(true));
    window.addEventListener("popstate", () => schedulePageProtectionScan(true));
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) schedulePageProtectionScan(false);
    });

    if (document.body) {
      const pageObserver = new MutationObserver(() => schedulePageProtectionScan(false));
      pageObserver.observe(document.body, { childList: true, subtree: true });
    }
  }
})();
