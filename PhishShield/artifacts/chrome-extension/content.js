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
  let currentPageResult = null;
  let lastPageFingerprint = "";

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

  function cloneResult(result) {
    return result ? JSON.parse(JSON.stringify(result)) : result;
  }

  function extractSenderDomain(sender) {
    const match = String(sender || "").match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
    return match ? match[1].toLowerCase() : "";
  }

  function pickTopSignals(payload) {
    const blob = [
      ...(payload.keySignals || []),
      ...(payload.flags || []),
      ...(payload.detectedSignals || []),
      ...(payload.detected_signals || []),
      ...(payload.signals || []),
      ...(payload.reasons || []).map(getReasonText),
      payload.explanation || "",
    ].join(" ").toLowerCase();

    const topSignals = [];
    if (/(credential|otp|password|pin\b|passcode|identity|send your otp|reply with.*otp|confirm your credentials)/i.test(blob)) {
      topSignals.push("Credential request");
    }
    if (/(suspicious link|lookalike|domain|shortener|deceptive keyword|fake .*domain|url)/i.test(blob)) {
      topSignals.push("Suspicious link");
    }
    if (/(urgent|immediately|deadline|final notice|act now|pressure|suspension|blocked)/i.test(blob)) {
      topSignals.push("Real urgency");
    }
    if (/(impersonat|spoof|bank|google|amazon|microsoft|brand)/i.test(blob)) {
      topSignals.push("Impersonation");
    }

    return topSignals.slice(0, 3);
  }

  function normalizeUiResult(result, fallback) {
    const source = (result && result.source) || (fallback && fallback.source) || "api";
    const riskScore = Math.max(0, Math.min(100, Number((result && (result.riskScore ?? result.risk_score)) ?? (fallback && fallback.riskScore) ?? 0)));
    const classification = toVisualClassification((result && result.classification) || (fallback && fallback.classification) || (riskScore >= 71 ? "phishing" : riskScore >= 31 ? "suspicious" : "safe"));
    const reasons = dedupeStrings([
      ...((result && result.reasons) || []).map(getReasonText),
      ...(((fallback && fallback.reasons) || []).map(getReasonText)),
    ]).slice(0, 3);
    const keySignals = pickTopSignals({ ...fallback, ...result, reasons });
    const explanation = (result && result.explanation) || (fallback && fallback.explanation) || (
      classification === "safe"
        ? "This content looks routine and does not show strong phishing signs."
        : classification === "phishing"
          ? "This content shows strong phishing indicators and should not be trusted."
          : "This content shows suspicious signals, so verify it before acting."
    );

    return {
      ...(fallback || {}),
      ...(result || {}),
      source,
      riskScore,
      classification,
      visualClassification: classification,
      reasons,
      keySignals,
      flags: keySignals,
      explanation,
    };
  }

  function buildLocalFallbackResult(text, senderHint, source) {
    const lower = String(text || "").toLowerCase();
    const senderDomain = extractSenderDomain(senderHint);
    const trustedSender = /amazon\.(com|in)|google\.com|microsoft\.com|apple\.com|stripe\.com|hdfcbank\.com|icicibank\.com|axisbank\.com|sbi\.co\.in|paytm\.com|phonepe\.com|roocode\.com|cursor\.com/i.test(senderDomain || lower);
    const hasOtp = /\botp\b|one time password|verification code/i.test(lower);
    const hasDoNotShare = /do not share|don't share|never share|will never ask/i.test(lower);
    const hasLoginAlert = /new sign-?in|login alert|new device|recognized device|security alert/i.test(lower);
    const hasProtectiveLoginContext = /if you don't recognize this device|if you do not recognize this device|unauthorized activity|check your account for any unauthorized activity|review this activity|sign out of this device|no action required|can safely ignore/i.test(lower);
    const requestsCredentials = /send your otp|reply with.*otp|share.*otp|provide.*otp|enter.*password|send.*password|send.*pin|confirm your credentials|re-?enter .*details/i.test(lower);
    const hasSuspiciousLink = /https?:\/\/\S+/i.test(lower) && /(\.xyz|\.top|\.click|secure|verify|login|update|claim)/i.test(lower);
    const hasUrgency = /urgent|immediately|act now|within \d+ ?hours?|avoid suspension|account suspended|final notice|blocked/i.test(lower);

    if ((trustedSender && hasOtp && hasDoNotShare && !requestsCredentials) || ((trustedSender || /roocode\.com|cursor\.com/i.test(senderDomain)) && hasLoginAlert && hasProtectiveLoginContext && !requestsCredentials && !hasSuspiciousLink)) {
      return {
        source,
        classification: "safe",
        riskScore: hasOtp ? 18 : 24,
        explanation: "This message looks like a legitimate security notice and does not request that you send credentials.",
        reasons: ["Trusted sender context", "Protective wording such as 'Do not share' or 'No action required'"],
      };
    }

    if (requestsCredentials || (hasOtp && hasUrgency) || hasSuspiciousLink) {
      return {
        source,
        classification: "phishing",
        riskScore: 72,
        explanation: "This content asks for sensitive information or uses a suspicious link pattern, which is a strong phishing signal.",
        reasons: ["Credential request", hasSuspiciousLink ? "Suspicious link" : "Real urgency"].filter(Boolean),
      };
    }

    if (hasUrgency || /verify|confirm|update.*account|review your account/i.test(lower)) {
      return {
        source,
        classification: "suspicious",
        riskScore: 38,
        explanation: "This content uses account-verification language or urgency, so it should be verified before you act.",
        reasons: [hasUrgency ? "Real urgency" : "Impersonation risk"],
      };
    }

    return {
      source,
      classification: "safe",
      riskScore: 12,
      explanation: "No strong phishing signals were detected locally.",
      reasons: ["No strong phishing signals detected"],
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
          payload.emailText,
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

    if (!skipCache && Date.now() < apiOfflineUntil) {
      return buildFallback();
    }

    let lastError = null;

    for (const baseUrl of API_BASE_CANDIDATES) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      try {
        const res = await fetch(`${baseUrl}/scan-email`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
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

    const isExpectedConnectivityFailure =
      lastError && (
        lastError.name === "AbortError" ||
        /Failed to fetch|NetworkError|Load failed/i.test(String(lastError && lastError.message || lastError))
      );

    if (isExpectedConnectivityFailure) {
      apiOfflineUntil = Date.now() + API_RETRY_COOLDOWN_MS;
      if (Date.now() - lastApiFallbackLogAt > API_LOG_THROTTLE_MS) {
        lastApiFallbackLogAt = Date.now();
        console.info("PhishShield local API is unavailable; using built-in fallback protection.");
      }
    } else if (lastError) {
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

    const fingerprint = [subject, sender, bodyText.slice(0, 4000)]
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

  function pushTabResult(result) {
    try {
      chrome.runtime.sendMessage({ type: "SET_EMAIL_RESULT", result }, () => {
        void chrome.runtime.lastError;
      });
    } catch {
      // ignore extension messaging errors
    }
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
      ? "Scanning"
      : classification === "phishing"
        ? "High Risk"
        : classification === "suspicious"
          ? "Suspicious"
          : "Safe";
    const bannerTitle = isLoading
      ? "Scanning this email…"
      : classification === "phishing"
        ? "⚠️ High Risk Email Detected"
        : classification === "suspicious"
          ? "⚠️ Suspicious Email — Verify Before Acting"
          : "✅ This Email Looks Safe";
    const reasons = (normalized.reasons || []).slice(0, 3);
    const signals = (normalized.keySignals || []).slice(0, 3);
    const explanation = isLoading
      ? "PhishShield is waiting for a complete verdict so the result does not flicker or contradict itself."
      : normalized.explanation;

    if (!gmailBannerEl) {
      gmailBannerEl = document.createElement("div");
      gmailBannerEl.id = "ps-gmail-banner";
    }

    gmailBannerEl.className = `ps-gmail-banner ps-gmail-banner--${classification}`;
    gmailBannerEl.innerHTML = `
      <div class="ps-gmail-banner__top">
        <div class="ps-gmail-banner__summary">
          <div class="ps-gmail-banner__label">PhishShield AI · Gmail Guard</div>
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
        <button type="button" class="ps-gmail-btn" data-action="rescan">Re-scan</button>
        <button type="button" class="ps-gmail-btn ps-gmail-btn--ghost" data-action="dismiss">Dismiss</button>
      </div>
    `;

    if (gmailBannerEl.parentElement !== mountPoint.parentElement) {
      mountPoint.parentElement.insertBefore(gmailBannerEl, mountPoint);
    }

    const dismissBtn = gmailBannerEl.querySelector("[data-action='dismiss']");
    const rescanBtn = gmailBannerEl.querySelector("[data-action='rescan']");

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
  }

  async function scanCurrentGmailEmail(force) {
    if (!IS_GMAIL) return;

    const meta = extractGmailEmailData();
    if (!meta) {
      lastGmailFingerprint = "";
      lastGmailRenderKey = "";
      currentPageResult = null;
      if (gmailBannerEl) {
        gmailBannerEl.remove();
        gmailBannerEl = null;
      }
      try {
        chrome.runtime.sendMessage({ type: "CLEAR_EMAIL_RESULT" }, () => {
          void chrome.runtime.lastError;
        });
      } catch {
        // ignore messaging errors
      }
      return;
    }

    const emailHash = stableHash(`${meta.subject}|${meta.sender}|${meta.bodyText}`);
    meta.fingerprint = emailHash;
    const cacheKey = `gmail:${emailHash}`;
    const now = Date.now();

    if (!force && emailHash === lastGmailFingerprint && (now - lastGmailScanAt) < GMAIL_SCAN_MIN_INTERVAL_MS) {
      const cached = resultCache.get(cacheKey);
      if (cached) {
        const normalizedCached = normalizeUiResult(cached, {
          domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
          source: "gmail-email",
          fingerprint: emailHash,
        });
        renderGmailBanner(normalizedCached, meta);
        pushTabResult(normalizedCached);
      }
      return;
    }

    const emailChanged = emailHash !== lastGmailFingerprint;
    lastGmailFingerprint = emailHash;
    lastGmailScanAt = now;

    if (emailChanged) {
      lastGmailRenderKey = "";
      if (gmailBannerEl) {
        gmailBannerEl.remove();
        gmailBannerEl = null;
      }
    }

    const cachedResult = !force ? resultCache.get(cacheKey) : null;
    if (cachedResult) {
      const normalizedCached = normalizeUiResult(cachedResult, {
        domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
        source: "gmail-email",
        fingerprint: emailHash,
      });
      renderGmailBanner(normalizedCached, meta);
      pushTabResult(normalizedCached);
      currentPageResult = normalizedCached;
      return;
    }

    const scanToken = ++latestGmailScanToken;
    renderGmailBanner({ isLoading: true }, meta);

    const apiResult = await analyzeWithApi(meta.combinedText, "", cacheKey, {
      sender: meta.sender,
      fingerprint: emailHash,
      domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
      source: "gmail-email",
    }, {
      skipCache: force,
    });

    if (scanToken !== latestGmailScanToken || lastGmailFingerprint !== emailHash) {
      return;
    }

    const normalized = normalizeUiResult(apiResult, {
      domain: meta.sender ? `Gmail · ${meta.sender}` : "mail.google.com",
      source: "gmail-email",
      fingerprint: emailHash,
    });

    const renderKey = `${emailHash}|${normalized.classification}|${normalized.riskScore}|${normalized.explanation || ""}`;
    if (renderKey !== lastGmailRenderKey || !gmailBannerEl) {
      renderGmailBanner(normalized, meta);
      lastGmailRenderKey = renderKey;
    }

    currentPageResult = normalized;
    pushTabResult({ ...normalized, fingerprint: emailHash });
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
      gmailObserver = new MutationObserver(() => scheduleGmailScan(false));
      gmailObserver.observe(document.body, { childList: true, subtree: true });
    }

    window.addEventListener("hashchange", () => scheduleGmailScan(true));
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) scheduleGmailScan(false);
    });
  }

  // ─── Simple-language explanation generator (Hinglish, rule-based) ──────────

  function generateSimpleExplanation(reasons, score, isIndian) {
    const r = reasons.join(" ").toLowerCase();
    const lines = [];

    if (score >= 80) {
      lines.push("🚨 Yeh website almost certainly ek SCAM hai. Isko turant band karo aur kuch bhi mat daalo.");
    } else if (score >= 50) {
      lines.push("⚠️ Yeh website bahut suspicious lag rahi hai. Apni koi bhi personal ya financial details mat daalo.");
    } else {
      lines.push("⚠️ Yeh website thodi suspicious hai. Kuch bhi share karne se pehle soch lo.");
    }

    if (/otp/.test(r))
      lines.push("🔐 Yeh page aapka OTP maang raha hai — real banks kabhi bhi OTP kisi link ke through nahi maangte. Yeh clearly ek scam hai.");
    if (/pin|password/.test(r))
      lines.push("🔑 Yeh page aapka password ya PIN maang raha hai — koi bhi genuine website aisa kabhi nahi karta.");
    if (/cvv/.test(r))
      lines.push("💳 Yeh page aapka CVV number maang raha hai — yeh aapke card ka secret code hai. Ise share mat karo.");
    if (/kyc/.test(r))
      lines.push("📋 Yeh page KYC ke naam par aapki details maang raha hai — scammers aksar KYC ka naam use karke log thagate hain.");
    if (/aadhaar/.test(r))
      lines.push("🪪 Yeh page aapka Aadhaar number maang raha hai — ise kisi bhi unknown website pe kabhi mat daalo.");
    if (/pan card|pan number/.test(r))
      lines.push("🪪 Yeh page aapka PAN card number maang raha hai — link pe share mat karo.");
    if (/suspend|block|restrict/.test(r))
      lines.push("🚫 Yeh page keh raha hai aapka account band ho jayega — yeh ek scam trick hai. Ghabrao mat.");
    if (/urgency|act now|immediately|within.*hours/.test(r))
      lines.push("⏰ Yeh page aapko jaldi karwane ki koshish kar raha hai — scammers hamesha yahi karte hain. Ruko, sochho, phir decide karo.");
    if (/input fields|sensitive input/.test(r))
      lines.push("📝 Is page pe ek form hai jo aapki private information maang raha hai — aise forms kabhi mat bharo.");
    if (/prize|reward|lottery|free gift|free offer/.test(r))
      lines.push("🎁 Yeh page free prize ya reward dene ka wada kar raha hai — yeh ek laalach wala trap hai.");
    if (/lookalike|impersonat|fake.*domain|spoofed/.test(r))
      lines.push("🎭 Yeh website kisi trusted brand ki copy lag rahi hai — URL dhyan se dekho, yeh original website nahi hai.");
    if (/sbi|hdfc|icici|paytm|phonepe|upi|bank/.test(r))
      lines.push("🏦 Yeh ek naqli bank ya payment website lag rahi hai — apne bank ko seedha official number pe call karo.");
    if (/suspicious.*tld|\.xyz|\.tk|\.ml|\.cf|\.gq/.test(r))
      lines.push("🌐 Is website ka address (URL) suspicious hai — real banks aur companies aisi websites use nahi karte.");

    if (isIndian) {
      lines.push("✅ Safe rehne ke liye: link close karo, apne bank ka official app kholo ya helpline pe call karo. Koi bhi OTP, PIN ya password kisi ke saath share mat karo.");
    } else {
      lines.push("✅ Agar koi bhi doubt ho — page band karo. Apni koi bhi personal ya financial details mat daalo.");
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
            <div class="ps-title">⚠️ High Risk Website Detected</div>
            <div class="ps-score">Risk score: <strong>${riskScore}/100</strong> — Do not enter passwords, OTPs, or payment details here.</div>
          </div>
        </div>

        <div class="ps-url-box">
          <div class="ps-url-label">Suspicious URL:</div>
          ${highlightUrl(url, suspiciousParts)}
        </div>

        ${indianWarning}

        ${reasonsHtml ? `
          <div class="ps-reasons-label">Why we flagged this site:</div>
          <ul class="ps-reasons">${reasonsHtml}</ul>
        ` : ""}

        <button id="ps-explain" class="ps-btn-explain">💬 Explain in simple language</button>
        <div id="ps-explain-box" class="ps-explain-box" style="display:none"></div>

        <div class="ps-actions">
          <button id="ps-close-tab" class="ps-btn-primary">✕ Close this tab</button>
          <button id="ps-proceed" class="ps-btn-ghost">Proceed anyway (not recommended)</button>
        </div>

        <div class="ps-footer">
          Powered by PhishShield AI — Real-time phishing protection for India
        </div>
      </div>
    `;

    overlayEl = document.createElement("div");
    overlayEl.id = "ps-overlay";
    overlayEl.innerHTML = html;
    injectStyles();
    document.documentElement.appendChild(overlayEl);

    document.body.style.overflow = "hidden";

    overlayEl.querySelector("#ps-close-tab").addEventListener("click", () => {
      window.close();
      setTimeout(() => { location.href = "about:blank"; }, 300);
    });

    overlayEl.querySelector("#ps-proceed").addEventListener("click", () => {
      markDismissed();
      removeOverlay();
    });

    // ── Explain button ──
    overlayEl.querySelector("#ps-explain").addEventListener("click", () => {
      const box = overlayEl.querySelector("#ps-explain-box");
      const btn = overlayEl.querySelector("#ps-explain");
      if (box.style.display !== "none") {
        box.style.display = "none";
        btn.textContent = "💬 Explain in simple language";
        return;
      }
      const lines = generateSimpleExplanation(reasons, riskScore, isIndianBankingRelated);
      box.innerHTML = "<div class='ps-explain-title'>Simple Explanation</div>" +
        lines.map(l => `<div class="ps-explain-line">${escapeHtml(l)}</div>`).join("");
      box.style.display = "block";
      btn.textContent = "✕ Hide explanation";
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
        <strong>Suspicious site:</strong> This page shows warning signs (risk score ${riskScore}/100).
        Verify the domain before you sign in or enter personal details.
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
    if (!linkGuardModalEl) {
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
    if (!overlayEl) {
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

    const result = await new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "CHECK_URL", url: href }, (response) => {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(response || null);
      });
    });

    if (result) {
      const normalized = normalizeUiResult(result, { url: href, source: "url" });
      urlRiskCache.set(href, normalized);
      return cloneResult(normalized);
    }

    return null;
  }

  function showLinkInterceptionModal(result, href) {
    injectStyles();
    removeLinkGuardModal();

    const normalized = normalizeUiResult(result, { url: href, source: "url" });
    const classification = normalized.visualClassification;
    const title = classification === "phishing" ? "⚠️ This link may be unsafe" : "⚠️ Check this link before opening it";
    const actionText = classification === "phishing"
      ? "This destination shows strong phishing signals."
      : "This destination looks suspicious and should be verified first.";

    linkGuardModalEl = document.createElement("div");
    linkGuardModalEl.id = "ps-link-guard-modal";
    linkGuardModalEl.innerHTML = `
      <div class="ps-link-guard__backdrop"></div>
      <div class="ps-link-guard__card ps-link-guard__card--${classification}">
        <div class="ps-link-guard__eyebrow">PhishShield Browser Guard</div>
        <div class="ps-link-guard__title">${title}</div>
        <div class="ps-link-guard__url">${escapeHtml(href)}</div>
        <div class="ps-link-guard__body">${escapeHtml(normalized.explanation || actionText)}</div>
        ${normalized.keySignals && normalized.keySignals.length ? `<div class="ps-link-guard__signals">${normalized.keySignals.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        <div class="ps-link-guard__actions">
          <button type="button" class="ps-link-guard__btn ps-link-guard__btn--ghost" data-action="cancel">Go back</button>
          <button type="button" class="ps-link-guard__btn ps-link-guard__btn--primary" data-action="proceed">Proceed anyway</button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(linkGuardModalEl);
    document.body.style.overflow = "hidden";

    linkGuardModalEl.querySelector("[data-action='cancel']").onclick = () => removeLinkGuardModal();
    linkGuardModalEl.querySelector("[data-action='proceed']").onclick = () => {
      chrome.runtime.sendMessage({ type: "ALLOW_URL", url: href }, () => {
        void chrome.runtime.lastError;
        removeLinkGuardModal();
        window.location.href = href;
      });
    };
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
      if (!/^https?:/i.test(href) || href === location.href || href.startsWith(chrome.runtime.getURL("warning.html"))) {
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
    chrome.runtime.sendMessage({ type: "GET_RESULT" }, (result) => {
      if (chrome.runtime.lastError) return;
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

    const text = document.body.innerText.slice(0, 15000);
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

    let hasSensitiveInputs = false;
    for (const input of document.querySelectorAll("input")) {
      const attrs = [input.type, input.name, input.id, input.placeholder, input.autocomplete].join(" ");
      if (input.type === "password" || SENSITIVE_INPUT_RE.test(attrs)) {
        hasSensitiveInputs = true;
        break;
      }
    }

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

    chrome.runtime.sendMessage(message, (updatedResult) => {
      if (chrome.runtime.lastError || !updatedResult) return;
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
