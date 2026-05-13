(function () {
  const TRUSTED_SENDERS = [
    "google.com", "youtube.com", "gmail.com", "amazon.com", "amazon.in",
    "flipkart.com", "swiggy.com", "zomato.com", "linkedin.com", "twitter.com",
    "x.com", "instagram.com", "facebook.com", "microsoft.com", "apple.com",
    "netflix.com", "razorpay.com", "paytm.com", "irctc.co.in", "incometax.gov.in",
    "uidai.gov.in", "npci.org.in", "mongodb.com",
    "adobe.com", "mail.adobe.com", "email.adobe.com",
    "openai.com", "email.openai.com", "chatgpt.com",
    "perplexity.ai", "mail.perplexity.ai",
    "vercel.com", "info.vercel.com",
    "educative.io", "mail.educative.io",
    "playo.co",
    "unstop.news", "unstop.com", "dare2compete.news", "dare2compete.com",
    "devfolio.io",
    "replit.com",
    "roocode.com", "roomote.dev",
    "kaggle.com",
    "applytojob.com",
  ];
  const SAFE_DOMAINS = [...TRUSTED_SENDERS, "wikipedia.org", "github.com"];
  const SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".top", ".ru", ".pw", ".cc"];
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd", "cutt.ly"];
  const TYPO_PATTERNS = [/am4zon/i, /paypa1/i, /sbi-verify/i, /g00gle/i, /micros0ft/i];
  /** Transactional email / ESP hosts — neutral in UI, not “unknown phishing”. */
  const EMAIL_INFRA_SUFFIXES = [
    "sendgrid.net",
    "mailchimp.com",
    "klaviyo.com",
    "constantcontact.com",
    "mailgun.org",
    "mailgun.com",
    "sparkpost.com",
    "postmarkapp.com",
    "amazonses.com",
    "mandrillapp.com",
    "sendinblue.com",
    "brevo.com",
    "mailer.com",
    "hubspotemail.net",
    "exacttarget.com",
    "salesforce.com",
  ];
  const CAREER_EDU_RE =
    /career development|internship program|internships?\b|register now|register here|webinar|\bsession\b|campus|university|certificate|\bIIM\b|\bIIT\b|mentor|career pathways|career services|assistant director/i;

  const PAGE_SCAN_DELAY_MS = 1500;
  const GMAIL_DEBOUNCE_MS = 500;
  const LINK_HOVER_DELAY_MS = 600;

  let runtimeState = {
    apiBaseUrl: "http://localhost:8000",
    settings: {
      enableLinkTooltips: true,
      enableLinkInterception: true,
      enableAutoPageScanning: true,
      enableGmailIntegration: true,
      enableLinkBadges: false,
    },
  };

  let hoverTimer = null;
  let hoverTooltip = null;
  let hoverTarget = null;
  let activeBanner = null;
  let activeOverlay = null;
  let gmailObserver = null;
  let gmailDebounceTimer = null;
  let gmailPanel = null;
  let gmailBadge = null;
  /** Fingerprint of the last Gmail message we fully analyzed (avoids duplicate API calls; not set if scan aborted). */
  let lastCompletedGmailFingerprint = "";
  let gmailScanGeneration = 0;
  let lastScanAt = 0;

  function normalizeExplanation(explanation) {
    if (typeof explanation === "string") return explanation;
    if (explanation && typeof explanation === "object") {
      if (typeof explanation.why_risky === "string" && explanation.why_risky.trim()) {
        return explanation.why_risky.trim();
      }
      if (Array.isArray(explanation.top_words)) {
        const words = explanation.top_words
          .map((item) => (item && typeof item.word === "string" ? item.word.trim() : ""))
          .filter(Boolean);
        if (words.length) return `Top indicators: ${words.join(", ")}`;
      }
    }
    return "No explanation returned by backend.";
  }

  function normalizeSignals(signals) {
    if (!Array.isArray(signals)) return [];
    return signals
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && typeof item.signal === "string") return item.signal;
        return "";
      })
      .filter(Boolean);
  }

  function getScore(result) {
    return Math.max(0, Math.min(100, Number(result?.risk_score ?? result?.riskScore ?? 0)));
  }

  function getBand(score) {
    if (score >= 61) return "high_risk";
    if (score >= 26) return "suspicious";
    return "safe";
  }

  function getVerdict(score, result) {
    const raw = String(result?.verdict || "").toLowerCase();
    if (raw.includes("high")) return "HIGH RISK";
    if (raw.includes("susp")) return "SUSPICIOUS";
    if (raw.includes("safe")) return "SAFE";
    if (score >= 61) return "HIGH RISK";
    if (score >= 26) return "SUSPICIOUS";
    return "SAFE";
  }

  function getDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return "";
    }
  }

  function domainMatches(domain, candidate) {
    return domain === candidate || domain.endsWith(`.${candidate}`);
  }

  function isTrustedSenderDomain(domain) {
    return TRUSTED_SENDERS.some((entry) => domainMatches(domain, entry));
  }

  function sameDomain(a, b) {
    const left = getDomain(a);
    const right = getDomain(b);
    if (!left || !right) return false;
    return left === right || left.endsWith(`.${right}`) || right.endsWith(`.${left}`);
  }

  function isCredentialRequest(text) {
    const lower = String(text || "").toLowerCase();
    return /\botp\b|\bpin\b|password|passcode|share.*otp|send.*otp|enter.*otp|credential|login details|bank details|routing number|swift|iban/.test(lower);
  }

  function hasSuspiciousUrlInText(text) {
    const urls = String(text || "").match(/https?:\/\/[^\s<>"')]+/gi) || [];
    return urls.some((url) => {
      const risk = classifyUrlRisk(url);
      return risk.band === "high_risk" || (risk.band === "suspicious" && risk.kind !== "email_infra");
    });
  }

  function isEmailInfraHost(domain) {
    const d = String(domain || "").toLowerCase();
    if (!d) return false;
    if (/^[a-z0-9-]+\.ct\.sendgrid\.net$/i.test(d)) return true;
    return EMAIL_INFRA_SUFFIXES.some((suf) => domainMatches(d, suf) || d.endsWith(`.${suf}`));
  }

  function classifyUrlRisk(url) {
    const domain = getDomain(url);
    const lowerUrl = String(url || "").toLowerCase();
    if (!domain) {
      return {
        indicator: "?",
        reason: "Unknown — verify before clicking",
        line2: "? Unknown — verify before clicking",
        band: "unknown",
        kind: "unknown",
      };
    }

    if (isEmailInfraHost(domain)) {
      return {
        indicator: "📧",
        reason: "Email delivery service",
        line2: "📧 Email delivery service",
        band: "neutral",
        kind: "email_infra",
      };
    }

    const safe = SAFE_DOMAINS.some((entry) => domainMatches(domain, entry));
    if (safe) {
      return {
        indicator: "✓",
        reason: "Verified safe domain",
        line2: "✓ Verified safe domain",
        band: "safe",
        kind: "safe",
      };
    }

    const suspiciousTld = SUSPICIOUS_TLDS.find((tld) => domain.endsWith(tld));
    if (suspiciousTld) {
      return {
        indicator: "⚠",
        reason: `High-risk domain extension (${suspiciousTld})`,
        line2: "⚠ High-risk domain extension",
        band: "high_risk",
        kind: "tld",
      };
    }

    if (SHORTENERS.some((entry) => domainMatches(domain, entry))) {
      return {
        indicator: "🔗",
        reason: "Shortened URL — destination hidden",
        line2: "🔗 Shortened URL — destination hidden",
        band: "suspicious",
        kind: "shortener",
      };
    }

    if (TYPO_PATTERNS.some((pattern) => pattern.test(domain) || pattern.test(lowerUrl))) {
      return {
        indicator: "🎭",
        reason: "Lookalike domain — possible spoof",
        line2: "🎭 Lookalike domain — possible spoof",
        band: "high_risk",
        kind: "typo",
      };
    }

    const trackingRoots = ["vialoops.com", "linklyhq.com", "redirect.ing", "t.hubspotemail.net"];
    if (trackingRoots.some((root) => domain === root || domain.endsWith(`.${root}`))) {
      return {
        indicator: "↪",
        reason: "Tracking / redirect link (common in marketing mail)",
        line2: "↪ Tracking redirect — only click if you trust this email",
        band: "neutral",
        kind: "tracking_redirect",
      };
    }

    return {
      indicator: "?",
      reason: "Unknown — verify before clicking",
      line2: "? Unknown — verify before clicking",
      band: "unknown",
      kind: "unknown",
    };
  }

  function applyCareerFpClamp(result, fullText) {
    if (!result) return null;
    const t = String(fullText || "");
    if (!CAREER_EDU_RE.test(t)) return result;
    if (isCredentialRequest(t) || hasSuspiciousUrlInText(t)) return result;
    let score = getScore(result);
    if (score <= 40) return result;
    score = 40;
    const rawSignals = normalizeSignals(result?.signals ?? result?.normalized_signals).filter(
      (s) => !/419-style|advance-fee.*romance/i.test(String(s))
    );
    const next = {
      ...result,
      risk_score: score,
      verdict: score >= 26 ? "Suspicious" : "SAFE",
      normalized_signals: rawSignals.length
        ? rawSignals
        : ["Career / education context — capped for false-positive safety"],
      explanation_text:
        normalizeExplanation(result?.explanation) ||
        "Legitimate career or education outreach heuristics matched; score capped.",
    };
    return next;
  }

  async function notifyScanState(scanning) {
    try {
      await chrome.runtime.sendMessage({ type: "TAB_SCAN_STATE", scanning: Boolean(scanning) });
    } catch {
      /* ignore */
    }
  }

  async function fetchScan(text) {
    const payload = String(text || "").trim();
    if (!payload) return null;
    try {
      const response = await fetch(`${runtimeState.apiBaseUrl}/scan-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email_text: payload }),
      });
      if (!response.ok) return null;
      const result = await response.json();
      const normalized = {
        ...result,
        explanation_text: normalizeExplanation(result?.explanation),
        normalized_signals: normalizeSignals(result?.signals),
      };
      return applyCareerFpClamp(normalized, payload);
    } catch {
      return null;
    }
  }

  function ensureStyle() {
    if (document.getElementById("phishshield-pro-style")) return;
    const style = document.createElement("style");
    style.id = "phishshield-pro-style";
    style.textContent = `
      @keyframes ps-pulse { 0%,100%{opacity:1} 50%{opacity:0.55} }
      @keyframes ps-slide-in-panel {
        from { transform: translateX(100%); opacity: 0.55; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes ps-glow-hr { 0%,100%{ box-shadow: 0 0 0 0 rgba(239,68,68,0.35);} 50%{ box-shadow: 0 0 12px 2px rgba(239,68,68,0.45);} }
      .ps-banner {
        position: fixed; top: 0; left: 0; right: 0; z-index: 99998;
        padding: 12px 14px; font: 13px/1.4 Inter, system-ui, sans-serif; color: #f0f9ff;
        display: flex; justify-content: space-between; gap: 10px; align-items: center;
      }
      .ps-banner.high_risk { background: linear-gradient(90deg, #450a0a, #7f1d1d); border-bottom: 2px solid #ef4444; }
      .ps-banner.suspicious { background: linear-gradient(90deg, #422006, #78350f); border-bottom: 2px solid #f59e0b; }
      .ps-banner button {
        border: 1px solid rgba(255,255,255,0.35); background: rgba(15,23,42,0.4); color: #f0f9ff;
        border-radius: 8px; padding: 6px 10px; cursor: pointer;
      }
      .ps-tooltip-wrap {
        position: fixed; z-index: 99999; max-width: 280px; pointer-events: none;
        filter: drop-shadow(0 8px 24px rgba(0,0,0,0.45));
        opacity: 0; transition: opacity 0.25s ease;
      }
      .ps-tooltip-wrap.visible { opacity: 1; }
      .ps-tooltip-arrow {
        position: absolute; top: -6px; left: 18px; width: 0; height: 0;
        border-left: 7px solid transparent; border-right: 7px solid transparent;
        border-bottom: 7px solid rgba(59,130,246,0.45);
      }
      .ps-tooltip {
        margin-top: 5px;
        background: rgba(13,31,56,0.95); backdrop-filter: blur(10px);
        border: 1px solid rgba(59,130,246,0.3); border-radius: 10px;
        padding: 10px 14px; color: #e2e8f0; font: 12px/1.45 Inter, system-ui, sans-serif;
      }
      .ps-tooltip-url { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #94a3b8; word-break: break-all; font-size: 11px; }
      .ps-tooltip-div { height: 1px; background: rgba(59,130,246,0.2); margin: 8px 0; }
      .ps-tooltip-risk { font-size: 12px; }
      .ps-tooltip-risk.safe { color: #10b981; }
      .ps-tooltip-risk.neutral { color: #60a5fa; }
      .ps-tooltip-risk.unknown { color: #94a3b8; }
      .ps-tooltip-risk.suspicious { color: #f59e0b; }
      .ps-tooltip-risk.high_risk { color: #ef4444; }
      .ps-overlay {
        position: fixed; inset: 0; z-index: 99999; background: rgba(5,13,26,0.78);
        display: flex; align-items: center; justify-content: center; padding: 18px;
      }
      .ps-card {
        width: min(560px, 100%); background: linear-gradient(180deg, #0d1f38, #0a1628);
        border: 1px solid rgba(59,130,246,0.25); border-radius: 16px;
        padding: 20px; color: #f0f9ff; font-family: Inter, system-ui, sans-serif;
        box-shadow: 0 20px 50px rgba(0,0,0,0.5);
      }
      .ps-card h3 { margin: 0 0 10px; font-size: 20px; font-weight: 800; }
      .ps-card p { margin: 8px 0; font-size: 13px; color: #cbd5e1; word-break: break-word; }
      .ps-actions { margin-top: 14px; display: flex; gap: 10px; }
      .ps-actions button {
        border: none; border-radius: 10px; padding: 10px 14px; cursor: pointer; font-weight: 700;
      }
      .ps-actions .proceed { background: linear-gradient(135deg,#ef4444,#dc2626); color: #fff; }
      .ps-actions .back { background: #1e293b; color: #e2e8f0; border: 1px solid rgba(148,163,184,0.35); }
      .ps-link-dot { display: inline-block; width: 5px; height: 5px; border-radius: 999px; margin-left: 4px; vertical-align: middle; opacity: 0.85; }
      .ps-dot-gray { background: #64748b; }
      .ps-dot-yellow { background: #f59e0b; }
      .ps-dot-red { background: #ef4444; }
      .ps-gmail-badge {
        margin-left: 8px; display: inline-flex; align-items: center; vertical-align: middle;
        font: 11px/1.2 Inter, system-ui, sans-serif; font-weight: 600; border-radius: 20px;
        padding: 2px 10px 2px 8px; letter-spacing: 0.01em;
      }
      .ps-gmail-badge.safe { color: #10b981; background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.35); }
      .ps-gmail-badge.suspicious { color: #f59e0b; background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.35); }
      .ps-gmail-badge.high_risk { color: #ef4444; background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); animation: ps-glow-hr 2s ease-in-out infinite; }
      .ps-gmail-badge.trusted { color: #60a5fa; background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.35); }
      @keyframes ps-badge-pop { from { transform: scale(0.85); opacity: 0; } to { transform: scale(1); opacity: 1; } }
      .ps-gmail-badge { cursor: default; transition: transform 0.15s ease, filter 0.15s ease; animation: ps-badge-pop 0.22s ease 0.4s both; }
      .ps-gmail-badge:hover { transform: scale(1.05); filter: brightness(1.12); }
      .ps-gmail-panel {
        all: initial;
        position: fixed;
        right: 0;
        top: 64px;
        transform: none;
        width: min(360px, calc(100vw - 16px));
        max-height: none;
        overflow: visible;
        overflow-x: hidden;
        box-sizing: border-box;
        display: block;
        isolation: isolate;
        contain: layout style;
        font-family: Inter, system-ui, -apple-system, Segoe UI, sans-serif !important;
        font-size: 14px !important;
        line-height: 1.5 !important;
        color: #f1f5f9 !important;
        background: linear-gradient(180deg, #050d1a, #0a1628) !important;
        border: 1px solid rgba(59,130,246,0.25) !important;
        border-right: none !important;
        border-radius: 16px 0 0 16px !important;
        padding: 20px !important;
        z-index: 2147483646 !important;
        box-shadow: -8px 0 32px rgba(0,0,0,0.55), -1px 0 0 rgba(59,130,246,0.12) !important;
        animation: ps-slide-in-panel 0.35s cubic-bezier(0.4, 0, 0.2, 1) both;
        word-wrap: break-word !important;
        word-break: break-word !important;
      }
      .ps-gmail-panel .ps-accent-top { height: 2px; border-radius: 2px 0 0 0; margin: -8px -20px 12px -20px; opacity: 0.9; }
      .ps-gmail-panel .ps-accent-top.safe { background: linear-gradient(90deg, #10b981, transparent); }
      .ps-gmail-panel .ps-accent-top.suspicious { background: linear-gradient(90deg, #f59e0b, transparent); }
      .ps-gmail-panel .ps-accent-top.high_risk { background: linear-gradient(90deg, #ef4444, transparent); }
      .ps-gmail-panel .ps-accent-top.trusted { background: linear-gradient(90deg, #3b82f6, transparent); }
      .ps-gmail-panel .ps-gh { display: flex !important; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }
      .ps-gmail-panel .ps-gh strong { font-size: 16px !important; font-weight: 700 !important; color: #ffffff !important; }
      .ps-gmail-panel .ps-close {
        all: unset;
        display: inline-block;
        font-size: 22px !important;
        line-height: 1 !important;
        cursor: pointer !important;
        color: rgba(255,255,255,0.4) !important;
        transition: color 0.2s ease, transform 0.2s ease;
      }
      .ps-gmail-panel .ps-close:hover { color: #fff !important; transform: rotate(90deg); }
      .ps-gmail-panel .ps-divider { height: 1px; background: rgba(59,130,246,0.2); margin: 12px 0; }
      .ps-gmail-panel .ps-row-label { font-size: 11px !important; text-transform: uppercase; letter-spacing: 0.06em !important; color: #cbd5e1 !important; margin-bottom: 5px !important; font-weight: 600 !important; }
      .ps-gmail-panel .ps-row-val { font-size: 14px !important; color: #e0f2fe !important; font-weight: 500 !important; }
      .ps-gmail-panel .ps-gauge-row { display: flex; align-items: center; gap: 12px; margin-bottom: 4px; }
      .ps-gmail-panel .ps-mini-ring {
        width: 64px; height: 64px; border-radius: 50%;
        display: grid; place-items: center; font-size: 22px; font-weight: 800;
        border: 3px solid rgba(148,163,184,0.25); flex-shrink: 0;
      }
      .ps-gmail-panel .ps-mini-ring.safe { border-color: rgba(16,185,129,0.65); color: #34d399; }
      .ps-gmail-panel .ps-mini-ring.suspicious { border-color: rgba(251,191,36,0.75); color: #fcd34d; }
      .ps-gmail-panel .ps-mini-ring.high_risk { border-color: rgba(239,68,68,0.75); color: #fca5a5; }
      .ps-gmail-panel .ps-v { font-size: 17px; font-weight: 800; }
      .ps-gmail-panel .ps-v.safe { color: #34d399; }
      .ps-gmail-panel .ps-v.suspicious { color: #fcd34d; }
      .ps-gmail-panel .ps-v.high_risk {
        color: #ef4444 !important;
        border: 1px solid rgba(239,68,68,0.45);
        border-radius: 8px;
        padding: 4px 8px;
        display: inline-block;
        animation: ps-hr-verdict-border 2.2s ease-in-out infinite;
      }
      @keyframes ps-hr-verdict-border {
        0%, 100% { border-color: rgba(239,68,68,0.35); }
        50% { border-color: rgba(239,68,68,0.85); }
      }
      .ps-gmail-panel .ps-analysis-body {
        font-size: 14px !important;
        line-height: 1.55 !important;
        color: #f1f5f9 !important;
        margin: 0 !important;
      }
      .ps-signal-pill {
        display: inline-block; margin: 4px 6px 0 0; padding: 6px 12px 6px 14px; border-radius: 999px; font-size: 12px !important; font-weight: 600 !important;
        background: rgba(15,23,42,0.85); color: #fecaca !important; border: 1px solid rgba(248,113,113,0.45);
        border-left: 3px solid #f87171 !important;
      }
      .ps-signal-pill--safe {
        background: rgba(16,185,129,0.14) !important; color: #a7f3d0 !important;
        border: 1px solid rgba(52,211,153,0.45) !important; border-left: 3px solid #34d399 !important;
      }
      .ps-signal-pill--warn {
        background: rgba(245,158,11,0.12) !important; color: #fde68a !important;
        border: 1px solid rgba(251,191,36,0.4) !important; border-left: 3px solid #fbbf24 !important;
      }
      .ps-rec-box {
        margin-top: 12px; padding: 12px 14px; border-radius: 10px; font-size: 14px !important; font-style: italic; line-height: 1.45 !important;
        border-left: 4px solid #3b82f6; background: rgba(30,58,138,0.35); color: #f8fafc !important;
      }
      .ps-rec-box.safe { border-left-color: #10b981; background: rgba(16,185,129,0.06); }
      .ps-rec-box.suspicious { border-left-color: #f59e0b; background: rgba(245,158,11,0.06); }
      .ps-rec-box.high_risk { border-left-color: #ef4444; background: rgba(239,68,68,0.06); }
    `;
    document.documentElement.appendChild(style);
  }

  function removeBanner() {
    if (activeBanner) {
      activeBanner.remove();
      activeBanner = null;
    }
  }

  function showBanner(result) {
    const score = getScore(result);
    const band = getBand(score);
    if (band === "safe") {
      removeBanner();
      return;
    }
    ensureStyle();
    removeBanner();
    const signals = normalizeSignals(result?.signals ?? result?.normalized_signals);
    const topSignal = signals[0] || "Suspicious indicators detected";
    const banner = document.createElement("div");
    banner.className = `ps-banner ${band}`;
    banner.innerHTML = `
      <div>⚠️ PhishShield AI: This page contains phishing indicators. Risk Score: ${score}/100 — ${topSignal}. Proceed with caution.</div>
      ${band === "suspicious" ? '<button type="button">Dismiss</button>' : ""}
    `;
    banner.querySelector("button")?.addEventListener("click", () => banner.remove());
    document.documentElement.appendChild(banner);
    activeBanner = banner;
  }

  async function submitPageResult(result, timelineMeta) {
    await chrome.runtime.sendMessage({
      type: "STORE_PAGE_RESULT",
      result,
      timelineMeta: timelineMeta || null,
    });
  }

  function cleanContentText(rawText) {
    const text = String(rawText || "")
      .replace(/\s+/g, " ")
      .trim();
    if (!text) return "";

    const cookiePattern = /cookie|consent|accept all|reject all|privacy choices|manage preferences/i;
    const filteredLines = text
      .split(/[.?!]\s+/)
      .map((line) => line.trim())
      .filter((line) => line.length >= 20)
      .filter((line) => !cookiePattern.test(line));

    return filteredLines.join(". ").slice(0, 3000);
  }

  function extractMainPageText() {
    const candidate =
      document.querySelector("main")?.innerText ||
      document.querySelector("article")?.innerText ||
      document.querySelector('[role="main"]')?.innerText ||
      document.body?.innerText ||
      "";
    return cleanContentText(candidate);
  }

  function extractGmailEmailBody() {
    const primary = document.querySelector(".a3s.aiL")?.innerText || "";
    const fallback1 = document.querySelector("[data-message-id] .gs")?.innerText || "";
    const fallback2 = document.querySelector(".ii.gt .a3s")?.innerText || "";
    return cleanContentText(primary || fallback1 || fallback2);
  }

  async function scanCurrentPage() {
    if (!runtimeState.settings.enableAutoPageScanning) return;
    const now = Date.now();
    if (now - lastScanAt < 2000) return;
    lastScanAt = now;

    if (location.hostname.includes("mail.google.com")) {
      const emailBody = extractGmailEmailBody();
      if (!emailBody) {
        await submitPageResult({
          source: "gmail",
          risk_score: 0,
          verdict: "SAFE",
          explanation_text: "Open an email to analyze.",
          normalized_signals: ["No opened email detected"],
          savedAt: Date.now(),
        });
        return;
      }
      return;
    }

    const title = document.title || "";
    const metaDescription = document.querySelector('meta[name="description"]')?.getAttribute("content") || "";
    const mainText = extractMainPageText();
    const payload = [title, metaDescription, location.href, mainText].filter(Boolean).join("\n");
    if (!payload.trim()) return;

    await notifyScanState(true);
    const result = await fetchScan(payload);
    await notifyScanState(false);
    if (!result) return;
    showBanner(result);
    await submitPageResult({
      ...result,
      source: "page",
      url: location.href,
      risk_score: getScore(result),
      verdict: getVerdict(getScore(result), result),
      explanation_text: normalizeExplanation(result?.explanation ?? result?.explanation_text),
      normalized_signals: normalizeSignals(result?.signals ?? result?.normalized_signals),
    });
  }

  function truncateUrl(url) {
    const value = String(url || "");
    return value.length > 40 ? `${value.slice(0, 40)}...` : value;
  }

  function placeTooltip(x, y) {
    if (!hoverTooltip) return;
    hoverTooltip.style.left = `${Math.min(window.innerWidth - 300, x + 14)}px`;
    hoverTooltip.style.top = `${Math.min(window.innerHeight - 120, y + 16)}px`;
  }

  function removeTooltip() {
    if (hoverTooltip) {
      hoverTooltip.remove();
      hoverTooltip = null;
    }
  }

  function tooltipRiskClass(band, kind) {
    if (kind === "email_infra" || kind === "tracking_redirect") return "neutral";
    if (band === "neutral") return "neutral";
    if (band === "safe") return "safe";
    if (band === "high_risk") return "high_risk";
    if (band === "suspicious") return "suspicious";
    return "unknown";
  }

  function showTooltip(link, event) {
    if (!runtimeState.settings.enableLinkTooltips) return;
    if (sameDomain(location.href, link.href)) return;
    const risk = classifyUrlRisk(link.href);
    ensureStyle();
    removeTooltip();
    const wrap = document.createElement("div");
    wrap.className = "ps-tooltip-wrap";
    const riskClass = tooltipRiskClass(risk.band, risk.kind);
    wrap.innerHTML = `
      <div class="ps-tooltip-arrow"></div>
      <div class="ps-tooltip">
        <div class="ps-tooltip-url">${truncateUrl(link.href)}</div>
        <div class="ps-tooltip-div"></div>
        <div class="ps-tooltip-risk ${riskClass}">${risk.line2}</div>
      </div>
    `;
    document.documentElement.appendChild(wrap);
    placeTooltip(event.clientX, event.clientY);
    requestAnimationFrame(() => wrap.classList.add("visible"));
    hoverTooltip = wrap;
  }

  function removeOverlay() {
    if (activeOverlay) {
      activeOverlay.remove();
      activeOverlay = null;
    }
  }

  function showInterceptionOverlay(linkHref, reason, band) {
    ensureStyle();
    removeOverlay();
    const overlay = document.createElement("div");
    overlay.className = "ps-overlay";
    const bandLabel = band === "high_risk" ? "HIGH RISK" : "SUSPICIOUS";
    overlay.innerHTML = `
      <div class="ps-card">
        <h3>🛡️ PhishShield AI — Link Risk Warning</h3>
        <p><strong>Destination:</strong> ${linkHref}</p>
        <p><strong>Risk:</strong> ${bandLabel}</p>
        <p><strong>Reason:</strong> ${reason}</p>
        <div class="ps-actions">
          <button type="button" class="proceed">Proceed Anyway</button>
          <button type="button" class="back">Go Back — Stay Safe</button>
        </div>
      </div>
    `;
    overlay.querySelector(".proceed")?.addEventListener("click", () => {
      window.open(linkHref, "_blank", "noopener,noreferrer");
      removeOverlay();
    });
    overlay.querySelector(".back")?.addEventListener("click", () => {
      removeOverlay();
    });
    document.documentElement.appendChild(overlay);
    activeOverlay = overlay;
  }

  function shouldIntercept(linkHref) {
    const risk = classifyUrlRisk(linkHref);
    if (risk.kind === "email_infra") return null;
    const external = !sameDomain(location.href, linkHref);
    const suspicious = risk.band === "high_risk" || risk.band === "suspicious";
    return external && suspicious ? risk : null;
  }

  function isInsideGmailOpenEmail(link) {
    if (!location.hostname.includes("mail.google.com")) return false;
    return Boolean(link.closest?.(".a3s") || link.closest?.(".ii.gt") || link.closest?.("[data-message-id] .gs"));
  }

  function applyLinkBadges() {
    if (!runtimeState.settings.enableLinkBadges) return;
    const links = Array.from(document.querySelectorAll("a[href]"));
    links.slice(0, 700).forEach((link) => {
      if (link.dataset.psBadgeApplied === "1") return;
      if (isInsideGmailOpenEmail(link)) return;
      if (sameDomain(location.href, link.href)) return;

      const risk = classifyUrlRisk(link.href);
      let dotClass = null;
      if (risk.band === "high_risk" || risk.kind === "typo" || risk.kind === "tld") dotClass = "ps-dot-red";
      else if (risk.kind === "shortener") dotClass = "ps-dot-yellow";
      else if (risk.band === "safe" || risk.kind === "email_infra") dotClass = null;
      else if (risk.band === "unknown") dotClass = "ps-dot-gray";

      if (dotClass) {
        const dot = document.createElement("span");
        dot.className = `ps-link-dot ${dotClass}`;
        link.appendChild(dot);
      }
      link.dataset.psBadgeApplied = "1";
    });
  }

  function setupLinkProtection() {
    document.addEventListener(
      "mouseover",
      (event) => {
        const link = event.target?.closest?.("a[href]");
        if (!link) return;
        if (sameDomain(location.href, link.href)) return;
        hoverTarget = link;
        clearTimeout(hoverTimer);
        hoverTimer = window.setTimeout(() => {
          if (hoverTarget === link) {
            showTooltip(link, event);
            chrome.runtime.sendMessage({ type: "INCREMENT_STATS", delta: { linksScanned: 1 } }).catch(() => null);
          }
        }, LINK_HOVER_DELAY_MS);
      },
      true
    );
    document.addEventListener("mousemove", (event) => placeTooltip(event.clientX, event.clientY), true);
    document.addEventListener(
      "mouseout",
      (event) => {
        if (event.target?.closest?.("a[href]")) {
          clearTimeout(hoverTimer);
          hoverTarget = null;
          removeTooltip();
        }
      },
      true
    );

    document.addEventListener(
      "click",
      async (event) => {
        const link = event.target?.closest?.("a[href]");
        if (!link || !runtimeState.settings.enableLinkInterception) return;
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        const risk = shouldIntercept(link.href);
        if (!risk) return;
        event.preventDefault();
        event.stopPropagation();
        showInterceptionOverlay(link.href, risk.reason, risk.band);
        await chrome.runtime.sendMessage({ type: "INCREMENT_STATS", delta: { threatsBlocked: 1, linksScanned: 1 } });
      },
      true
    );
  }

  function getGmailMeta() {
    const subject = document.querySelector("h2.hP")?.textContent?.trim() || "";
    const senderNode = document.querySelector(".gD");
    const sender = senderNode?.getAttribute("email") || senderNode?.textContent?.trim() || "";
    const bodyText = extractGmailEmailBody();
    if (!subject && !bodyText) return null;
    return { subject, sender, senderNode, bodyText };
  }

  function renderGmailBadge(meta, result, trustedFlow) {
    if (!meta?.senderNode) return;
    ensureStyle();
    if (!gmailBadge || !gmailBadge.isConnected) {
      gmailBadge = document.createElement("span");
      gmailBadge.className = "ps-gmail-badge";
      meta.senderNode.parentElement?.appendChild(gmailBadge);
    }
    const score = getScore(result);
    const band = getBand(score);
    gmailBadge.title = "Scanned by PhishShield AI · Click to view details";
    gmailBadge.tabIndex = 0;
    gmailBadge.onclick = () => {
      gmailPanel?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    };
    if (trustedFlow) {
      gmailBadge.className = "ps-gmail-badge trusted";
      gmailBadge.textContent = `🛡 Trusted · ${score}`;
      return;
    }
    gmailBadge.className = `ps-gmail-badge ${band}`;
    if (band === "high_risk") gmailBadge.textContent = `✕ High Risk · ${score}`;
    else if (band === "suspicious") gmailBadge.textContent = `⚠ Suspicious · ${score}`;
    else gmailBadge.textContent = `✓ Safe · ${score}`;
  }

  function renderGmailPanel(result, meta, trustedSender) {
    ensureStyle();
    const score = getScore(result);
    const band = getBand(score);
    const verdict = getVerdict(score, result);
    const explanation = normalizeExplanation(result?.explanation ?? result?.explanation_text);
    const signals = normalizeSignals(result?.signals ?? result?.normalized_signals).slice(0, 6);
    const recommendation =
      String(result?.recommendation || "") ||
      (band === "high_risk"
        ? "Do not click links or share credentials."
        : band === "suspicious"
          ? "Verify sender and links before acting."
          : "Looks safe. Continue normally.");

    const trustedFlow = Boolean(
      trustedSender && !isCredentialRequest(meta?.bodyText) && !hasSuspiciousUrlInText(meta?.bodyText)
    );
    renderGmailBadge(meta, result, trustedFlow);

    if (!gmailPanel || !gmailPanel.isConnected) {
      gmailPanel = document.createElement("div");
      gmailPanel.className = "ps-gmail-panel";
      document.documentElement.appendChild(gmailPanel);
    }

    const pillTone =
      band === "high_risk" ? "" : band === "suspicious" ? "ps-signal-pill--warn" : "ps-signal-pill--safe";
    const pills =
      signals.map((s) => `<span class="ps-signal-pill ${pillTone}">${s}</span>`).join("") ||
      `<span class="ps-signal-pill ${pillTone}">None listed</span>`;
    const accentClass = trustedFlow ? "trusted" : band;

    gmailPanel.innerHTML = `
      <div class="ps-accent-top ${accentClass}"></div>
      <div class="ps-gh">
        <strong>🛡️ PhishShield Analysis</strong>
        <button type="button" class="ps-close" aria-label="Close">×</button>
      </div>
      <div class="ps-gauge-row">
        <div class="ps-mini-ring ${band}" data-score="${score}">0</div>
        <div>
          <div class="ps-row-label">Verdict</div>
          <div class="ps-v ${band}">${verdict}</div>
        </div>
      </div>
      <div class="ps-divider"></div>
      <div class="ps-row-label">Sender</div>
      <div class="ps-row-val">${meta?.sender || "unknown"}</div>
      <div class="ps-divider"></div>
      <div class="ps-row-label">Threat analysis</div>
      <div class="ps-analysis-body">${explanation}</div>
      <div class="ps-divider"></div>
      <div class="ps-row-label">Signals</div>
      <div>${pills}</div>
      <div class="ps-rec-box ${band}">${recommendation}</div>
    `;

    gmailPanel.querySelector(".ps-close")?.addEventListener("click", () => {
      gmailPanel?.remove();
      gmailPanel = null;
    });

    const ringEl = gmailPanel.querySelector(".ps-mini-ring[data-score]");
    if (ringEl) {
      const target = Number(ringEl.getAttribute("data-score")) || 0;
      const startTs = performance.now();
      const dur = 900;
      const step = (now) => {
        const p = Math.min(1, (now - startTs) / dur);
        const eased = 1 - (1 - p) ** 3;
        ringEl.textContent = String(Math.round(target * eased));
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }
  }

  async function scanGmailEmail() {
    if (!runtimeState.settings.enableGmailIntegration) return;
    const gen = ++gmailScanGeneration;
    const meta = getGmailMeta();
    if (!meta) return;
    const threadKey = `${location.hash || ""}|${location.pathname || ""}`;
    const senderDomain = getDomain(`https://${(meta.sender || "").split("@")[1] || ""}`);
    const trustedSender = Boolean(senderDomain && isTrustedSenderDomain(senderDomain));
    const phishingSignals = isCredentialRequest(meta.bodyText) || hasSuspiciousUrlInText(meta.bodyText);
    const fingerprint = `${threadKey}|${meta.subject}|${meta.sender}|${meta.bodyText.slice(0, 2200)}`;
    if (!fingerprint.trim() || fingerprint === lastCompletedGmailFingerprint) return;

    let result = null;
    if (trustedSender && !phishingSignals) {
      result = {
        risk_score: 20,
        verdict: "SAFE",
        explanation_text: "Trusted sender and no credential-harvesting indicators detected.",
        normalized_signals: ["Trusted sender", "No credential request", "No suspicious URLs"],
        recommendation: "Safe informational message.",
      };
    } else {
      const payload = [meta.subject, meta.sender, meta.bodyText].filter(Boolean).join("\n");
      await notifyScanState(true);
      try {
        result = await fetchScan(payload);
      } finally {
        await notifyScanState(false);
      }
      if (!result) return;
      if (gen !== gmailScanGeneration) return;
    }

    if (gen !== gmailScanGeneration) return;

    const capped = trustedSender && !phishingSignals ? 20 : getScore(result);
    const verdictStr = getVerdict(capped, result);
    const displayResult = {
      ...result,
      risk_score: capped,
      verdict: verdictStr,
      explanation_text: normalizeExplanation(result?.explanation ?? result?.explanation_text),
      normalized_signals: normalizeSignals(result?.signals ?? result?.normalized_signals),
    };
    renderGmailPanel(displayResult, meta, trustedSender);
    if (gen !== gmailScanGeneration) return;
    lastCompletedGmailFingerprint = fingerprint;
    const senderHost = (meta.sender || "").split("@")[1] || "";
    const previewText = [meta.subject, meta.bodyText].filter(Boolean).join(" ").trim().slice(0, 120);
    await submitPageResult(
      {
        ...displayResult,
        source: "gmail",
        url: location.href,
      },
      { senderDomain: senderHost, preview: previewText, verdict: verdictStr }
    );
  }

  function setupGmailObserver() {
    if (!location.hostname.includes("mail.google.com")) return;
    if (!runtimeState.settings.enableGmailIntegration) return;
    if (!document.body || gmailObserver) return;
    gmailObserver = new MutationObserver(() => {
      clearTimeout(gmailDebounceTimer);
      gmailDebounceTimer = window.setTimeout(() => {
        void scanGmailEmail();
      }, GMAIL_DEBOUNCE_MS);
    });
    gmailObserver.observe(document.body, { childList: true, subtree: true });
    void scanGmailEmail();
  }

  async function loadRuntimeState() {
    try {
      const popupState = await chrome.runtime.sendMessage({ type: "GET_POPUP_STATE" });
      runtimeState = {
        apiBaseUrl: popupState?.apiBaseUrl || runtimeState.apiBaseUrl,
        settings: { ...runtimeState.settings, ...(popupState?.settings || {}) },
      };
    } catch {
      /* keep defaults */
    }
  }

  function schedulePageScan() {
    const run = () => {
      window.setTimeout(() => {
        void scanCurrentPage();
        applyLinkBadges();
        setupGmailObserver();
      }, PAGE_SCAN_DELAY_MS);
    };
    if ("requestIdleCallback" in window) {
      window.requestIdleCallback(run, { timeout: 2500 });
    } else {
      run();
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "PHISHSHIELD_TRIGGER_PAGE_SCAN") {
      schedulePageScan();
    }
    if (message?.type === "PHISHSHIELD_SETTINGS_UPDATED") {
      runtimeState.settings = { ...runtimeState.settings, ...(message.settings || {}) };
      document.querySelectorAll('a[data-ps-badge-applied="1"]').forEach((a) => {
        a.querySelectorAll(".ps-link-dot").forEach((d) => d.remove());
        delete a.dataset.psBadgeApplied;
      });
      applyLinkBadges();
    }
  });

  async function init() {
    await loadRuntimeState();
    ensureStyle();
    setupLinkProtection();
    schedulePageScan();
  }

  void init();
})();
