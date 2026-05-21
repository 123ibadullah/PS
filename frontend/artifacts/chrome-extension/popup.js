const manualInput = document.getElementById("manual-input");
const backendStatus = document.getElementById("backend-status");
const statusDot = document.getElementById("status-dot");
const modelInline = document.getElementById("model-inline");
const modelText = document.getElementById("model-text");
const pageDomain = document.getElementById("page-domain");
const pageVerdict = document.getElementById("page-verdict");
const pageScoreLabel = document.getElementById("page-score-label");
const pageScoreFill = document.getElementById("page-score-fill");
const pageLastScan = document.getElementById("page-last-scan");
const pageDetails = document.getElementById("page-details");
const manualLoading = document.getElementById("scan-fx");
const matrixChars = document.getElementById("matrix-chars");
const manualError = document.getElementById("manual-error");
const manualResult = document.getElementById("manual-result");
const scanBtn = document.getElementById("scan-text-btn");
const scanBtnLabel = document.getElementById("scan-btn-label");
const scanBtnDots = document.getElementById("scan-btn-dots");
const shieldIcon = document.getElementById("shield-icon");
const gaugeWrap = document.getElementById("threat-gauge-wrap");
const gaugeRingHost = document.getElementById("gauge-ring-host");
const gaugeArc = document.getElementById("gauge-arc");
const gaugeScore = document.getElementById("gauge-score");
const gaugeVerdict = document.getElementById("gauge-verdict");
const manualScanWrap = document.getElementById("manual-scan-wrap");
const timelineList = document.getElementById("timeline-list");
const trustHelp = document.getElementById("trust-help");
const trustTooltip = document.getElementById("trust-tooltip");

const toggleLinkBadges = document.getElementById("toggle-link-badges");
const toggleAutoScan = document.getElementById("toggle-auto-scan");
const toggleLinkInterception = document.getElementById("toggle-link-interception");

const GAUGE_C = 2 * Math.PI * 52;
const SESSION_STATS_KEY = "phishshield_session_stats";
const SESSION_HISTORY_KEY = "phishshield_scan_history";
const DEFAULT_SESSION_STATS = { linksScanned: 0, threatsBlocked: 0, pagesAnalyzed: 0 };

let popupState = null;
let matrixInterval = null;
let gaugeVerdictTimer = null;

function escAttr(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

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
  return "No explanation available.";
}

function formatExplanationMeta(explanation) {
  if (!explanation || typeof explanation !== "object") return "";
  const parts = [];
  if (explanation.method) parts.push(`Attribution: ${explanation.method}`);
  if (explanation.explanation_degraded) {
    parts.push(`Fallback (${explanation.degraded_reason || "timeout"})`);
  }
  return parts.length ? parts.join(" · ") : "";
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

function setBackendStatus(health) {
  if (health?.connected) {
    backendStatus.className = "backend-status-label online";
    backendStatus.textContent = "Connected";
    statusDot.classList.add("online");
    const m = health?.modelInfo && String(health.modelInfo).toLowerCase() !== "connected" ? String(health.modelInfo) : "";
    modelInline.textContent = m ? `· ${m}` : "";
    modelText.textContent = "";
  } else {
    backendStatus.className = "backend-status-label offline";
    backendStatus.textContent = "Offline";
    statusDot.classList.remove("online");
    modelInline.textContent = "";
    modelText.textContent = "";
  }
}

function getAgo(ms) {
  if (!ms) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

function renderGauge(score, verdictText, band) {
  gaugeWrap.classList.remove("hidden");
  if (gaugeVerdictTimer) {
    clearTimeout(gaugeVerdictTimer);
    gaugeVerdictTimer = null;
  }

  if (gaugeRingHost) {
    gaugeRingHost.classList.remove("safe", "suspicious", "high_risk");
    gaugeRingHost.classList.add(band);
  }

  gaugeArc.classList.remove("safe", "suspicious", "high_risk");
  gaugeArc.classList.add(band);
  gaugeArc.style.strokeDasharray = String(GAUGE_C);
  gaugeArc.style.strokeDashoffset = String(GAUGE_C);

  gaugeVerdict.textContent = verdictText;
  gaugeVerdict.classList.remove("visible", "safe", "suspicious", "high_risk");
  gaugeVerdict.classList.add(band);

  gaugeScore.textContent = "0";

  const offset = GAUGE_C * (1 - score / 100);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      gaugeArc.style.strokeDashoffset = String(offset);
    });
  });

  const start = performance.now();
  const dur = 1000;
  const step = (now) => {
    const p = Math.min(1, (now - start) / dur);
    const eased = 1 - (1 - p) ** 3;
    gaugeScore.textContent = String(Math.round(score * eased));
    if (p < 1) requestAnimationFrame(step);
    else gaugeScore.textContent = String(score);
  };
  requestAnimationFrame(step);

  gaugeVerdictTimer = window.setTimeout(() => {
    gaugeVerdict.classList.add("visible");
  }, dur);
}

function hideGauge() {
  if (gaugeVerdictTimer) {
    clearTimeout(gaugeVerdictTimer);
    gaugeVerdictTimer = null;
  }
  gaugeWrap.classList.add("hidden");
  gaugeVerdict.classList.remove("visible", "safe", "suspicious", "high_risk");
  gaugeRingHost?.classList.remove("safe", "suspicious", "high_risk");
}


function setScoreBarFill(score) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0));
  pageScoreFill.style.setProperty("--fill-pct", String(pct));
}

function renderScoreBar(score, band) {
  pageScoreFill.classList.remove("safe", "suspicious", "high_risk");
  pageScoreFill.classList.add(band);
  setScoreBarFill(0);
  requestAnimationFrame(() => {
    setScoreBarFill(score);
  });
}

function renderCurrentPage(result, activeTab) {
  const url = activeTab?.url || "";
  let domain = "—";
  try {
    domain = new URL(url).hostname;
  } catch {
    domain = url || "—";
  }
  pageDomain.textContent = domain;

  if (!result || result.explanation_text === "Open an email to analyze.") {
    hideGauge();
    pageVerdict.textContent = result?.explanation_text ? "No email" : "No scan yet";
    pageVerdict.className = "verdict-pill unknown";
    pageScoreLabel.textContent = "0/100";
    setScoreBarFill(0);
    pageLastScan.textContent = "—";
    pageDetails.innerHTML = result?.explanation_text || "No result for this tab.";
    shieldIcon.classList.remove("threat-pulse");
    return;
  }

  const score = getScore(result);
  const band = getBand(score);
  const verdict = getVerdict(score, result);
  pageVerdict.textContent = verdict;
  pageVerdict.className = `verdict-pill ${band}`;
  pageScoreLabel.textContent = `${score}/100`;
  renderScoreBar(score, band);
  pageLastScan.textContent = getAgo(result?.savedAt);
  if (band === "high_risk" || band === "suspicious") {
    shieldIcon.classList.add("threat-pulse");
  } else {
    shieldIcon.classList.remove("threat-pulse");
  }
  renderGauge(score, verdict, band);

  const explanation = normalizeExplanation(result?.explanation ?? result?.explanation_text);
  const meta = formatExplanationMeta(result?.explanation);
  const signals = normalizeSignals(result?.signals ?? result?.normalized_signals).slice(0, 6);
  pageDetails.innerHTML = `
    <div><strong>Explanation</strong></div>
    ${meta ? `<div class="page-detail-meta">${meta}</div>` : ""}
    <div>${explanation}</div>
    <div class="page-detail-signals-title"><strong>Signals</strong></div>
    <ul class="page-detail-signals-list">${signals.map((item) => `<li>${item}</li>`).join("") || "<li>None</li>"}</ul>
  `;
}

function renderStats(stats) {
  document.getElementById("stat-links").textContent = String(stats?.linksScanned || 0);
  document.getElementById("stat-blocked").textContent = String(stats?.threatsBlocked || 0);
  document.getElementById("stat-pages").textContent = String(stats?.pagesAnalyzed || 0);
}

function renderSettings(settings) {
  toggleLinkBadges.checked = Boolean(settings?.enableLinkBadges);
  toggleAutoScan.checked = Boolean(settings?.enableAutoPageScanning);
  toggleLinkInterception.checked = Boolean(settings?.enableLinkInterception);
}

function renderTimeline(entries) {
  timelineList.innerHTML = "";
  const list = Array.isArray(entries) ? entries : [];
  if (!list.length) {
    timelineList.innerHTML = `<div class="muted tiny timeline-empty">No emails scanned yet in this session.</div>`;
    return;
  }
  list.forEach((entry) => {
    const r = entry?.result || {};
    const score = Math.max(0, Math.min(100, Number(entry?.score ?? getScore(r))));
    const band = getBand(score);
    const ledClass = band === "high_risk" ? "timeline-led--high" : band === "suspicious" ? "timeline-led--warn" : "timeline-led--safe";
    const domain = String(entry?.senderDomain || entry?.label || "—").slice(0, 42);
    const preview = escAttr(entry?.preview || entry?.label || "");
    const row = document.createElement("button");
    row.type = "button";
    row.className = "timeline-item";
    row.innerHTML = `
      <span class="timeline-led ${ledClass}" aria-hidden="true"></span>
      <span class="timeline-domain" title="${preview}">${escAttr(domain)}</span>
      <span class="timeline-right"><span class="timeline-score">${score}</span><span class="timeline-meta"> · ${getAgo(entry?.timestamp)}</span></span>
    `;
    row.addEventListener("click", () => {
      renderManualResult(r);
      manualResult.classList.remove("hidden");
      manualResult.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
    timelineList.appendChild(row);
  });
}

function renderManualResult(result) {
  const score = getScore(result);
  const band = getBand(score);
  const verdict = getVerdict(score, result);
  const explanation = normalizeExplanation(result?.explanation ?? result?.explanation_text);
  const signals = normalizeSignals(result?.signals).slice(0, 6);
  const language = String(result?.detectedLanguage || result?.language || "EN");
  const category = String(result?.category || "—");
  const recommendation = String(
    result?.recommendation ||
      (band === "high_risk"
        ? "Do not click links or share credentials."
        : band === "suspicious"
          ? "Verify independently before acting."
          : "Looks safe. Stay cautious.")
  );

  const pills = signals.map((s) => `<span class="signal-pill">${s}</span>`).join("") || "";

  manualResult.innerHTML = `
    <div class="manual-top">
      <div>
        <div class="manual-verdict ${band}">${verdict}</div>
        <div class="muted tiny">${category} · ${language}</div>
      </div>
      <div class="score-ring-wrap ${band}">${score}</div>
    </div>
    <div class="threat-analysis-label">Threat analysis</div>
    <div class="threat-analysis-body" id="analysis-body">${explanation}</div>
    <button type="button" class="btn-text expand-analysis-btn" id="expand-analysis">Show more</button>
    <div class="signal-pills">${pills}</div>
    <div class="rec-box ${band}">${recommendation}</div>
  `;
  const body = document.getElementById("analysis-body");
  document.getElementById("expand-analysis")?.addEventListener("click", () => {
    body?.classList.toggle("expanded");
  });
  manualResult.classList.remove("hidden");
}

function guessTimelineLabel(text) {
  const t = String(text || "");
  const at = t.match(/[\w.%+-]+@([\w.-]+\.[a-z]{2,})/i);
  if (at) return at[1];
  const line = t.split(/\r?\n/).find((l) => l.trim().length > 8);
  return (line || t).trim().slice(0, 36) || "Manual scan";
}

function startMatrixFx() {
  const chars = "012アイウエオカキクケコΣΨΩ01";
  const tick = () => {
    let out = "";
    for (let i = 0; i < 120; i++) out += chars[Math.floor(Math.random() * chars.length)] + (i % 14 === 13 ? "\n" : "");
    if (matrixChars) matrixChars.textContent = out;
  };
  tick();
  matrixInterval = window.setInterval(tick, 180);
}

function stopMatrixFx() {
  if (matrixInterval) {
    clearInterval(matrixInterval);
    matrixInterval = null;
  }
}

async function hydrateFromSessionStorage() {
  try {
    const raw = await chrome.storage.session.get([SESSION_STATS_KEY, SESSION_HISTORY_KEY]);
    renderStats({ ...DEFAULT_SESSION_STATS, ...(raw[SESSION_STATS_KEY] || {}) });
    const hist = Array.isArray(raw[SESSION_HISTORY_KEY]) ? raw[SESSION_HISTORY_KEY] : [];
    renderTimeline(hist.slice(0, 5));
  } catch {
    /* ignore */
  }
}

async function loadState() {
  await hydrateFromSessionStorage();
  popupState = await chrome.runtime.sendMessage({ type: "GET_POPUP_STATE" });
  setBackendStatus(popupState?.health);
  renderCurrentPage(popupState?.currentPageResult, popupState?.activeTab);
  renderStats({ ...DEFAULT_SESSION_STATS, ...(popupState?.stats || {}) });
  renderSettings(popupState?.settings || {});
  renderTimeline(popupState?.timeline || []);
  window.setTimeout(() => {
    void hydrateFromSessionStorage();
  }, 500);

  if (popupState?.pendingScanText) {
    manualInput.value = popupState.pendingScanText;
    await chrome.runtime.sendMessage({ type: "CLEAR_PENDING_SELECTION" });
    if (popupState?.autoScan) {
      await runManualScan();
      return;
    }
  }
  if (popupState?.lastManualResult) {
    renderManualResult(popupState.lastManualResult);
  }
}

function setScanningUi(on) {
  if (on) {
    manualLoading.classList.remove("hidden");
    scanBtn.disabled = true;
    scanBtnLabel.textContent = "Analyzing...";
    scanBtnDots.classList.remove("hidden");
    manualScanWrap?.classList.add("is-scanning");
    startMatrixFx();
  } else {
    manualLoading.classList.add("hidden");
    scanBtn.disabled = false;
    scanBtnLabel.textContent = "Scan text";
    scanBtnDots.classList.add("hidden");
    manualScanWrap?.classList.remove("is-scanning");
    stopMatrixFx();
  }
}

function showManualError(message) {
  manualError.textContent = message;
  manualError.classList.remove("hidden");
}

function clearManualError() {
  manualError.textContent = "";
  manualError.classList.add("hidden");
}

async function runManualScan() {
  const text = String(manualInput.value || "").trim();
  if (!text) {
    showManualError("Enter text to scan.");
    return;
  }
  clearManualError();
  setScanningUi(true);
  await chrome.runtime.sendMessage({ type: "POPUP_MANUAL_SCAN_STATE", scanning: true });
  try {
    const envelope = await chrome.runtime.sendMessage({ type: "SCAN_EMAIL", email_text: text });
    if (!envelope?.ok || !envelope?.result) {
      throw new Error(envelope?.error || "scan failed");
    }
    const result = envelope.result;
    renderManualResult(result);
    const label = guessTimelineLabel(text);
    await chrome.runtime.sendMessage({ type: "SAVE_MANUAL_RESULT", result, timelineLabel: label });
    await loadState();
  } catch {
    showManualError("Scan failed. Backend may be offline or unreachable.");
  } finally {
    setScanningUi(false);
    await chrome.runtime.sendMessage({ type: "POPUP_MANUAL_SCAN_STATE", scanning: false });
  }
}

async function saveSettings() {
  const settings = {
    enableLinkBadges: Boolean(toggleLinkBadges.checked),
    enableAutoPageScanning: Boolean(toggleAutoScan.checked),
    enableLinkInterception: Boolean(toggleLinkInterception.checked),
  };
  await chrome.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings });
  await loadState();
}

document.getElementById("scan-text-btn").addEventListener("click", () => {
  void runManualScan();
});

document.getElementById("rescan-page-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "FORCE_RESCAN_ACTIVE_TAB" }).then(() => {
    window.setTimeout(() => {
      void loadState();
    }, 1400);
  });
});

document.getElementById("view-details-btn").addEventListener("click", () => {
  pageDetails.classList.toggle("hidden");
});

document.getElementById("save-settings-btn").addEventListener("click", () => {
  void saveSettings();
});

trustHelp.addEventListener("click", (e) => {
  e.stopPropagation();
  trustTooltip.classList.toggle("hidden");
});

document.addEventListener("click", (e) => {
  if (!trustHelp.contains(e.target) && !trustTooltip.contains(e.target)) {
    trustTooltip.classList.add("hidden");
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    window.close();
    return;
  }
  if (e.key === "s" || e.key === "S") {
    if (document.activeElement === manualInput) return;
    e.preventDefault();
    manualInput.focus();
  }
});

manualInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    void runManualScan();
  }
});

void loadState();
