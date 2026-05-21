const API_URL_KEY = "phishshield_api_url";
const DEFAULT_API_BASE = "http://localhost:8000";
const SETTINGS_KEY = "phishshield_settings";
const HEALTH_KEY = "phishshield_health";
const TAB_RESULTS_KEY = "phishshield_tab_results";
const STATS_KEY = "phishshield_session_stats";
const LAST_MANUAL_RESULT_KEY = "phishshield_last_manual_result";
const PENDING_SCAN_TEXT_KEY = "phishshield_pending_scan_text";
const AUTO_SCAN_KEY = "phishshield_auto_scan";
const SCAN_HISTORY_KEY = "phishshield_scan_history";
const CONTEXT_MENU_ID = "phishshield_scan_selection";
const HEALTH_ALARM = "phishshield_health_alarm";

/** @type {Set<number>} */
const scanningTabs = new Set();

function tabLabelFromUrl(url) {
  try {
    return new URL(String(url || "")).hostname || "Page";
  } catch {
    return "Page";
  }
}

const DEFAULT_SETTINGS = {
  enableLinkTooltips: true,
  enableLinkInterception: true,
  enableAutoPageScanning: true,
  enableGmailIntegration: true,
  enableLinkBadges: false,
};

const DEFAULT_STATS = {
  linksScanned: 0,
  threatsBlocked: 0,
  pagesAnalyzed: 0,
};

function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function getVerdictBandFromScore(score) {
  const numeric = Number(score || 0);
  if (numeric >= 61) return "high_risk";
  if (numeric >= 26) return "suspicious";
  return "safe";
}

async function getApiBaseUrl() {
  const stored = await chrome.storage.sync.get(API_URL_KEY);
  return normalizeBaseUrl(stored[API_URL_KEY]) || DEFAULT_API_BASE;
}

async function getSettings() {
  const stored = await chrome.storage.sync.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...(stored[SETTINGS_KEY] || {}) };
}

async function getTabResults() {
  const state = await chrome.storage.session.get(TAB_RESULTS_KEY);
  return state[TAB_RESULTS_KEY] || {};
}

async function saveTabResult(tabId, result) {
  const tabResults = await getTabResults();
  tabResults[String(tabId)] = {
    ...(result || {}),
    savedAt: Date.now(),
  };
  await chrome.storage.session.set({ [TAB_RESULTS_KEY]: tabResults });
  return tabResults[String(tabId)];
}

async function getStats() {
  const state = await chrome.storage.session.get(STATS_KEY);
  return { ...DEFAULT_STATS, ...(state[STATS_KEY] || {}) };
}

async function updateStats(delta) {
  const current = await getStats();
  const next = {
    linksScanned: Math.max(0, current.linksScanned + Number(delta?.linksScanned || 0)),
    threatsBlocked: Math.max(0, current.threatsBlocked + Number(delta?.threatsBlocked || 0)),
    pagesAnalyzed: Math.max(0, current.pagesAnalyzed + Number(delta?.pagesAnalyzed || 0)),
  };
  await chrome.storage.session.set({ [STATS_KEY]: next });
  return next;
}

function verdictFromScore(score) {
  const n = Number(score || 0);
  if (n >= 61) return "HIGH RISK";
  if (n >= 26) return "SUSPICIOUS";
  return "SAFE";
}

async function appendHistory(entry) {
  const state = await chrome.storage.session.get(SCAN_HISTORY_KEY);
  const history = Array.isArray(state[SCAN_HISTORY_KEY]) ? state[SCAN_HISTORY_KEY] : [];
  const r = entry?.result || {};
  const score = Math.max(0, Math.min(100, Number(r.risk_score ?? r.riskScore ?? 0)));
  const verdict = String(entry.verdict || verdictFromScore(score));
  const senderDomain = String(entry.senderDomain || entry.label || "").slice(0, 120);
  const preview = String(entry.preview || "").slice(0, 120);
  history.unshift({
    ...entry,
    timestamp: Date.now(),
    score,
    verdict,
    senderDomain,
    preview,
  });
  await chrome.storage.session.set({ [SCAN_HISTORY_KEY]: history.slice(0, 200) });
}

async function updateBadgeForTab(tabId) {
  if (scanningTabs.has(tabId)) {
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6366f1" });
    chrome.action.setBadgeText({ tabId, text: "…" });
    return;
  }

  const healthState = await chrome.storage.session.get(HEALTH_KEY);
  const health = healthState[HEALTH_KEY] || { connected: false };
  const tabResults = await getTabResults();
  const result = tabResults[String(tabId)];
  const band = getVerdictBandFromScore(result?.risk_score ?? result?.riskScore ?? 0);

  if (band === "high_risk") {
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
    chrome.action.setBadgeText({ tabId, text: "!" });
    return;
  }

  if (band === "suspicious") {
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
    chrome.action.setBadgeText({ tabId, text: "?" });
    return;
  }

  if (health.connected) {
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
    chrome.action.setBadgeText({ tabId, text: "✓" });
    return;
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
  chrome.action.setBadgeText({ tabId, text: "!" });
}

async function createContextMenu() {
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({
    id: CONTEXT_MENU_ID,
    title: "Scan with PhishShield AI",
    contexts: ["selection"],
  });
}

async function postScanEmail(emailText) {
  const apiBase = await getApiBaseUrl();
  const payload = String(emailText || "").trim();
  if (!payload) {
    return { ok: false, status: 0, error: "empty" };
  }
  try {
    const response = await fetch(`${apiBase}/scan-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email_text: payload }),
    });
    if (!response.ok) {
      return { ok: false, status: response.status, error: `HTTP ${response.status}` };
    }
    const result = await response.json();
    return { ok: true, result };
  } catch (err) {
    return { ok: false, status: 0, error: String(err?.message || err) };
  }
}

async function pingHealth() {
  const apiBase = await getApiBaseUrl();
  let health = {
    connected: false,
    modelInfo: "Unknown",
    updatedAt: Date.now(),
  };

  try {
    const response = await fetch(`${apiBase}/health`, { method: "GET" });
    if (response.ok) {
      const body = await response.json();
      const model = String(body?.model_used || body?.model || "Connected");
      health = {
        connected: true,
        modelInfo: model,
        raw: body,
        updatedAt: Date.now(),
      };
    }
  } catch {
    // Keep offline state.
  }

  await chrome.storage.session.set({ [HEALTH_KEY]: health });
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.filter((tab) => typeof tab.id === "number").map((tab) => updateBadgeForTab(tab.id)));
  return health;
}

async function initializeDefaults() {
  const syncState = await chrome.storage.sync.get([API_URL_KEY, SETTINGS_KEY]);
  const updates = {};
  if (!normalizeBaseUrl(syncState[API_URL_KEY])) {
    updates[API_URL_KEY] = DEFAULT_API_BASE;
  }
  if (!syncState[SETTINGS_KEY]) {
    updates[SETTINGS_KEY] = DEFAULT_SETTINGS;
  }
  if (Object.keys(updates).length) {
    await chrome.storage.sync.set(updates);
  }

  const sessionState = await chrome.storage.session.get([STATS_KEY, TAB_RESULTS_KEY, SCAN_HISTORY_KEY]);
  const sessionUpdates = {};
  if (!sessionState[STATS_KEY]) {
    sessionUpdates[STATS_KEY] = DEFAULT_STATS;
  }
  if (!sessionState[TAB_RESULTS_KEY]) {
    sessionUpdates[TAB_RESULTS_KEY] = {};
  }
  if (!Array.isArray(sessionState[SCAN_HISTORY_KEY])) {
    sessionUpdates[SCAN_HISTORY_KEY] = [];
  }
  if (Object.keys(sessionUpdates).length) {
    await chrome.storage.session.set(sessionUpdates);
  }
}

async function notifyTabForScan(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: "PHISHSHIELD_TRIGGER_PAGE_SCAN" });
  } catch {
    // Ignore tabs that don't have content script yet.
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void initializeDefaults();
  void createContextMenu();
  void pingHealth();
  chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: 0.5 });
});

chrome.runtime.onStartup.addListener(() => {
  void initializeDefaults();
  void createContextMenu();
  void pingHealth();
  chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: 0.5 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEALTH_ALARM) {
    void pingHealth();
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "complete") {
    void updateBadgeForTab(tabId);
    void notifyTabForScan(tabId);
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  void updateBadgeForTab(activeInfo.tabId);
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== CONTEXT_MENU_ID) return;
  const selectedText = String(info.selectionText || "").trim();
  await chrome.storage.session.set({
    [PENDING_SCAN_TEXT_KEY]: selectedText,
    [AUTO_SCAN_KEY]: Boolean(selectedText),
  });
  try {
    await chrome.action.openPopup();
  } catch {
    // Some environments require manual popup open.
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SCAN_EMAIL") {
    void postScanEmail(message.email_text).then(sendResponse);
    return true;
  }

  if (message?.type === "GET_POPUP_STATE") {
    Promise.all([
      getApiBaseUrl(),
      getSettings(),
      chrome.storage.session.get([
        HEALTH_KEY,
        STATS_KEY,
        LAST_MANUAL_RESULT_KEY,
        PENDING_SCAN_TEXT_KEY,
        AUTO_SCAN_KEY,
        SCAN_HISTORY_KEY,
      ]),
      chrome.tabs.query({ active: true, currentWindow: true }),
      getTabResults(),
    ])
      .then(([apiBaseUrl, settings, sessionState, tabs, tabResults]) => {
        const activeTab = tabs[0];
        const tabId = activeTab?.id;
        const hist = Array.isArray(sessionState[SCAN_HISTORY_KEY]) ? sessionState[SCAN_HISTORY_KEY] : [];
        const timeline = hist.slice(0, 5);
        sendResponse({
          apiBaseUrl,
          settings,
          health: sessionState[HEALTH_KEY] || { connected: false, modelInfo: "Unknown" },
          stats: { ...DEFAULT_STATS, ...(sessionState[STATS_KEY] || {}) },
          activeTab: activeTab || null,
          currentPageResult: typeof tabId === "number" ? tabResults[String(tabId)] || null : null,
          lastManualResult: sessionState[LAST_MANUAL_RESULT_KEY] || null,
          pendingScanText: sessionState[PENDING_SCAN_TEXT_KEY] || "",
          autoScan: Boolean(sessionState[AUTO_SCAN_KEY]),
          timeline,
        });
      })
      .catch(() => {
        sendResponse({
          apiBaseUrl: DEFAULT_API_BASE,
          settings: DEFAULT_SETTINGS,
          health: { connected: false, modelInfo: "Unknown" },
          stats: DEFAULT_STATS,
          activeTab: null,
          currentPageResult: null,
          lastManualResult: null,
          pendingScanText: "",
          autoScan: false,
          timeline: [],
        });
      });
    return true;
  }

  if (message?.type === "TAB_SCAN_STATE") {
    const tabId = sender?.tab?.id;
    if (typeof tabId !== "number") {
      sendResponse({ ok: false });
      return true;
    }
    if (message.scanning) {
      scanningTabs.add(tabId);
    } else {
      scanningTabs.delete(tabId);
    }
    void updateBadgeForTab(tabId);
    sendResponse({ ok: true });
    return true;
  }

  if (message?.type === "POPUP_MANUAL_SCAN_STATE") {
    chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
      const id = tabs[0]?.id;
      if (typeof id === "number") {
        if (message.scanning) {
          scanningTabs.add(id);
        } else {
          scanningTabs.delete(id);
        }
        void updateBadgeForTab(id);
      }
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "UPDATE_SETTINGS") {
    getSettings()
      .then((current) => chrome.storage.sync.set({ [SETTINGS_KEY]: { ...current, ...(message.settings || {}) } }))
      .then(async () => {
        const settings = await getSettings();
        const tabs = await chrome.tabs.query({});
        await Promise.all(
          tabs
            .filter((tab) => typeof tab.id === "number")
            .map((tab) => chrome.tabs.sendMessage(tab.id, { type: "PHISHSHIELD_SETTINGS_UPDATED", settings }).catch(() => null))
        );
        sendResponse({ ok: true, settings });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "SAVE_MANUAL_RESULT") {
    const result = message.result || null;
    const timelineLabel = String(message.timelineLabel || "Manual scan").slice(0, 120);
    chrome.storage.session
      .set({ [LAST_MANUAL_RESULT_KEY]: result })
      .then(async () => {
        await appendHistory({ source: "manual", result, label: timelineLabel });
        sendResponse({ ok: true });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "STORE_PAGE_RESULT") {
    const tabId = sender?.tab?.id;
    if (typeof tabId !== "number") {
      sendResponse({ ok: false });
      return true;
    }
    saveTabResult(tabId, message.result || null)
      .then(async (saved) => {
        const meta = message.timelineMeta || {};
        const score = Number(saved?.risk_score ?? saved?.riskScore ?? 0);
        const senderDomain = String(meta.senderDomain || "").trim();
        const preview = String(meta.preview || "").slice(0, 120);
        const pageLabel = tabLabelFromUrl(sender?.tab?.url || "");
        await appendHistory({
          source: saved?.source === "gmail" ? "gmail" : "page",
          url: sender?.tab?.url || "",
          result: saved,
          label: saved?.source === "gmail" && senderDomain ? senderDomain : pageLabel,
          senderDomain: senderDomain || (saved?.source === "gmail" ? "" : pageLabel),
          preview,
          verdict: String(meta.verdict || verdictFromScore(score)),
        });
        await updateStats({ pagesAnalyzed: 1 });
        await updateBadgeForTab(tabId);
        sendResponse({ ok: true, result: saved });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "INCREMENT_STATS") {
    updateStats(message.delta || {})
      .then((stats) => sendResponse({ ok: true, stats }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "CLEAR_PENDING_SELECTION") {
    chrome.storage.session
      .set({ [PENDING_SCAN_TEXT_KEY]: "", [AUTO_SCAN_KEY]: false })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "FORCE_RESCAN_ACTIVE_TAB") {
    chrome.tabs
      .query({ active: true, currentWindow: true })
      .then(async (tabs) => {
        const tab = tabs[0];
        if (!tab || typeof tab.id !== "number") {
          sendResponse({ ok: false });
          return;
        }
        await notifyTabForScan(tab.id);
        sendResponse({ ok: true });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "GET_OPTIONS_STATE") {
    Promise.all([
      getApiBaseUrl(),
      getSettings(),
      chrome.storage.session.get([HEALTH_KEY, SCAN_HISTORY_KEY]),
    ])
      .then(([apiBaseUrl, settings, sessionState]) => {
        sendResponse({
          apiBaseUrl,
          settings,
          health: sessionState[HEALTH_KEY] || { connected: false, modelInfo: "Unknown" },
          history: Array.isArray(sessionState[SCAN_HISTORY_KEY]) ? sessionState[SCAN_HISTORY_KEY] : [],
        });
      })
      .catch(() => sendResponse({ apiBaseUrl: DEFAULT_API_BASE, settings: DEFAULT_SETTINGS, health: { connected: false }, history: [] }));
    return true;
  }

  if (message?.type === "SAVE_OPTIONS") {
    const nextApiBase = normalizeBaseUrl(message.apiBaseUrl) || DEFAULT_API_BASE;
    const nextSettings = { ...DEFAULT_SETTINGS, ...(message.settings || {}) };
    chrome.storage.sync
      .set({ [API_URL_KEY]: nextApiBase, [SETTINGS_KEY]: nextSettings })
      .then(async () => {
        await pingHealth();
        const tabs = await chrome.tabs.query({});
        await Promise.all(
          tabs
            .filter((tab) => typeof tab.id === "number")
            .map((tab) => chrome.tabs.sendMessage(tab.id, { type: "PHISHSHIELD_SETTINGS_UPDATED", settings: nextSettings }).catch(() => null))
        );
        sendResponse({ ok: true });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "EXPORT_HISTORY") {
    chrome.storage.session
      .get(SCAN_HISTORY_KEY)
      .then((state) => {
        sendResponse({
          ok: true,
          history: Array.isArray(state[SCAN_HISTORY_KEY]) ? state[SCAN_HISTORY_KEY] : [],
        });
      })
      .catch(() => sendResponse({ ok: false, history: [] }));
    return true;
  }

  if (message?.type === "PING_HEALTH_NOW") {
    pingHealth()
      .then((health) => sendResponse({ ok: true, health }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
});
