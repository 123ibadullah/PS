const apiUrlInput = document.getElementById("api-url");
const toggleTooltips = document.getElementById("toggle-tooltips");
const toggleInterception = document.getElementById("toggle-interception");
const toggleAutoScan = document.getElementById("toggle-auto-scan");
const toggleGmail = document.getElementById("toggle-gmail");
const toggleLinkBadges = document.getElementById("toggle-link-badges");
const resultEl = document.getElementById("result");

function setResult(message, isError = false) {
  resultEl.textContent = message;
  resultEl.style.color = isError ? "#fca5a5" : "#93c5fd";
}

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function loadOptions() {
  const state = await chrome.runtime.sendMessage({ type: "GET_OPTIONS_STATE" });
  apiUrlInput.value = state?.apiBaseUrl || "http://localhost:8000";
  const settings = state?.settings || {};
  toggleTooltips.checked = Boolean(settings.enableLinkTooltips);
  toggleInterception.checked = Boolean(settings.enableLinkInterception);
  toggleAutoScan.checked = Boolean(settings.enableAutoPageScanning);
  toggleGmail.checked = Boolean(settings.enableGmailIntegration);
  toggleLinkBadges.checked = Boolean(settings.enableLinkBadges);

  const model = state?.health?.modelInfo ? ` Model: ${state.health.modelInfo}` : "";
  setResult(state?.health?.connected ? `Connected.${model}` : "Backend currently offline.");
}

async function saveOptions() {
  const payload = {
    apiBaseUrl: apiUrlInput.value,
    settings: {
      enableLinkTooltips: Boolean(toggleTooltips.checked),
      enableLinkInterception: Boolean(toggleInterception.checked),
      enableAutoPageScanning: Boolean(toggleAutoScan.checked),
      enableGmailIntegration: Boolean(toggleGmail.checked),
      enableLinkBadges: Boolean(toggleLinkBadges.checked),
    },
  };
  const res = await chrome.runtime.sendMessage({ type: "SAVE_OPTIONS", ...payload });
  setResult(res?.ok ? "Settings saved." : "Failed to save settings.", !res?.ok);
}

async function testConnection() {
  setResult("Testing connection...");
  const res = await chrome.runtime.sendMessage({ type: "PING_HEALTH_NOW" });
  if (!res?.ok) {
    setResult("Connection failed.", true);
    return;
  }
  const model = res.health?.modelInfo ? ` Model: ${res.health.modelInfo}` : "";
  setResult(res.health?.connected ? `Connected.${model}` : "Backend offline.", !res.health?.connected);
}

async function exportHistory() {
  const res = await chrome.runtime.sendMessage({ type: "EXPORT_HISTORY" });
  if (!res?.ok) {
    setResult("Could not export history.", true);
    return;
  }
  downloadJson(`phishshield-history-${Date.now()}.json`, res.history || []);
  setResult("History exported.");
}

document.getElementById("save-btn").addEventListener("click", () => {
  void saveOptions();
});
document.getElementById("test-btn").addEventListener("click", () => {
  void testConnection();
});
document.getElementById("export-btn").addEventListener("click", () => {
  void exportHistory();
});

void loadOptions();
