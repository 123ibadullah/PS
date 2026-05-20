# PhishShield AI Chrome Extension

PhishShield AI Chrome extension provides proactive page/link/email phishing protection with an analyst-focused command-center popup.

## Features

- Real-time page auto-scan (`content.js`) with risk banners:
  - `HIGH RISK` (`>=61`) red top warning
  - `SUSPICIOUS` (`26-60`) amber dismissible warning
  - `SAFE` silent
- Gmail integration (`mail.google.com`):
  - mutation-observed email open detection
  - sender-adjacent risk badge (`🟢/🟡/🔴 + score`)
  - expandable inline panel with score, verdict, signals, explanation, recommendation
- Link protection:
  - hover tooltip with destination + domain heuristic risk
  - suspicious click interception overlay with `Proceed Anyway` / `Go Back`
  - optional per-link colored dot overlays
- Popup command center (420px cyber UI):
  - backend/model status
  - current tab risk snapshot + rescan
  - manual scan with robust parsing (`explanation.why_risky` support)
  - session threat stats and toggles
- Options page:
  - API URL config
  - toggles for tooltips/interception/auto-scan/Gmail/link badges
  - connection test
  - export scan history JSON

## Install (Developer Mode)

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `frontend/artifacts/chrome-extension/`

## Configure API URL and Protection Toggles

1. Open extension details -> **Extension options**
2. Set API URL (example: `http://localhost:8000`)
3. Click **Save**
4. Use **Test Connection** to call `/health` and verify model status
5. Configure proactive settings and save

## API Contract

Popup scan request:

```http
POST /scan-email
Content-Type: application/json

{ "email_text": "..." }
```

Expected response fields used by popup/content scripts:

- `risk_score` (0-100)
- `verdict`
- `confidence` (calibrated percent when present)
- `signals` (array)
- `explanation` (object with `why_risky`, `top_words`, `method`, optional `explanation_degraded` / `degraded_reason`)

**Explainability default:** backend uses fast `linear-weights` attributions unless `PHISHSHIELD_TRY_SHAP_ON_SCAN=1` on the server. The extension surfaces `method` and fallback notes when degraded.

**Not used by extension:** `/feedback`, `/retrain`, `/api/metrics`, WebSocket feed (dashboard-only).

### Defensive parsing details

- Explanation is rendered using `explanation.why_risky` when available
- If missing, top words are converted to readable text
- Signals are normalized to strings before rendering
- This prevents `[object Object]` UI leakage

Backend status check:

```http
GET /health
```

## Permissions

- `storage`, `activeTab`, `tabs`, `contextMenus`, `scripting`, `webNavigation`, `alarms`
- `host_permissions`: `<all_urls>`

## Manual Test Checklist

- Load extension with no manifest errors
- Verify `[object Object]` fix on explanation rendering
- Verify page auto-scan banner behavior on risky/safe pages
- Verify link hover tooltip and suspicious click interception
- Verify Gmail inline badge/panel updates across emails
- Verify popup stats and toggles persistence
- Stop backend and verify graceful offline behavior
- Verify context menu selected text -> popup auto-scan
