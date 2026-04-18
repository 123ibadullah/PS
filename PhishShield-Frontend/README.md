# PhishShield AI

**Explainable phishing defense for real-world Indian scam patterns, multilingual email abuse, and risky web destinations.**

PhishShield is a full-stack cybersecurity project that combines a React dashboard, a TypeScript service layer, a FastAPI + ML backend, and a Chrome extension to help users spot phishing **before** they click, reply, or share credentials.

---

## What is included

| Surface | Path | Role |
|---|---|---|
| Web dashboard | `artifacts/phishshield/` | Scan emails, view verdicts, history, and model-health signals |
| API server | `artifacts/api-server/` | Shared analysis, history/metrics routes, and verification tooling |
| Python ML backend | `..\PhisShield-Backend\` | FastAPI phishing analysis, TF-IDF fallback, and IndicBERT support |
| Browser extension | `artifacts/chrome-extension/` | `PhishShield Guardian` warnings for suspicious sites and Gmail content |

---

## Core capabilities

- **Explainable verdicts** with risk score, category, signals, and human-readable reasons
- **India-focused scam coverage** for OTP, UPI, KYC, Aadhaar, PAN, GST, refund, delivery-fee, and bank impersonation fraud
- **Advanced Threat Analysis** for **Thread Hijacking**, **Malicious Attachments** (PDF/HTML/DOCX), and **QR Code Evasion**
- **Multilingual detection** for English, Hindi, Telugu, and mixed-script phishing content
- **Browser-side protection** through the Chrome extension warning UI
- **Feedback loop** for continuous improvement and retraining support
- **Validation artifacts** for QA, benchmark runs, and final demo checks

---

## Current project snapshot

### Verified now
- ✅ `pnpm build` passes locally from `PhishShield-Frontend` (**verified on April 18, 2026**)
- ✅ Live backend check on `http://127.0.0.1:8000/api/analyze`:
  - OTP scam sample (`Your account is suspended. Send your OTP immediately to restore access.`) returns `classification: phishing` with `riskScore: 79`
  - safe sample (`Project Update for this week`) returns `classification: safe` with `riskScore: 0`
- ✅ In-memory scan cache uses startup clear + cache version invalidation (`cache_version: 2`) to avoid stale verdict reuse

### Stored project evidence
- 📄 `artifacts/reports/qa/system-readiness-audit-latest.md` reports **`SYSTEM VERIFIED: 100% WORKING — NO CRITICAL ISSUES`**
- 📄 `artifacts/api-server/reports/verification/real-world-mass-benchmark-latest.md` reports **`2000` scenarios / `2300` executions / `100.00%` accuracy**
- 📊 `..\PhisShield-Backend\training_meta.json` reports:
  - Accuracy: `97.19%`
  - Precision: `94.05%`
  - Recall: `99.11%`
  - F1 Score: `96.52%`
  - Dataset rows: `18,684`

> `pnpm validate:final` is a **live** suite. It requires the frontend on `http://127.0.0.1:5173` and the Python backend on `http://127.0.0.1:8000` to be reachable first.

---

## Quick start

### 1) Install workspace dependencies
From `PhishShield-Frontend`:

```bash
pnpm install
```

### 2) Start the web workspace
This starts the React app and the TypeScript workspace processes:

```bash
pnpm dev
```

### 3) Start the Python backend
From the sibling backend folder `PhisShield-Backend`:

```bash
py -3.12 -m pip install -r requirements.txt
py -3.12 -m uvicorn main:app --reload --port 8000
```

### 4) Open the app
- Dashboard: `http://localhost:5173`
- Python backend health: `http://localhost:8000/health`

### 5) Optional demo helper
For a quick local demo boot from the frontend repo root:

```bat
run.bat
```

---

## Load the Chrome extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `artifacts/chrome-extension/`

This loads **`PhishShield Guardian`**, the browser layer that surfaces warnings on suspicious destinations and Gmail content.

---

## Validation commands

Run these from `PhishShield-Frontend`:

```bash
pnpm build
pnpm --filter @workspace/api-server run verify:full
pnpm --filter @workspace/scripts run qa:system
pnpm --filter @workspace/scripts run qa:ui
pnpm validate:final
```

### Validation note
If `pnpm validate:final` stops with a `/health` error, start the frontend and Python backend first, then rerun the command.

---

## Repo layout

```text
PhishShield-Frontend/
├─ artifacts/phishshield/           # React/Vite dashboard
├─ artifacts/api-server/            # Express + TypeScript API + verification
├─ artifacts/chrome-extension/      # PhishShield Guardian extension
├─ artifacts/reports/qa/            # QA and readiness reports
├─ scripts/                         # Final validation and Playwright tests
├─ README.md
└─ MASTER_GUIDE.md

PhisShield-Backend/
├─ main.py                          # FastAPI service
├─ explain.py                       # Explainability helpers
├─ train_model.py                   # TF-IDF model training
├─ train_indicbert.py               # IndicBERT training/export
├─ feedback.csv                     # Collected feedback samples
└─ indicbert_model/                 # Local model files
```

---

## Best files to read next

1. `MASTER_GUIDE.md`
2. `FINAL_VALIDATION_SUITE.md`
3. `DEMO_RECORDING_SCRIPT.md`
4. `SHOWCASE_PITCH.md`

---

## One-line summary

> **PhishShield AI helps users understand phishing risk, not just detect it, through explainable AI, multilingual analysis, and browser-side protection.**

