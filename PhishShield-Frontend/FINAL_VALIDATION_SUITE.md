# PhishShield AI — Final Validation Suite

This document describes how to validate the current project in a way that matches the repo as it exists today.

---

## 1) What this suite covers

- backend email phishing detection
- safe-mail false positive control
- multilingual scam handling
- link, domain, and header-risk checks
- fallback / UI path behavior
- consistency across repeated scans

---

## 2) Required local services

| Service | Expected URL | Why it matters |
|---|---|---|
| React frontend | `http://127.0.0.1:5173` | demo UI and fallback route checks |
| Python backend | `http://127.0.0.1:8000/health` | live phishing analysis and health validation |

> If `/health` is unreachable, the automated runner exits early by design.

---

## 3) Start-up commands

### Frontend workspace

```bash
cd PhishShield-Frontend
pnpm install
pnpm dev
```

### Python backend

```bash
cd ..\PhisShield-Backend
py -3.12 -m pip install -r requirements.txt
py -3.12 -m uvicorn main:app --reload --port 8000
```

---

## 4) Automated validation commands

Run these from `PhishShield-Frontend`:

```bash
pnpm build
pnpm --filter @workspace/api-server run verify:full
pnpm --filter @workspace/scripts run qa:system
pnpm --filter @workspace/scripts run qa:ui
pnpm validate:final
```

---

## 5) Core pass criteria

A strong validation run should confirm that:

- critical phishing emails are **not** marked safe
- clearly safe emails are **not** escalated to high risk
- explanation data is present in results
- multilingual scam samples are detected consistently
- risky domains and spoofing patterns are surfaced clearly
- repeated scans stay stable enough for demo and portfolio use

---

## 6) Recommended manual spot checks

| Group | Example | Expected |
|---|---|---|
| OTP override regression | `Your account is suspended. Send your OTP immediately to restore access.` | `phishing` |
| Safe control regression | `Project Update for this week` | `safe` |
| Safe | Google alert, Amazon order update, LinkedIn newsletter | `safe` |
| Banking phishing | SBI OTP scam, HDFC spoof | `phishing` |
| Government impersonation | tax refund / PAN lure | `phishing` |
| Delivery fraud | FedEx / customs fee mail | `phishing` |
| BEC | confidential transfer request | `phishing` |
| Multilingual | Hindi / Telugu / Hinglish OTP mail | `phishing` |

Cache note: current backend behavior includes startup scan-cache clear and cache-entry version invalidation (`cache_version: 2`) to prevent stale verdict reuse.

---

## 7) Evidence files already in the repo

- `artifacts/reports/qa/system-readiness-audit-latest.md`
- `artifacts/api-server/reports/verification/real-world-mass-benchmark-latest.md`
- `artifacts/api-server/reports/verification/verification-report-latest.json`

---

## 8) Troubleshooting

- If `pnpm validate:final` fails with `No reachable service found for /health`, start the Python backend first.
- If the UI tests fail, confirm the dashboard is reachable on `:5173`.
- If the extension demo is part of your walkthrough, reload `artifacts/chrome-extension/` in Chrome.

---

## Final statement

> A good PhishShield validation run proves both detection quality and user-facing explainability.

