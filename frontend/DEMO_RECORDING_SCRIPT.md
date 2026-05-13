# PhishShield AI — Demo Recording Script

Use this for a clean **60–90 second** walkthrough of the current project.

---

## Goal

Show that `PhishShield AI` is:
- real
- explainable
- visually polished
- grounded in real phishing scenarios
- more useful than a black-box detector

---

## Before recording

### Start and prepare
- open the dashboard at `http://localhost:5173`
- keep the backend running at `http://localhost:8000`
- prepare **one strong phishing sample** and **one safe sample**
- optionally load `PhishShield Guardian` from `artifacts/chrome-extension/`

### Clean setup
- close unrelated tabs and apps
- keep the desktop uncluttered
- set a readable browser zoom level
- disable notifications if possible

---

## 60-second flow

### 0–10 sec — Intro
**Say:**
> This is PhishShield AI, a phishing defense project that explains why a message is dangerous instead of only labeling it.

### 10–25 sec — Show the dashboard
Open the main scan view and point to the scan area, result card, and model-health section.

**Say:**
> The dashboard combines risk scoring, explanation, and history so the user can understand the verdict immediately.

### 25–45 sec — Run a phishing sample
Paste an OTP, bank impersonation, or delivery-fee scam. Click **Analyze Email**.

**Say:**
> Here the system surfaces a high-risk phishing attempt and highlights the strongest signals behind the decision.

### 45–60 sec — Show trust and contrast
Point to the **risk score**, **attack category**, and **top reasons**, then switch to a safe message.

**Say:**
> The key value is that PhishShield explains the risk clearly while still avoiding obvious false positives on safe messages.

---

## Optional 90-second extension add-on

If you have time, open the extension popup or a Gmail/page warning example.

**Say:**
> The same protection flow also extends into the browser through PhishShield Guardian, which helps warn users before they interact with a risky page or message.

---

## Best sample types

### Strong phishing examples
- SBI OTP scam
- HDFC spoofing email
- fake tax refund lure
- FedEx delivery-fee scam

### Safe contrast examples
- Google security alert
- Amazon shipment update
- LinkedIn newsletter
- payment success receipt

---

## What to show on screen

### Always show
- email input area
- **Analyze Email** action
- final verdict
- risk score
- attack category
- top 3 reasons or signals

### Optional extras
- extension popup
- warning overlay
- scan history / metrics panel
- feedback button or correction flow

---

## Recording formula

**problem → product → live scan → explanation → close**

---

## Final closing line

> PhishShield turns phishing detection from a black-box alert into a clear, actionable security experience.

