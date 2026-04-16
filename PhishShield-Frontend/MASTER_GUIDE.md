# PhishShield AI — Master Guide

> Canonical overview of the current project, setup flow, verification evidence, and demo story.

---

## Current Project Status (Updated)

As of **April 10, 2026**, this repo contains a working phishing-defense project with:

- a **React dashboard** in `artifacts/phishshield/`
- a **TypeScript API + verification layer** in `artifacts/api-server/`
- a **FastAPI + ML backend** in the sibling `PhisShield-Backend/` folder
- a **Chrome extension** in `artifacts/chrome-extension/`

### Fresh verification evidence

| Check | Result |
|---|---|
| `pnpm build` | ✅ passes locally |
| OTP scam runtime check | ✅ `classification: phishing`, `riskScore: 79` |
| Safe mail runtime check | ✅ `classification: safe`, `riskScore: 0` |
| cache behavior | ✅ startup cache clear + `cache_version: 2` invalidation enabled |
| `artifacts/reports/qa/system-readiness-audit-latest.md` | `SYSTEM VERIFIED: 100% WORKING — NO CRITICAL ISSUES` |
| `artifacts/api-server/reports/verification/real-world-mass-benchmark-latest.md` | `2000` scenarios / `2300` executions / `100.00%` accuracy |
| `..\PhisShield-Backend\training_meta.json` | `97.19%` accuracy / `96.52%` F1 |

### Important run note

`pnpm validate:final` is a **live** validation runner. It only works when the dashboard on `:5173` and the Python backend on `:8000` are already reachable.

---

## What Is This?

**PhishShield AI** is an India-focused phishing detection system built to classify suspicious emails for real users in real time.

It combines:
- **deterministic phishing rules** for high-confidence scams,
- **TF-IDF + Logistic Regression** for fast lexical scoring,
- **IndicBERT** for multilingual semantic understanding,
- **URL and email-header analysis** for infrastructure-level threats,
- **explainability and active learning** for trust and long-term improvement.

The product is designed around the reality of the Indian threat landscape: scams impersonating **SBI, HDFC, ICICI, IRCTC, UPI apps, GST, Aadhaar, PAN, and Income Tax workflows**, often written in **English, Hindi, Telugu, and mixed script**.

> India reported **13.9 lakh+ cyber fraud cases in 2023**. A large portion of these attacks started with phishing or impersonation-driven messaging.

---

## The Problem

Indian phishing is different from generic Western spam:

- attackers impersonate **banks, payment apps, railways, telcos, and government services**
- lures revolve around **OTP sharing, UPI, KYC, Aadhaar/PAN verification, GST compliance, and refund scams**
- messages appear in **English, Hindi, Telugu, and mixed Hinglish**
- many scams use **short, urgent, low-context instructions** that generic mail filters miss

PhishShield AI was built to close that gap.

---

## Architecture Overview

PhishShield has **two backends and one frontend** that work together:

```text
User (Browser)
     │
     ▼
React Frontend (http://localhost:5173)
     │
     ├──► Node.js Express API (`artifacts/api-server`)
     │         ├── intentEngine.ts
     │         ├── confidenceEngine.ts
     │         ├── decisionEngine.ts
     │         ├── behaviorEngine.ts
     │         ├── domainEngine.ts
     │         ├── trustEngine.ts
     │         └── explanationEngine.ts
     │
     └──► Python FastAPI (`PhisShield-Backend`, http://localhost:8000)
               ├── IndicBERT primary model
               ├── TF-IDF + Logistic Regression fallback
               ├── VirusTotal URL checking
               ├── SPF / DKIM / DMARC header checks
               ├── SHAP / LIME style explanations
               └── Active learning feedback loop
```

### How the frontend uses both

The React dashboard calls the **Python backend directly on `localhost:8000`** for:
- `/scan-email`
- `/check-url`
- `/check-headers`
- `/health`
- `/feedback`
- `/feedback/stats`
- `/explain/{scan_id}`

It also talks to the **Node.js API** for generated analysis hooks, history, and metrics. The UI merges these results and uses the **higher risk score** as the final safety verdict. If the Python backend is offline, the frontend gracefully falls back to frontend/Node-only analysis.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 7, Tailwind CSS 4, Framer Motion |
| UI Components | Radix UI, Lucide icons, Recharts |
| Node.js API | Express 5, TypeScript, tsx |
| Validation / Types | Zod, OpenAPI 3.1, Orval codegen |
| Data / DB | SQLite / libSQL, Drizzle ORM |
| Python API | FastAPI, Uvicorn |
| Primary ML | IndicBERT (`ai4bharat/IndicBERTv2-MLM-only`) |
| Fallback ML | TF-IDF + Logistic Regression |
| Explainability | SHAP, LIME, heuristic fallback |
| Threat Intel | VirusTotal API v3 |
| Training | Python, scikit-learn, Transformers, Datasets, Torch |
| Monorepo | pnpm workspaces |

---

## How Detection Works

Every email is processed through a layered pipeline:

```text
Email input
    │
    ▼
Preprocessing + normalization
    │
    ├── Intent Engine
    │   (verify / update / confirm / pay / transfer / review)
    │
    ├── Behavior Engine
    │   (social engineering, BEC, urgency, finance patterns)
    │
    ├── Indian Rule Patterns
    │   (OTP, UPI, KYC, Aadhaar, PAN, GST, refund, lottery)
    │
    ├── TF-IDF + Logistic Regression
    │   (fast lexical risk scoring)
    │
    ├── IndicBERT
    │   (semantic multilingual understanding)
    │
    ├── URL Analysis
    │   (lookalike domains, suspicious TLDs, VirusTotal)
    │
    ├── Header Analysis
    │   (SPF, DKIM, DMARC, Reply-To mismatch)
    │
    ├── Explainability Layer
    │   (top risky words + confidence interval)
    │
    └── Confidence / Decision Engine
        (weighted fusion + hard overrides)
              │
              ▼
Final Risk Score (0–100)
+ Verdict + Category + Explanation + Recommendation
```

### Score Thresholds

| Score | Verdict | Meaning |
|---|---|---|
| `0 – 25` | `Safe` | No significant threat signals |
| `26 – 60` | `Suspicious` | Caution advised |
| `61 – 100` | `High Risk` | Do not interact |

### Hard Override Rules

Some patterns should **never** be downgraded to safe:
- OTP / PIN / password requests
- urgency + action + account/payment context
- wire transfer + confidentiality + executive impersonation
- suspicious lookalike domains for banks/government services
- explicit code/SQL strings without phishing context are forced to **score = 5** to avoid false positives

---

## ML Models Explained

### Primary Model: IndicBERT

The Python backend prefers the local `indicbert_model/` bundle when these files exist:
- `model.safetensors`
- `config.json`
- `tokenizer.json`
- `tokenizer_config.json`

The `/health` endpoint currently reports:
- **`model_used: IndicBERT-GPU-97.4%`**
- **Accuracy: `97.4%`**
- **F1 Score: `96.8%`**

### Fallback Model: TF-IDF + Logistic Regression

If IndicBERT is unavailable, the backend falls back to:
- `model.pkl`
- `vectorizer.pkl`

Training scripts in the backend:
- `train_model.py` → classical ML training
- `train_indicbert.py` → transformer fine-tuning and checkpoint export

Current `training_meta.json` shows:
- dataset rows: **18,684**
- train rows: **14,947**
- test rows: **3,737**
- TF-IDF active-learning accuracy: **~97.19%**

### Why both models?

| Capability | TF-IDF + LR | IndicBERT |
|---|---|---|
| Speed | Very fast | Slower on CPU |
| Explainability | Easy | Requires SHAP/LIME-style explanation |
| Multilingual semantics | Limited | Stronger |
| Determinism | High | Moderate |
| Paraphrase handling | Limited | Better |

The hybrid design gives PhishShield both **speed** and **semantic coverage**.

---

## Detection Logic

### India-specific signals currently implemented

- **OTP / PIN / password request**
- **urgency language** in English, Hindi, and Telugu
- **Indian brand impersonation**
- **UPI / wallet / payment handle detection**
- **GSTIN / PAN / Aadhaar** patterns
- **Business Email Compromise (BEC)**
- **delivery fee scams** (FedEx, DHL, India Post, etc.)
- **lottery / prize scams** (KBC, lucky draw, WhatsApp numbers)
- **government impersonation** (Income Tax / refund / PAN)
- **SMS banking spoofing**
- **newsletter false-positive suppression** for trusted digest domains

### Primary attack categories

The current backend supports categories such as:
1. `OTP Scam`
2. `Business Email Compromise`
3. `Delivery Fee Scam`
4. `Government Impersonation`
5. `GST Compliance Scam`
6. `Lottery / Prize Scam`
7. `SMS Spoofing Attack`
8. `Newsletter / Digest`
9. `Credential Harvesting`
10. `Social Engineering`

### Language detection

The backend uses Unicode-range detection and returns:
- `EN` → English
- `HI` → Hindi
- `TE` → Telugu
- `MX` → Mixed script

The frontend maps these codes to full labels in the dashboard.

---

## Explainability (SHAP / LIME / Heuristic)

Every `/scan-email` response includes an `explanation` object shaped like this:

```json
{
  "explanation": {
    "top_words": [
      { "word": "OTP", "contribution": 0.22 },
      { "word": "urgent", "contribution": 0.18 }
    ],
    "why_risky": "Top words driving this verdict",
    "confidence_interval": "100% ± 8%",
    "method": "shap"
  }
}
```

PhishShield stores scan explanations in memory and exposes them via:

```http
GET /explain/{scan_id}
```

This is critical for trust: users do not just get a score; they see **why** the email looks dangerous.

---

## Active Learning

PhishShield includes a lightweight human-feedback loop:

1. user scans an email
2. user clicks **Mark as Safe** or **Mark as Phishing**
3. feedback is saved into `feedback.csv`
4. after **50 pending feedback rows**, the TF-IDF model can auto-retrain
5. `/feedback/stats` reports progress and last retrain status

This makes the system **self-improving over time** while preserving a simple local workflow.

---

## Project Journey

PhishShield did not become reliable in one step. It evolved through repeated QA hardening and bug fixing:

1. started with rule-based checks plus TF-IDF scoring
2. exposed false positives on safe newsletters and billing-style emails
3. tightened Indian-brand detection to real India-specific services only
4. fixed **BEC under-detection** by adding wire transfer, secrecy, executive, and mobile-signature cues
5. fixed **SQL/code false positives** by forcing technical strings into a low-risk safe band
6. fixed **delivery-fee scam misses** for FedEx / DHL / customs-fee payment lures
7. strengthened **SMS banking spoofing** detection for HDFC-style debit alert scams
8. improved **KBC / prize / WhatsApp** lottery scam recognition
9. upgraded from basic TF-IDF-only logic to a **hybrid IndicBERT + TF-IDF** pipeline
10. added explainability via `explain.py`, top-word contributions, and `/explain/{scan_id}`
11. added active learning through `feedback.csv`, `/feedback`, and `/feedback/stats`
12. fixed the dashboard’s overlapping highlight bug so users no longer see doubled text like `OTPOTP` or `SBISBI`
13. added backend connectivity status, fallback mode, model version display, and persistent scan history
14. completed repeated live verification against OTP, BEC, government, GST, KBC, newsletter, and multilingual phishing samples
15. created a **50-email self-testing readiness audit** via `pnpm --filter @workspace/scripts run qa:system`
16. added a **Playwright UI regression suite** via `pnpm --filter @workspace/scripts run qa:ui`
17. polished the result page and dashboard to remove duplicated wording, fix singular/plural copy, and improve session summaries
18. published the full parent-folder project snapshot to GitHub, with the large backend model tracked through **Git LFS** so the repository is cloneable and usable

This history matters because the current system reflects **real bug fixes driven by real failure cases**, not just idealized design.

---

## Model Training Metrics

### Current reported metrics in the running backend

The live `/health` endpoint currently reports:

| Metric | Value |
|---|---:|
| `model_used` | `IndicBERT-GPU-97.4%` |
| Accuracy | `97.4%` |
| F1 Score | `96.8%` |
| Device | `cpu` |

### Metadata from `training_meta.json`

| Metric | Value |
|---|---:|
| Dataset rows | `18,684` |
| Train rows | `14,947` |
| Test rows | `3,737` |
| TF-IDF active-learning accuracy | `0.9719` |
| TF-IDF precision | `0.9405` |
| TF-IDF recall | `0.9911` |
| TF-IDF F1 | `0.9652` |
| Pretrained model | `ai4bharat/IndicBERTv2-MLM-only` |

### Training scripts

- `train_model.py` → classical TF-IDF + Logistic Regression training
- `train_indicbert.py` → IndicBERT fine-tuning, evaluation, and model export into `indicbert_model/`

---

## Deployment Guide

### Frontend deployment (Vercel)

1. push `PhishShield/` to GitHub
2. import the repo into **Vercel**
3. set the project root to `PhishShield/`
4. build command:

```bash
pnpm run build
```

5. output directory:

```text
artifacts/phishshield/dist/public
```

6. add any public frontend environment variables if needed
7. deploy and verify the app loads and can reach the backend host URL

### Backend deployment (Render)

1. create a new **Render Web Service** from the repo
2. set the root directory to:

```text
PhisShield-Backend
```

3. install command:

```bash
py -3.12 -m pip install -r requirements.txt
```

4. start command:

```bash
py -3.12 -m uvicorn main:app --host 0.0.0.0 --port 10000
```

5. add environment variables:

```env
VT_KEY=your_virustotal_api_key
HF_TOKEN=your_huggingface_token
```

6. verify deployed endpoints:
- `GET /health`
- `POST /scan-email`
- `POST /check-url`
- `POST /check-headers`

### Production notes

- keep `model.pkl`, `vectorizer.pkl`, and the `indicbert_model/` root files in the deployment artifact
- do **not** commit `.env`, `feedback.csv`, or raw datasets publicly
- for higher throughput, move IndicBERT inference to a GPU-backed service or managed inference endpoint

---

## Known Limitations

PhishShield is strong, but it still has honest limitations:

1. **CPU inference is slower than GPU inference** for IndicBERT-heavy workloads.
2. **VirusTotal results depend on API availability and quota**; when unavailable, `/check-url` falls back to a safe zero-risk response instead of crashing.
3. **Language detection is script-based**, so mixed Romanized Hindi/Telugu (“Hinglish” or transliterated Telugu) is not as strong as native-script detection.
4. **Active learning currently retrains only the TF-IDF pipeline**, not the IndicBERT model automatically.
5. **Some borderline corporate or promotional emails can still require manual review**, especially when they blend urgency with legitimate transactional wording.
6. **Frontend offline fallback preserves usability but may reduce detection depth** if the Python backend is unavailable.
7. **The current deployment flow is dev-friendly, not enterprise-hardened**; a full production rollout would still need auth, monitoring, rate limiting, secret rotation, and structured audit logs.

These limitations are normal for a real applied security product and provide a clear roadmap for future improvement.

---

## Live Demo Walkthrough (2 Minutes)

If an interviewer says **"show me the product"**, use this exact flow:

### Demo script

1. open the dashboard at `http://localhost:5173`
2. point to the backend badge showing:
   - `Backend: Connected`
   - model info from `/health`
   - live accuracy / F1 values
3. paste a **safe email** first to show the system is not over-blocking
4. paste an **OTP or bank phishing email** to show a hard jump to `High Risk`
5. open the explanation panel and show the risky words / signals
6. click **Mark as Safe** or **Mark as Phishing** to show active learning
7. optionally test a suspicious URL with `/check-url`

### Best screens to capture for screenshots

If you want to embed screenshots before a final GitHub push, capture these four views:

- **Dashboard overview** with the risk gauge and backend health badge
- **High-risk phishing result** showing category, score, and highlighted phrases
- **Explanation panel** showing top words / feature contributions
- **Feedback / active-learning area** showing model improvement workflow

> Even without embedded PNGs, this section gives you a repeatable live-demo plan instead of saying “please imagine the UI.”

---

## Accuracy Proof and Validation Evidence

### 1) Fresh local verification

A fresh local build from `PhishShield-Frontend` completed successfully on **April 7, 2026**:

| Command | Result |
|---|---|
| `pnpm build` | success |

### 2) Stored repo evidence

The repository already contains the following project artifacts:

| Source | Evidence |
|---|---|
| `artifacts/reports/qa/system-readiness-audit-latest.md` | `SYSTEM VERIFIED: 100% WORKING — NO CRITICAL ISSUES` |
| `artifacts/api-server/reports/verification/real-world-mass-benchmark-latest.md` | `2000` scenarios / `2300` executions / `100.00%` accuracy |
| `..\PhisShield-Backend\training_meta.json` | Accuracy `97.19%`, Precision `94.05%`, Recall `99.11%`, F1 `96.52%` |

### 3) Live validation note

`pnpm validate:final` is a live integration check. If `http://127.0.0.1:5173` or `http://127.0.0.1:8000/health` is not reachable, the script exits early by design.

### How to say this honestly in an interview

> “The repo includes stored audit and benchmark evidence, and the live validation scripts can be rerun locally once the frontend and Python backend are running.”

---

## Competitive Positioning

### How PhishShield compares to Gmail / Outlook filtering

PhishShield is **not a claim that Google or Microsoft are weak overall**. It is a **specialized India-focused phishing analysis layer** with features that default mailbox filters do not expose directly to end users.

| Dimension | Generic Mail Filters | PhishShield AI |
|---|---|---|
| India-specific scam focus | Broad / global | Tuned for OTP, UPI, GST, PAN, Aadhaar, delivery-fee, KBC scams |
| Transparency | Usually opaque | Full score, category, signals, and explanation object |
| Multilingual local tuning | Limited user visibility | Explicit English / Hindi / Telugu / mixed-script handling |
| Security analyst feedback loop | Vendor-controlled | Local `feedback.csv` + retrain workflow |
| Demo / research extensibility | Closed platform | Fully inspectable code and rules |
| URL / header drill-down | Not user-facing | Separate `/check-url` and `/check-headers` endpoints |

### Best interview answer

> “I would not say this replaces Gmail or Microsoft Defender. I would say it adds explainable, India-specific phishing detection and developer-controlled security logic that is useful for research, demos, and specialized enterprise workflows.”

---

## Real-World Usage Status (Honest Version)

### Current adoption status

PhishShield is currently a **working engineering prototype / portfolio-grade security product**, not a mass public SaaS with thousands of production users.

That means:
- ✅ the app is real and runnable
- ✅ the models are real and validated
- ✅ the APIs, explainability, and feedback loop are working
- ✅ the threat categories were hardened against realistic samples
- ❌ there is **no claim of large-scale real-user deployment yet**

### Safe way to answer “How many real users used it?”

> “I built and validated it as a deployable security product and research prototype. It is demo-ready, technically deployable, and tested against realistic phishing cases, but it has not yet been rolled out to a large external user base.”

That answer is strong because it is **honest, technically mature, and credible**.

---

## Features List

### Detection
- ✅ Hybrid rules + ML + transformer design
- ✅ IndicBERT primary model with TF-IDF fallback
- ✅ VirusTotal URL reputation lookup
- ✅ SPF / DKIM / DMARC header analysis
- ✅ BEC / executive fraud detection
- ✅ delivery-fee scam detection
- ✅ lottery / prize scam detection
- ✅ SMS spoofing detection
- ✅ government and GST impersonation detection
- ✅ newsletter / digest false-positive prevention
- ✅ SQL/code-string suppression to avoid technical false positives

### Languages
- ✅ English support
- ✅ Hindi support
- ✅ Telugu support
- ✅ mixed-script handling

### Frontend / UX
- ✅ live risk gauge
- ✅ highlighted risky words
- ✅ explanation bars and feature contributions
- ✅ backend online/offline badge
- ✅ model version display from `/health`
- ✅ scan history persistence in `localStorage` (`phishshield_history`)
- ✅ loading state protection and anti-result-switch logic
- ✅ feedback buttons for active learning

### Privacy / robustness
- ✅ offline fallback mode when Python backend is down
- ✅ local scan history support
- ✅ no external storage for pasted email content beyond local feedback file when user explicitly submits feedback

---

## How to Run

### Prerequisites
- **Node.js 20+**
- **Python 3.12+**
- **pnpm** (`npm install -g pnpm`)
- both workspace folders available: `PhishShield-Frontend/` and `PhisShield-Backend/`

### Local workspace layout

```text
workspace/
├── PhishShield-Frontend/   # frontend, API layer, scripts, docs
└── PhisShield-Backend/     # FastAPI service and local ML assets
```

### Option 1 — Quick demo boot (Windows)

```bat
Double-click: PhishShield-Frontend\run.bat
```

This is the easiest local demo path and starts the app using the current Windows workflow.

### Option 2 — Manual

#### Frontend + Node.js API

```bash
cd PhishShield
pnpm install
pnpm run dev
# Frontend at http://localhost:5173
```

#### Python FastAPI backend

```bash
cd ../PhisShield-Backend
py -3.12 -m pip install -r requirements.txt
py -3.12 -m uvicorn main:app --reload --port 8000
# Backend at http://localhost:8000
```

### Recommended verification after setup

```bash
cd PhishShield
pnpm validate:final
pnpm --filter @workspace/scripts run qa:system
pnpm --filter @workspace/scripts run qa:ui
```

### Environment variables

Create `.env` inside `PhisShield-Backend/`:

```env
VT_KEY=your_virustotal_api_key
HF_TOKEN=your_huggingface_token
```

---

## API Reference

### Python FastAPI (`localhost:8000`)

#### `GET /`

```json
{
  "status": "PhishShield backend running",
  "version": "1.0"
}
```

#### `GET /health`

```json
{
  "status": "healthy",
  "model_used": "IndicBERT-GPU-97.4%",
  "accuracy": "97.4%",
  "f1_score": "96.8%",
  "device": "cpu"
}
```

#### `POST /scan-email`

```json
{
  "email_text": "Dear Customer your SBI account suspended. Share OTP immediately at http://sbi-verify.net"
}
```

Response:

```json
{
  "scan_id": "abc123def456",
  "risk_score": 100,
  "verdict": "High Risk",
  "confidence": 100,
  "category": "OTP Scam",
  "detectedLanguage": "EN",
  "signals": ["OTP request detected", "Urgency language"],
  "ml_probability": 0.97,
  "model_used": "IndicBERT-GPU-97.4%",
  "recommendation": "Block and quarantine",
  "explanation": {
    "top_words": [
      { "word": "OTP", "contribution": 0.22 }
    ],
    "why_risky": "Top words driving this verdict",
    "confidence_interval": "100% ± 8%"
  }
}
```

#### `POST /check-url`

```json
{
  "url": "http://sbi-verify.net"
}
```

#### `POST /check-headers`

```json
{
  "headers": "Authentication-Results: spf=fail dkim=fail dmarc=fail"
}
```

#### `POST /feedback`

```json
{
  "email_text": "...",
  "correct_label": "phishing",
  "scan_id": "abc123"
}
```

#### `GET /feedback/stats`

Returns the total feedback count, pending retrain count, remaining examples needed, and improvement status.

#### `GET /explain/{scan_id}`

Returns the stored explanation payload for a prior scan.

### Node.js Express API

Primary routes exposed through the workspace API layer:
- `POST /api/analyze`
- `GET /api/history`
- `DELETE /api/history`
- `GET /api/metrics`
- `GET /api/healthz`

---

## Verified Test Results (Current)

The latest project state is backed by multiple validation layers, not just a small sample set.

| Verification Layer | Scope | Result |
|---|---|---|
| Fresh local build | workspace typecheck + production build | **success** |
| System readiness audit | **50-email** end-to-end audit | **`100% WORKING — NO CRITICAL ISSUES`** |
| Playwright UI suite | trusted-safe flow, spoofing flow, dashboard counters | **`3 passed`** |
| Final validation suite | live backend + fallback + consistency checks | **run when `:5173` and `:8000` are up** |

### Examples covered by the current checks

- OTP scams
- header spoofing
- BEC / vendor transfer fraud
- delivery-fee scams
- government impersonation
- invoice lures
- multilingual phishing (Hindi / Telugu / Hinglish)
- trusted safe emails and newsletters
- dashboard counter consistency
- result-page explanation clarity

**Bottom line:** the current build is verified well beyond the earlier 12-case smoke pass.

---

## Interview Q&A (20 questions)

### 1. Why a hybrid system instead of one model?
Because phishing is a safety problem, not just a classification problem. Rules, classical ML, and transformers cover different failure modes.

### 2. Why keep TF-IDF in 2026?
It is fast, transparent, and extremely effective for repetitive scam language. It is also cheap to retrain.

### 3. Why add IndicBERT?
To handle semantic and multilingual content better than plain lexical models.

### 4. Why is explainability important here?
Users and reviewers need to understand **why** an email was flagged, not just see a score.

### 5. What does SHAP/LIME add?
It surfaces top contributing words and phrases behind each verdict.

### 6. How do you reduce false positives?
With newsletter whitelisting, safe context patterns, technical-string suppression, and trust checks.

### 7. How do you prevent false negatives?
Hard override rules ensure OTP, payment pressure, and BEC patterns cannot slip into safe.

### 8. How do you handle Hindi and Telugu?
Using Unicode-range detection plus multilingual rules and IndicBERT semantic support.

### 9. How do you detect BEC with no link?
By looking for wire transfer language, secrecy, executive cues, and payment-account instructions.

### 10. How do you handle SMS-style phishing?
Dedicated banking-alert patterns escalate SMS spoofing into a high-risk bucket.

### 11. Why check URLs separately?
The domain often reveals the scam even when the email text is clean.

### 12. Why check headers separately?
Spoofed sender identity and Reply-To mismatch are strong phishing indicators.

### 13. What happens when the Python backend is offline?
The frontend falls back to the local/Node analysis path and shows an offline warning badge.

### 14. Why is active learning useful?
It lets the model improve based on real user corrections over time.

### 15. What retrains automatically today?
The TF-IDF pipeline retrains after a feedback threshold is reached.

### 16. Why not rely only on a generic LLM?
LLMs are slower, costlier, and less deterministic than a local hybrid safety pipeline.

### 17. What makes PhishShield India-specific?
It targets UPI, KYC, Aadhaar, PAN, GST, OTP, bank impersonation, and regional-language scams.

### 18. How is the frontend made stable?
It uses locked scan tokens, cached results, local history persistence, and deduped highlight spans.

### 19. What was one hard bug fixed recently?
A word-doubling/highlight-overlap issue in the dashboard (`OTPOTP`, `SBISBI`) was fixed by span normalization and deduplication.

### 20. What would you improve next?
GPU-backed inference, larger multilingual datasets, external threat feeds, and production deployment hardening.

---

## Folder Structure

```text
New folder (2)/
├── PhishShield/                      # frontend monorepo + Node API + docs
│   ├── artifacts/
│   │   ├── api-server/
│   │   │   └── src/
│   │   │       ├── engines/
│   │   │       ├── lib/
│   │   │       ├── routes/
│   │   │       └── verification/
│   │   └── phishshield/
│   │       └── src/
│   │           ├── pages/
│   │           └── components/
│   ├── lib/
│   ├── README.md
│   ├── PROJECT_GUIDE.md
│   ├── PROJECT_OVERVIEW.md
│   ├── MASTER_GUIDE.md
│   └── run.bat
└── PhisShield-Backend/              # Python FastAPI + models
    ├── main.py
    ├── explain.py
    ├── train_model.py
    ├── train_indicbert.py
    ├── model.pkl
    ├── vectorizer.pkl
    ├── indicbert_model/
    │   ├── model.safetensors
    │   ├── config.json
    │   ├── tokenizer.json
    │   └── tokenizer_config.json
    ├── feedback.csv
    ├── requirements.txt
    └── .env
```

---

## What Makes This Project Unique

1. **India-first design** instead of generic Western spam logic
2. **Multilingual support** for English, Hindi, Telugu, and mixed script
3. **Explainable output** with risky words and reasoning
4. **Self-improving feedback loop** through active learning
5. **Hybrid safety architecture** that balances determinism and semantic understanding

---

*Built for Indian internet users.*

**PhishShield AI — Detect. Explain. Protect.**
