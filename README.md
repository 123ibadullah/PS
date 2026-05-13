# PhishShield 🛡️
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

> Real-time phishing email detection with explainable scoring, multilingual checks, and a full-stack dashboard + browser extension workflow.

## Why I Built This
I kept seeing smart people around me still fall for phishing because the emails looked "normal enough."  
Most tools just say safe or unsafe, but they do not explain why in a way regular users can trust.  
I wanted to build something that catches real scam patterns we actually see here (OTP, KYC, UPI, fake bank urgency), and also shows the reasoning clearly.  
This project became my way of learning security engineering by building a product end to end, not just training a model in a notebook.

## What Does It Do?
Most of the time you paste email text straight into the app (from your inbox, a forward, or a screenshot dump) and hit scan.  
You are not clicking through a fake wizard: you bring the messy real message, and PhishShield walks it through checks in order.  
You get a risk score, a plain verdict, and short reasons you can skim in a few seconds.  
If it looks like a scam it names the vibe; if it looks fine it says so, so you are not stuck guessing.

## Features

> **Chrome Extension:** Includes a Chrome Extension for in-browser scanning — paste any email directly from Gmail or any webmail tab without leaving the page.

- Scans email text and returns a risk score with verdicts like Safe, Suspicious, or High Risk.
- Uses both rule-based detection and machine-learning scoring for better phishing coverage.
- Supports multilingual scam signals (including English, Hindi, Telugu, and mixed-script patterns).
- Has API endpoints for email scan, URL check, header analysis, user feedback, and explanation retrieval.
- Saves user feedback to improve future detections over time.
- Includes a React dashboard, TypeScript API layer, and FastAPI backend.
- Comes with Docker setup to run frontend and backend together with one command.

## Tech Stack
| Layer | Technology |
|-------|------------|
| Backend | Python, FastAPI, Uvicorn |
| ML Model | TF-IDF + Logistic Regression, SecureBERT/MuRIL (Transformers, Torch) |
| Frontend | React 19, Vite 7, TypeScript, Tailwind CSS |
| Database | SQLite (local dev DB), JSON/CSV flat file stores |
| DevOps | Docker, Docker Compose, Nginx |

## How It Works
1. A user submits an email to scan.
2. The backend cleans the text and checks phishing patterns (urgency, impersonation, credential lures, etc.).
3. ML scoring runs (SecureBERT/MuRIL when available, with TF-IDF fallback). The transformer path runs when the machine has enough RAM or a GPU; on smaller laptops TF-IDF is picked automatically so the same request still returns a score.
4. Rule signals + ML signals are fused into one final risk score.
5. The app returns a clear verdict, confidence context, and explanation so the user knows what to do next.

## Architecture

The backend (FastAPI) handles all phishing analysis — text cleaning, rule-based pattern checks, ML inference, score fusion, and feedback storage.
The frontend (React + TypeScript) talks to the backend over a REST API and shows scan results, risk scores, and explanations in a clean dashboard UI.
Docker Compose wires both services together. Nginx serves the frontend and proxies API traffic to the backend.

See `docs/PHISHSHIELD_COMPLETE_OVERVIEW.md` for a full deep-dive.

## Screenshots

All UI captures below are stored under `screenshots/`; each block lists the exact file path before the image.

### Dashboard — home / email paste

**Image:** `screenshots/dashboard-home-screen-scam-email-draft-01.png`  
![Dashboard home with scam-style email draft 1](screenshots/dashboard-home-screen-scam-email-draft-01.png)

**Image:** `screenshots/dashboard-home-screen-scam-email-draft-02.png`  
![Dashboard home with scam-style email draft 2](screenshots/dashboard-home-screen-scam-email-draft-02.png)

**Image:** `screenshots/dashboard-home-screen-safe-email-draft.png`  
![Dashboard home with safe / legitimate-style email draft](screenshots/dashboard-home-screen-safe-email-draft.png)

### Dashboard — scan results

**Image:** `screenshots/dashboard-scan-results-phishing-view-01.png`  
![Dashboard scan result — phishing-style outcome 1](screenshots/dashboard-scan-results-phishing-view-01.png)

**Image:** `screenshots/dashboard-scan-results-phishing-view-02.png`  
![Dashboard scan result — phishing-style outcome 2](screenshots/dashboard-scan-results-phishing-view-02.png)

**Image:** `screenshots/dashboard-scan-results-safe-verdict-view.png`  
![Dashboard scan result — safe verdict](screenshots/dashboard-scan-results-safe-verdict-view.png)

### Chrome extension

**Image:** `screenshots/chrome-extension-popup-phishshield-scan.png`  
![Chrome extension PhishShield scan popup](screenshots/chrome-extension-popup-phishshield-scan.png)

## Getting Started

### Quick Start

The full **frontend + backend** stack is meant to come up with **one command** via **Docker Compose** from the repo root — no separate terminal per service.

```bash
git clone https://github.com/123ibadullah/PhishShield.git
cd PhishShield
cp .env.example .env
docker compose up --build
```

`docker compose up --build` starts both services together (images build on first run or when Dockerfiles change). Use **Prerequisites**, **Installation**, and **Running the Project** below only if you prefer a local dev setup without Docker.

### Prerequisites
- Python `3.12+` (from `backend/Dockerfile`)
- Node.js `20+` (from `frontend/Dockerfile`)
- pnpm (workspace package manager)
- Docker + Docker Compose (for containerized run)

### Installation
```bash
# 1) Clone
git clone https://github.com/123ibadullah/PhishShield.git
cd PhishShield

# 2) Environment file
cp .env.example .env

# 3) Frontend workspace deps
cd frontend
pnpm install
cd ..

# 4) Backend Python deps
python -m pip install -r backend/requirements.txt
```

### Running the Project

**Docker Compose (recommended):** From the repo root, the same single command as in **Quick Start** runs the full stack — frontend and backend in one go:

```bash
# Option A: Docker — full frontend + backend with one command
docker compose up --build
```

```bash
# Option B: Local dev (two terminals)
# Terminal 1
cd backend
python -m uvicorn main:app --reload --port 8000

# Terminal 2
cd frontend
pnpm dev
```

Once running: frontend at http://localhost:5173 — API docs at http://localhost:8000/docs

## Project Structure
```text
.
├── backend/                 # FastAPI app, ML logic, training and evaluation scripts
│   ├── analyze_report.py     # Prints eval summary and sample misses/false positives from data/test_report.json
│   └── certify_dataset.py    # Audits, normalizes, and writes Phishing_Email.csv → Phishing_Email_cleaned.csv
├── frontend/                # React + TypeScript workspace and extension artifacts
├── data/                    # CSV/JSON datasets and evaluation artifacts
├── tests/                   # Centralized Python test files (test_*.py)
├── pytest.ini               # Repo-root pytest config (shared by tests/ above)
├── docs/                    # Architecture diagrams and technical docs
│   └── PHISHSHIELD_COMPLETE_OVERVIEW.md  # Detailed project deep-dive
├── screenshots/             # `dashboard-*.png`, `chrome-extension-*.png` (see Screenshots section)
├── docker-compose.yml       # Root compose for backend + frontend services
└── README.md                # Recruiter-facing project overview
```

`pytest.ini` stays at the repository root on purpose: pytest discovers it automatically and applies one shared configuration to the centralized `tests/` directory, so you do not need duplicate config files next to each test package.

## Dataset
This repo contains multiple phishing datasets and curated test corpora in `data/`.  
Key visible files include:
- `data/Phishing_Email.csv` (~18,133 rows)
- `data/Phishing_Email_cleaned.csv` (~1,401 rows)
- `data/elite_emails_1000.json` (~1,020 items)
- `data/phishtank_dataset.json` (~200 items)
- `data/dataset_100.json` (80 labeled evaluation items)

Source notes in the code/docs reference curated phishing corpora plus internally cleaned and synthetic balancing steps.  
The training metadata in `data/training_meta.json` reports `rows: 18684`.

## Results

### Offline held-out test split (TF-IDF active learning)

These numbers are the **offline benchmark** on the train/test split recorded when the model was last trained (same figures summarized in `docs/PHISHSHIELD_COMPLETE_OVERVIEW.md`).

| Metric | Value |
|--------|-------|
| Accuracy | 97.19% |
| Precision | 94.05% |
| Recall | 99.11% |
| F1 Score | 96.52% |
| Train Rows | 14,947 |
| Test Rows | 3,737 |

Source: `data/training_meta.json` (`metrics` + row counts).

### Real inbox–style check (live UI QA, May 2026)

Curated offline metrics can look stronger than what users see in a mixed real inbox. A **manual live UI run on 100 real emails** (documented in the same overview) estimated roughly **~80–85%** accuracy after hardening, with the caveat that live mail has more benign security/ops traffic and paraphrase variance than the offline split. That honest range is also stored under `live_qa` in `data/training_meta.json` for transparency.

## What I Learned
- During the live 100-email pass I watched real mail get flagged as phishing when it was just boring IT or bank security copy; that sting of a wrong red banner mattered more than squeezing another point on the offline split.
- Rule-based checks and ML together work better than either one alone for phishing edge cases.
- Data cleaning quality can change model behavior more than hyperparameter tweaks.
- End-to-end architecture (frontend + API + ML backend + deployment) is a different skill than writing isolated scripts.
- Explainability output is essential when users need to make safety decisions quickly.

## Future Improvements
- A live Gmail or Outlook hook is next on my list because paste-only flows still add friction for people who live inside their inbox all day, and that is where most risky threads actually land.
- I want broader Indian-language coverage and cleaner transliteration handling because mixed-script bait already shows up in the wild and the model still stumbles when the script hops mid-sentence.
- A small model and version log in the UI would help me compare runs without diffing JSON by hand; right now the honest numbers live in files and that is fine for me, not great for a teammate joining cold.
- Signed-in accounts with stored scan history belong in a serious deployment because feedback and repeat checks need a home that is not a shared CSV on disk.
- CI that runs backend pytest plus the frontend checks on every PR is overdue because I still catch regressions manually, and that does not scale once the surface area grows.

## Author
**MOHD IBADULLAH**  
[GitHub](https://github.com/123ibadullah?tab=repositories) · [PhishShield repo](https://github.com/123ibadullah/PhishShield) · *LinkedIn — (add your URL here)*

## License
MIT License

---
📄 For technical and Docker details → [TECHNICAL_GUIDE](docs/TECHNICAL_GUIDE.md)
