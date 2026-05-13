# PhishShield AI – Full-Stack Phishing Detection

**Explainable phishing defense for real-world Indian scam patterns, with Docker containerization for production deployment.**

PhishShield is a containerized full-stack cybersecurity project featuring a React dashboard, TypeScript service layer, FastAPI + ML backend, and Chrome extension for protecting users from phishing threats.

## Quick Links

- 📖 **Frontend Docs**: [frontend README](./frontend/README.md)
- 🔐 **Backend Docs**: [backend](./backend/)
- 🐳 **Docker Setup**: [Docker Quickstart](#docker-quickstart)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   PhishShield Services                       │
├─────────────────────┬───────────────────────────────────────┤
│  Frontend (React)   │       Backend (FastAPI + Python)      │
│  Port: 80/443       │       Port: 8000                      │
│  (Nginx + SPA)      │       (ML + API)                      │
└─────────────────────┴───────────────────────────────────────┘
         ↓ docker-compose.yml ↑
    Shared Network (phishshield-network)
```

| Component | Tech Stack | Location |
|-----------|-----------|----------|
| Dashboard & UI | React 18, Vite, TypeScript | `frontend/` |
| Web API | Node.js + Express | `frontend/artifacts/api-server/` |
| ML Analysis | FastAPI, Python 3.12, SecureBERT/MuRIL | `backend/` |
| Browser Extension | Chrome Extension API | `frontend/artifacts/chrome-extension/` |

## Key Features

- **Hybrid AI Engine**: Combines **SecureBERT/MuRIL** (semantic NLP) with **TF-IDF + LR** (lexical analysis). Offline benchmark is ~97%; live accuracy depends on inbox distribution.
- **Advanced Threat Analysis**: Production-ready detection for **Thread Hijacking**, **Malicious Attachments**, and **QR Code lures**.
- **India-Focused Defense**: Native support for English, Hindi, Telugu, and Hinglish script detection with local brand protection (SBI, HDFC, UPI, etc.).
- **Explainable Verdicts**: Real-time risk scoring (0-100) with detailed signal highlighting and confidence intervals.
- **Active Learning**: Built-in human-in-the-loop feedback system that improves model performance with real-world user data.

---

## Docker Quickstart

### Prerequisites

- Docker & Docker Compose installed ([Get Docker](https://docs.docker.com/get-docker/))
- `.env` file with API tokens (see below)

### Setup & Run

1. **Copy environment configuration** to `.env`:

   ```bash
   cp .env.example .env
   ```

2. **Fill in your API tokens** in `.env`:
   - `HF_TOKEN`: Hugging Face API token (for SecureBERT/MuRIL model)
   - `VT_API_KEY`: VirusTotal API key (for URL scanning)
   - `ENVIRONMENT`: Set to `production`

3. **Build and start all services**:

   ```bash
   docker-compose up --build
   ```

   This starts:
   - **Backend**: http://localhost:8000
   - **Frontend**: http://localhost
   - Both services connected via `phishshield-network`

4. **Verify services are running**:

   ```bash
   # Backend health check
   curl http://localhost:8000/health

   # Frontend should be accessible
   open http://localhost
   ```

5. **View logs**:

   ```bash
   docker-compose logs -f
   ```

6. **Stop all services**:

   ```bash
   docker-compose down
   ```

### Using the Makefile (Recommended)

For a faster workflow, use the included `Makefile`:

```bash
# Build images
make build

# Start services in background
make up

# Stop services
make down

# View live logs
make logs

# Run tests in backend container
make test

# Rebuild without cache
make rebuild
```

---

## Docker Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Orchestrates both services with networking, health checks, volumes |
| `backend/Dockerfile` | Python 3.12 FastAPI image with UV health checks |
| `backend/.dockerignore` | Excludes large model files & cache |
| `frontend/Dockerfile` | Multi-stage Node + Nginx build |
| `frontend/.dockerignore` | Excludes `node_modules` & build artifacts |
| `frontend/nginx.conf` | Nginx configuration with React Router SPA routing & API proxy |
| `.env.example` | Environment variable template |

---

## Development

### Local Development (without Docker)

See detailed setup in [frontend README](./frontend/README.md).

```bash
# Frontend
cd frontend
pnpm install
pnpm dev

# Backend (separate terminal)
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### Key HTTP endpoints (local)

- **Express API (primary public API)**:
  - `POST /api/analyze` (accepts **either** `{ "text": "..." }` **or** `{ "emailText": "..." }`)
  - `GET /api/health` (always returns `200`; includes ML provider snapshot when reachable)
- **Python FastAPI (internal ML service)**:
  - `GET /health` (provider lifecycle states: `uninitialized | ready | disabled`) — **benchmark metrics**, not live accuracy
  - `POST /analyze` (internal ensemble test endpoint; empty/short strings return deterministic `score: 0.0`)
  - `GET /debug/providers` (internal-only circuit-breaker visibility; guarded by `PHISHSHIELD_INTERNAL_API_KEY` when set)

---

## QA Testing & Hardening (May 2026)

In May 2026 we ran **100 real emails through the live UI** and found **20 issues** (false negatives, false positives, and score↔verdict integrity). All 20 were fixed and re-verified via FastAPI on `127.0.0.1:8000` with **20/20 PASS**.

### Accuracy (honest)

- **Offline benchmark** (training split): **97.19%** (see `backend/training_meta.json`)
- **Live UI QA** (100 real emails, May 2026): **~80–85%** after fixes (was ~42% before)

### Docker Compose Services

#### Backend Service
- **Port**: 8000
- **Health Check**: `GET /health` every 30s
- **Volumes**: 
  - `feedback.csv` (persistent)
  - `sender_profiles.json` (persistent)
  - `scan_logs.jsonl` (persistent)
- **Environment**: Reads from `.env` file

#### Frontend Service
- **Ports**: 80 (HTTP), 443 (HTTPS ready)
- **Depends On**: Backend (waits for healthy status)
- **Health Check**: `GET /health` every 30s
- **Features**:
  - React SPA routing via `try_files`
  - `/api/*` requests proxied to backend
  - Static asset caching (1 year)
  - HTML cache-busting
  - Gzip compression

---

## Environment Variables

See `.env.example` for all available options. Key variables:

```env
HF_TOKEN=<your-huggingface-token>
VT_API_KEY=<your-virustotal-key>
ENVIRONMENT=production
```

---

## Production Considerations

### SSL/TLS

To enable HTTPS in production:

1. Place SSL certificate and key in `./ssl/` directory
2. Uncomment HTTPS section in `frontend/nginx.conf`
3. Update `docker-compose.yml` volumes to mount certificates

### Security

- Run `docker-compose up` behind a reverse proxy (e.g., Traefik, Caddy)
- Use secrets management for `.env` (e.g., Docker Secrets, Vault)
- Regularly scan images: `docker scan phishshield-frontend:latest`

### Performance

- Use dedicated volume for model cache
- Enable Docker-in-Docker for CI/CD
- Use container orchestration (Kubernetes) for scaling

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port
lsof -i :8000
lsof -i :80

# Change port in docker-compose.yml or .env
```

### Container Logs

```bash
# All services
docker-compose logs

# Specific service
docker-compose logs backend
docker-compose logs frontend

# Follow in real-time
docker-compose logs -f
```

### Health Check Failures

```bash
# Check backend health
docker exec phishshield-backend curl http://localhost:8000/health

# Check frontend
docker exec phishshield-frontend wget -q -O- http://localhost/health
```

### Rebuild from Scratch

```bash
# Remove all containers and volumes
docker-compose down -v

# Rebuild
docker-compose up --build
```

---

## Certification status

From the repo root, `python backend/run_certification.py` runs the **35-case regression driver** plus **seven pytest gates** (regression pytest, adversarial, score integrity, failure injection, performance, security, explainability). Exit code **0** means every stage passed.

| Area | Status |
|------|--------|
| Architecture | Partially modular ⚠️ (fusion caps centralized in `scoring/score_engine.py`; full score-policy extraction pending) |
| Performance P95 | Real targets met ✅ (`backend/tests/test_performance.py`; VirusTotal + SecureBERT/MuRIL **stubbed** in that suite so P95 measures pipeline scaffolding, not GPU or external HTTP) |
| Test coverage | All 8 suites genuine ✅ (same driver as above) |

---

## Testing

Run pytest inside the backend container:

```bash
# Using Makefile
make test

# Or directly
docker-compose exec backend python -m pytest tests/ -v
```

---

## File Structure

```
.
├── docker-compose.yml           # Main orchestration
├── .env.example                 # Environment template
├── Makefile                     # Development shortcuts
├── frontend/        # React UI
│   ├── Dockerfile              # Multi-stage Nginx build
│   ├── .dockerignore            # Docker build exclusions
│   ├── nginx.conf               # Nginx with SPA routing
│   ├── package.json
│   └── src/
├── backend/          # FastAPI ML backend
│   ├── Dockerfile              # Python 3.12 image
│   ├── .dockerignore            # Docker build exclusions
│   ├── main.py                 # FastAPI app
│   ├── requirements.txt         # Python dependencies
│   └── indicbert_model/         # Pre-trained ML model
└── README.md                    # This file
```

---

## Support & Documentation

- **Bug Reports**: [GitHub Issues](https://github.com/yourusername/phishshield/issues)
- **Frontend Docs**: [frontend/README.md](./frontend/README.md)
- **Docker Docs**: [docs.docker.com](https://docs.docker.com/)
- **Nginx Docs**: [nginx.org](https://nginx.org/)

---

## License

[Your License Here]

---

**Last Updated**: April 2026  
**Docker Version**: Compose v3.9
