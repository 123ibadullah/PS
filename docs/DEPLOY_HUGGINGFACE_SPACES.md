# Deploy PhishShield Backend on Hugging Face Spaces with Docker

This deploys only the FastAPI backend in `backend/`.

## 1. Create the Space

1. Open Hugging Face.
2. Go to **Spaces** -> **Create new Space**.
3. Set:
   - Space name: `phishshield-backend`
   - SDK: `Docker`
   - Hardware: start with CPU Basic/2 vCPU for testing; upgrade if build/runtime memory is too small.
   - Visibility: Public or Private, your choice.
4. Create the Space.

## 2. Clone the empty Space repo

Replace `YOUR_HF_USERNAME` with your Hugging Face username or organization.

```bash
git lfs install
git clone https://huggingface.co/spaces/YOUR_HF_USERNAME/phishshield-backend phishshield-backend-space
```

## 3. Copy and push (automated)

From the PhishShield repo root:

```powershell
.\scripts\deploy-hf-space.ps1 -HfUser "Mohd1314234123"
```

This clones/updates `phishshield-backend-space/`, copies `backend/` (without large weight folders), includes `model.pkl` + `vectorizer.pkl`, commits, and pushes.

Manual copy (alternative):

```powershell
robocopy backend phishshield-backend-space /E `
  /XD indicbert_model "models\securebert_model" "models\muril_model" reports __pycache__ .pytest_cache .mypy_cache `
  /XF .env *.log *.db *.db-* *.sqlite *.pyc scan_logs.jsonl feedback.csv sender_profiles.json test_results*.txt verify_output.txt
```

`robocopy` exit codes `0` through `7` are success states.

See **`docs/HF_SPACE_SECRETS.md`** for the full secrets checklist.

The Space repo root must contain these files:

```text
Dockerfile
README.md
main.py
requirements.txt
model.pkl
vectorizer.pkl
scoring/
models/
analyzers/
```

## 4. Commit and push to Hugging Face

```bash
cd phishshield-backend-space
git add .
git commit -m "Deploy PhishShield backend Docker Space"
git push
```

Hugging Face will build the Docker image automatically after the push.

## 5. Add secrets or variables

In the Space page, go to **Settings** -> **Variables and secrets**.

Recommended variables:

```text
ENVIRONMENT=production
PYTHONUNBUFFERED=1
CORS_ALLOWED_ORIGINS=https://YOUR-FRONTEND-DOMAIN.vercel.app
```

Optional secrets:

```text
VT_API_KEY=your_virustotal_key
LLM_API_KEY=your_openrouter_or_llm_key
OPENROUTER_API_KEY=your_openrouter_key
HF_TOKEN=your_huggingface_token_if_loading_private_models
```

After changing variables/secrets, restart the Space.

## 6. Test the deployed backend

Your backend URL will be:

```text
https://YOUR_HF_USERNAME-phishshield-backend.hf.space
```

Health:

```bash
curl https://YOUR_HF_USERNAME-phishshield-backend.hf.space/health
```

Swagger docs:

```text
https://YOUR_HF_USERNAME-phishshield-backend.hf.space/docs
```

Email scan:

```bash
curl -X POST https://YOUR_HF_USERNAME-phishshield-backend.hf.space/scan-email \
  -H "Content-Type: application/json" \
  -d "{\"email_text\":\"Urgent: verify your bank account OTP now to avoid suspension.\"}"
```

## 7. Point the frontend to the Space backend

In Vercel, set:

```text
VITE_BACKEND_URL=https://YOUR_HF_USERNAME-phishshield-backend.hf.space
VITE_API_BASE_URL=https://YOUR_HF_USERNAME-phishshield-backend.hf.space
VITE_WS_URL=wss://YOUR_HF_USERNAME-phishshield-backend.hf.space
```

Redeploy the frontend after changing these variables.

## Notes

- `backend/README.md` contains `sdk: docker` and `app_port: 7860`; keep it in the Space repo root.
- The backend listens on `${PORT:-7860}` and the Space routes to port `7860`.
- Space filesystem changes are ephemeral unless you enable Hugging Face persistent storage.
- Transformer weight folders are ignored from Docker builds by default. The deployed backend uses the included TF-IDF artifacts plus deterministic phishing rules unless you intentionally ship or download transformer artifacts.
