# Hugging Face Space — secrets checklist

Space: **Mohd1314234123/phishshield-backend**  
URL: `https://mohd1314234123-phishshield-backend.hf.space`

## Push code (one command)

From repo root (PowerShell):

```powershell
.\scripts\deploy-hf-space.ps1
```

First time: `huggingface-cli login` or `git config credential.helper` for HF.

## Secrets (Settings → Secrets)

Copy from your local `.env` — **never commit these to git**:

| Secret | Required for |
|--------|----------------|
| `HF_TOKEN` | Download models from your HF Model repos at startup |
| `PHISHSHIELD_SECUREBERT_HF_REPO` | e.g. `Mohd1314234123/phishshield-securebert` (see upload script below) |
| `PHISHSHIELD_MURIL_HF_REPO` | e.g. `Mohd1314234123/phishshield-muril` |
| `VT_API_KEY` | VirusTotal URL checks |
| `GOOGLE_API_KEY` | Gemini explanations |
| `LLM_API_KEY` | OpenRouter (if `LLM_PROVIDER=openrouter`) |

### One-time: upload local weights to HF Model repos

Space git is only **1 GB** — do **not** push `model.safetensors` into the Space repo.

1. Create a **Write** token: https://huggingface.co/settings/tokens (not Read).
2. Login once:

```powershell
cd c:\Users\froms\Desktop\2
.\.venv\Scripts\huggingface-cli.exe login
# paste Write token
```

3. Upload (~1.4 GB, 15–40 min):

```powershell
.\scripts\upload-hf-models.ps1
```

Or upload one model at a time:

```powershell
.\.venv\Scripts\python.exe .\scripts\upload_hf_models.py --secure-only
.\.venv\Scripts\python.exe .\scripts\upload_hf_models.py --muril-only
```

Add the two `PHISHSHIELD_*_HF_REPO` secrets above, then **Restart Space**. Logs should show `Downloading SecureBERT artifacts from ...` then `ready`.

## Variables (Settings → Variables)

| Variable | Example |
|----------|---------|
| `ENVIRONMENT` | `production` |
| `PYTHONUNBUFFERED` | `1` |
| `LLM_PROVIDER` | `gemini` |
| `GEMINI_MODEL` | `gemini-2.5-flash` |
| `CORS_ALLOWED_ORIGINS` | Your Vercel URL, `https://mail.google.com` |

CORS also allows `*.hf.space` and `chrome-extension://` by default in code.

## After push

1. Wait for **Building** → **Running** (first build 10–20 min).
2. Open `/health` — wait until `securebert` and `muril` are **ready** (may take 2–5 min after boot with `HF_TOKEN`).
3. Extension / Vercel: set API base to `https://mohd1314234123-phishshield-backend.hf.space`

## Hardware

- **CPU basic** — works, slow warmup.
- **CPU upgrade (32 GB)** — closer to local Docker speed.

## If models stay `unavailable`

- Add or fix `HF_TOKEN` → **Restart Space**
- Or upload weights via Git LFS (very large; not recommended on free tier)
