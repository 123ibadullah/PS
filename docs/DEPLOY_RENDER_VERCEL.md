# Deploy PhishShield on Render + Vercel

This repo deploys as two services:

- Backend: FastAPI Docker service from `backend/` on Render.
- Frontend: Vite static app from `frontend/` on Vercel.

## 1. Commit and push

```bash
git add backend/.dockerignore backend/Dockerfile backend/main.py frontend/artifacts/api-server/src/lib/phishingDetector.ts frontend/artifacts/phishshield/package.json frontend/pnpm-lock.yaml render.yaml docs/DEPLOY_RENDER_VERCEL.md
git commit -m "Prepare Render and Vercel deployment"
git push origin main
```

## 2. Deploy the backend on Render

Recommended path:

1. Open Render Dashboard.
2. Select **New +** -> **Blueprint**.
3. Connect the GitHub repository and select the branch you pushed.
4. Use the repository `render.yaml`.
5. Create the service named `phishshield-backend`.
6. In the generated service environment variables, set:
   - `CORS_ALLOWED_ORIGINS`: leave temporary value blank until Vercel gives you the frontend URL, or set `http://localhost:5173` for local testing.
   - `VT_API_KEY`: optional VirusTotal key.
   - `LLM_API_KEY` or `OPENROUTER_API_KEY`: optional LLM key.
7. Wait for deploy to finish.
8. Copy the Render backend URL, for example `https://phishshield-backend.onrender.com`.
9. Verify:

```bash
curl https://phishshield-backend.onrender.com/health
```

Expected: JSON with `"status":"ok"`.

Manual Render settings, if you do not use Blueprint:

- Runtime/Language: `Docker`
- Dockerfile Path: `backend/Dockerfile`
- Docker Context: `backend`
- Health Check Path: `/health`
- Environment:
  - `ENVIRONMENT=production`
  - `PYTHONUNBUFFERED=1`
  - `CORS_ALLOWED_ORIGINS=https://YOUR-VERCEL-APP.vercel.app`
  - optional `VT_API_KEY`, `LLM_API_KEY`, `OPENROUTER_API_KEY`

## 3. Deploy the frontend on Vercel

1. Open Vercel Dashboard.
2. Select **Add New** -> **Project**.
3. Import the same GitHub repository.
4. Set **Root Directory** to `frontend`.
5. Keep or set these build settings:
   - Framework Preset: `Vite`
   - Install Command: `pnpm install --frozen-lockfile`
   - Build Command: `pnpm build`
   - Output Directory: `artifacts/phishshield/dist/public`
6. Add these Vercel environment variables for Production and Preview:
   - `VITE_BACKEND_URL=https://YOUR-RENDER-BACKEND.onrender.com`
   - `VITE_API_BASE_URL=https://YOUR-RENDER-BACKEND.onrender.com`
   - `VITE_WS_URL=wss://YOUR-RENDER-BACKEND.onrender.com`
   - `BASE_PATH=/`
   - `ENABLE_RUNTIME_ERROR_OVERLAY=false`
7. Deploy.
8. Copy the Vercel production URL, for example `https://phishshield.vercel.app`.

## 4. Lock CORS to the frontend URL

1. Go back to Render -> `phishshield-backend` -> **Environment**.
2. Set:

```text
CORS_ALLOWED_ORIGINS=https://YOUR-VERCEL-APP.vercel.app
```

For multiple domains, use commas:

```text
CORS_ALLOWED_ORIGINS=https://YOUR-VERCEL-APP.vercel.app,https://www.yourcustomdomain.com
```

3. Save and redeploy the Render service.

## 5. Production smoke tests

Backend:

```bash
curl https://YOUR-RENDER-BACKEND.onrender.com/health
```

Frontend:

1. Open `https://YOUR-VERCEL-APP.vercel.app`.
2. Paste a test email.
3. Run a scan.
4. Confirm the browser Network tab sends scan requests to `https://YOUR-RENDER-BACKEND.onrender.com`.

If scans fail with a browser CORS error, the Vercel URL is missing from `CORS_ALLOWED_ORIGINS` on Render.
