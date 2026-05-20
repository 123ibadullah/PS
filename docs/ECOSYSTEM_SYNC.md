# PhishShield ecosystem sync reference

Last audited: engineering completion pass (full-system consistency).

## Canonical runtime (Python FastAPI `:8000`)

| Flow | Route | Notes |
|------|-------|-------|
| Scan | `POST /scan-email` | Dashboard + Chrome extension |
| Feedback | `POST /feedback`, `POST /api/feedback` | Dashboard |
| Feedback stats | `GET /feedback/stats`, `GET /api/feedback/stats` | Dashboard |
| Retrain | `POST /retrain`, `POST /api/retrain` | Dashboard |
| Metrics | `GET /api/metrics` | `offline_evaluation` + `runtime_operational` |
| History | `GET /api/history`, `GET /recent-scans` | Dashboard / LiveFeed |
| Health | `GET /health` | All clients |
| WebSocket | `WS /ws/feed` | Dashboard LiveFeed |
| Prometheus | `GET /metrics` | Ops only (not UI accuracy) |

## Explainability defaults

- Scan attributions: `linear-weights` → `lime` → `heuristic` (SHAP only if `PHISHSHIELD_TRY_SHAP_ON_SCAN=1`)
- Narrative: `POST /explain` (LLM or rule fallback) — separate from word attributions

## Clients

| Client | Backend coupling |
|--------|------------------|
| Dashboard (`phishshield`) | `VITE_BACKEND_URL` → Python routes |
| Chrome extension | User-configured API URL → `/scan-email`, `/health` |
| api-client-react hooks | `/api/*` via `VITE_API_BASE_URL` or localhost:8000 |
| Node api-server | Optional legacy layer; not required for core demo |

## Metrics honesty

- **Offline:** `data/training_meta.json` → `offline_evaluation` in `/api/metrics`
- **Runtime:** session scan counters → `runtime_operational`
- **Not claimed:** live production accuracy in metrics API
