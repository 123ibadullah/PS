# Backend module layout (incremental extraction)

`main.py` remains the application entrypoint and scoring orchestrator. Extracted modules preserve API compatibility.

| Package | Responsibility |
|---------|----------------|
| `routes/metrics_routes.py` | `GET /api/metrics` honest offline + runtime payload |
| `services/metrics_service.py` | Training metadata + session scan counters |
| `ws/connection_manager.py` | WebSocket `/ws/feed` lifecycle |
| `models/` | SecureBERT + MuRIL provider wrappers |
| `explain.py` | SHAP/LIME/heuristic explainability |
| `scoring/` | Deterministic + fusion score engine |

Future safe extractions (not yet moved): feedback/retrain handlers, scan routes, persistence helpers, auth middleware.
