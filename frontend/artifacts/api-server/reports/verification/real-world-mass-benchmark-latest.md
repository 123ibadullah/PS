# Real-World Mass Benchmark

- Generated: 2026-04-04T19:39:31.256Z
- Total scenarios: 2000
- Total executions: 2300
- Accuracy: 100.00%
- False positives: 0
- False negatives: 0
- Critical false negatives: 0
- Inconsistent outputs: 0
- Wrong explanations: 0
- Wrong scoring: 0
- Consistency: stable
- Final verdict (APR 2026 internal suite): ✅ suite PASS

## QA Testing & Hardening (May 2026) — live UI reality check

This April benchmark is an **internal scenario suite**, not a claim of “perfect live accuracy”.

In May 2026 we ran **100 real emails** through the live UI and measured **~80–85% live accuracy** before/after hardening:

- **Before**: ~42% live accuracy (many real-world misses + false positives)
- **After**: ~80–85% live accuracy after fixing 20 issues
- **Verification**: 20/20 targeted samples PASS via FastAPI on `127.0.0.1:8000`

See `MASTER_GUIDE.md` for the exact bug list and the May 2026 hardening narrative.
