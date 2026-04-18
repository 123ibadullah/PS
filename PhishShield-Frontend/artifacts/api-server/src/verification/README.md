# PhishShield Verification Guide

Use this folder to reproduce the verification workflow for the current repo.

## Main commands

```bash
pnpm --filter @workspace/api-server run verify:full
pnpm --filter @workspace/api-server run verify:red-team
pnpm --filter @workspace/api-server run verify:massive
```

## Also useful from the repo root

```bash
pnpm --filter @workspace/scripts run qa:system
pnpm --filter @workspace/scripts run qa:ui
pnpm validate:final
```

## What is covered
- safe-email false positive control
- phishing and impersonation detection
- URL and header analysis
- multilingual scam recognition
- repeated-input consistency checks
- red-team and large-benchmark style validation

## Preconditions
- `pnpm validate:final` is a **live** runner and expects the frontend on `:5173` and the Python backend on `:8000` to be reachable.
- If `/health` is not reachable, the final validation command stops early by design.

## Output artifacts
Reports are written under:

- `artifacts/api-server/reports/verification/`
- `artifacts/api-server/reports/red-team/`
- `artifacts/reports/qa/`

## Recommendation
Start with `verify:full`, use `verify:red-team` for adversarial checks, and use the repo-root scripts when you want user-facing demo validation evidence.

