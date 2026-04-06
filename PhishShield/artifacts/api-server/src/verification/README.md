# PhishShield Verification Suite

Run the full production-grade verification suite with:

```bash
pnpm --filter @workspace/api-server run verify:full
```

## What it covers
- Dynamic dataset generation (100+ cases)
- Rule engine, ML, transformer, and LLM fallback coverage
- URL and header analysis checks
- Multilingual phishing detection (English, Hindi, Telugu)
- Failure handling and resilience tests
- Repeated-input consistency validation
- End-to-end HTTP integration checks
- Performance validation and structured JSON/HTML reporting

## Output artifacts
Reports are written to:

- `artifacts/api-server/reports/verification/verification-report-latest.json`
- `artifacts/api-server/reports/verification/verification-report-latest.html`

## Final red-team pack
Run the adversarial simulation pack with:

```bash
pnpm --filter @workspace/api-server run verify:red-team
```

It does all of the following in one pass:
- loads the curated seed corpus from `red_team_seed_dataset_2026_04_03.json`
- expands it into a 100+ case red-team attack set
- runs each case 3 times to catch instability
- checks for phishing → safe misses, weak detections, explanation gaps, and duplicate reasoning
- writes artifacts to `artifacts/api-server/reports/red-team/`
