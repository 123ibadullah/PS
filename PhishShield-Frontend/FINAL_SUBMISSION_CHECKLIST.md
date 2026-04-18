# PhishShield AI — Final Submission Checklist

Use this before recording, presenting, or pushing a final repo update.

---

## 1) Runtime readiness

- [ ] from `PhishShield-Frontend`, `pnpm build` completes successfully
- [ ] `http://127.0.0.1:5173` is reachable
- [ ] `http://127.0.0.1:8000/health` returns healthy
- [ ] OTP scam check returns phishing: `Your account is suspended. Send your OTP immediately to restore access.`
- [ ] safe control check returns safe: `Project Update for this week`
- [ ] backend cache protection is active (`cache_version: 2` invalidation + startup clear)
- [ ] one clear phishing sample and one safe sample are ready
- [ ] the `PhishShield Guardian` extension loads cleanly from `artifacts/chrome-extension/`

---

## 2) Demo evidence ready

- [ ] `artifacts/reports/qa/system-readiness-audit-latest.md` is present
- [ ] `artifacts/api-server/reports/verification/real-world-mass-benchmark-latest.md` is present
- [ ] `..\PhisShield-Backend\training_meta.json` metrics are ready to reference
- [ ] screenshots or screen captures are prepared if needed

---

## 3) Docs and repo polish

- [ ] `README.md` reflects the latest project structure
- [ ] `MASTER_GUIDE.md` matches the current architecture and setup flow
- [ ] `FINAL_VALIDATION_SUITE.md` matches the actual local validation process
- [ ] `SHOWCASE_PITCH.md`, `PPT_FINAL_SCRIPT.md`, and `DEMO_RECORDING_SCRIPT.md` are the versions being used

---

## 4) Presentation flow

- [ ] open with the one-line positioning statement
- [ ] show the dashboard before diving into implementation
- [ ] demonstrate a strong phishing example first
- [ ] follow with a safe example for contrast
- [ ] mention metrics only after the demo proof

---

## 5) Final recommended command check

```bash
pnpm build
pnpm --filter @workspace/scripts run qa:system
pnpm --filter @workspace/scripts run qa:ui
```

> For `pnpm validate:final`, make sure the local frontend and Python backend are running first.

---

## Final rule

> Show the product, show the reason behind the verdict, and show the proof.

