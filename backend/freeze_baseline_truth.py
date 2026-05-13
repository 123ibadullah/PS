"""One-shot: write baseline_truth.json from current calculate_email_risk (do not edit by hand)."""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import certification_run as cr  # noqa: E402
import main as m  # noqa: E402


def main() -> None:
    cr._init_app_state()
    out: list[dict] = []
    for i, (text, exp) in enumerate(cr.CERT_CASES, 1):
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()
        t0 = time.perf_counter()
        r = m.calculate_email_risk(text)
        ms = (time.perf_counter() - t0) * 1000.0
        sc = r.get("score_components") or {}
        out.append(
            {
                "case_id": f"cert_{i:03d}_{exp}",
                "input_hash": h,
                "risk_score": int(r.get("risk_score", 0) or 0),
                "verdict": str(r.get("verdict", "")),
                "ml_contribution": float(sc.get("ml_contribution", 0) or 0),
                "rule_contribution": float(sc.get("rule_contribution", 0) or 0),
                "signals": list(r.get("signals") or r.get("matched_signals") or []),
                "latency_ms": round(ms, 2),
            }
        )
    path = ROOT / "baseline_truth.json"
    path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Wrote {path} ({len(out)} cases)")


if __name__ == "__main__":
    main()
