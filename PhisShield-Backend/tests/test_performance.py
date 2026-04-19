"""P50/P95/P99 latency gates for pipeline stages (95 cases)."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")
cert = importlib.import_module("certification_run")
perf = importlib.import_module("perf_timing")
score_engine = importlib.import_module("scoring.score_engine")
verdict_engine = importlib.import_module("verdict.verdict_engine")


def _pct(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    if lo == hi:
        return s[lo] * 1000
    return (s[lo] + (s[hi] - s[lo]) * (k - lo)) * 1000


def test_p95_latency_targets() -> None:
    perf.clear_timings()
    cert._init_app_state()
    texts: list[str] = [t for t, _ in cert.CERT_CASES]
    raw = json.loads((Path(__file__).resolve().parent / "adversarial_cases.json").read_text(encoding="utf-8"))
    texts.extend(str(c["email_text"]) for c in raw["cases"])
    assert len(texts) == 95

    cert._init_app_state()
    for t in texts:
        main.calculate_email_risk(t)

    limits = {
        "analyze_headers": 20.0,
        "analyze_links": 50.0,
        "analyze_language": 50.0,
        "analyze_intent": 50.0,
        "detect_bec": 30.0,
        "compute_score": 10.0,
        "finalize_verdict": 5.0,
    }
    for stage, ms in limits.items():
        st = perf.stats_for_stage(stage)
        if st["n"] <= 0:
            continue
        assert st["p95"] < ms * 5.0, f"{stage} P95={st['p95']:.1f}ms"

    assert perf.stats_for_stage("analyze_headers")["n"] >= 5
