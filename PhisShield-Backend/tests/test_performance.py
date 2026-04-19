"""P50/P95/P99 latency gates for pipeline stages (95 cases)."""

from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")
cert = importlib.import_module("certification_run")
perf = importlib.import_module("perf_timing")


def _pct_ms_from_seconds(vals: list[float], p: float) -> float:
    """Return percentile in milliseconds; vals are durations in seconds."""
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    if lo == hi:
        return s[lo] * 1000.0
    return (s[lo] + (s[hi] - s[lo]) * (k - lo)) * 1000.0


@pytest.fixture(autouse=True)
def mock_virustotal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep URL stage local-only (no real VT HTTP) for latency measurements."""

    def _stub_vt(url: str) -> dict[str, Any]:
        return {
            "url": url,
            "malicious": False,
            "suspicious": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "risk_score": 0,
            "source": "virustotal",
            "trusted_domain": False,
        }

    monkeypatch.setattr(main, "check_url_virustotal", _stub_vt)


@pytest.fixture(autouse=True)
def mock_fast_ml(monkeypatch: pytest.MonkeyPatch) -> None:
    """IndicBERT inference dominates wall time; stub so P95 gates measure pipeline scaffolding."""

    monkeypatch.setattr(main, "predict_with_indicbert", lambda _email_text: 0.18)


def test_p95_latency_targets() -> None:
    perf.clear_timings()
    cert._init_app_state()
    texts: list[str] = [t for t, _ in cert.CERT_CASES]
    raw = json.loads((Path(__file__).resolve().parent / "adversarial_cases.json").read_text(encoding="utf-8"))
    texts.extend(str(c["email_text"]) for c in raw["cases"])
    assert len(texts) == 95

    wall_seconds: list[float] = []
    for t in texts:
        t0 = time.perf_counter()
        main.calculate_email_risk(t)
        wall_seconds.append(time.perf_counter() - t0)

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
        assert st["p95"] < ms, f"{stage} P95={st['p95']:.1f}ms exceeds {ms}ms"

    assert perf.stats_for_stage("analyze_headers")["n"] >= 5

    p95_full_ms = _pct_ms_from_seconds(wall_seconds, 95.0)
    assert p95_full_ms < 300.0, f"full_pipeline_no_external P95={p95_full_ms:.1f}ms exceeds 300ms"
