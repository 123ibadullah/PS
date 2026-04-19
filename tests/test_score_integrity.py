"""Score / verdict invariants across certification cases and scoring helpers."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "PhisShield-Backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")
cert = importlib.import_module("certification_run")
score_engine = importlib.import_module("scoring.score_engine")


VERDICTS = frozenset({"Critical", "High Risk", "Suspicious", "Safe"})


def _init_app_state() -> None:
    import collections

    main.app.state.scan_explanations = collections.OrderedDict()
    main.app.state.scan_cache = collections.OrderedDict()
    main.app.state.scan_rate_limits = {}
    main.app.state.sender_profiles = {}
    main.app.state.threat_intel = main.load_threat_intel_feed()
    main.app.state.feedback_memory = {}
    main.load_artifacts()


@pytest.mark.parametrize("idx", range(len(cert.CERT_CASES)))
def test_cert_case_score_verdict_bounds(idx: int) -> None:
    _init_app_state()
    text, _label = cert.CERT_CASES[idx]
    r = main.calculate_email_risk(text)
    score = int(r.get("risk_score") or 0)
    verdict = str(r.get("verdict") or "")
    assert 0 <= score <= 100
    assert verdict in VERDICTS
    if verdict == "Safe":
        assert score <= 20
    elif verdict == "Critical":
        assert score >= 90
    elif verdict == "High Risk":
        assert 70 <= score <= 89
    elif verdict == "Suspicious":
        assert 40 <= score <= 69


def test_signal_trace_pure_math_matches_final_score() -> None:
    trace = score_engine.build_signal_trace(
        final_score=73,
        ml_contribution=40.0,
        rule_contribution=35.0,
        link_risk_score=10,
        header_spoofing_score=15,
        enterprise_bonus=5.0,
        hard_signal_count=2,
        header_has_fail=False,
        trusted_sender=False,
        has_brand_impersonation=False,
        vt_confirmed_suspicious=0,
        raw_language_model_probability=0.42,
    )
    total = sum(float(t["weight"]) for t in trace.values())
    assert abs(total - 73.0) <= 0.55


def test_math_check_matches_build_signal_trace() -> None:
    trace = score_engine.build_signal_trace(
        final_score=73,
        ml_contribution=40.0,
        rule_contribution=35.0,
        link_risk_score=10,
        header_spoofing_score=15,
        enterprise_bonus=5.0,
        hard_signal_count=2,
        header_has_fail=False,
        trusted_sender=False,
        has_brand_impersonation=False,
        vt_confirmed_suspicious=0,
        raw_language_model_probability=0.42,
    )
    chk = score_engine.math_check(trace, final_score=73)
    assert chk["matches"]

