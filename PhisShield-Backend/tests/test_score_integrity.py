"""Six scoring / verdict integrity proofs."""

from __future__ import annotations

import importlib
import random
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")
cert = importlib.import_module("certification_run")
score_engine = importlib.import_module("scoring.score_engine")


def _init() -> None:
    cert._init_app_state()


def test_bounds_random_inputs() -> None:
    """Fuzz the same fusion entrypoint used by calculate_email_risk (via compute_score)."""
    rng = random.Random(42)
    for i in range(1000):
        result = score_engine.compute_score_result_dict(
            language_model_score=rng.randint(0, 100),
            pattern_score=rng.randint(0, 100),
            link_risk_score=rng.randint(0, 100),
            header_spoofing_score=rng.randint(0, 100),
            enterprise_bonus_breakdown={
                "url_sandbox": rng.randint(0, 20),
                "attachment_analysis": rng.randint(0, 20),
                "thread_context": rng.randint(0, 20),
                "threat_intel": rng.randint(0, 20),
                "sender_reputation": rng.randint(0, 20),
            },
            hard_signal_count=rng.randint(0, 5),
            header_has_fail=rng.choice([True, False]),
            trusted_sender=rng.choice([True, False]),
            has_brand_impersonation=rng.choice([True, False]),
            safe_reputation_signals=[],
            ml_max_contribution=score_engine.ML_MAX_CONTRIBUTION,
            rule_max_contribution=score_engine.RULE_MAX_CONTRIBUTION,
        )
        fs = int(result["final_score"])
        assert 0 <= fs <= 100, f"Score out of bounds on iteration {i}: {fs}"


def test_determinism_cert_cases() -> None:
    _init()
    for text, _ in cert.CERT_CASES:
        outs = []
        for _ in range(5):
            _init()
            outs.append(main.calculate_email_risk(text))
        for k in ("risk_score", "verdict"):
            first = outs[0].get(k)
            for o in outs[1:]:
                assert o.get(k) == first, f"drift on {k}"


def test_ml_boundary_contribution(monkeypatch: pytest.MonkeyPatch) -> None:
    _init()

    def fake_predict(_: str) -> float:
        return 0.99

    monkeypatch.setattr(main, "predict_with_indicbert", fake_predict)
    text = "Meeting notes for tomorrow standup."
    r = main.calculate_email_risk(text)
    sc = r.get("score_components") or {}
    mlc = float(sc.get("ml_contribution", 0) or 0)
    assert mlc <= 35.0 + 1e-6


def test_signal_trace_sum_matches_final() -> None:
    _init()
    for idx in range(0, len(cert.CERT_CASES), 7):
        text, _ = cert.CERT_CASES[idx]
        r = main.calculate_email_risk(text)
        st = r.get("signal_trace") or {}
        assert st
        fs = int(r.get("risk_score", 0) or 0)
        s = sum(float(v.get("weight", 0) or 0) for v in st.values())
        assert abs(s - float(fs)) <= 0.55


def test_monotonicity_adding_phishing_signal() -> None:
    _init()
    base = "Team lunch at 1pm today at the usual place."
    boosted = base + " Urgent: verify your bank account now http://evil-login.xyz"
    _init()
    s0 = int(main.calculate_email_risk(base).get("risk_score", 0) or 0)
    _init()
    s1 = int(main.calculate_email_risk(boosted).get("risk_score", 0) or 0)
    assert s1 >= s0


def test_override_isolation_otp_safe() -> None:
    _init()
    text = "OTP for your Zepto login is 847291. Valid for 10 minutes. Do not share with anyone."
    r = main.calculate_email_risk(text)
    assert str(r.get("verdict", "")) == "Safe"
    st = r.get("signal_trace") or {}
    assert isinstance(st, dict)
