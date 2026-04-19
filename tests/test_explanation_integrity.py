"""Assert /scan-email payloads expose signal_trace math for certification-style cases."""

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


def _init() -> None:
    main.app.state.scan_explanations = __import__("collections").OrderedDict()
    main.app.state.scan_cache = __import__("collections").OrderedDict()
    main.app.state.scan_rate_limits = {}
    main.app.state.sender_profiles = {}
    main.app.state.threat_intel = main.load_threat_intel_feed()
    main.app.state.feedback_memory = {}
    main.load_artifacts()


@pytest.mark.parametrize("idx", range(1, 36))
def test_cert_case_signal_trace_sums(idx: int) -> None:
    _init()
    text, _exp = cert.CERT_CASES[idx - 1]
    r = main.calculate_email_risk(text)
    st = r.get("signal_trace") or {}
    assert st, "signal_trace missing"
    assert r.get("explanation_source") == "signal_trace"
    s = sum(float(v.get("weight", 0) or 0) for v in st.values())
    fs = int(r.get("risk_score", 0) or 0)
    assert abs(s - float(fs)) <= 0.5, f"sum={s} final={fs}"
    tops = r.get("top_signals") or []
    for row in tops:
        assert float(row.get("weight", 0) or 0) > 0
