"""Load adversarial_cases.json and assert robustness constraints on calculate_email_risk."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "PhisShield-Backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")

_CASES_PATH = ROOT_DIR / "tests" / "adversarial_cases.json"


def _load_cases() -> list[dict]:
    raw = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
    return list(raw["cases"])


CASES = _load_cases()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_adversarial_case_properties(case: dict) -> None:
    text = case["email_text"]
    exp = case.get("expect") or {}
    result = main.calculate_email_risk(text)

    score = int(result.get("risk_score") or 0)
    verdict = str(result.get("verdict") or "")
    assert 0 <= score <= 100

    lo = exp.get("min_score")
    hi = exp.get("max_score")
    if lo is not None:
        assert score >= int(lo), f"score={score} wanted min {lo}"
    if hi is not None:
        assert score <= int(hi), f"score={score} wanted max {hi}"

    vn = exp.get("verdict_not")
    if vn:
        assert verdict != vn

    vs = exp.get("verdict_in")
    if vs:
        assert verdict in vs


def test_adversarial_dataset_present() -> None:
    assert _CASES_PATH.is_file()
