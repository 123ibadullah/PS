"""Adversarial robustness cases from data/adversarial_cases.json."""

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

_CASES_PATH = Path(__file__).resolve().parents[1] / "data" / "adversarial_cases.json"


def _load_cases() -> list[dict]:
    raw = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
    return list(raw["cases"])


CASES = _load_cases()


@pytest.fixture(autouse=True)
def _init_state() -> None:
    cert._init_app_state()


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_adversarial_case_properties(case: dict) -> None:
    text = str(case.get("email_text", ""))
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
    assert len(CASES) >= 5
