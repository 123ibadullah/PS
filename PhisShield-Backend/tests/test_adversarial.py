"""Adversarial suite: 60 cases (A–F) vs calculate_email_risk."""

from __future__ import annotations

import importlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

main = importlib.import_module("main")
cert = importlib.import_module("certification_run")

_CASES_PATH = Path(__file__).resolve().parent / "adversarial_cases.json"
_RESULTS_PATH = Path(__file__).resolve().parent / "adversarial_results.json"


def _init() -> None:
    cert._init_app_state()


def _load_cases() -> list[dict]:
    raw = json.loads(_CASES_PATH.read_text(encoding="utf-8"))
    return list(raw["cases"])


def test_adversarial_categories() -> None:
    cases = _load_cases()
    _init()
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for c in cases:
        by_cat[str(c.get("category", "?"))].append(c)

    results: list[dict] = []
    passed = {k: 0 for k in "ABCDEF"}
    total = {k: 0 for k in "ABCDEF"}

    for c in cases:
        cat = str(c["category"])
        total[cat] += 1
        text = str(c.get("email_text", ""))
        try:
            r = main.calculate_email_risk(text)
            score = int(r.get("risk_score", 0) or 0)
            verdict = str(r.get("verdict", ""))
        except Exception as exc:  # noqa: BLE001 — category F should still avoid crashes where specified
            results.append({"id": c["id"], "category": cat, "error": type(exc).__name__, "msg": str(exc)[:200]})
            continue
        assert 0 <= score <= 100
        exp = c.get("expect") or {}
        ok = True
        if "min_score" in exp and score < int(exp["min_score"]):
            ok = False
        if "max_score" in exp and score > int(exp["max_score"]):
            ok = False
        if ok:
            passed[cat] += 1
        results.append(
            {
                "id": c["id"],
                "category": cat,
                "score": score,
                "verdict": verdict,
                "pass": ok,
            }
        )

    _RESULTS_PATH.write_text(json.dumps({"results": results}, indent=2), encoding="utf-8")

    print("\n--- Adversarial per-category ---")
    for cat in "ABCDEF":
        print(f"  {cat}: {passed[cat]}/{total[cat]} pass")

    assert passed["A"] >= 9, f"A need >=9 got {passed['A']}"
    assert passed["B"] >= 9, f"B need >=9 got {passed['B']}"
    assert passed["C"] >= 9, f"C need >=9 got {passed['C']}"
    assert passed["D"] >= 8, f"D need >=8 got {passed['D']}"
    assert passed["E"] >= 9, f"E need >=9 got {passed['E']}"
    assert passed["F"] == 10, f"F need 10 no-crash got {passed['F']}"
