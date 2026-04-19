#!/usr/bin/env python3
"""
PhishShield certification driver: 35-case regression + seven hard pytest gates.

Run from repo root:
  python PhisShield-Backend/run_certification.py

Exit 0 only if every stage passes. Writes PhisShield-Backend/certification_report.txt.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
REPORT_PATH = ROOT / "certification_report.txt"

ADVERSARIAL_JSON = ROOT / "tests" / "adversarial_cases.json"


def _run_cert_35() -> tuple[bool, str]:
    import certification_run as cr

    cr._init_app_state()
    fp, fn, n, _rows, max_ms = cr.run_certification_tests()
    ok = fp == 0 and fn == 0
    detail = f"{n - fp - fn}/{n} pass | FP={fp} | FN={fn} | max_ms={max_ms:.0f}"
    return ok, detail


def _pytest_cmd(cmd: list[str]) -> tuple[bool, str]:
    p = subprocess.run(cmd, cwd=str(REPO))
    return p.returncode == 0, f"exit {p.returncode}"


def main() -> int:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    wall0 = time.perf_counter()
    lines: list[str] = []
    failing: list[str] = []
    timings: list[tuple[str, bool, str, float]] = []

    def emit(msg: str) -> None:
        print(msg)
        lines.append(msg)

    emit("=" * 59)
    emit("PHISHSHIELD AI - BATTLE HARDENING CERTIFICATION REPORT")
    emit(f"Build: {ts}")
    emit("=" * 59)

    if not ADVERSARIAL_JSON.is_file():
        emit(f"[FAIL] Required adversarial dataset missing: {ADVERSARIAL_JSON}")
        emit("Exit code: 1")
        try:
            REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass
        return 1

    py = sys.executable

    gate_cmds: list[tuple[str, list[str]]] = [
        (
            "REGRESSION_35",
            [],  # special: handled below
        ),
        (
            "REGRESSION_PYTEST",
            [
                py,
                "-m",
                "pytest",
                "tests/",
                "-k",
                "test_cert or test_regression",
                "-v",
                "--tb=short",
            ],
        ),
        (
            "ADVERSARIAL",
            [py, "-m", "pytest", str(ROOT / "tests" / "test_adversarial.py"), "-v", "--tb=short"],
        ),
        (
            "SCORE_INTEGRITY",
            [py, "-m", "pytest", str(ROOT / "tests" / "test_score_integrity.py"), "-v", "--tb=short"],
        ),
        (
            "FAILURE_INJECTION",
            [py, "-m", "pytest", str(ROOT / "tests" / "test_failure_injection.py"), "-v", "--tb=short"],
        ),
        (
            "PERFORMANCE",
            [py, "-m", "pytest", str(ROOT / "tests" / "test_performance.py"), "-v", "--tb=short"],
        ),
        (
            "SECURITY",
            [py, "-m", "pytest", str(ROOT / "tests" / "test_security.py"), "-v", "--tb=short"],
        ),
        (
            "EXPLAINABILITY",
            [py, "-m", "pytest", "tests/test_explanation_integrity.py", "-v", "--tb=short"],
        ),
    ]

    for gate_id, cmd in gate_cmds:
        t0 = time.perf_counter()
        if gate_id == "REGRESSION_35":
            ok, det = _run_cert_35()
        else:
            ok, det = _pytest_cmd(cmd)
        timings.append((gate_id, ok, det, time.perf_counter() - t0))
        label = {
            "REGRESSION_35": "[REGRESSION]         35-case score bands",
            "REGRESSION_PYTEST": "[REGRESSION]         pytest test_cert|test_regression",
            "ADVERSARIAL": "[ADVERSARIAL]        PhisShield-Backend/tests/test_adversarial",
            "SCORE_INTEGRITY": "[SCORE INTEGRITY]    test_score_integrity.py",
            "FAILURE_INJECTION": "[FAILURE INJECTION]  test_failure_injection.py",
            "PERFORMANCE": "[PERFORMANCE]        test_performance.py",
            "SECURITY": "[SECURITY]           test_security.py",
            "EXPLAINABILITY": "[EXPLAINABILITY]     tests/test_explanation_integrity.py",
        }.get(gate_id, gate_id)
        emit(f"{label:<54} {'[OK]' if ok else '[FAIL]'}  {det}")
        if not ok:
            failing.append(gate_id)

    wall_s = time.perf_counter() - wall0
    overall = len(failing) == 0
    emit("=" * 59)
    emit("--- TIMING (wall seconds per stage) ---")
    for name, ok, det, sec in timings:
        tag = "ok" if ok else "FAIL"
        emit(f"  {name:<42} {sec:8.2f}s  [{tag}]  {det}")
    emit(f"  {'TOTAL (sequential stages)':<42} {wall_s:8.2f}s")
    emit("=" * 59)
    if overall:
        emit("OVERALL: [OK] All certification gates passed.")
    else:
        emit("OVERALL: [FAIL] One or more gates failed.")
        emit("FAILING: " + ", ".join(failing))
    emit(f"Exit code: {0 if overall else 1}")

    try:
        REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[REPORT] Wrote {REPORT_PATH}")
    except OSError as exc:
        print(f"[REPORT] Could not write {REPORT_PATH}: {exc}", file=sys.stderr)

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
