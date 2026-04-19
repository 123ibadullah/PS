"""Failure injection: enrichers raise or misbehave; pipeline must degrade predictably."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "PhisShield-Backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")

pytestmark = pytest.mark.asyncio


async def test_check_url_raises_falls_back_to_heuristic_scan(client, monkeypatch) -> None:
    calls: list[str] = []

    def boom(url: str) -> dict:
        calls.append(url)
        raise RuntimeError("VirusTotal client unavailable")

    monkeypatch.setattr(backend_main, "check_url_virustotal", boom)

    response = await client.post(
        "/scan-email",
        json={"email_text": "Please open http://secure-login.xyz/verify to continue."},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "verdict" in payload
    assert int(payload.get("risk_score") or 0) >= 0
    urls = payload.get("url_results") or []
    assert calls, "check_url_virustotal should have been invoked"
    assert urls, "URL results should still be present after VT failure"


async def test_calculate_email_risk_uncaught_raises_500(client, monkeypatch) -> None:
    def broken(*_args, **_kwargs):
        raise RuntimeError("simulated analyzer crash")

    monkeypatch.setattr(backend_main, "calculate_email_risk", broken)

    response = await client.post("/scan-email", json={"email_text": "Hello world"})
    assert response.status_code == 500
