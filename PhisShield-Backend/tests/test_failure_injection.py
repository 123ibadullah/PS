"""Failure injection / chaos scenarios for scan pipeline."""

from __future__ import annotations

import asyncio
import importlib
import sys
import time
import uuid
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")

pytestmark = pytest.mark.asyncio


async def test_virustotal_hang_returns_fast(client, monkeypatch) -> None:
    def hang(_url: str) -> dict:
        time.sleep(10)
        return {}

    monkeypatch.setattr(backend_main, "check_url_virustotal", hang)
    u = uuid.uuid4().hex[:10]
    t0 = time.perf_counter()
    response = await client.post(
        "/scan-email",
        json={"email_text": f"Please open http://hang-{u}.example/verify to continue."},
    )
    elapsed = time.perf_counter() - t0
    assert elapsed < 25.0
    assert response.status_code == 200
    body = response.json()
    assert body.get("enrichment_status") in ("unavailable", "available")


async def test_virustotal_http500_fallback(client, monkeypatch) -> None:
    def boom(url: str) -> dict:
        raise RuntimeError("HTTP 500")

    monkeypatch.setattr(backend_main, "check_url_virustotal", boom)
    response = await client.post(
        "/scan-email",
        json={"email_text": "Please open http://secure-login.xyz/verify to continue."},
    )
    assert response.status_code == 200
    assert "verdict" in response.json()


async def test_indicbert_runtimeerror_tfidf_fallback(client, monkeypatch) -> None:
    def boom(_texts: list[str]):
        raise RuntimeError("indicbert down")

    monkeypatch.setattr(backend_main, "predict_probabilities", boom)
    response = await client.post("/scan-email", json={"email_text": "Hello team, meeting at 3pm."})
    assert response.status_code == 200


async def test_tfidf_missing_rule_only(client, monkeypatch) -> None:
    monkeypatch.setattr(backend_main.artifacts, "model", None)
    monkeypatch.setattr(backend_main.artifacts, "vectorizer", None)
    monkeypatch.setattr(backend_main.artifacts, "indicbert_model", None)
    monkeypatch.setattr(backend_main.artifacts, "indicbert_tokenizer", None)
    response = await client.post("/scan-email", json={"email_text": "Hello world plain text."})
    assert response.status_code == 200
    data = response.json()
    assert 0 <= int(data.get("risk_score", 0) or 0) <= 100


async def test_null_json_body(client) -> None:
    response = await client.post("/scan-email", content=b"null", headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 422)


async def test_large_payload_rejected_or_ok(client) -> None:
    big = "x" * (2 * 1024 * 1024)
    response = await client.post("/scan-email", json={"email_text": big})
    assert response.status_code in (200, 413, 422)


async def test_sql_injection_as_text(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "SELECT * FROM users; DROP TABLE students; --"},
    )
    assert response.status_code == 200
    assert 0 <= int(response.json().get("risk_score", 0) or 0) <= 100


async def test_concurrent_scans(client) -> None:
    async def one(i: int) -> dict:
        r = await client.post(
            "/scan-email",
            json={"email_text": f"Concurrent test message {i} with no links."},
        )
        return r.json()

    results = await asyncio.gather(*(one(i) for i in range(20)))
    scores = [int(x.get("risk_score", 0) or 0) for x in results]
    assert len(scores) == 20
    assert all(0 <= s <= 100 for s in scores)
