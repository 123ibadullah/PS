"""Security hardening checks (413/422/null bytes/rate limit/error hygiene)."""

from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

backend_main = importlib.import_module("main")
app = backend_main.app

pytestmark = pytest.mark.asyncio


async def test_body_over_1mb_returns_413() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pad = b"x" * (1024 * 1024 + 64)
        r = await client.post(
            "/scan-email",
            content=pad,
            headers={"Content-Type": "application/json", "content-length": str(len(pad))},
        )
        assert r.status_code == 413


async def test_invalid_json_422(client) -> None:
    r = await client.post("/scan-email", content=b"{", headers={"Content-Type": "application/json"})
    assert r.status_code == 422


async def test_null_bytes_stripped_no_crash(client) -> None:
    r = await client.post("/scan-email", json={"email_text": "hello\x00world"})
    assert r.status_code == 200


async def test_rate_limit_429(monkeypatch) -> None:
    monkeypatch.setattr(backend_main, "get_scan_client_key", lambda *_a, **_k: "ip:10.0.0.99")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        codes = []
        for _ in range(65):
            resp = await client.post("/scan-email", json={"email_text": f"rate test {_}"})
            codes.append(resp.status_code)
        assert 429 in codes


async def test_scan_internal_error_no_stack(client, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("SECRET_STACK")

    monkeypatch.setattr(backend_main, "calculate_email_risk", boom)
    r = await client.post("/scan-email", json={"email_text": "x"})
    assert r.status_code == 500
    body = str(r.json())
    assert "SECRET_STACK" not in body
