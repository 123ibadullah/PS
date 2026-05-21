from __future__ import annotations

import pytest

import main as backend_main


pytestmark = pytest.mark.asyncio


def _sample_scan_record(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "email_text": "URGENT: Verify your account now to avoid suspension.",
        "risk_score": 86,
        "verdict": "High Risk",
        "model_used": "SecureBERT/MuRIL-GPU-97.4%",
        "signals": ["Urgency language", "Suspicious link", "Credential request"],
        "safe_signals": [],
        "explanation": {
            "why_risky": "Suspicious verification request with urgency and credential-harvest wording.",
        },
    }


async def test_explain_not_found_returns_404(client) -> None:
    response = await client.post("/explain", json={"scan_id": "does-not-exist"})

    assert response.status_code == 404
    assert "Explanation not found" in response.json().get("detail", "")


async def test_explain_uses_openrouter_on_success(client, monkeypatch) -> None:
    scan_id = "scan-openrouter-success"
    backend_main.app.state.scan_explanations[scan_id] = _sample_scan_record(scan_id)

    class _FakeResponse:
        status_code = 200
        text = '{"ok":true}'

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": "This looks high risk because it pressures immediate verification and resembles credential theft patterns.",
                        }
                    }
                ]
            }

    monkeypatch.setattr(backend_main, "OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(backend_main.requests, "post", lambda *args, **kwargs: _FakeResponse())

    try:
        response = await client.post("/explain", json={"scan_id": scan_id})
        assert response.status_code == 200

        payload = response.json()
        assert payload["scan_id"] == scan_id
        assert payload["source"] == "openrouter"
        assert payload["fallback_used"] is False
        assert "high risk" in payload["explanation"].lower()
    finally:
        backend_main.app.state.scan_explanations.pop(scan_id, None)


async def test_explain_falls_back_on_openrouter_http_error(client, monkeypatch) -> None:
    scan_id = "scan-openrouter-fallback"
    backend_main.app.state.scan_explanations[scan_id] = _sample_scan_record(scan_id)

    class _FakeResponse:
        status_code = 503
        text = "upstream unavailable"

        def json(self):
            return {"error": "upstream unavailable"}

    monkeypatch.setattr(backend_main, "OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(backend_main, "GEMINI_API_KEY", "")
    monkeypatch.setattr(backend_main, "LLM_PROVIDER", "openrouter")
    monkeypatch.setattr(backend_main.requests, "post", lambda *args, **kwargs: _FakeResponse())

    try:
        response = await client.post("/explain", json={"scan_id": scan_id})
        assert response.status_code == 200

        payload = response.json()
        assert payload["scan_id"] == scan_id
        assert payload["source"] == "signal_trace"
        assert payload["fallback_used"] is False
        assert payload["fallback_reason"] == "openrouter_http_503"
        assert payload.get("narrative_source") == "signal_trace"
        assert "suspicious" in payload["explanation"].lower() or "high risk" in payload["explanation"].lower()
    finally:
        backend_main.app.state.scan_explanations.pop(scan_id, None)


async def test_explain_falls_back_when_key_missing(client, monkeypatch) -> None:
    scan_id = "scan-missing-key"
    backend_main.app.state.scan_explanations[scan_id] = _sample_scan_record(scan_id)

    monkeypatch.setattr(backend_main, "OPENROUTER_API_KEY", "")
    monkeypatch.setattr(backend_main, "GEMINI_API_KEY", "")

    try:
        response = await client.post("/explain", json={"scan_id": scan_id})
        assert response.status_code == 200

        payload = response.json()
        assert payload["scan_id"] == scan_id
        assert payload["source"] == "signal_trace"
        assert payload["fallback_used"] is False
        assert payload["fallback_reason"] is None
        assert payload.get("narrative_source") == "signal_trace"
        assert payload["explanation"]
    finally:
        backend_main.app.state.scan_explanations.pop(scan_id, None)
