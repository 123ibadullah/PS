from __future__ import annotations

import pytest

import main as backend_main


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/health"),
        ("GET", "/api/metrics"),
        ("GET", "/api/history"),
        ("GET", "/feedback/stats"),
        ("GET", "/api/feedback/stats"),
        ("GET", "/recent-scans"),
    ],
)
@pytest.mark.asyncio
async def test_public_routes_exist(client, method: str, path: str) -> None:
    response = await client.request(method, path)
    assert response.status_code != 404, f"{method} {path} returned 404"


@pytest.mark.asyncio
async def test_feedback_routes_alias_equivalent(client, sample_emails, monkeypatch) -> None:
    monkeypatch.setattr(backend_main, "save_scan_to_db", lambda *args, **kwargs: None)
    scan = await client.post("/scan-email", json={"email_text": sample_emails["otp_scam"]})
    scan_id = scan.json().get("scan_id")
    payload = {"email_text": sample_emails["otp_scam"], "correct_label": "safe", "scan_id": scan_id}
    primary = await client.post("/feedback", json=payload)
    alias = await client.post("/api/feedback", json=payload)
    assert primary.status_code == alias.status_code == 200


@pytest.mark.asyncio
async def test_metrics_payload_structure(client) -> None:
    response = await client.get("/api/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body.get("accuracy_source") == "offline_holdout_evaluation"
    assert "offline_evaluation" in body
    assert "runtime_operational" in body
