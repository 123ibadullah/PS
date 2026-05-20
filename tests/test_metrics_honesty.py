from __future__ import annotations

import pytest

from services.metrics_service import build_api_metrics_payload, load_training_metadata


def test_metrics_not_hardcoded_defaults() -> None:
    payload = build_api_metrics_payload([])
    assert payload["accuracy_source"] == "offline_holdout_evaluation"
    assert payload["metrics_kind"] == "offline_evaluation_plus_runtime_operational"
    # Previous API returned static marketing values (0.968/0.974) unrelated to training_meta.json.
    assert payload["precision"] != 0.968
    assert payload["recall"] != 0.968


def test_metrics_offline_from_training_metadata() -> None:
    metadata = load_training_metadata()
    if not metadata:
        pytest.skip("training_meta.json not present")
    payload = build_api_metrics_payload([])
    offline = payload["offline_evaluation"]
    expected = float((metadata.get("metrics") or {}).get("accuracy", 0) or 0)
    assert abs(float(offline["accuracy"]) - expected) < 1e-6
    assert offline.get("evaluated_at") == metadata.get("trained_at")
    assert offline.get("evaluation_dataset_size") == metadata.get("test_rows")


@pytest.mark.asyncio
async def test_api_metrics_endpoint_returns_honest_payload(client) -> None:
    response = await client.get("/api/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body.get("accuracy_source") == "offline_holdout_evaluation"
    assert "offline_evaluation" in body
    assert "runtime_operational" in body
    assert body["runtime_operational"]["total_scans"] >= 0
