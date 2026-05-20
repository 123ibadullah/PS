from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from services.metrics_service import build_api_metrics_payload

router = APIRouter(tags=["metrics"])


@router.get("/api/metrics")
def legacy_metrics(request: Request) -> dict[str, Any]:
    scans = list(getattr(request.app.state, "scan_explanations", {}).values())
    return build_api_metrics_payload(scans)
