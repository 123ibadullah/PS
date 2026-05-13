"""Coarse performance guard: scan must complete and report processing time."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio

# First call can include model load; cap is loose to avoid CI flakes.
_MAX_MS = 180_000


async def test_scan_email_returns_processing_ms_within_cap(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "Subject: ping\nPlease review the notes for the standup."},
    )
    assert response.status_code == 200
    data = response.json()
    assert "processing_ms" in data
    assert int(data["processing_ms"]) < _MAX_MS
