"""SPF/DKIM/DMARC-derived header and sender trust analysis."""

from __future__ import annotations

from typing import Any

from perf_timing import timed


@timed("analyze_headers")
def analyze_headers(
    email_text: str,
    headers_text: str | None,
    linked_domains: list[str],
) -> dict[str, Any]:
    import main as m

    return m._analyze_headers_impl(email_text, headers_text, linked_domains)
