"""URL extraction and reputation aggregation with bounded VT wait."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any
from urllib.parse import urlparse

from perf_timing import timed

_VT_WAIT_SEC = 2.5


@timed("analyze_links")
def analyze_links(
    email_text: str,
    sender_domain: str,
    detected_brand: str | None,
    enrichment_ctx: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    import main as m

    url_results: list[dict[str, Any]] = []
    link_risk_score = 0
    for url in m.extract_urls(email_text, limit=5):
        url_scan: dict[str, Any]
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(m.check_url_virustotal, url)
                try:
                    url_scan = fut.result(timeout=_VT_WAIT_SEC)
                except FuturesTimeout:
                    if enrichment_ctx is not None:
                        enrichment_ctx["status"] = "unavailable"
                    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", str(url)) else f"https://{url}"
                    parsed = urlparse(candidate)
                    domain = m.normalize_domain_for_comparison(parsed.hostname or parsed.netloc or "")
                    url_scan = m._local_url_heuristic_scan(str(url), domain)
        except Exception:
            if enrichment_ctx is not None:
                enrichment_ctx["status"] = "unavailable"
            candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", str(url)) else f"https://{url}"
            parsed = urlparse(candidate)
            domain = m.normalize_domain_for_comparison(parsed.hostname or parsed.netloc or "")
            url_scan = m._local_url_heuristic_scan(str(url), domain)
        source = m.normalize_url_source(str(url_scan.get("source", "unavailable")))
        trusted_domain = bool(url_scan.get("trusted_domain")) or source == "trusted_allowlist"
        malicious_count = 0 if trusted_domain else int(url_scan.get("malicious_count", 0) or 0)
        suspicious_count = 0 if trusted_domain else int(url_scan.get("suspicious_count", 0) or 0)
        risk_score = 0 if trusted_domain else m.clamp_int(url_scan.get("risk_score", 0) or 0, 0, 100)
        normalized_url_entry = {
            "url": str(url_scan.get("url") or url),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "risk_score": risk_score,
            "source": source,
            "reputation_source": m.build_url_reputation_source(url_scan),
            "trusted_domain": trusted_domain,
        }
        url_results.append(normalized_url_entry)
        link_risk_score = max(link_risk_score, int(normalized_url_entry["risk_score"]))
    vt_confirmed_malicious = sum(
        int(entry.get("malicious_count", 0) or 0)
        for entry in url_results
        if entry.get("source") == "virustotal" and int(entry.get("malicious_count", 0) or 0) > 0
    )
    vt_confirmed_suspicious = sum(
        int(entry.get("suspicious_count", 0) or 0)
        for entry in url_results
        if entry.get("source") == "virustotal" and int(entry.get("suspicious_count", 0) or 0) > 0
    )
    if vt_confirmed_malicious > 0:
        link_risk_score = max(link_risk_score, 85)
    if vt_confirmed_suspicious > 0:
        link_risk_score = min(100, link_risk_score + vt_confirmed_suspicious * 4)
    return url_results, link_risk_score, vt_confirmed_suspicious
