"""Primary risk fusion from ML, rules, links, headers, enterprise modules (numeric only)."""

from __future__ import annotations

from typing import Any


def enterprise_bonus_scalar(enterprise_bonus_breakdown: dict[str, Any]) -> float:
    """Raw weighted enterprise module bonus (before min(25, ...) cap inside fusion)."""
    return (
        0.45 * float(enterprise_bonus_breakdown.get("url_sandbox", 0) or 0)
        + 0.55 * float(enterprise_bonus_breakdown.get("attachment_analysis", 0) or 0)
        + 0.62 * float(enterprise_bonus_breakdown.get("thread_context", 0) or 0)
        + 0.65 * float(enterprise_bonus_breakdown.get("threat_intel", 0) or 0)
        + 0.40 * float(enterprise_bonus_breakdown.get("sender_reputation", 0) or 0)
    )


def fuse_primary_risk_base(
    *,
    ml_contribution: float,
    rule_contribution: float,
    link_risk_score: int,
    header_spoofing_score: int,
    enterprise_bonus_breakdown: dict[str, Any],
    hard_signal_count: int,
    header_has_fail: bool,
    trusted_sender: bool,
    has_brand_impersonation: bool,
) -> float:
    """Weighted blend + enterprise/hard/header/trust boosts. Returns raw float before clamp."""
    risk_base = (
        0.35 * float(ml_contribution)
        + 0.30 * float(rule_contribution)
        + 0.20 * float(link_risk_score)
        + 0.15 * float(header_spoofing_score)
    )
    eb = enterprise_bonus_scalar(enterprise_bonus_breakdown)
    risk_base += min(25.0, eb)
    risk_base += min(20.0, float(hard_signal_count) * 4.0)
    if header_has_fail:
        risk_base += 20.0
    if not trusted_sender:
        risk_base += 12.0
    if has_brand_impersonation:
        risk_base += 15.0
    return float(risk_base)
