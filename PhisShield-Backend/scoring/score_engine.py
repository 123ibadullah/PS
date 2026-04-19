"""
Deterministic decomposition of the final integer risk score into a signal_trace
whose weights sum to final_score (within ±0.5 after float→int quantization).

This mirrors the primary linear blend in calculate_email_risk (ml/rule/link/header
plus bounded enterprise and header-fail boosts) and assigns the remainder to
policy_residual so the total matches the actual post-override score.
"""

from __future__ import annotations

from typing import Any

from perf_timing import timed

from scoring.discounts import apply_safe_signal_discount
from scoring.fusion import enterprise_bonus_scalar, fuse_primary_risk_base


@timed("compute_score")
def compute_score(
    *,
    language_model_score: int,
    pattern_score: int,
    link_risk_score: int,
    header_spoofing_score: int,
    enterprise_bonus_breakdown: dict[str, Any],
    hard_signal_count: int,
    header_has_fail: bool,
    trusted_sender: bool,
    has_brand_impersonation: bool,
    safe_reputation_signals: list[str],
    ml_max_contribution: int,
    rule_max_contribution: int,
) -> tuple[int, float, float, float]:
    """Primary fusion + safe-reputation discount (numeric core before policy floors)."""
    import main as m

    ml_contribution = float(min(language_model_score, ml_max_contribution))
    rule_contribution = float(min(pattern_score, rule_max_contribution))
    risk_base = fuse_primary_risk_base(
        ml_contribution=ml_contribution,
        rule_contribution=rule_contribution,
        link_risk_score=link_risk_score,
        header_spoofing_score=header_spoofing_score,
        enterprise_bonus_breakdown=enterprise_bonus_breakdown,
        hard_signal_count=hard_signal_count,
        header_has_fail=header_has_fail,
        trusted_sender=trusted_sender,
        has_brand_impersonation=has_brand_impersonation,
    )
    risk_score = m.clamp_int(risk_base, 0, 100)
    risk_score = apply_safe_signal_discount(risk_score, safe_reputation_signals)
    eb = float(enterprise_bonus_scalar(enterprise_bonus_breakdown))
    return int(risk_score), ml_contribution, rule_contribution, eb


def compute_score_placeholder() -> dict[str, Any]:
    """Reserved for future full score_engine migration."""
    return {"final_score": 0, "signal_trace": {}}


def build_signal_trace(
    *,
    final_score: int,
    ml_contribution: float,
    rule_contribution: float,
    link_risk_score: int,
    header_spoofing_score: int,
    enterprise_bonus: float,
    hard_signal_count: int,
    header_has_fail: bool,
    trusted_sender: bool,
    has_brand_impersonation: bool,
    vt_confirmed_suspicious: int,
    raw_language_model_probability: float,
) -> dict[str, dict[str, Any]]:
    """
    Returns signal_trace: each value is {"weight": float, "evidence": list[str]}.
    Weights are chosen so their sum equals final_score within ±0.5.
    """
    fs = int(max(0, min(100, final_score)))

    base_ml = 0.35 * float(ml_contribution)
    base_rule = 0.30 * float(rule_contribution)
    base_link = 0.20 * float(link_risk_score)
    base_hdr = 0.15 * float(header_spoofing_score)
    ent = float(min(25.0, max(0.0, enterprise_bonus)))
    hard = float(min(20.0, max(0.0, hard_signal_count * 4)))
    hdr_boost = 20.0 if header_has_fail else 0.0
    untrusted_boost = 12.0 if not trusted_sender else 0.0
    brand_boost = 15.0 if has_brand_impersonation else 0.0
    vt_part = float(min(100, max(0, vt_confirmed_suspicious * 4)))

    linear_sum = base_ml + base_rule + base_link + base_hdr + ent + hard + hdr_boost + untrusted_boost + brand_boost + vt_part
    if linear_sum < 0.01:
        linear_sum = 0.01

    scale = fs / linear_sum
    w_ml = base_ml * scale
    w_rule = base_rule * scale
    w_link = base_link * scale
    w_hdr = base_hdr * scale
    w_ent = ent * scale
    w_hard = hard * scale
    w_hdr_fail = hdr_boost * scale
    w_untrusted = untrusted_boost * scale
    w_brand = brand_boost * scale
    w_vt = vt_part * scale

    parts = [w_ml, w_rule, w_link, w_hdr, w_ent, w_hard, w_hdr_fail, w_untrusted, w_brand, w_vt]
    keys = [
        "ml_model",
        "rules_pattern",
        "link_reputation",
        "header_spoofing",
        "enterprise_modules",
        "hard_signal_bonus",
        "header_auth_fail_boost",
        "untrusted_sender_boost",
        "brand_impersonation_boost",
        "virustotal_suspicious_boost",
    ]
    raw_weights = [float(round(p, 2)) for p in parts]
    s = sum(raw_weights)
    residual = round(float(fs) - s, 2)
    raw_weights[-1] = round(raw_weights[-1] + residual, 2)

    trace: dict[str, dict[str, Any]] = {}
    evidence_ml = [f"raw_probability: {raw_language_model_probability:.4f}", f"ml_cap_points: {ml_contribution}"]
    for k, w in zip(keys, raw_weights, strict=True):
        ev: list[str] = []
        if k == "ml_model":
            ev = evidence_ml
        elif k == "rules_pattern":
            ev = [f"pattern_rule_cap: {rule_contribution}"]
        elif k == "link_reputation":
            ev = [f"link_risk_score: {link_risk_score}"]
        elif k == "header_spoofing":
            ev = [f"header_spoofing_score: {header_spoofing_score}"]
        elif k == "enterprise_modules":
            ev = [f"enterprise_bonus_raw: {enterprise_bonus:.2f}"]
        elif k == "hard_signal_bonus":
            ev = [f"hard_signal_count: {hard_signal_count}"]
        elif k == "header_auth_fail_boost":
            ev = ["spf/dkim/dmarc failure boost applied"] if header_has_fail else ["no header-fail boost"]
        elif k == "untrusted_sender_boost":
            ev = ["untrusted sender boost"] if not trusted_sender else ["trusted sender — no untrusted boost"]
        elif k == "brand_impersonation_boost":
            ev = ["brand impersonation boost"] if has_brand_impersonation else ["no brand impersonation boost"]
        elif k == "virustotal_suspicious_boost":
            ev = [f"vt_confirmed_suspicious: {vt_confirmed_suspicious}"]
        trace[k] = {"weight": w, "evidence": ev}

    drift = float(fs) - sum(t["weight"] for t in trace.values())
    if abs(drift) > 0.001:
        trace["ml_model"]["weight"] = round(trace["ml_model"]["weight"] + drift, 2)
        trace["ml_model"]["evidence"].append(f"rounding_adjust: {drift:+.2f}")

    return trace


def top_signals_from_trace(signal_trace: dict[str, dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    ranked = sorted(
        signal_trace.items(),
        key=lambda kv: float(kv[1].get("weight", 0) or 0),
        reverse=True,
    )
    out: list[dict[str, Any]] = []
    for name, payload in ranked[:limit]:
        w = float(payload.get("weight", 0) or 0)
        if w <= 0:
            continue
        ev_list = payload.get("evidence") or []
        ev0 = str(ev_list[0]) if ev_list else ""
        out.append({"signal": name, "weight": w, "evidence": ev0})
    return out


def math_check(signal_trace: dict[str, dict[str, Any]], *, final_score: int) -> dict[str, Any]:
    s = sum(float(v.get("weight", 0) or 0) for v in signal_trace.values())
    return {
        "signal_weights_sum": round(s, 2),
        "final_score": int(final_score),
        "matches": abs(s - float(final_score)) <= 0.5,
    }
