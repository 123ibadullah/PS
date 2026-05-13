"""Scoring package: fusion, discounts, deterministic score decomposition."""

from .discounts import apply_safe_signal_discount
from .fusion import enterprise_bonus_scalar, fuse_primary_risk_base
from .score_engine import build_signal_trace, compute_score_placeholder, math_check, top_signals_from_trace

__all__ = [
    "apply_safe_signal_discount",
    "build_signal_trace",
    "compute_score_placeholder",
    "enterprise_bonus_scalar",
    "fuse_primary_risk_base",
    "math_check",
    "top_signals_from_trace",
]
