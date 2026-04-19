"""Verdict mapping: product verdict strings, Safe downgrades, score caps."""

from .safe_overrides import apply_safe_overrides
from .verdict_engine import apply_safe_verdict_score_cap, map_score_to_verdict_and_recommendation

__all__ = ["apply_safe_overrides", "apply_safe_verdict_score_cap", "map_score_to_verdict_and_recommendation"]
