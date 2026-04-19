"""Central verdict assignment from numeric risk (no URL/ML logic)."""

from perf_timing import timed


def map_score_to_verdict_and_recommendation(risk_score: int) -> tuple[str, str]:
    """Map 0–100 score to product verdict + user-facing recommendation."""
    if risk_score >= 90:
        return "Critical", "Immediate block and quarantine"
    if risk_score >= 70:
        return "High Risk", "Block / quarantine"
    if risk_score >= 40:
        return "Suspicious", "Manual review"
    return "Safe", "Allow but continue monitoring"


def apply_safe_verdict_score_cap(risk_score: int, final_verdict: str) -> int:
    """When verdict is Safe, cap displayed score to the Safe band."""
    if final_verdict == "Safe":
        return min(int(risk_score), 20)
    return int(risk_score)


@timed("finalize_verdict")
def finalize_verdict_from_score(risk_score: int) -> tuple[str, str]:
    """Thin verdict mapping entrypoint for performance instrumentation."""
    return map_score_to_verdict_and_recommendation(int(risk_score))
