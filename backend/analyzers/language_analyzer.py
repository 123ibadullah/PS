"""Language / ML probability for phishing vs benign."""

from __future__ import annotations

from perf_timing import timed


@timed("analyze_language")
def compute_language_model_probability(email_text: str, cleaned_text: str) -> tuple[float, str]:
    import main as m

    return m._compute_language_model_probability_impl(email_text, cleaned_text)
