"""Safe-signal discounts applied to integer risk score."""

from __future__ import annotations

_SAFE_SIGNAL_WEIGHTS: dict[str, int] = {
    "spf, dkim, and dmarc passed": 12,
    "known sender history looks normal": 8,
    "newsletter / digest": 10,
    "no attachments detected": 2,
    "otp safety notice": 15,
    "informational": 10,
    "trusted provider with aligned links": 12,
}


def apply_safe_signal_discount(risk_score: int, safe_signals: list[str]) -> int:
    """Subtracts weighted discount for each confirmed safe signal. Floor = 0."""
    discount = 0
    for signal in safe_signals:
        for key, weight in _SAFE_SIGNAL_WEIGHTS.items():
            if key in signal.lower():
                discount += weight
                break
    return max(0, risk_score - discount)
