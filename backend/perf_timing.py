"""Lightweight timing hooks for performance certification (P50/P95/P99)."""
from __future__ import annotations

import functools
import time
from collections import defaultdict
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

_stage_samples: dict[str, list[float]] = defaultdict(list)


def clear_timings() -> None:
    _stage_samples.clear()


def record_timing(stage: str, seconds: float) -> None:
    _stage_samples[stage].append(seconds)


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def stats_for_stage(stage: str) -> dict[str, float]:
    vals = sorted(_stage_samples.get(stage, []))
    if not vals:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "n": 0.0}
    return {
        "p50": percentile(vals, 50) * 1000,
        "p95": percentile(vals, 95) * 1000,
        "p99": percentile(vals, 99) * 1000,
        "n": float(len(vals)),
    }


def timed(stage: str) -> Callable[[F], F]:
    def deco(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                record_timing(stage, time.perf_counter() - t0)

        return wrapper  # type: ignore[return-value]

    return deco
