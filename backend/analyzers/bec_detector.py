"""Deterministic no-link BEC detection."""

from __future__ import annotations

from perf_timing import timed


@timed("detect_bec")
def evaluate_bec_no_link(
    email_text: str,
    *,
    linked_domains: list[str],
    action_money_requested: bool,
    behavior_urgency: bool,
    behavior_secrecy: bool,
) -> tuple[bool, str]:
    import main as m

    return m._evaluate_bec_no_link_impl(
        email_text,
        linked_domains=linked_domains,
        action_money_requested=action_money_requested,
        behavior_urgency=behavior_urgency,
        behavior_secrecy=behavior_secrecy,
    )
