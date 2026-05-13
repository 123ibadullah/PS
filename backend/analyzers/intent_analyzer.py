"""Intent, authority, action, behavior, and context engines."""

from __future__ import annotations

from typing import Any

from perf_timing import timed


@timed("analyze_intent")
def analyze_intent(
    email_text: str,
    sender_domain: str,
    linked_domains: list[str],
    trusted_sender: bool,
    has_attachment_lure_context: bool,
    has_bec_pattern_signal_engine: bool,
    has_spoof_or_lookalike_signal_engine: bool,
    has_invoice_thread_pretext: bool,
    has_mixed_link_context: bool,
    has_no_url_phishing_signal: bool,
    has_thread_hijack_signal: bool,
    has_credential_signal: bool,
    has_otp_signal: bool,
) -> dict[str, Any]:
    import main as m

    return m._analyze_intent_impl(
        email_text,
        sender_domain,
        linked_domains,
        trusted_sender,
        has_attachment_lure_context,
        has_bec_pattern_signal_engine,
        has_spoof_or_lookalike_signal_engine,
        has_invoice_thread_pretext,
        has_mixed_link_context,
        has_no_url_phishing_signal,
        has_thread_hijack_signal,
        has_credential_signal,
        has_otp_signal,
    )
