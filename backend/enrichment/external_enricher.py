"""Bundle URL sandbox, reputation, thread, threat intel, and attachment analysis."""

from __future__ import annotations

from typing import Any


def enrich_external(
    *,
    email_text: str,
    sender_domain: str,
    detected_brand: str | None,
    linked_domains: list[str],
    attachments: list[Any] | None,
    trusted_sender: bool,
    url_list: list[str],
) -> dict[str, Any]:
    import main as m

    return {
        "url_sandbox": m.analyze_url_sandbox(
            url_list,
            sender_domain=sender_domain,
            detected_brand=detected_brand,
        ),
        "attachment_analysis": m.analyze_attachment_intel(
            attachments,
            email_text,
            sender_domain=sender_domain,
        ),
        "thread_analysis": m.analyze_thread_context(
            email_text,
            sender_domain=sender_domain,
            trusted_sender=trusted_sender,
        ),
        "threat_intel": m.analyze_threat_intel(sender_domain, linked_domains, email_text),
        "sender_reputation": m.analyze_sender_reputation(
            sender_domain,
            is_trusted_sender=trusted_sender,
            suspicious_context=bool(m.URGENCY_PATTERN.search(email_text) or m.BEC_TRANSFER_PATTERN.search(email_text) or linked_domains),
            has_sensitive_request=bool(
                (m.OTP_HARVEST_PATTERN.search(email_text) and not m.is_otp_safety_notice(email_text))
                or m.CREDENTIAL_HARVEST_PATTERN.search(email_text)
            ),
        ),
    }
