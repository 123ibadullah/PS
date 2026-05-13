"""Safe-band downgrades (verdict + score cap); no hard-evidence bypass.

Q1: Downgrade borderline newsletter / awareness / trusted-link-only when no hard evidence.
Q2: Early exit on malicious URL or credential/attachment harvest; never raises score.
Q3: Covered by safe fixtures + regression safe rows in certification.
"""

from __future__ import annotations

import re


def _education_reading_context(email_text: str, linked_domains: list[str]) -> bool:
    """True for internal/security education copy: discusses threats without actionable lures."""
    if linked_domains or re.search(r"https?://", email_text, re.IGNORECASE):
        return False
    return bool(
        re.search(
            r"\b(training|awareness|digest|handbook|newsletter|module|simulated|education\s+only|compliance)\b",
            email_text,
            re.IGNORECASE,
        )
        and re.search(r"\b(phishing|otp|credential|password\s+policies|stuffing)\b", email_text, re.IGNORECASE)
        and not re.search(
            r"\b(click\s+here|verify\s+now|send\s+your\s+otp|share\s+your\s+otp|http://|https://)\b",
            email_text,
            re.IGNORECASE,
        )
    )


def apply_safe_overrides(
    risk_score: int,
    verdict: str,
    email_text: str,
    *,
    has_malicious_url: bool,
    has_suspicious_url: bool,
    has_credential_or_otp: bool,
    has_attachment_credential: bool,
    has_urgency: bool,
    trusted_sender: bool,
    linked_domains: list[str],
) -> tuple[int, str]:
    """Can ONLY lower risk_score and change verdict to Safe; skipped when hard evidence is present."""
    import main as m

    edu_read = _education_reading_context(email_text, linked_domains)
    if has_malicious_url or has_attachment_credential or (has_credential_or_otp and not edu_read):
        return risk_score, verdict

    if (
        linked_domains
        and all(
            m.is_safe_override_trusted_domain(m.extract_root_domain(domain) or domain)
            for domain in linked_domains
            if str(domain).strip()
        )
        and not has_suspicious_url
        and not has_urgency
    ):
        return min(risk_score, 10), "Safe"

    if (
        m.is_otp_safety_notice(email_text)
        and not linked_domains
        and not has_suspicious_url
        and re.search(r"\b(awareness|reminder|training|report(?:\s+it)?|security team)\b", email_text, re.IGNORECASE)
    ):
        return min(risk_score, 20), "Safe"

    if (
        re.search(r"\bweekly digest\b", email_text, re.IGNORECASE)
        and re.search(r"\blinkedin\b", email_text, re.IGNORECASE)
        and not has_malicious_url
        and not has_suspicious_url
        and not has_credential_or_otp
        and not has_urgency
        and not has_attachment_credential
    ):
        return min(risk_score, 18), "Safe"

    if m._WELCOME_PATTERN.search(email_text) and not has_suspicious_url and not has_urgency:
        return min(risk_score, 15), "Safe"

    if m._NOTIFICATION_PATTERN.search(email_text) and not has_suspicious_url and not linked_domains:
        return min(risk_score, 18), "Safe"

    if (
        trusted_sender
        and m._NEWSLETTER_FOOTER_PATTERN.search(email_text)
        and not has_suspicious_url
        and not has_urgency
    ):
        return min(risk_score, 20), "Safe"

    if (
        m._NEWSLETTER_FOOTER_PATTERN.search(email_text)
        and not has_suspicious_url
        and not has_malicious_url
        and not linked_domains
        and not has_urgency
    ):
        return min(risk_score, 20), "Safe"

    if edu_read and not has_suspicious_url:
        return min(risk_score, 18), "Safe"

    return risk_score, verdict
