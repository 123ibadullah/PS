"""
PhishShield Thread Hijacking Detector
======================================
Detects conversation thread hijacking patterns in email chains:
- Reply-chain abuse (sudden payment/transfer requests in ongoing threads)
- Tone shift detection (conversational -> urgent/threatening)
- Sender mismatch vs previous messages in thread
- BEC (Business Email Compromise) indicators within threads

Works by parsing reply chains and comparing the newest message
segment against the thread history.
"""

from __future__ import annotations

import re
import logging
from typing import Any

logger = logging.getLogger("phishshield.thread_analyzer")

# ---------------------------------------------------------------------------
# Thread boundary detection
# ---------------------------------------------------------------------------

THREAD_BOUNDARY_PATTERNS = [
    re.compile(r"^-{3,}\s*Original\s+Message\s*-{3,}", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^On\s+.+\s+wrote\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^>{1,3}\s*", re.MULTILINE),
    re.compile(r"^-{3,}\s*Forwarded\s+(?:message|Message)\s*-{3,}", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^From:\s+.+\nSent:\s+", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^Begin\s+forwarded\s+message:", re.IGNORECASE | re.MULTILINE),
]

THREAD_SUBJECT_PATTERN = re.compile(
    r"^(?:re|fw|fwd)\s*:\s*",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Threat indicators in newest message segment
# ---------------------------------------------------------------------------

PAYMENT_SWITCH_PATTERNS = [
    re.compile(r"\b(updated?\s+(?:bank|account)\s+(?:details?|information|number))\b", re.IGNORECASE),
    re.compile(r"\b(new\s+(?:bank|account)\s+details?)\b", re.IGNORECASE),
    re.compile(r"\b(change\s+(?:of|in)\s+(?:bank|account|payment)\s+details?)\b", re.IGNORECASE),
    re.compile(r"\b((?:please|kindly)\s+(?:wire|transfer|send)\s+(?:to|the)\s+(?:new|updated|following))\b", re.IGNORECASE),
    re.compile(r"\b(updated?\s+beneficiary)\b", re.IGNORECASE),
    re.compile(r"\b(different\s+account)\b", re.IGNORECASE),
    re.compile(r"\b((?:use|process)\s+(?:this|the)\s+(?:new|updated)\s+(?:account|bank))\b", re.IGNORECASE),
    re.compile(r"\b(payment\s+(?:should|must)\s+(?:go|be\s+(?:sent|made|transferred))\s+to)\b", re.IGNORECASE),
    re.compile(r"\b(urgent(?:ly)?\s+(?:wire|transfer|pay|send))\b", re.IGNORECASE),
    re.compile(r"\b(confidential(?:ly)?\s+(?:handle|process|transfer|wire))\b", re.IGNORECASE),
]

URGENCY_ESCALATION_PATTERNS = [
    re.compile(r"\b(urgent(?:ly)?|asap|immediately|right\s+now|time[\s-]?sensitive)\b", re.IGNORECASE),
    re.compile(r"\b(do\s+not\s+(?:delay|wait)|act\s+(?:now|immediately|fast))\b", re.IGNORECASE),
    re.compile(r"\b(deadline\s+(?:is|was)\s+(?:today|now|passed|tomorrow))\b", re.IGNORECASE),
    re.compile(r"\b(last\s+chance|final\s+notice|final\s+warning)\b", re.IGNORECASE),
    re.compile(r"\b(failure\s+to\s+(?:comply|respond|act)\s+(?:will|may))\b", re.IGNORECASE),
]

CONFIDENTIALITY_PRESSURE_PATTERNS = [
    re.compile(r"\b(keep\s+this\s+(?:confidential|private|between\s+us))\b", re.IGNORECASE),
    re.compile(r"\b(do\s+not\s+(?:share|discuss|tell|forward|copy)\s+(?:this|anyone))\b", re.IGNORECASE),
    re.compile(r"\b(strictly\s+confidential)\b", re.IGNORECASE),
    re.compile(r"\b((?:don't|do\s+not)\s+(?:involve|loop\s+in|cc)\s+(?:anyone|others))\b", re.IGNORECASE),
]

BEC_AUTHORITY_PATTERNS = [
    re.compile(r"\b(ceo|cfo|cto|managing\s+director|president|chairman)\b", re.IGNORECASE),
    re.compile(r"\b(I(?:'m|'m|\s+am)\s+(?:in\s+a\s+meeting|traveling|at\s+a\s+conference|busy))\b", re.IGNORECASE),
    re.compile(r"\b((?:can\s+you|please)\s+(?:handle|process|take\s+care\s+of)\s+(?:this|it))\b", re.IGNORECASE),
]

# Conversational/normal tone indicators (for baseline comparison)
NORMAL_TONE_PATTERNS = [
    re.compile(r"\b(thank(?:s|\s+you)|regards|best\s+wishes|sincerely|cheers|take\s+care)\b", re.IGNORECASE),
    re.compile(r"\b(hope\s+(?:you(?:'re| are)?\s+)?(?:doing\s+)?well|how\s+are\s+you)\b", re.IGNORECASE),
    re.compile(r"\b(looking\s+forward|please\s+(?:find|see)\s+attached|as\s+discussed)\b", re.IGNORECASE),
    re.compile(r"\b((?:hi|hello|dear|hey)\s+\w+)\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Parse thread segments
# ---------------------------------------------------------------------------

def _split_thread_segments(email_text: str) -> list[str]:
    """Split email into thread segments (newest first).
    
    Returns list where [0] is the newest message and subsequent 
    entries are older messages in the thread.
    """
    segments: list[str] = []

    # Find all boundary positions
    boundaries: list[int] = []
    for pattern in THREAD_BOUNDARY_PATTERNS:
        for match in pattern.finditer(email_text):
            boundaries.append(match.start())

    if not boundaries:
        return [email_text.strip()]

    boundaries = sorted(set(boundaries))

    # Extract segments
    prev_pos = 0
    for boundary in boundaries:
        segment = email_text[prev_pos:boundary].strip()
        if segment and len(segment) > 10:
            segments.append(segment)
        prev_pos = boundary

    # Last segment (the quoted/forwarded content)
    last_segment = email_text[boundaries[-1]:].strip()
    if last_segment and len(last_segment) > 10:
        segments.append(last_segment)

    return segments if segments else [email_text.strip()]


def _extract_sender_from_segment(segment: str) -> str:
    """Extract sender email/name from a thread segment."""
    # Try "From: ..." header
    from_match = re.search(
        r"(?:^|\n)From:\s*(?:.*?<)?([^@\s<>]+@[a-z0-9.-]+\.[a-z]{2,})(?:>)?",
        segment,
        re.IGNORECASE,
    )
    if from_match:
        return from_match.group(1).lower().strip()

    # Try "On <date> <name> wrote:" pattern
    wrote_match = re.search(
        r"On\s+.+\s+<?([^@\s<>]+@[a-z0-9.-]+\.[a-z]{2,})>?\s+wrote",
        segment,
        re.IGNORECASE,
    )
    if wrote_match:
        return wrote_match.group(1).lower().strip()

    return ""


def _compute_tone_score(text: str) -> dict[str, float]:
    """Compute a simple tone profile for a text segment."""
    text_lower = text.lower()
    word_count = max(len(text_lower.split()), 1)

    urgency_hits = sum(1 for p in URGENCY_ESCALATION_PATTERNS if p.search(text))
    payment_hits = sum(1 for p in PAYMENT_SWITCH_PATTERNS if p.search(text))
    confidentiality_hits = sum(1 for p in CONFIDENTIALITY_PRESSURE_PATTERNS if p.search(text))
    authority_hits = sum(1 for p in BEC_AUTHORITY_PATTERNS if p.search(text))
    normal_hits = sum(1 for p in NORMAL_TONE_PATTERNS if p.search(text))

    return {
        "urgency": urgency_hits / word_count * 100,
        "payment": payment_hits / word_count * 100,
        "confidentiality": confidentiality_hits / word_count * 100,
        "authority": authority_hits / word_count * 100,
        "normal": normal_hits / word_count * 100,
        "urgency_raw": urgency_hits,
        "payment_raw": payment_hits,
        "confidentiality_raw": confidentiality_hits,
        "authority_raw": authority_hits,
        "normal_raw": normal_hits,
    }


# ---------------------------------------------------------------------------
# Main thread hijack analyzer
# ---------------------------------------------------------------------------

def analyze_thread_hijack(
    email_text: str,
    *,
    sender_domain: str = "",
    trusted_sender: bool = False,
) -> dict[str, Any]:
    """
    Comprehensive thread hijacking detection.
    
    Detects:
    1. Sudden payment/transfer requests within reply threads
    2. Tone shifts (conversational -> urgent/threatening)
    3. Sender mismatches within the thread
    4. Confidentiality pressure tactics (BEC indicator)
    5. Authority impersonation within threads
    
    Returns dict with signals, score_bonus, and analysis details.
    """
    signals: list[str] = []
    score_bonus = 0
    analysis: dict[str, Any] = {
        "is_thread": False,
        "segment_count": 0,
        "sender_mismatch": False,
        "tone_shift": False,
        "hijack_indicators": [],
    }

    # Check if this is a thread/reply
    is_thread = bool(
        THREAD_SUBJECT_PATTERN.search(email_text)
        or any(p.search(email_text) for p in THREAD_BOUNDARY_PATTERNS)
    )
    analysis["is_thread"] = is_thread

    if not is_thread:
        return {
            "signals": signals,
            "score_bonus": 0,
            "analysis": analysis,
        }

    # Split into segments
    segments = _split_thread_segments(email_text)
    analysis["segment_count"] = len(segments)

    if len(segments) < 2:
        # Thread marker present but no clear separation — still analyze newest
        newest = segments[0] if segments else email_text
        tone = _compute_tone_score(newest)

        # Even without segments, check for BEC patterns in threads
        if tone["payment_raw"] >= 2 and tone["urgency_raw"] >= 1:
            sig = "Thread hijack behavior detected"
            signals.append(sig)
            analysis["hijack_indicators"].append("payment_switch_in_thread")
            score_bonus += 18

        if tone["confidentiality_raw"] >= 1 and tone["payment_raw"] >= 1:
            sig = "Conversation tone anomaly"
            if sig not in signals:
                signals.append(sig)
            analysis["hijack_indicators"].append("confidentiality_pressure")
            score_bonus += 12

        return {
            "signals": signals,
            "score_bonus": min(score_bonus, 30),
            "analysis": analysis,
        }

    newest = segments[0]
    older_segments = segments[1:]
    older_combined = " ".join(older_segments)

    # --- 1. Sender mismatch detection ---
    newest_sender = _extract_sender_from_segment(newest) or sender_domain
    older_senders = [_extract_sender_from_segment(seg) for seg in older_segments]
    older_senders = [s for s in older_senders if s]

    if newest_sender and older_senders:
        for old_sender in older_senders:
            if old_sender and newest_sender:
                newest_domain = newest_sender.split("@")[-1] if "@" in newest_sender else newest_sender
                old_domain = old_sender.split("@")[-1] if "@" in old_sender else old_sender
                if newest_domain != old_domain and not trusted_sender:
                    analysis["sender_mismatch"] = True
                    sig = "Sender mismatch in thread chain"
                    if sig not in signals:
                        signals.append(sig)
                    analysis["hijack_indicators"].append(f"sender_switch: {old_domain} -> {newest_domain}")
                    score_bonus += 15
                    break

    # --- 2. Tone shift detection ---
    newest_tone = _compute_tone_score(newest)
    older_tone = _compute_tone_score(older_combined)

    # Detect shift: older messages are normal, newest is urgent/payment-focused
    tone_shift_detected = (
        (newest_tone["urgency_raw"] >= 2 and older_tone["urgency_raw"] == 0)
        or (newest_tone["payment_raw"] >= 2 and older_tone["payment_raw"] == 0)
        or (
            newest_tone["urgency_raw"] >= 1
            and newest_tone["payment_raw"] >= 1
            and older_tone["urgency_raw"] == 0
            and older_tone["payment_raw"] == 0
        )
    )

    if tone_shift_detected:
        analysis["tone_shift"] = True
        sig = "Conversation tone anomaly"
        if sig not in signals:
            signals.append(sig)
        analysis["hijack_indicators"].append("tone_shift_detected")
        score_bonus += 15

    # --- 3. Payment/transfer request in thread ---
    payment_switch_count = sum(1 for p in PAYMENT_SWITCH_PATTERNS if p.search(newest))
    if payment_switch_count >= 2:
        sig = "Thread hijack behavior detected"
        if sig not in signals:
            signals.append(sig)
        analysis["hijack_indicators"].append("multiple_payment_switches")
        score_bonus += 20
    elif payment_switch_count == 1 and (newest_tone["urgency_raw"] >= 1 or analysis["sender_mismatch"]):
        sig = "Thread hijack behavior detected"
        if sig not in signals:
            signals.append(sig)
        analysis["hijack_indicators"].append("payment_switch_with_urgency_or_sender_mismatch")
        score_bonus += 15

    # --- 4. Confidentiality pressure (BEC hallmark) ---
    if newest_tone["confidentiality_raw"] >= 1:
        if payment_switch_count >= 1 or newest_tone["authority_raw"] >= 1:
            sig = "BEC confidentiality pressure in thread"
            if sig not in signals:
                signals.append(sig)
            analysis["hijack_indicators"].append("confidentiality_with_payment_or_authority")
            score_bonus += 15

    # --- 5. Authority impersonation ---
    if newest_tone["authority_raw"] >= 2 and payment_switch_count >= 1:
        sig = "Authority impersonation in reply thread"
        if sig not in signals:
            signals.append(sig)
        analysis["hijack_indicators"].append("authority_impersonation")
        score_bonus += 12

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 40),  # Cap to prevent FP inflation
        "analysis": analysis,
    }
