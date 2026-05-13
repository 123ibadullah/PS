from __future__ import annotations

import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _safe_text(value: Any, fallback: str = "N/A") -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def _normalize_confidence_percent(value: Any, *, risk_score: int) -> str:
    raw_value = value
    if raw_value is not None and str(raw_value).strip():
        text = str(raw_value).strip()
        try:
            number = float(text.rstrip("%"))
            if 0 <= number <= 1:
                number *= 100
            return f"{int(round(number))}%"
        except (TypeError, ValueError):
            if text.endswith("%"):
                return text

    # Fallback is only used when confidence is genuinely missing.
    fallback = max(5.0, min(95.0, 100.0 - float(risk_score)))
    return f"{int(round(fallback))}%"


def _normalize_language(value: Any) -> str:
    text = str(value).strip().upper() if value is not None else ""
    return text or "EN"


def _is_low_value_signal(signal: str) -> bool:
    normalized = signal.strip().lower()
    if not normalized:
        return True

    low_value_patterns = (
        "no attachments detected",
        "attachment present - scan recommended",
        "informational tone detected",
        "known sender history looks normal",
        "header verification passed",
        "header authenticity could not be fully verified",
        "trusted sender with no strong phishing signals detected",
        "benign transaction language detected",
        "known brand pattern looks normal",
        "official in-app kyc reminder",
        "bank safety reminder",
        "otp safety notification",
        "trusted otp or security notice",
    )
    return any(pattern in normalized for pattern in low_value_patterns)


def _collect_signal_block(scan_data: dict[str, Any]) -> tuple[list[str], list[str], str]:
    source_risk_signals = _normalize_list(scan_data.get("signals"))
    source_safe_signals = _normalize_list(scan_data.get("safe_signals"))
    risk_signals = [signal for signal in source_risk_signals if not _is_low_value_signal(signal)]
    safe_signals = [signal for signal in source_safe_signals if not _is_low_value_signal(signal)]
    email_text = str(scan_data.get("email_text") or "")
    detection_text = " ".join([email_text, " ".join(source_risk_signals), " ".join(source_safe_signals)]).lower()

    def add_unique(items: list[str], label: str) -> None:
        if label and label.lower() not in {item.lower() for item in items}:
            items.append(label)

    if not any(re.search(r"\botp\b", signal, re.I) for signal in risk_signals):
        if re.search(r"\botp\b", detection_text):
            add_unique(risk_signals, "OTP request detected")

    if not any(re.search(r"\b(verify|login|continue)\b", signal, re.I) for signal in risk_signals):
        if re.search(r"\b(verify|login|continue)\b", detection_text):
            add_unique(risk_signals, "Credential verification intent detected")

    has_url = bool(re.search(r"https?://|www\.", detection_text)) or any(
        re.search(r"\blink\b|\burl\b|domain", signal, re.I) for signal in risk_signals
    )
    has_urgency = bool(re.search(r"urgent|immediately|suspend|deadline|act now|pressure|jaldi|band ho jayega", detection_text)) or any(
        re.search(r"urgent|urgency|immediately|deadline|suspend|pressure", signal, re.I) for signal in risk_signals
    )

    if has_url and not any(re.search(r"\blink\b|\burl\b|domain", signal, re.I) for signal in risk_signals):
        add_unique(risk_signals, "Link included in message")
    if has_urgency and not any(re.search(r"urgency|urgent|pressure|deadline|immediately|suspend", signal, re.I) for signal in risk_signals):
        add_unique(risk_signals, "Urgency language")

    if not has_url:
        add_unique(safe_signals, "No malicious link detected")
    if not has_urgency:
        add_unique(safe_signals, "No urgency language detected")

    domain_trust = scan_data.get("domainTrust") if isinstance(scan_data.get("domainTrust"), dict) else {}
    has_trusted_domain = str(domain_trust.get("status", "")).strip().lower() == "trusted" or any(
        re.search(r"trusted domain", signal, re.I) for signal in [*source_safe_signals, *source_risk_signals]
    )
    if has_trusted_domain:
        add_unique(safe_signals, "Trusted domain detected")

    allowed_safe_order = ["No malicious link detected", "No urgency language detected", "Trusted domain detected"]
    safe_lookup = {signal.strip().lower(): signal.strip() for signal in safe_signals if signal.strip()}
    safe_signals = [label for label in allowed_safe_order if label.lower() in safe_lookup]

    if risk_signals:
        risk_signals = risk_signals[:8]
    if safe_signals:
        safe_signals = safe_signals[:3]

    return risk_signals, safe_signals, detection_text


def _derive_key_findings(risk_signals: list[str], safe_signals: list[str], detection_text: str) -> list[str]:
    findings: list[str] = []

    has_link_signal = any(re.search(r"\blink\b|\burl\b|domain", signal, re.I) for signal in risk_signals) or bool(re.search(r"https?://|www\.", detection_text))
    has_urgency_signal = any(re.search(r"urgent|urgency|immediately|deadline|suspend|pressure", signal, re.I) for signal in risk_signals) or bool(
        re.search(r"urgent|immediately|suspend|deadline|act now|pressure|jaldi|band ho jayega", detection_text)
    )

    if any(re.search(r"\botp\b", signal, re.I) for signal in risk_signals) or re.search(r"\botp\b", detection_text):
        findings.append("OTP request detected")
    if any(re.search(r"credential|verify|login|continue|verification intent", signal, re.I) for signal in risk_signals) or re.search(r"\b(verify|login|continue)\b", detection_text):
        findings.append("Credential intent detected")
    if has_link_signal:
        findings.append("Suspicious link detected")
    if has_urgency_signal:
        findings.append("Urgency or pressure language detected")
    if any(signal.lower() == "no malicious link detected" for signal in safe_signals) or not re.search(r"https?://|www\.", detection_text):
        findings.append("No malicious link detected")

    deduped: list[str] = []
    seen: set[str] = set()
    for item in findings:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped or ["No critical high-risk finding detected"]


def _build_reasoning_sections(risk_signals: list[str], safe_signals: list[str]) -> tuple[str, str, str]:
    normalized_risk = [signal.lower() for signal in risk_signals]
    normalized_safe = [signal.lower() for signal in safe_signals]

    has_otp = any("otp" in signal for signal in normalized_risk)
    has_credential_intent = any(re.search(r"credential|verification intent|verify|login|continue", signal) for signal in normalized_risk)
    has_no_link_signal = any(signal == "no malicious link detected" for signal in normalized_safe)
    has_no_urgency_signal = any(signal == "no urgency language detected" for signal in normalized_safe)
    has_link_issue = any("link" in signal or "url" in signal or "domain" in signal for signal in normalized_risk) and not has_no_link_signal
    has_urgency = any("urgency" in signal or "urgent" in signal or "deadline" in signal or "suspend" in signal for signal in normalized_risk) and not has_no_urgency_signal

    risk_parts: list[str] = []
    if has_otp:
        risk_parts.append("an OTP request")
    if has_credential_intent:
        risk_parts.append("credential usage intent")
    if has_link_issue:
        risk_parts.append("link or domain concerns")
    if has_urgency:
        risk_parts.append("urgency pressure")

    if risk_parts:
        if len(risk_parts) == 1:
            primary = f"The message shows {risk_parts[0]}, which can lead to unauthorized account access."
        else:
            joined = ", ".join(risk_parts[:-1]) + f" and {risk_parts[-1]}"
            primary = f"The message combines {joined}, which increases the likelihood of phishing or account misuse."
    else:
        primary = "The message contains no strong high-risk signals, so it should be reviewed against the sender context before action."

    mitigations: list[str] = []
    if has_no_link_signal:
        mitigations.append("No malicious link detected")
    if has_no_urgency_signal:
        mitigations.append("No urgency language detected")

    if mitigations:
        if len(mitigations) == 1:
            secondary = f"The report also notes {mitigations[0]}, which lowers immediate exposure."
        else:
            secondary = f"The report also notes {mitigations[0]} and {mitigations[1]}, which lower immediate exposure."
    else:
        if has_urgency and has_link_issue:
            secondary = "Presence of urgency language and suspicious link increases risk severity."
        elif has_urgency:
            secondary = "Urgency or pressure language increases the risk of rushed user action."
        elif has_link_issue:
            secondary = "Suspicious link or domain indicators increase the chance of credential capture."
        else:
            secondary = "The message has no clear reducing indicators, so manual verification is recommended."

    if has_otp and has_credential_intent and has_link_issue:
        details = "An OTP request combined with credential usage intent and link/domain risk points to a coordinated phishing flow targeting account access."
    elif has_otp and has_credential_intent:
        details = "An OTP request together with credential usage intent suggests a social-engineering flow that could lead to unauthorized account access."
    elif has_otp:
        details = "An OTP request alone is sensitive because one-time codes should never be shared through reply chains or unverified prompts."
    elif has_credential_intent:
        details = "Credential usage intent can indicate an attempt to move the recipient into a sign-in or verification flow that may result in account compromise."
    elif has_link_issue:
        details = "Link or domain concerns remain important because a malicious destination can be used to capture credentials or redirect the user."
    else:
        details = "The signal mix still warrants caution because subtle phishing attempts can rely on context, sender identity, or account-related prompts."

    return primary, secondary, details


def generate_pdf_report(scan_data: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="PhishShield Threat Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    section_style = ParagraphStyle(
        "SectionStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#111827"),
    )

    verdict = _safe_text(scan_data.get("verdict"), "Unknown")
    risk_score = int(scan_data.get("risk_score", 0) or 0)
    confidence = _normalize_confidence_percent(scan_data.get("confidence"), risk_score=risk_score)
    detected_language = _normalize_language(scan_data.get("detectedLanguage") or scan_data.get("language"))
    recommendation = _safe_text(scan_data.get("recommendation"), "Review manually")
    scan_id = _safe_text(scan_data.get("scan_id"))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    risk_signals, safe_signals, detection_text = _collect_signal_block(scan_data)
    key_findings = _derive_key_findings(risk_signals, safe_signals, detection_text)
    primary_reason, secondary_reason, why_risky = _build_reasoning_sections(risk_signals, safe_signals)

    email_preview = _safe_text(scan_data.get("email_text"), "")
    email_preview = email_preview.replace("\n", " ").strip()
    if len(email_preview) > 420:
        email_preview = email_preview[:417] + "..."

    story: list[Any] = [
        Paragraph("PhishShield Threat Intelligence Report", title_style),
        Paragraph(f"Scan ID: {scan_id} | Generated: {generated_at}", subtitle_style),
        Spacer(1, 8),
    ]

    summary_table = Table(
        [
            ["Verdict", verdict],
            ["Risk Score", f"{risk_score}/100"],
            ["Confidence", str(confidence)],
            ["Detected Language", detected_language],
            ["Recommendation", recommendation],
        ],
        colWidths=[44 * mm, 126 * mm],
        hAlign="LEFT",
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f8fafc")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ]
        )
    )
    story.append(summary_table)

    story.extend(
        [
            Spacer(1, 10),
            Paragraph("Key Findings", section_style),
            *[Paragraph(f"- {finding}", body_style) for finding in key_findings],
            Spacer(1, 8),
            Paragraph("Why This Was Flagged", section_style),
            Paragraph(f"Primary: {primary_reason}", body_style),
            Paragraph(f"Secondary: {secondary_reason}", body_style),
            Paragraph(f"Details: {why_risky}", body_style),
            Spacer(1, 8),
            Paragraph("Risk Signals", section_style),
            Paragraph("Risk Signals: " + (", ".join(risk_signals) if risk_signals else "None"), body_style),
            Spacer(1, 6),
            Paragraph("Safe Signals", section_style),
            Paragraph("Safe Signals: " + (", ".join(safe_signals) if safe_signals else "None"), body_style),
            Spacer(1, 8),
            Paragraph("Email Preview", section_style),
            Paragraph(_safe_text(email_preview, "No preview available"), body_style),
        ]
    )

    doc.build(story)
    return buffer.getvalue()
