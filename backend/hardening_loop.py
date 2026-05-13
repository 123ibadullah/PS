from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any

import main as backend_main
from main import ExplainRequest, calculate_email_risk, explain_scan, load_artifacts


BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports" / "verification" / "hardening-loop"


@dataclass
class EmailCase:
    case_id: str
    expected_verdict: str
    email_text: str
    headers_text: str | None = None
    attachments: list[dict[str, Any]] | None = None
    tags: list[str] = field(default_factory=list)
    required_signal_keywords: list[str] = field(default_factory=list)
    consistency_group: str | None = None


@dataclass
class CaseResult:
    case_id: str
    expected_verdict: str
    actual_verdict: str
    risk_score: int
    confidence: int
    scan_id: str
    matched_signals: list[str]
    explanation: str
    tags: list[str]
    required_signal_keywords: list[str]
    consistency_group: str | None
    passed: bool
    error: str | None = None


def _normalize_verdict(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"high risk", "phishing", "high-risk", "high_risk"}:
        return "High Risk"
    if normalized in {"suspicious", "review", "manual review"}:
        return "Suspicious"
    return "Safe"


def _build_email(from_line: str, subject: str, body: str) -> str:
    return f"From: {from_line}\nSubject: {subject}\n\n{body.strip()}"


def _headers_pass(from_email: str) -> str:
    domain = from_email.split("@")[-1]
    return (
        f"From: <{from_email}>\n"
        f"Reply-To: {from_email}\n"
        f"Return-Path: <{from_email}>\n"
        f"Authentication-Results: mx.{domain}; spf=pass dkim=pass dmarc=pass"
    )


def _headers_softfail(from_email: str, reply_to: str | None = None) -> str:
    domain = from_email.split("@")[-1]
    reply = reply_to or from_email
    return (
        f"From: <{from_email}>\n"
        f"Reply-To: {reply}\n"
        f"Return-Path: <bounce@{domain}>\n"
        f"Authentication-Results: mx.{domain}; spf=softfail dkim=none dmarc=none"
    )


def _headers_fail(from_email: str, reply_to: str, return_path: str) -> str:
    domain = from_email.split("@")[-1]
    return (
        f"From: <{from_email}>\n"
        f"Reply-To: {reply_to}\n"
        f"Return-Path: <{return_path}>\n"
        f"Authentication-Results: mx.{domain}; spf=fail dkim=fail dmarc=fail"
    )


def _add_case(cases: list[EmailCase], case: EmailCase) -> None:
    cases.append(case)


def generate_dataset(seed: int) -> list[EmailCase]:
    random.seed(seed)
    cases: list[EmailCase] = []

    safe_id = 1
    suspicious_id = 1
    high_id = 1

    safe_senders = [
        ("Google Security <no-reply@accounts.google.com>", "no-reply@accounts.google.com", "Google"),
        ("GitHub Notifications <noreply@github.com>", "noreply@github.com", "GitHub"),
        ("Medium Digest <newsletter@medium.com>", "newsletter@medium.com", "Medium"),
        ("LinkedIn Updates <updates@linkedin.com>", "updates@linkedin.com", "LinkedIn"),
        ("Amazon Alerts <account-update@amazon.com>", "account-update@amazon.com", "Amazon"),
        ("Paytm Info <alerts@paytm.com>", "alerts@paytm.com", "Paytm"),
        ("OpenAI Updates <no-reply@openai.com>", "no-reply@openai.com", "OpenAI"),
    ]

    safe_templates = [
        "We noticed a new sign-in from your saved device. If this was you, no action is needed.",
        "This is your weekly digest. You can manage notification settings or unsubscribe any time.",
        "Your monthly invoice was processed successfully. No OTP, password, or PIN is requested in this email.",
        "Routine account activity summary. Review details from the official app when convenient.",
        "Security reminder: never share OTPs, passwords, or PINs. This is an awareness notice only.",
    ]

    for sender_label, sender_email, brand in safe_senders:
        for template in safe_templates:
            subject = f"{brand} account update"
            body = f"{template} Official support page: https://{sender_email.split('@')[-1]}/help"
            _add_case(
                cases,
                EmailCase(
                    case_id=f"SAFE-{safe_id:03d}",
                    expected_verdict="Safe",
                    email_text=_build_email(sender_label, subject, body),
                    headers_text=_headers_pass(sender_email),
                    tags=["safe", "legitimate"],
                    consistency_group=f"safe-{brand.lower()}",
                ),
            )
            safe_id += 1

    legit_urgency_cases = [
        (
            "HR Team <hr@company.com>",
            "Payroll close reminder",
            "Payroll closes at 5 PM today. Submit timesheets in the internal HR portal.",
        ),
        (
            "IT Service Desk <it-helpdesk@company.com>",
            "Urgent maintenance notice",
            "Urgent maintenance starts tonight. Save your work before 8 PM. No verification is requested.",
        ),
        (
            "Security Team <security@hdfcbank.com>",
            "Official safety reminder",
            "Do not share OTP with anyone. If anyone asks, call official support from the bank app.",
        ),
        (
            "Repo Bot <notifications@github.com>",
            "Action required: branch protection",
            "Action required for branch protection policy. Review in your repository settings.",
        ),
    ]

    for sender_label, subject, body in legit_urgency_cases:
        sender_email = re.search(r"<([^>]+)>", sender_label)
        sender_addr = sender_email.group(1) if sender_email else "noreply@example.com"
        _add_case(
            cases,
            EmailCase(
                case_id=f"SAFE-{safe_id:03d}",
                expected_verdict="Safe",
                email_text=_build_email(sender_label, subject, body),
                headers_text=_headers_pass(sender_addr),
                tags=["safe", "legitimate_urgency", "edge_case"],
            ),
        )
        safe_id += 1

    suspicious_domains = [
        "bank-alert.com",
        "company-careers.net",
        "google-security-notice.net",
        "account-care-center.org",
        "billing-checkdesk.com",
        "secure-review-center.net",
        "user-notice-hub.com",
        "mail-update-desk.org",
    ]

    suspicious_templates = [
        "Your account needs attention. Please review your details soon.",
        "We need you to confirm your profile information within 48 hours to continue processing.",
        "A policy change requires you to review your account notice. No immediate payment is requested.",
        "Please verify your contact details to avoid interruption of notifications.",
    ]

    for domain in suspicious_domains:
        for template in suspicious_templates:
            sender = f"Support Team <support@{domain}>"
            _add_case(
                cases,
                EmailCase(
                    case_id=f"SUS-{suspicious_id:03d}",
                    expected_verdict="Suspicious",
                    email_text=_build_email(sender, "Account notice", template),
                    headers_text=_headers_softfail(f"support@{domain}"),
                    tags=["suspicious", "clean_content_bad_domain", "edge_case"],
                    required_signal_keywords=["risky brand-action keyword", "soft-pressure", "domain"],
                    consistency_group=f"suspicious-domain-{domain.split('.')[0]}",
                ),
            )
            suspicious_id += 1

    subdomain_trick_cases = [
        "login.amazon.com.security-check.xyz",
        "accounts.google.com.session-review.top",
        "signin.microsoft.com.verify-center.click",
        "github.com.login-review.work",
    ]

    for trick_domain in subdomain_trick_cases:
        body = (
            f"We detected unusual activity. Review your account status at http://{trick_domain}/notice "
            "and confirm your recent session details."
        )
        _add_case(
            cases,
            EmailCase(
                case_id=f"SUS-{suspicious_id:03d}",
                expected_verdict="Suspicious",
                email_text=_build_email(f"Alert Desk <notify@{trick_domain}>", "Session review", body),
                headers_text=None,
                tags=["suspicious", "subdomain_trick", "edge_case"],
                required_signal_keywords=["lookalike", "suspicious"],
            ),
        )
        suspicious_id += 1

    short_link_suspicious = [
        "http://bit.ly/update-notice",
        "http://tinyurl.com/account-review",
        "http://rb.gy/securitynotice",
        "http://t.co/profile-check",
    ]

    for short_url in short_link_suspicious:
        body = (
            f"Please read this account notice: {short_url}. "
            "No password is requested, but verify if this message is expected."
        )
        _add_case(
            cases,
            EmailCase(
                case_id=f"SUS-{suspicious_id:03d}",
                expected_verdict="Suspicious",
                email_text=_build_email("Notification Center <notice@updates-mail.net>", "Notice update", body),
                headers_text=_headers_softfail("notice@updates-mail.net", "helpdesk@outlook.com"),
                tags=["suspicious", "short_link", "edge_case"],
            ),
        )
        suspicious_id += 1

    banks = [
        ("SBI", "sbi-verify-login.xyz"),
        ("HDFC", "hdfc-secure-login.xyz"),
        ("ICICI", "icici-auth-check.xyz"),
    ]

    high_risk_templates = [
        "URGENT: Your {brand} account will be suspended in 24 hours. Verify now: http://{domain}/verify and enter OTP and password immediately.",
        "Security alert: {brand} account limited. Login here http://{domain}/unlock and share OTP to restore access.",
        "Final warning from {brand}. Confirm PAN, Aadhaar and OTP at http://{domain}/kyc now.",
        "Action required: {brand} profile locked. Open http://{domain}/signin and submit passcode immediately.",
    ]

    for brand, domain in banks:
        for template in high_risk_templates:
            sender_email = f"security@{domain}"
            body = template.format(brand=brand, domain=domain)
            _add_case(
                cases,
                EmailCase(
                    case_id=f"HR-{high_id:03d}",
                    expected_verdict="High Risk",
                    email_text=_build_email(f"{brand} Security <{sender_email}>", f"{brand} urgent verification", body),
                    headers_text=_headers_fail(sender_email, "helpdesk@outlook.com", f"bounce@{domain}"),
                    tags=["high_risk", "bank_scam", "otp_harvest", "upi_kyc", "header_fail_impact"],
                    required_signal_keywords=["otp-harvesting", "credential", "high-risk tld", "brand impersonation"],
                    consistency_group=f"hr-bank-{brand.lower()}",
                ),
            )
            high_id += 1

    brand_spoof_cases = [
        ("paypaI-security.com", "PayPal"),
        ("amaz0n-security-notice.com", "Amazon"),
        ("g00gle-account-protect.net", "Google"),
        ("micr0soft-login-team.org", "Microsoft"),
        ("hdfc-alert.co", "HDFC"),
        ("sbi-secure-alert.net", "SBI"),
    ]

    for spoof_domain, brand in brand_spoof_cases:
        body = (
            f"Your {brand} account is limited. Login now to fix it. "
            "Share OTP immediately to avoid permanent block."
        )
        sender_email = f"alerts@{spoof_domain}"
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email(f"{brand} Security <{sender_email}>", "Verify account", body),
                headers_text=_headers_fail(sender_email, "verify-team@protonmail.com", "bounce@mailer-top.work"),
                tags=["high_risk", "brand_spoof", "no_link_phishing"],
                required_signal_keywords=["lookalike", "sender lookalike", "brand impersonation"],
                consistency_group=f"hr-spoof-{brand.lower()}",
            ),
        )
        high_id += 1

    short_link_high_risk = [
        "http://bit.ly/otp-verify-now",
        "http://tinyurl.com/bank-urgent-login",
        "http://rb.gy/pan-kyc-fast",
        "http://t.co/secure-restore",
    ]

    for idx, short_link in enumerate(short_link_high_risk, start=1):
        body = (
            "URGENT: We noticed unusual transaction activity. "
            f"Verify immediately at {short_link} and provide OTP + password now."
        )
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email("Transaction Alert <alerts@bank-notice.center>", "Transaction blocked", body),
                headers_text=_headers_softfail("alerts@bank-notice.center", "urgent-help@outlook.com"),
                tags=["high_risk", "short_link", "otp_harvest"],
                required_signal_keywords=["otp-harvesting", "suspicious verification link"],
                consistency_group=f"hr-short-{idx}",
            ),
        )
        high_id += 1

    multilingual_high_risk = [
        (
            "Hinglish OTP",
            "Aapka bank account block hone wala hai. OTP abhi bhejo aur link kholo: http://wallet-restore.xyz/verify. Jaldi karo.",
        ),
        (
            "Hindi KYC",
            "\u0906\u092a\u0915\u093e \u0916\u093e\u0924\u093e \u092c\u0902\u0926 \u0939\u094b \u091c\u093e\u090f\u0917\u093e. \u0924\u0941\u0930\u0902\u0924 OTP \u0938\u093e\u091d\u093e \u0915\u0930\u0947\u0902 \u0914\u0930 http://kyc-urgent.xyz/login \u092a\u0930 \u0938\u0924\u094d\u092f\u093e\u092a\u0928 \u0915\u0930\u0947\u0902.",
        ),
        (
            "Telugu OTP",
            "\u092e\u0940 \u0c2c\u0c4d\u0c2f\u0c3e\u0c02\u0c15\u0c4d \u0c16\u0c3e\u0c24\u0c3e \u0c28\u0c3f\u0c32\u0c3f\u0c2a\u0c3f\u0c35\u0c47\u0c2f\u0c2c\u0c21\u0c41\u0c24\u0c41\u0c02\u0c26\u0c3f. \u0c35\u0c46\u0c02\u0c1f\u0c28\u0c47 OTP \u0c2a\u0c02\u0c2a\u0c3f http://secure-wallet-check.xyz/otp \u0c32\u0c4b \u0c27\u0c43\u0c35\u0c40\u0c15\u0c30\u0c3f\u0c02\u0c1a\u0c02\u0c21\u0c3f.",
        ),
        (
            "Mixed Reward",
            "Congrats! \u0906\u092a \u20b950,000 jeet gaye. Claim karo at http://reward-claim.xyz and share OTP abhi.",
        ),
    ]

    for name, body in multilingual_high_risk:
        sender_email = "alerts@regional-security-alert.xyz"
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email(f"Regional Alerts <{sender_email}>", name, body),
                headers_text=_headers_fail(sender_email, "desk@outlook.com", "bounce@regional-security-alert.xyz"),
                tags=["high_risk", "multilingual", "mixed_language", "reward_or_otp"],
                required_signal_keywords=["reward", "otp", "high-risk tld"],
                consistency_group="hr-multilingual",
            ),
        )
        high_id += 1

    unicode_spoof_domains = [
        "\u0440\u0430\u0443\u0440\u0430l-security.com",
        "g\u03bfoogle-verify.net",
        "paypa\u04cf-alert.org",
    ]

    for unicode_domain in unicode_spoof_domains:
        sender_email = f"security@{unicode_domain}"
        body = (
            "Critical verification required. Your account access is limited. "
            "Login now and submit OTP to restore access immediately."
        )
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email(f"Security Team <{sender_email}>", "Unicode domain check", body),
                headers_text=_headers_softfail(sender_email, "verify@outlook.com"),
                tags=["high_risk", "unicode_domain", "brand_spoof", "no_link_phishing"],
                required_signal_keywords=["lookalike", "sender", "brand"],
            ),
        )
        high_id += 1

    attachment_cases = [
        {
            "filename": "Payroll_Update.pdf",
            "contentType": "application/pdf",
            "hasQrCode": True,
            "isPasswordProtected": False,
            "extractedText": "Scan the QR code and submit OTP to keep salary active.",
        },
        {
            "filename": "Invoice_Review.zip",
            "contentType": "application/zip",
            "hasQrCode": False,
            "isPasswordProtected": True,
            "extractedText": "Verify beneficiary details and transfer code immediately.",
        },
    ]

    for attachment in attachment_cases:
        sender_email = "notify@docs-security-check.xyz"
        body = (
            f"Open attachment {attachment['filename']} now. "
            "Complete verification immediately to avoid account suspension today."
        )
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email(f"Document Center <{sender_email}>", "Attachment verification", body),
                headers_text=_headers_fail(sender_email, "helpdesk@outlook.com", "bounce@docs-security-check.xyz"),
                attachments=[attachment],
                tags=["high_risk", "attachment_lure", "qr_or_password_protected"],
                required_signal_keywords=["attachment", "qr", "credential"],
            ),
        )
        high_id += 1

    no_link_high_risk = [
        "URGENT: Send your OTP immediately to avoid permanent account block.",
        "Final warning. Share your verification code now. Do not delay.",
        "Account lock triggered. Reply with OTP and PIN to restore access right now.",
    ]

    for body in no_link_high_risk:
        sender_email = "alerts@urgent-recovery-center.net"
        _add_case(
            cases,
            EmailCase(
                case_id=f"HR-{high_id:03d}",
                expected_verdict="High Risk",
                email_text=_build_email(f"Recovery Desk <{sender_email}>", "Immediate verification", body),
                headers_text=_headers_fail(sender_email, "helpdesk@outlook.com", "bounce@urgent-recovery-center.net"),
                tags=["high_risk", "no_link_phishing", "otp_harvest", "very_short"],
                required_signal_keywords=["otp-harvesting"],
                consistency_group="hr-no-link-otp",
            ),
        )
        high_id += 1

    long_safe_text = (
        "Weekly engineering update. "
        "No credentials requested. "
        "Review the internal dashboard when available. "
    ) * 160
    _add_case(
        cases,
        EmailCase(
            case_id=f"SAFE-{safe_id:03d}",
            expected_verdict="Safe",
            email_text=_build_email("Engineering Ops <updates@company.com>", "Very long internal digest", long_safe_text),
            headers_text=_headers_pass("updates@company.com"),
            tags=["safe", "very_long", "internal"],
        ),
    )
    safe_id += 1

    long_phishing_text = (
        "Your bank account is under review. "
        "Verify OTP, password, PAN, and Aadhaar immediately at http://urgent-kyc-review.xyz/login. "
        "Failure to complete in 30 minutes will permanently suspend access. "
    ) * 80
    _add_case(
        cases,
        EmailCase(
            case_id=f"HR-{high_id:03d}",
            expected_verdict="High Risk",
            email_text=_build_email("Compliance Desk <alerts@urgent-kyc-review.xyz>", "Very long phishing lure", long_phishing_text),
            headers_text=_headers_fail("alerts@urgent-kyc-review.xyz", "helpdesk@outlook.com", "bounce@urgent-kyc-review.xyz"),
            tags=["high_risk", "very_long", "otp_harvest", "upi_kyc"],
            required_signal_keywords=["otp", "credential", "high-risk tld"],
        ),
    )

    random.shuffle(cases)
    return cases


def _explanation_matches_verdict(verdict: str, explanation: str) -> bool:
    text = str(explanation or "").strip().lower()
    if not text:
        return False
    if verdict == "High Risk":
        return any(token in text for token in ["risk", "phish", "suspicious", "block", "otp", "credential", "spoof"])
    if verdict == "Suspicious":
        return any(token in text for token in ["suspicious", "review", "verify", "unverified", "caution"])
    return any(token in text for token in ["safe", "no high-risk", "allow", "monitor", "no strong phishing"])


def _collect_case_issues(case_result: CaseResult) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    expected = case_result.expected_verdict
    actual = case_result.actual_verdict

    if case_result.error:
        issues.append(("runtime_error", f"{case_result.case_id}: {case_result.error}"))
        return issues

    if expected != actual:
        if expected == "High Risk" and actual == "Safe":
            issues.append(("critical_false_negative", case_result.case_id))
        elif expected == "High Risk":
            issues.append(("false_negative", case_result.case_id))
        elif expected == "Safe":
            issues.append(("false_positive", case_result.case_id))
        elif expected == "Suspicious" and actual == "Safe":
            issues.append(("suspicious_missed_low", case_result.case_id))
        elif expected == "Suspicious" and actual == "High Risk":
            issues.append(("suspicious_over_escalated", case_result.case_id))

    if case_result.required_signal_keywords and actual == expected == "High Risk":
        all_signals = " ".join(case_result.matched_signals).lower()
        if not any(keyword.lower() in all_signals for keyword in case_result.required_signal_keywords):
            issues.append(("weak_signal_trace", case_result.case_id))

    return issues


def _evaluate_consistency(case_results: list[CaseResult]) -> list[dict[str, Any]]:
    grouped: dict[str, list[CaseResult]] = defaultdict(list)
    for case_result in case_results:
        if case_result.consistency_group:
            grouped[case_result.consistency_group].append(case_result)

    issues: list[dict[str, Any]] = []
    for group_name, group_results in grouped.items():
        if len(group_results) < 2:
            continue
        scores = [item.risk_score for item in group_results if not item.error]
        verdicts = {item.actual_verdict for item in group_results if not item.error}
        if not scores:
            continue
        score_spread = max(scores) - min(scores)
        if len(verdicts) > 1 or score_spread > 8:
            issues.append(
                {
                    "group": group_name,
                    "score_spread": score_spread,
                    "verdicts": sorted(verdicts),
                    "cases": [item.case_id for item in group_results],
                }
            )
    return issues


def _validate_explain_all_cases(case_results: list[CaseResult]) -> dict[str, Any]:
    original_provider = backend_main.LLM_PROVIDER
    original_key = backend_main.OPENROUTER_API_KEY
    explain_ok = 0
    explain_total = 0
    verdict_match_ok = 0
    failures: list[str] = []

    try:
        # Force fallback path for deterministic full-dataset explain checks.
        backend_main.LLM_PROVIDER = "openrouter"
        backend_main.OPENROUTER_API_KEY = ""

        for case_result in case_results:
            if case_result.error:
                continue
            explain_total += 1
            try:
                response = explain_scan(ExplainRequest(scan_id=case_result.scan_id))
                explanation = str(response.get("explanation") or "")
                source = str(response.get("source") or "")
                if explanation and source in {"fallback", "openrouter"}:
                    explain_ok += 1
                if _explanation_matches_verdict(case_result.actual_verdict, explanation):
                    verdict_match_ok += 1
                else:
                    failures.append(f"explanation_verdict_mismatch:{case_result.case_id}")
            except Exception as exc:  # pragma: no cover - defensive logging path
                failures.append(f"explain_error:{case_result.case_id}:{type(exc).__name__}")
    finally:
        backend_main.LLM_PROVIDER = original_provider
        backend_main.OPENROUTER_API_KEY = original_key

    return {
        "total": explain_total,
        "success": explain_ok,
        "success_percent": round((explain_ok / explain_total * 100) if explain_total else 0.0, 2),
        "verdict_alignment_success": verdict_match_ok,
        "verdict_alignment_percent": round((verdict_match_ok / explain_total * 100) if explain_total else 0.0, 2),
        "failures": failures[:20],
    }


class _MockOpenRouterResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self) -> dict[str, Any]:
        return self._payload


def _validate_explain_paths(sample_scan_id: str) -> dict[str, Any]:
    original_provider = backend_main.LLM_PROVIDER
    original_key = backend_main.OPENROUTER_API_KEY
    original_post = backend_main.requests.post

    tests: dict[str, Any] = {}

    try:
        backend_main.LLM_PROVIDER = "openrouter"

        backend_main.OPENROUTER_API_KEY = ""
        response_missing_key = explain_scan(ExplainRequest(scan_id=sample_scan_id))
        tests["fallback_missing_key"] = {
            "source": response_missing_key.get("source"),
            "fallback_reason": response_missing_key.get("fallback_reason"),
            "pass": response_missing_key.get("source") == "fallback",
        }

        def _mock_success(*_args: Any, **_kwargs: Any) -> _MockOpenRouterResponse:
            return _MockOpenRouterResponse(
                200,
                {
                    "choices": [
                        {
                            "message": {
                                "content": "Verdict rationale: suspicious sender patterns and credential-harvesting language indicate high risk phishing."
                            }
                        }
                    ]
                },
            )

        backend_main.OPENROUTER_API_KEY = "mock-key"
        backend_main.requests.post = _mock_success
        response_openrouter = explain_scan(ExplainRequest(scan_id=sample_scan_id))
        tests["openrouter_available_path"] = {
            "source": response_openrouter.get("source"),
            "fallback_used": response_openrouter.get("fallback_used"),
            "pass": response_openrouter.get("source") == "openrouter" and not bool(response_openrouter.get("fallback_used")),
        }

        def _mock_exception(*_args: Any, **_kwargs: Any) -> _MockOpenRouterResponse:
            raise RuntimeError("simulated_openrouter_failure")

        backend_main.requests.post = _mock_exception
        response_exception_fallback = explain_scan(ExplainRequest(scan_id=sample_scan_id))
        tests["fallback_on_openrouter_failure"] = {
            "source": response_exception_fallback.get("source"),
            "fallback_reason": response_exception_fallback.get("fallback_reason"),
            "pass": response_exception_fallback.get("source") == "fallback",
        }

        if original_key:
            backend_main.requests.post = original_post
            backend_main.OPENROUTER_API_KEY = original_key
            try:
                live_response = explain_scan(ExplainRequest(scan_id=sample_scan_id))
                tests["live_openrouter_attempt"] = {
                    "source": live_response.get("source"),
                    "fallback_used": bool(live_response.get("fallback_used")),
                    "pass": live_response.get("source") in {"openrouter", "fallback"},
                }
            except Exception as exc:  # pragma: no cover - defensive path
                tests["live_openrouter_attempt"] = {
                    "pass": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
        else:
            tests["live_openrouter_attempt"] = {
                "pass": True,
                "skipped": "OPENROUTER_API_KEY is not configured in this environment",
            }

    finally:
        backend_main.LLM_PROVIDER = original_provider
        backend_main.OPENROUTER_API_KEY = original_key
        backend_main.requests.post = original_post

    tests["all_paths_valid"] = all(bool(item.get("pass")) for item in tests.values())
    return tests


def run_cycle(cycle_index: int, deterministic_url: bool, seed: int) -> dict[str, Any]:
    if deterministic_url:
        backend_main.VT_API_KEY = ""

    backend_main.app.state.scan_explanations = {}
    backend_main.app.state.scan_cache = {}
    backend_main.app.state.scan_rate_limits = {}

    cases = generate_dataset(seed + cycle_index)
    case_results: list[CaseResult] = []

    for case in cases:
        try:
            result = calculate_email_risk(
                case.email_text,
                headers_text=case.headers_text,
                attachments=case.attachments,
                session_id=f"hardening-cycle-{cycle_index}",
            )
            actual_verdict = _normalize_verdict(str(result.get("verdict") or result.get("classification") or ""))
            risk_score = int(result.get("risk_score", result.get("riskScore", 0)) or 0)
            confidence = int(result.get("confidence", 0) or 0)
            matched_signals = list(result.get("matched_signals") or result.get("signals") or [])
            explanation = str(result.get("explanation") or "")
            scan_id = str(result.get("scan_id") or result.get("id") or "")
            case_results.append(
                CaseResult(
                    case_id=case.case_id,
                    expected_verdict=case.expected_verdict,
                    actual_verdict=actual_verdict,
                    risk_score=risk_score,
                    confidence=confidence,
                    scan_id=scan_id,
                    matched_signals=matched_signals,
                    explanation=explanation,
                    tags=case.tags,
                    required_signal_keywords=case.required_signal_keywords,
                    consistency_group=case.consistency_group,
                    passed=(actual_verdict == case.expected_verdict),
                )
            )
        except Exception as exc:  # pragma: no cover - defensive path
            case_results.append(
                CaseResult(
                    case_id=case.case_id,
                    expected_verdict=case.expected_verdict,
                    actual_verdict="Safe",
                    risk_score=0,
                    confidence=0,
                    scan_id="",
                    matched_signals=[],
                    explanation="",
                    tags=case.tags,
                    required_signal_keywords=case.required_signal_keywords,
                    consistency_group=case.consistency_group,
                    passed=False,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    issue_entries: list[tuple[str, str]] = []
    for case_result in case_results:
        issue_entries.extend(_collect_case_issues(case_result))

    consistency_issues = _evaluate_consistency(case_results)
    for issue in consistency_issues:
        issue_entries.append(("score_instability", issue["group"]))

    issue_counter = Counter(key for key, _ in issue_entries)
    issue_examples: dict[str, list[str]] = defaultdict(list)
    for key, detail in issue_entries:
        if len(issue_examples[key]) < 5 and detail not in issue_examples[key]:
            issue_examples[key].append(detail)

    total = len(case_results)
    correct = sum(1 for item in case_results if item.passed and not item.error)
    false_positives = sum(1 for item in case_results if item.expected_verdict == "Safe" and item.actual_verdict != "Safe")
    false_negatives = sum(1 for item in case_results if item.expected_verdict == "High Risk" and item.actual_verdict != "High Risk")
    critical_false_negatives = sum(
        1 for item in case_results if item.expected_verdict == "High Risk" and item.actual_verdict == "Safe"
    )

    def _tag_success_rate(tag: str) -> dict[str, Any]:
        tagged = [item for item in case_results if tag in item.tags and not item.error]
        if not tagged:
            return {"total": 0, "passed": 0, "percent": 100.0}
        passed = sum(1 for item in tagged if item.passed)
        return {"total": len(tagged), "passed": passed, "percent": round(passed / len(tagged) * 100, 2)}

    brand_spoof_rate = _tag_success_rate("brand_spoof")
    otp_rate = _tag_success_rate("otp_harvest")
    safe_rate = _tag_success_rate("safe")
    header_fail_rate = _tag_success_rate("header_fail_impact")

    explain_dataset_stats = _validate_explain_all_cases(case_results)
    sample_scan_id = next((item.scan_id for item in case_results if item.scan_id), "")
    explain_path_stats = _validate_explain_paths(sample_scan_id) if sample_scan_id else {"all_paths_valid": False}

    target_accuracy = 98.0
    accuracy = round((correct / total * 100) if total else 0.0, 2)

    checks = {
        "accuracy_gte_98": accuracy >= target_accuracy,
        "no_critical_false_negatives": critical_false_negatives == 0,
        "safe_false_positive_free": false_positives == 0,
        "brand_spoof_detected": brand_spoof_rate["percent"] == 100.0,
        "otp_high_risk_detected": otp_rate["percent"] == 100.0,
        "consistency_stable": len(consistency_issues) == 0,
        "explain_dataset_working": explain_dataset_stats["success_percent"] == 100.0,
        "explain_paths_valid": bool(explain_path_stats.get("all_paths_valid", False)),
    }

    meets_success_criteria = all(checks.values())

    top_issues = [
        {
            "issue": key,
            "count": count,
            "examples": issue_examples.get(key, []),
        }
        for key, count in issue_counter.most_common(5)
    ]

    score_values = [item.risk_score for item in case_results if not item.error]
    avg_score = round(mean(score_values), 2) if score_values else 0.0

    cycle_summary = {
        "cycle": cycle_index,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_size": total,
        "accuracy_percent": accuracy,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "critical_false_negatives": critical_false_negatives,
        "average_risk_score": avg_score,
        "top_issues": top_issues,
        "checks": checks,
        "meets_success_criteria": meets_success_criteria,
        "coverage": {
            "brand_spoof": brand_spoof_rate,
            "otp_harvest": otp_rate,
            "safe": safe_rate,
            "header_fail_impact": header_fail_rate,
        },
        "consistency_issues": consistency_issues,
        "explain_validation": {
            "dataset": explain_dataset_stats,
            "paths": explain_path_stats,
        },
        "results": [asdict(item) for item in case_results],
    }

    return cycle_summary


def run_hardening_loop(max_cycles: int, min_cycles: int, deterministic_url: bool, seed: int) -> dict[str, Any]:
    load_artifacts()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    cycle_reports: list[dict[str, Any]] = []
    stable_pass_cycles = 0

    for cycle_index in range(1, max_cycles + 1):
        summary = run_cycle(cycle_index=cycle_index, deterministic_url=deterministic_url, seed=seed)
        if cycle_reports:
            previous_accuracy = cycle_reports[-1]["accuracy_percent"]
            summary["improvement_vs_previous_percent"] = round(summary["accuracy_percent"] - previous_accuracy, 2)
        else:
            summary["improvement_vs_previous_percent"] = None

        cycle_reports.append(summary)

        cycle_path = REPORT_DIR / f"cycle_{cycle_index:02d}.json"
        cycle_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        print("=" * 90)
        print(f"CYCLE {cycle_index} SUMMARY")
        print(f"Total tests run: {summary['dataset_size']}")
        print(f"Accuracy: {summary['accuracy_percent']}%")
        print(
            "False positives / negatives / critical FN: "
            f"{summary['false_positives']} / {summary['false_negatives']} / {summary['critical_false_negatives']}"
        )
        print("Top 5 issues:")
        if summary["top_issues"]:
            for issue in summary["top_issues"]:
                print(f"- {issue['issue']}: {issue['count']} (examples: {', '.join(issue['examples'])})")
        else:
            print("- none")
        improvement = summary["improvement_vs_previous_percent"]
        print(f"Improvement vs previous cycle: {improvement if improvement is not None else 'N/A'}")
        print(f"Success checks: {json.dumps(summary['checks'], ensure_ascii=False)}")

        if summary["meets_success_criteria"]:
            stable_pass_cycles += 1
        else:
            stable_pass_cycles = 0

        if cycle_index >= min_cycles and stable_pass_cycles >= 2:
            break

    final_report = {
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "cycles_executed": len(cycle_reports),
        "target_accuracy_percent": 98.0,
        "deterministic_url_mode": deterministic_url,
        "reports": cycle_reports,
        "final_status": cycle_reports[-1]["meets_success_criteria"] if cycle_reports else False,
    }

    summary_path = REPORT_DIR / "hardening_loop_summary.json"
    summary_path.write_text(json.dumps(final_report, indent=2, ensure_ascii=False), encoding="utf-8")
    return final_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Production hardening loop for PhishShield AI")
    parser.add_argument("--max-cycles", type=int, default=4, help="Maximum loop iterations")
    parser.add_argument("--min-cycles", type=int, default=2, help="Minimum iterations before stable stop")
    parser.add_argument(
        "--deterministic-url",
        action="store_true",
        help="Disable live VirusTotal calls by forcing local URL heuristic mode",
    )
    parser.add_argument("--seed", type=int, default=20260415, help="Dataset seed for reproducibility")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_hardening_loop(
        max_cycles=args.max_cycles,
        min_cycles=args.min_cycles,
        deterministic_url=bool(args.deterministic_url),
        seed=args.seed,
    )

    print("=" * 90)
    print("FINAL HARDENING STATUS")
    print(f"Cycles executed: {report['cycles_executed']}")
    print(f"Final status: {'PASS' if report['final_status'] else 'REQUIRES_MORE_FIXES'}")
    print(f"Summary report: {REPORT_DIR / 'hardening_loop_summary.json'}")


if __name__ == "__main__":
    main()
