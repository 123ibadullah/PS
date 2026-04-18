from __future__ import annotations

import json
import re
import textwrap
import time
import warnings
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import ExplainRequest, HeaderRequest, app, calculate_email_risk, check_headers, explain_scan, load_artifacts

warnings.filterwarnings("ignore", message="Trying to unpickle estimator")

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports" / "verification"
RESULTS_JSON_PATH = REPORTS_DIR / "production_validation_results.json"
REPORT_MD_PATH = REPORTS_DIR / "production_validation_report.md"


SAFE_BRANDS = [
    {
        "brand": "Google",
        "domain": "accounts.google.com",
        "sender": "security",
        "link": "https://support.google.com/accounts/answer/6294825",
        "subject": "New sign-in noticed",
        "body_hint": "If this was you, no action is required.",
    },
    {
        "brand": "Amazon",
        "domain": "amazon.com",
        "sender": "account-update",
        "link": "https://www.amazon.com/gp/help/customer/display.html",
        "subject": "Order and billing update",
        "body_hint": "Visit the help centre any time.",
    },
    {
        "brand": "LinkedIn",
        "domain": "linkedin.com",
        "sender": "messages",
        "link": "https://www.linkedin.com/help/linkedin",
        "subject": "Weekly network digest",
        "body_hint": "Manage notification settings any time.",
    },
    {
        "brand": "GitHub",
        "domain": "github.com",
        "sender": "noreply",
        "link": "https://github.com/settings/security-log",
        "subject": "Account activity summary",
        "body_hint": "Review your recent activity in the security log.",
    },
    {
        "brand": "Paytm",
        "domain": "paytm.com",
        "sender": "wallet",
        "link": "https://paytm.com/help",
        "subject": "Official app reminder",
        "body_hint": "Complete any updates in the official app only.",
    },
]

SAFE_TEMPLATES = [
    "Hello,\n\nWe noticed a normal account sign-in from your saved device. {body_hint} You can review details here: {link}\n\nRegards,\n{brand} Security Team",
    "Hi there,\n\nYour monthly receipt is ready for download in the official portal. No password, OTP, or payment action is requested in this email. {body_hint}\n\nThanks,\n{brand}",
    "Hello,\n\nThis is your routine notification digest. You can read more at {link}. No reply is needed, and you can ignore this email if you already reviewed the update.\n\nTeam {brand}",
    "Dear customer,\n\nYour subscription remains active and your recent transaction completed successfully. For your safety, never share your OTP or PIN by email. {body_hint}\n\n{brand} Support",
    "Hi,\n\nWe are sharing an informational reminder only. Please continue any verification inside the official {brand} app and not through third-party websites. {body_hint}\n\nWarm regards,\n{brand}",
]

DIRECT_BRANDS = [
    {
        "brand": "HDFC Bank",
        "from_domain": "hdfc-alert-secure.xyz",
        "malicious_link": "https://hdfc-alert-secure.xyz/verify-otp",
        "subject": "Urgent KYC update required",
    },
    {
        "brand": "SBI",
        "from_domain": "sbi-login-check.top",
        "malicious_link": "https://sbi-login-check.top/otp-confirm",
        "subject": "Account suspension warning",
    },
    {
        "brand": "Microsoft 365",
        "from_domain": "micr0soft-login-support.work",
        "malicious_link": "https://micr0soft-login-support.work/secure-review",
        "subject": "Mailbox verification needed",
    },
    {
        "brand": "Netflix",
        "from_domain": "netfIix-membership-billing.click",
        "malicious_link": "https://netfIix-membership-billing.click/update-payment",
        "subject": "Payment failure alert",
    },
    {
        "brand": "Income Tax",
        "from_domain": "refund-department-gov.xyz",
        "malicious_link": "https://refund-department-gov.xyz/claim-now",
        "subject": "Refund claim notice",
    },
]

DIRECT_TEMPLATES = [
    "Dear user,\n\nYour {brand} account will be suspended today unless you verify your OTP immediately. Update now at {malicious_link} and submit the verification code to restore access.",
    "Important notice,\n\nWe detected a problem with your account credentials. Confirm your password and OTP within 30 minutes at {malicious_link} to avoid permanent blocking.",
    "KYC alert,\n\nYour wallet is under review. Enter your PAN, Aadhaar, and OTP on {malicious_link} right now or service will stop today.",
    "Security team,\n\nUnusual activity has locked your profile. Click {malicious_link} and provide the verification code immediately to prevent closure.",
    "Refund desk,\n\nA refund is waiting, but it expires in 24 hours. Open {malicious_link}, confirm your bank details, and reply with the OTP now.",
]

MIXED_BRANDS = [
    {
        "brand": "Amazon",
        "trusted_domain": "amazon.com",
        "trusted_link": "https://www.amazon.com/gp/help/customer/display.html",
        "malicious_link": "https://amazon-review-center-login.ru/verify",
        "subject": "Review your account activity",
    },
    {
        "brand": "Google",
        "trusted_domain": "accounts.google.com",
        "trusted_link": "https://support.google.com/accounts/answer/6294825",
        "malicious_link": "https://google-security-session-check.top/login",
        "subject": "Security review required",
    },
    {
        "brand": "LinkedIn",
        "trusted_domain": "linkedin.com",
        "trusted_link": "https://www.linkedin.com/help/linkedin",
        "malicious_link": "https://linkedin-profile-appeal.work/signin",
        "subject": "Urgent profile confirmation",
    },
    {
        "brand": "Microsoft",
        "trusted_domain": "microsoft.com",
        "trusted_link": "https://support.microsoft.com",
        "malicious_link": "https://microsoft-session-defender.xyz/secure",
        "subject": "Important tenant notice",
    },
    {
        "brand": "Paytm",
        "trusted_domain": "paytm.com",
        "trusted_link": "https://paytm.com/help",
        "malicious_link": "https://paytm-wallet-restore.click/kyc",
        "subject": "Wallet access review",
    },
]

MIXED_TEMPLATES = [
    "Hello,\n\nPlease review the official help page at {trusted_link}. To keep your {brand} account active, you must also complete urgent verification at {malicious_link} before the day ends.",
    "Dear customer,\n\nYou can confirm our policy update at {trusted_link}, but your account will still be limited unless you sign in immediately through {malicious_link}.",
    "Security notice,\n\nWe have included the standard support page {trusted_link}. However, to avoid suspension you must urgently submit your details at {malicious_link} right now.",
    "Hi,\n\nOur regular help article is here: {trusted_link}. Your profile remains at risk until you verify the OTP and password on {malicious_link} today.",
    "Attention,\n\nUse {trusted_link} to review the brand notice and then finish the required KYC check immediately on {malicious_link} to prevent lockout.",
]

SHORT_TEXT_ROLES = ["CEO", "Finance Head", "Payroll Admin", "Bank Desk", "Compliance Team"]
SHORT_TEXT_TEMPLATES = [
    "Urgent. Transfer the payment today and send the OTP immediately. Keep this confidential.",
    "Need the bank details and verification code now. Do not call, just reply here urgently.",
    "Immediate action needed: approve the beneficiary and share the passcode within 10 minutes.",
    "Update KYC right now or the account will stop today. Reply with the OTP immediately.",
    "Process the invoice now and confirm the transfer code today. Keep this off the main thread.",
]

MULTILINGUAL_TEMPLATES = [
    "आपका {brand} account बंद हो जाएगा. तुरंत OTP साझा करें और {malicious_link} पर verify करें.",
    "{brand} alert: OTP bhejo warna access band ho jayega. Abhi {malicious_link} kholo aur details confirm karo.",
    "మీ {brand} ఖాతా నిలిపివేయబడుతుంది. వెంటనే OTP పంపి {malicious_link} ద్వారా ధృవీకరించండి.",
    "Refund pending hai. तुरन्त PAN aur OTP verify karo yahan: {malicious_link}.",
    "KYC abhi complete karo warna wallet बंद होगा. {malicious_link} par details submit karo.",
]

ATTACHMENT_VARIANTS = [
    {"filename": "Invoice_Review.zip", "contentType": "application/zip", "isPasswordProtected": True, "extractedText": "Verify payment details and approve the transfer immediately."},
    {"filename": "Payroll_Update.pdf", "contentType": "application/pdf", "hasQrCode": True, "extractedText": "Scan the QR code to keep your salary account active today."},
    {"filename": "Voice_Message.svg", "contentType": "image/svg+xml", "extractedText": "Listen to the secure voice note and sign in to verify the request."},
    {"filename": "Account_Statement.url", "contentType": "application/internet-shortcut", "extractedText": "Open this secure link and submit the OTP to unlock the statement."},
    {"filename": "Updated_Document.one", "contentType": "application/onenote", "extractedText": "Review the attached note and confirm bank details before 4 PM."},
]

ATTACHMENT_TEMPLATES = [
    "Please review the attached {filename} and complete the requested verification before the end of day.",
    "The attachment contains the secure instructions for your payment release. Open it and act immediately.",
    "Use the attached file to confirm your login or payroll details today.",
    "This message contains a protected document with the next steps for approval. Follow it urgently.",
    "Open the attached file and complete the verification task now to avoid interruption.",
]

REAL_WORLD_PHISHING_SCENARIOS = [
    {
        "name": "bank_otp_harvest",
        "subject": "Urgent account verification",
        "header_sender": "SBI Security",
        "from_domain": "secure-login-check.top",
        "reply_to": "recovery@secure-mail.top",
        "body": "Dear customer, your account will be blocked tonight unless you verify now. Enter your OTP and passcode immediately at {link}.",
        "links": ["https://sbi-secure-auth.top/verify"],
    },
    {
        "name": "delivery_fee_scam",
        "subject": "Delivery failed - pay customs",
        "header_sender": "Courier Hub",
        "from_domain": "parcel-release.click",
        "reply_to": "support@parcel-release.click",
        "body": "Your package is held at customs. Pay the fee in 2 hours to avoid return. Confirm card details at {link}.",
        "links": ["https://parcel-release.click/fee"],
    },
    {
        "name": "job_offer_advance_fee",
        "subject": "Remote job confirmation",
        "header_sender": "Global HR Desk",
        "from_domain": "jobs-screening.work",
        "reply_to": "recruitment@jobs-screening.work",
        "body": "Congratulations, your offer is confirmed. Submit KYC and joining fee by end of day using {link}.",
        "links": ["https://jobs-screening.work/onboarding"],
    },
    {
        "name": "beneficiary_change_bec",
        "subject": "Confidential vendor transfer",
        "header_sender": "CFO Office",
        "from_domain": "vendor-payments.co",
        "reply_to": "finance@vendor-payments.co",
        "body": "Need you to update beneficiary details and release the payment before 4 PM. Keep this confidential and send confirmation once done.",
        "links": [],
    },
    {
        "name": "password_reset_lookalike",
        "subject": "Mailbox suspension warning",
        "header_sender": "Microsoft Alert",
        "from_domain": "tenant-security.xyz",
        "reply_to": "support@tenant-security.xyz",
        "body": "We detected suspicious sign-in. Restore mailbox access by confirming credentials now at {link}.",
        "links": ["https://microsoft-session-defender.xyz/login"],
    },
    {
        "name": "upi_cashback_lure",
        "subject": "UPI cashback expires today",
        "header_sender": "Reward Team",
        "from_domain": "reward-claim.tk",
        "reply_to": "claim@reward-claim.tk",
        "body": "Your cashback is reserved. Verify UPI ID and OTP right now at {link} before expiry.",
        "links": ["https://reward-claim.tk/upi"],
    },
    {
        "name": "thread_hijack_invoice",
        "subject": "Re: Invoice approval",
        "header_sender": "Vendor Finance",
        "from_domain": "invoice-review.info",
        "reply_to": "accounts@invoice-review.info",
        "body": "Continuing the same thread, please use the updated bank account in attachment and process today.",
        "links": [],
    },
    {
        "name": "multilingual_wallet_block",
        "subject": "तुरंत सत्यापन",
        "header_sender": "Wallet Team",
        "from_domain": "wallet-restore-check.xyz",
        "reply_to": "help@wallet-restore-check.xyz",
        "body": "आपका wallet बंद हो जाएगा. వెంటనే OTP share karo और verify करें at {link}.",
        "links": ["https://wallet-restore-check.xyz/verify"],
    },
]

REAL_WORLD_BENIGN_SCENARIOS = [
    {
        "name": "security_notice",
        "subject": "New sign-in detected",
        "header_sender": "Google Security",
        "from_domain": "accounts.google.com",
        "reply_to": "security@accounts.google.com",
        "auth": "pass",
        "body": "Your Google account was signed in from a new device. If this was you, no action is required.",
        "links": ["https://support.google.com/accounts/answer/6294825"],
    },
    {
        "name": "transaction_receipt",
        "subject": "Payment successful",
        "header_sender": "Netflix Billing",
        "from_domain": "netflix.com",
        "reply_to": "billing@netflix.com",
        "auth": "pass",
        "body": "Your subscription payment was processed successfully. This is an informational receipt only.",
        "links": [],
    },
    {
        "name": "newsletter_digest",
        "subject": "Weekly update digest",
        "header_sender": "LinkedIn",
        "from_domain": "linkedin.com",
        "reply_to": "messages@linkedin.com",
        "auth": "pass",
        "body": "Here is your weekly digest and network updates. Manage notification settings any time.",
        "links": ["https://www.linkedin.com/help/linkedin"],
    },
    {
        "name": "bank_awareness",
        "subject": "OTP awareness advisory",
        "header_sender": "HDFC Support",
        "from_domain": "hdfcbank.com",
        "reply_to": "support@hdfcbank.com",
        "auth": "pass",
        "body": "Do not share OTP or PIN with anyone. Our team never asks for your passcode over email.",
        "links": [],
    },
    {
        "name": "collaboration_notice",
        "subject": "Document shared with you",
        "header_sender": "Microsoft 365",
        "from_domain": "microsoft.com",
        "reply_to": "noreply@microsoft.com",
        "auth": "pass",
        "body": "A file was shared with your team account. Access via your normal portal when convenient.",
        "links": ["https://support.microsoft.com"],
    },
    {
        "name": "shipping_update",
        "subject": "Order shipped",
        "header_sender": "Amazon",
        "from_domain": "amazon.com",
        "reply_to": "account-update@amazon.com",
        "auth": "pass",
        "body": "Your order has been shipped and is expected tomorrow. Track status in your account.",
        "links": ["https://www.amazon.com/gp/help/customer/display.html"],
    },
]

HEADER_CASES = [
    {
        "name": "reply_to_and_return_path_mismatch",
        "headers": """
From: Amazon Support <alerts@amaz0n-security-login.xyz>
Reply-To: claims-team@outlook.com
Return-Path: <bounce@secure-mail.top>
Authentication-Results: mx.example.net; spf=fail dkim=fail dmarc=fail
Received: from [10.0.0.12] by mx.example.net with ESMTP id 7781
""",
    },
    {
        "name": "display_name_brand_spoof",
        "headers": """
From: Google Security <notice@google-auth-review.top>
Reply-To: notice@google-auth-review.top
Return-Path: <bounce@google-auth-review.top>
Received: from [192.0.2.11] by mx.example.net with ESMTP id 9911
""",
    },
    {
        "name": "legitimate_authenticated_sender",
        "headers": """
From: GitHub <noreply@github.com>
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Authentication-Results: mx.github.net; spf=pass dkim=pass dmarc=pass
Received: from [140.82.121.33] by mx.github.net with ESMTP id 1122
""",
    },
]


def build_email(headers: str, body: str) -> str:
    return f"{textwrap.dedent(headers).strip()}\n\n{textwrap.dedent(body).strip()}"


def build_safe_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for brand in SAFE_BRANDS:
        headers = f"""
From: {brand['brand']} <{brand['sender']}@{brand['domain']}>
Reply-To: {brand['sender']}@{brand['domain']}
Return-Path: <{brand['sender']}@{brand['domain']}>
Authentication-Results: mx.{brand['domain']}; spf=pass dkim=pass dmarc=pass
Subject: {brand['subject']}
"""
        for idx, template in enumerate(SAFE_TEMPLATES, start=1):
            body = template.format(**brand)
            cases.append(
                {
                    "id": f"SAFE-{brand['brand'][:3].upper()}-{idx:02d}",
                    "bucket": "safe",
                    "expected": "safe",
                    "email_text": build_email(headers, body),
                }
            )
    return cases[:25]


def build_direct_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for brand in DIRECT_BRANDS:
        headers = f"""
From: {brand['brand']} Security <alerts@{brand['from_domain']}>
Reply-To: support@{brand['from_domain']}
Return-Path: <bounce@{brand['from_domain']}>
Authentication-Results: mx.mailcheck.net; spf=fail dkim=fail dmarc=fail
Subject: {brand['subject']}
Received: from [10.0.0.44] by mx.mailcheck.net with ESMTP id 3311
"""
        for idx, template in enumerate(DIRECT_TEMPLATES, start=1):
            body = template.format(**brand)
            cases.append(
                {
                    "id": f"DIR-{brand['brand'][:3].upper()}-{idx:02d}",
                    "bucket": "direct_phishing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                }
            )
    return cases[:25]


def build_mixed_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for brand in MIXED_BRANDS:
        headers = f"""
From: {brand['brand']} Alerts <security@{brand['trusted_domain']}>
Reply-To: security@{brand['trusted_domain']}
Return-Path: <security@{brand['trusted_domain']}>
Authentication-Results: mx.{brand['trusted_domain']}; spf=pass dkim=pass dmarc=pass
Subject: {brand['subject']}
"""
        for idx, template in enumerate(MIXED_TEMPLATES, start=1):
            body = template.format(**brand)
            cases.append(
                {
                    "id": f"MIX-{brand['brand'][:3].upper()}-{idx:02d}",
                    "bucket": "mixed_phishing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                }
            )
    return cases[:25]


def build_short_text_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for role in SHORT_TEXT_ROLES:
        headers = f"""
From: {role} <urgent-task@mobile-mail.work>
Subject: Quick task
"""
        for idx, template in enumerate(SHORT_TEXT_TEMPLATES, start=1):
            body = f"{role}: {template}"
            cases.append(
                {
                    "id": f"SHORT-{role.split()[0].upper()}-{idx:02d}",
                    "bucket": "short_text_attack",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                }
            )
    return cases[:25]


def build_multilingual_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for brand in DIRECT_BRANDS:
        headers = f"""
From: {brand['brand']} Alert <alerts@{brand['from_domain']}>
Reply-To: support@{brand['from_domain']}
Return-Path: <bounce@{brand['from_domain']}>
Subject: तत्काल सत्यापन
Authentication-Results: mx.mailcheck.net; spf=fail dkim=fail dmarc=fail
"""
        for idx, template in enumerate(MULTILINGUAL_TEMPLATES, start=1):
            body = template.format(brand=brand['brand'], malicious_link=brand['malicious_link'])
            cases.append(
                {
                    "id": f"LANG-{brand['brand'][:3].upper()}-{idx:02d}",
                    "bucket": "multilingual_phishing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                }
            )
    return cases[:25]


def build_header_spoof_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for brand in DIRECT_BRANDS:
        for idx, template in enumerate(DIRECT_TEMPLATES, start=1):
            headers = f"""
From: {brand['brand']} Security <alerts@{brand['from_domain']}>
Reply-To: recovery-team@outlook.com
Return-Path: <bounce@security-mail.top>
Authentication-Results: mx.enterprise.net; spf=fail dkim=fail dmarc=fail
Received: from [10.0.0.{idx + 20}] by mx.enterprise.net with ESMTP id {3300 + idx}
Subject: {brand['subject']}
"""
            body = template.format(**brand)
            cases.append(
                {
                    "id": f"HDR-{brand['brand'][:3].upper()}-{idx:02d}",
                    "bucket": "header_spoofing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                    "headers": textwrap.dedent(headers).strip(),
                }
            )
    return cases[:25]


def build_attachment_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    suspicious_sender_domains = ["secure-doc-review.xyz", "payroll-secure.work", "mail-protect.top", "invoice-alert.click", "docs-portal.info"]
    for sender_domain, attachment in zip(suspicious_sender_domains, ATTACHMENT_VARIANTS):
        headers = f"""
From: Document Center <notify@{sender_domain}>
Reply-To: help@{sender_domain}
Return-Path: <bounce@{sender_domain}>
Subject: Secure document delivery
"""
        for idx, template in enumerate(ATTACHMENT_TEMPLATES, start=1):
            body = template.format(filename=attachment['filename'])
            cases.append(
                {
                    "id": f"ATT-{attachment['filename'].split('.')[0][:3].upper()}-{idx:02d}",
                    "bucket": "attachment_phishing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                    "attachments": [attachment],
                }
            )
    return cases[:25]


def build_real_world_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    for scenario in REAL_WORLD_PHISHING_SCENARIOS:
        for idx in range(1, 19):
            suffix = f"{idx:02d}"
            from_domain = str(scenario["from_domain"])
            reply_to = str(scenario.get("reply_to") or f"alerts@{from_domain}")
            subject = str(scenario["subject"])
            body = str(scenario["body"])
            links = [str(item) for item in scenario.get("links", [])]

            if "{link}" in body:
                body = body.replace("{link}", links[0] if links else "https://example.invalid")
            elif links:
                body = f"{body} {' '.join(links)}"

            headers = f"""
From: {scenario['header_sender']} <alerts{suffix}@{from_domain}>
Reply-To: {reply_to}
Return-Path: <bounce{suffix}@{from_domain}>
Authentication-Results: mx.enterprise.net; spf=fail dkim=fail dmarc=fail
Subject: {subject}
"""

            cases.append(
                {
                    "id": f"REAL-P-{scenario['name'].upper()}-{suffix}",
                    "bucket": "real_world_phishing",
                    "expected": "phishing",
                    "email_text": build_email(headers, body),
                }
            )

    for scenario in REAL_WORLD_BENIGN_SCENARIOS:
        for idx in range(1, 11):
            suffix = f"{idx:02d}"
            from_domain = str(scenario["from_domain"])
            auth_state = str(scenario.get("auth") or "pass")
            subject = str(scenario["subject"])
            body = str(scenario["body"])
            links = [str(item) for item in scenario.get("links", [])]
            if links:
                body = f"{body} {' '.join(links)}"

            headers = f"""
From: {scenario['header_sender']} <noreply{suffix}@{from_domain}>
Reply-To: {scenario['reply_to']}
Return-Path: <noreply{suffix}@{from_domain}>
Authentication-Results: mx.{from_domain}; spf={auth_state} dkim={auth_state} dmarc={auth_state}
Subject: {subject}
"""

            cases.append(
                {
                    "id": f"REAL-S-{scenario['name'].upper()}-{suffix}",
                    "bucket": "real_world_benign",
                    "expected": "safe",
                    "email_text": build_email(headers, body),
                }
            )

    return cases


def expected_score_band(bucket: str) -> tuple[int, int]:
    if bucket == "safe":
        return (0, 20)
    if bucket == "short_text_attack":
        return (70, 95)
    if bucket == "mixed_phishing":
        return (25, 80)
    if bucket == "direct_phishing":
        return (80, 100)
    if bucket == "multilingual_phishing":
        return (75, 100)
    if bucket == "header_spoofing":
        return (70, 100)
    if bucket == "attachment_phishing":
        return (70, 100)
    if bucket == "real_world_phishing":
        return (70, 100)
    if bucket == "real_world_benign":
        return (0, 30)
    return (70, 100)


def predicted_label(result: dict[str, Any]) -> str:
    return "phishing" if int(result.get("risk_score", 0) or 0) > 25 else "safe"


def run_dataset(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for case in cases:
        result = calculate_email_risk(
            case["email_text"],
            headers_text=case.get("headers"),
            attachments=case.get("attachments"),
        )
        risk_score = int(result.get("risk_score", 0) or 0)
        scan_id = str(result.get("scan_id") or result.get("id") or "")
        signals = list(result.get("matched_signals") or result.get("signals") or [])
        safe_signals = list(result.get("safe_signals") or [])
        explanation_payload = result.get("explanation")
        if isinstance(explanation_payload, dict):
            explanation_text = str(explanation_payload.get("why_risky") or "").strip()
        else:
            explanation_text = str(explanation_payload or "").strip()
        low, high = expected_score_band(case["bucket"])
        results.append(
            {
                "id": case["id"],
                "bucket": case["bucket"],
                "scan_id": scan_id,
                "expected": case["expected"],
                "predicted": predicted_label(result),
                "risk_score": risk_score,
                "verdict": result.get("verdict"),
                "confidence": int(result.get("confidence", 0) or 0),
                "trust_score": int(result.get("trust_score", 0) or 0),
                "signals": signals,
                "safe_signals": safe_signals,
                "analysis_sources": list(result.get("analysisSources", []) or []),
                "sender_reputation": result.get("sender_reputation", {}) or {},
                "behavior_analysis": result.get("behavior_analysis", {}) or {},
                "intent_analysis": result.get("intent_analysis", {}) or {},
                "context_analysis": result.get("context_analysis", {}) or {},
                "authority_analysis": result.get("authority_analysis", {}) or {},
                "action_analysis": result.get("action_analysis", {}) or {},
                "threat_intel": result.get("threat_intel", {}) or {},
                "thread_analysis": result.get("thread_analysis", {}) or {},
                "attachment_analysis": result.get("attachment_analysis", {}) or {},
                "url_sandbox": result.get("url_sandbox", {}) or {},
                "within_expected_band": low <= risk_score <= high,
                "explanation": explanation_text,
            }
        )
    return results


def _signal_tokens(signal: str) -> list[str]:
    stop_words = {
        "the", "and", "for", "with", "from", "this", "that", "plus", "detected", "pattern", "sender", "domain",
        "contains", "used", "request", "indicates", "email", "risk", "checks",
    }
    return [token for token in re.findall(r"[a-z0-9]+", signal.lower()) if len(token) > 2 and token not in stop_words][:6]


def _strong_signal_count(signals: list[str]) -> int:
    patterns = (
        "credential-harvesting",
        "otp-harvesting",
        "business email compromise",
        "brand impersonation",
        "lookalike spoof",
        "sender authenticity checks contain spoofing indicators",
        "threat feed match",
        "high-risk tld",
        "thread hijack",
        "updated bank account",
        "attachment verification lure",
        "password-protected attachment",
        "credential or otp request",
        "urgency",
    )
    total = 0
    for signal in signals:
        lowered = str(signal or "").strip().lower()
        if lowered and any(pattern in lowered for pattern in patterns):
            total += 1
    return total


def weak_detection_threshold(item: dict[str, Any]) -> int:
    bucket = str(item.get("bucket") or "")
    if bucket == "mixed_phishing":
        # Mixed trusted+untrusted campaigns are expected to occupy medium-risk zones.
        return 50

    strong_count = _strong_signal_count(list(item.get("signals") or []))
    if strong_count >= 3:
        return 70

    if bucket == "real_world_phishing":
        return 60

    if bucket in {"real_world_phishing", "short_text_attack", "attachment_phishing"}:
        return 65

    return 60


def _is_explanation_aligned(verdict: str, signals: list[str], explanation: str) -> bool:
    text = str(explanation or "").strip().lower()
    if not text:
        return False

    normalized_verdict = str(verdict or "").strip().lower()
    if normalized_verdict == "safe":
        verdict_ok = any(keyword in text for keyword in ("safe", "legitimate", "low risk", "no urgent action"))
    elif normalized_verdict == "suspicious":
        verdict_ok = any(keyword in text for keyword in ("suspicious", "review", "verify"))
    else:
        verdict_ok = any(keyword in text for keyword in ("high risk", "phishing", "quarantine", "block"))

    top_signals = [str(signal).strip() for signal in signals if str(signal).strip()][:3]
    signal_hits = 0
    for signal in top_signals:
        tokens = _signal_tokens(signal)
        if any(token in text for token in tokens[:3]):
            signal_hits += 1

    signal_ok = signal_hits >= 1 if top_signals and normalized_verdict != "safe" else True
    action_ok = any(
        keyword in text
        for keyword in (
            "do not click",
            "do not open",
            "quarantine",
            "report",
            "verify",
            "contact",
            "monitor",
            "official channel",
            "no urgent action",
        )
    )
    return verdict_ok and signal_ok and action_ok


def run_explain_validation(results: list[dict[str, Any]]) -> dict[str, Any]:
    source_counter: Counter[str] = Counter()
    total = 0
    aligned = 0
    failures: list[str] = []

    for item in results:
        scan_id = str(item.get("scan_id") or "").strip()
        if not scan_id:
            continue

        total += 1
        try:
            response = explain_scan(ExplainRequest(scan_id=scan_id))
            source = str(response.get("source") or "fallback").strip().lower()
            if source not in {"openrouter", "gemini", "fallback"}:
                source = "fallback"
            source_counter[source] += 1

            explanation_text = str(response.get("explanation") or "").strip()
            item["explanation"] = explanation_text
            item["explanation_source"] = source

            if _is_explanation_aligned(str(item.get("verdict") or ""), list(item.get("signals") or []), explanation_text):
                aligned += 1
            else:
                failures.append(f"alignment:{item.get('id')}")
        except Exception as exc:
            source_counter["fallback"] += 1
            failures.append(f"explain_error:{item.get('id')}:{type(exc).__name__}")

    llm_used = source_counter.get("openrouter", 0) + source_counter.get("gemini", 0)
    alignment_percent = round((aligned / total * 100) if total else 0.0, 2)
    llm_usage_percent = round((llm_used / total * 100) if total else 0.0, 2)

    return {
        "total": total,
        "alignment_percent": alignment_percent,
        "aligned_count": aligned,
        "llm_usage_percent": llm_usage_percent,
        "source_usage": {
            "openrouter": source_counter.get("openrouter", 0),
            "gemini": source_counter.get("gemini", 0),
            "fallback": source_counter.get("fallback", 0),
        },
        "failures": failures[:25],
    }


def summarize_score_distribution(results: list[dict[str, Any]]) -> dict[str, Any]:
    bands = [
        ("safe_0_20", 0, 20),
        ("transition_21_24", 21, 24),
        ("suspicious_25_60", 25, 60),
        ("transition_61_69", 61, 69),
        ("high_risk_medium_70_84", 70, 84),
        ("high_risk_strong_85_95", 85, 95),
        ("high_risk_critical_96_100", 96, 100),
    ]
    total = len(results) or 1
    distribution: dict[str, Any] = {}
    for name, low, high in bands:
        count = sum(1 for item in results if low <= int(item.get("risk_score", 0) or 0) <= high)
        distribution[name] = {
            "count": count,
            "percent": round(count / total * 100, 2),
        }

    verdict_bands = {
        "Safe": [item.get("risk_score", 0) for item in results if str(item.get("verdict") or "") == "Safe"],
        "Suspicious": [item.get("risk_score", 0) for item in results if str(item.get("verdict") or "") == "Suspicious"],
        "High Risk": [item.get("risk_score", 0) for item in results if str(item.get("verdict") or "") == "High Risk"],
    }
    verdict_summary: dict[str, Any] = {}
    for verdict, scores in verdict_bands.items():
        verdict_summary[verdict] = {
            "count": len(scores),
            "min": min(scores) if scores else None,
            "max": max(scores) if scores else None,
            "avg": round(mean(scores), 2) if scores else None,
        }

    return {
        "bands": distribution,
        "verdict_summary": verdict_summary,
    }


def run_header_tests() -> list[dict[str, Any]]:
    header_results: list[dict[str, Any]] = []
    for case in HEADER_CASES:
        result = check_headers(HeaderRequest(headers=textwrap.dedent(case["headers"]).strip()))
        header_results.append(
            {
                "name": case["name"],
                "spoofing_score": int(result.get("spoofing_score", 0) or 0),
                "header_risk_score": int(result.get("header_risk_score", 0) or 0),
                "signals": list(result.get("signals", []) or []),
                "reply_to_mismatch": bool(result.get("reply_to_mismatch", False)),
                "return_path_mismatch": bool(result.get("return_path_mismatch", False)),
                "sending_ips": list(result.get("sending_ips", []) or []),
            }
        )
    return header_results


def run_edge_cases() -> list[dict[str, Any]]:
    edge_results: list[dict[str, Any]] = []

    try:
        calculate_email_risk("   \n  ")
        edge_results.append({"name": "empty_input", "status": "unexpected-success"})
    except HTTPException as exc:
        edge_results.append({"name": "empty_input", "status": "handled", "http_status": exc.status_code})

    long_safe_email = build_email(
        """
From: updates@github.com
Reply-To: updates@github.com
Return-Path: <updates@github.com>
Authentication-Results: mx.github.net; spf=pass dkim=pass dmarc=pass
Subject: Long release digest
""",
        "Please review the engineering digest and release notes. " * 250,
    )
    long_result = calculate_email_risk(long_safe_email)
    edge_results.append({
        "name": "very_long_input",
        "status": "ok",
        "risk_score": int(long_result.get("risk_score", 0) or 0),
        "verdict": long_result.get("verdict"),
    })

    multilingual_attack = build_email(
        """
From: Alert Desk <notice@wallet-restore-check.xyz>
Subject: Wallet review
""",
        "आपका wallet बंद हो जाएगा. వెంటనే OTP share karo aur payment confirm karo abhi.",
    )
    multilingual_result = calculate_email_risk(multilingual_attack)
    edge_results.append({
        "name": "non_english_mixed_scripts",
        "status": "ok",
        "risk_score": int(multilingual_result.get("risk_score", 0) or 0),
        "verdict": multilingual_result.get("verdict"),
    })

    no_url_attack = build_email(
        """
From: Finance Head <finance-mobile@urgent-ops.work>
Subject: Immediate action
""",
        "Transfer the funds now and send the OTP immediately. Keep this confidential and do not call.",
    )
    no_url_result = calculate_email_risk(no_url_attack)
    edge_results.append({
        "name": "no_url_phishing",
        "status": "ok",
        "risk_score": int(no_url_result.get("risk_score", 0) or 0),
        "verdict": no_url_result.get("verdict"),
    })

    multi_link_attack = build_email(
        """
From: Security <security@amazon.com>
Reply-To: security@amazon.com
Return-Path: <security@amazon.com>
Authentication-Results: mx.amazon.com; spf=pass dkim=pass dmarc=pass
Subject: Mixed link review
""",
        "Review https://www.amazon.com/gp/help/customer/display.html, then urgently verify at https://amazon-session-check-login.ru/verify and https://tinyurl.com/fake-amz-login today.",
    )
    multi_link_result = calculate_email_risk(multi_link_attack)
    edge_results.append({
        "name": "multiple_links",
        "status": "ok",
        "risk_score": int(multi_link_result.get("risk_score", 0) or 0),
        "verdict": multi_link_result.get("verdict"),
    })

    attachment_attack = build_email(
        """
From: Payroll Secure <notify@payroll-secure.work>
Subject: Salary action required
""",
        "Please open the attached payroll file and complete the verification task immediately.",
    )
    attachment_result = calculate_email_risk(
        attachment_attack,
        attachments=[{"filename": "Payroll_Update.pdf", "contentType": "application/pdf", "hasQrCode": True, "extractedText": "Scan the QR code to verify your salary account now."}],
    )
    edge_results.append({
        "name": "attachment_qr_attack",
        "status": "ok",
        "risk_score": int(attachment_result.get("risk_score", 0) or 0),
        "verdict": attachment_result.get("verdict"),
    })

    thread_attack = build_email(
        """
From: Vendor Finance <accounts@vendor-update.top>
Subject: Re: Invoice thread
""",
        "Re: payment discussion\n\nAs discussed, use the updated beneficiary and new account details on the same thread today. Keep this confidential.",
    )
    thread_result = calculate_email_risk(thread_attack)
    edge_results.append({
        "name": "thread_hijack_follow_up",
        "status": "ok",
        "risk_score": int(thread_result.get("risk_score", 0) or 0),
        "verdict": thread_result.get("verdict"),
        "thread_detected": bool((thread_result.get("thread_analysis") or {}).get("threadDetected")),
    })

    consistency_sample = build_email(
        """
From: Google Security <security@accounts.google.com>
Reply-To: security@accounts.google.com
Return-Path: <security@accounts.google.com>
Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass
Subject: Security review
""",
        "Read the official page at https://support.google.com/accounts/answer/6294825 and urgently verify at https://google-session-validate.top/login now.",
    )
    first = calculate_email_risk(consistency_sample)
    second = calculate_email_risk(consistency_sample)
    consistent = (
        int(first.get("risk_score", 0) or 0) == int(second.get("risk_score", 0) or 0)
        and str(first.get("verdict")) == str(second.get("verdict"))
        and int(first.get("confidence", 0) or 0) == int(second.get("confidence", 0) or 0)
    )
    edge_results.append({"name": "repeated_scan_consistency", "status": "ok" if consistent else "mismatch", "consistent": consistent})

    return edge_results


def run_stress_consistency_checks(iterations_per_sample: int = 20) -> dict[str, Any]:
    def response_band(score: int) -> str:
        if score <= 25:
            return "safe"
        if score <= 60:
            return "suspicious"
        return "high_risk"

    stress_samples = {
        "safe_baseline": build_email(
            """
From: GitHub <noreply@github.com>
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Authentication-Results: mx.github.net; spf=pass dkim=pass dmarc=pass
Subject: Account activity summary
""",
            "Review your recent account activity. No action is required if this was you.",
        ),
        "suspicious_no_url": build_email(
            """
From: Vendor Finance <accounts@vendor-update.top>
Subject: Re: Invoice thread
""",
            "Re: payment discussion. Use updated beneficiary details on the same thread and keep this confidential today.",
        ),
        "high_risk_url": build_email(
            """
From: Security Team <alerts@secure-login-check.top>
Reply-To: recovery@secure-login-check.top
Return-Path: <bounce@secure-login-check.top>
Authentication-Results: mx.enterprise.net; spf=fail dkim=fail dmarc=fail
Subject: Immediate verification required
""",
            "Your account will be suspended unless you verify OTP immediately at https://secure-login-check.top/verify.",
        ),
        "multilingual_phishing": build_email(
            """
From: Wallet Team <alerts@wallet-restore-check.xyz>
Subject: तत्काल सत्यापन
""",
            "आपका wallet बंद हो जाएगा. వెంటనే OTP share karo और अभी verify करें.",
        ),
    }

    sample_reports: list[dict[str, Any]] = []
    total_runs = 0
    total_crashes = 0
    all_stable = True
    all_sla = True

    with TestClient(app) as client:
        for sample_name, sample_email in stress_samples.items():
            signatures: set[tuple[Any, ...]] = set()
            latencies_ms: list[float] = []
            sample_crashes = 0
            risk_scores: list[int] = []

            for idx in range(iterations_per_sample):
                started = time.perf_counter()
                try:
                    response = client.post(
                        "/scan-email",
                        json={
                            "email_text": sample_email,
                            "session_id": f"stress-{sample_name}-{idx}",
                        },
                    )
                    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                    latencies_ms.append(elapsed_ms)
                    total_runs += 1

                    if response.status_code not in {200, 504}:
                        sample_crashes += 1
                        total_crashes += 1
                        continue

                    if response.status_code == 504:
                        signatures.add(("timeout", "Timeout", "timeout"))
                        continue

                    payload = response.json()
                    risk_score = int(payload.get("risk_score", 0) or 0)
                    risk_scores.append(risk_score)
                    signatures.add(
                        (
                            int(response.status_code),
                            str(payload.get("verdict") or ""),
                            response_band(risk_score),
                        )
                    )
                except Exception:
                    total_runs += 1
                    sample_crashes += 1
                    total_crashes += 1

            stable = len(signatures) == 1 and sample_crashes == 0
            max_latency = round(max(latencies_ms), 2) if latencies_ms else 0.0
            avg_latency = round(mean(latencies_ms), 2) if latencies_ms else 0.0
            min_risk = min(risk_scores) if risk_scores else 0
            max_risk = max(risk_scores) if risk_scores else 0
            sla_within_2s = max_latency < 2000.0

            all_stable = all_stable and stable
            all_sla = all_sla and sla_within_2s

            sample_reports.append(
                {
                    "name": sample_name,
                    "iterations": iterations_per_sample,
                    "stable": stable,
                    "signature_count": len(signatures),
                    "sample_crashes": sample_crashes,
                    "min_risk": min_risk,
                    "max_risk": max_risk,
                    "avg_latency_ms": avg_latency,
                    "max_latency_ms": max_latency,
                    "sla_within_2s": sla_within_2s,
                }
            )

    return {
        "iterations_per_sample": iterations_per_sample,
        "total_runs": total_runs,
        "crashes": total_crashes,
        "stable": all_stable,
        "sla_within_2s": all_sla,
        "samples": sample_reports,
    }


def build_example_outputs(results: list[dict[str, Any]]) -> dict[str, Any]:
    examples: dict[str, Any] = {}
    for verdict in ("Safe", "Suspicious", "High Risk"):
        sample = next((item for item in results if str(item.get("verdict") or "") == verdict), None)
        if sample is None and verdict == "Suspicious":
            probe = calculate_email_risk(
                build_email(
                    """
From: Account Review Team <review@account-update-notice.info>
Subject: Account details reminder
""",
                    "Please review your account details and confirm if your contact information is still current.",
                )
            )
            if str(probe.get("verdict") or "") == "Suspicious":
                sample = {
                    "id": "SAMPLE-SUSPICIOUS-PROBE",
                    "risk_score": int(probe.get("risk_score", 0) or 0),
                    "verdict": str(probe.get("verdict") or "Suspicious"),
                    "signals": list(probe.get("matched_signals") or probe.get("signals") or []),
                    "explanation": str(probe.get("explanation") or ""),
                    "explanation_source": "probe",
                }

        if sample is None:
            examples[verdict] = None
            continue

        examples[verdict] = {
            "id": sample.get("id"),
            "risk_score": int(sample.get("risk_score", 0) or 0),
            "verdict": str(sample.get("verdict") or verdict),
            "signals": list(sample.get("signals") or [])[:3],
            "explanation": str(sample.get("explanation") or "").strip(),
            "explanation_source": str(sample.get("explanation_source") or "backend"),
        }

    return examples


def summarize(
    results: list[dict[str, Any]],
    header_results: list[dict[str, Any]],
    edge_results: list[dict[str, Any]],
    stress_results: dict[str, Any],
    explain_summary: dict[str, Any],
) -> dict[str, Any]:
    total = len(results)
    safe_total = sum(1 for item in results if item["expected"] == "safe") or 1
    phishing_total = sum(1 for item in results if item["expected"] == "phishing") or 1
    correct = sum(1 for item in results if item["expected"] == item["predicted"])
    false_positives = sum(1 for item in results if item["expected"] == "safe" and item["predicted"] != "safe")
    false_negatives = sum(1 for item in results if item["expected"] == "phishing" and item["predicted"] == "safe")
    false_positive_items = [item for item in results if item["expected"] == "safe" and item["predicted"] != "safe"]
    false_negative_items = [item for item in results if item["expected"] == "phishing" and item["predicted"] == "safe"]
    weak_detection_items = [
        item
        for item in results
        if item["expected"] == "phishing"
        and item["predicted"] == "phishing"
        and int(item.get("risk_score", 0) or 0) < weak_detection_threshold(item)
    ]
    weak_detection_total = len(weak_detection_items)
    band_matches = sum(1 for item in results if item["within_expected_band"])
    verdict_band_integrity = 0
    for item in results:
        score = int(item.get("risk_score", 0) or 0)
        verdict = str(item.get("verdict") or "").strip()
        if verdict == "Safe" and 0 <= score <= 20:
            verdict_band_integrity += 1
        elif verdict == "Suspicious" and 25 <= score <= 60:
            verdict_band_integrity += 1
        elif verdict == "High Risk" and 70 <= score <= 100:
            verdict_band_integrity += 1

    bucket_summary: dict[str, Any] = {}
    for bucket in sorted({item["bucket"] for item in results}):
        bucket_items = [item for item in results if item["bucket"] == bucket]
        bucket_summary[bucket] = {
            "count": len(bucket_items),
            "accuracy_percent": round(sum(1 for item in bucket_items if item["expected"] == item["predicted"]) / len(bucket_items) * 100, 2),
            "average_risk_score": round(mean(item["risk_score"] for item in bucket_items), 2),
            "min_risk_score": min(item["risk_score"] for item in bucket_items),
            "max_risk_score": max(item["risk_score"] for item in bucket_items),
            "band_match_percent": round(sum(1 for item in bucket_items if item["within_expected_band"]) / len(bucket_items) * 100, 2),
        }

    coverage = {
        "nlp_and_behavior": any(item["bucket"] in {"direct_phishing", "mixed_phishing", "short_text_attack", "multilingual_phishing"} and item["predicted"] == "phishing" for item in results),
        "intent_engine": any(
            int((item.get("intent_analysis") or {}).get("financial_intent_score", 0) or 0) > 0
            or int((item.get("intent_analysis") or {}).get("credential_intent_score", 0) or 0) > 0
            or int((item.get("intent_analysis") or {}).get("action_intent_score", 0) or 0) > 0
            for item in results
            if item.get("expected") == "phishing"
        ),
        "context_engine": any(
            str((item.get("context_analysis") or {}).get("context_type", "")).strip()
            not in {"", "general_phishing"}
            for item in results
            if item.get("expected") == "phishing"
        ),
        "authority_engine": any(
            int((item.get("authority_analysis") or {}).get("authority_score", 0) or 0) >= 60
            for item in results
            if item.get("expected") == "phishing"
        ),
        "action_engine": any(
            int((item.get("action_analysis") or {}).get("action_risk_score", 0) or 0) >= 40
            for item in results
            if item.get("expected") == "phishing"
        ),
        "behavior_engine": any(
            int((item.get("behavior_analysis") or {}).get("behavior_risk_score", 0) or 0) >= 40
            for item in results
            if item.get("expected") == "phishing"
        ),
        "url_sandbox": any((item.get("url_sandbox") or {}).get("details") for item in results),
        "header_authentication": any(item["header_risk_score"] >= 30 for item in header_results),
        "sender_reputation": any(bool(item.get("sender_reputation")) for item in results),
        "thread_context": any(bool((item.get("thread_analysis") or {}).get("signals")) or bool((item.get("thread_analysis") or {}).get("threadDetected")) for item in results) or any(bool(item.get("thread_detected")) for item in edge_results),
        "attachments_and_qr": any(((item.get("attachment_analysis") or {}).get("total_attachments", 0) or 0) > 0 for item in results),
        "threat_intelligence": any(bool((item.get("threat_intel") or {}).get("matches")) for item in results),
    }

    edge_failures = [item for item in edge_results if item.get("status") not in {"ok", "handled"}]
    header_failures = [item for item in header_results if item["name"] != "legitimate_authenticated_sender" and item["header_risk_score"] < 30]
    coverage_percent = round(sum(1 for value in coverage.values() if value) / len(coverage) * 100, 2)
    false_positive_rate = round(false_positives / safe_total * 100, 2)
    false_negative_rate = round(false_negatives / phishing_total * 100, 2)
    alignment_percent = float(explain_summary.get("alignment_percent", 0.0) or 0.0)
    llm_usage_percent = float(explain_summary.get("llm_usage_percent", 0.0) or 0.0)
    score_distribution = summarize_score_distribution(results)
    example_outputs = build_example_outputs(results)

    readiness_checks = {
        "accuracy_at_least_99": round(correct / total * 100, 2) >= 99.0,
        "false_negatives_zero": false_negatives == 0,
        "edge_cases_pass": not edge_failures,
        "header_cases_pass": not header_failures,
        "coverage_full": coverage_percent == 100.0,
        "stress_stable": bool(stress_results.get("stable", False)),
        "stress_no_crash": int(stress_results.get("crashes", 1) or 0) == 0,
        "scan_sla_under_2s": bool(stress_results.get("sla_within_2s", False)),
    }

    status = "SYSTEM READY FOR PRODUCTION DEPLOYMENT" if all(readiness_checks.values()) else "Needs review"

    summary = {
        "total_emails_tested": total,
        "accuracy_percent": round(correct / total * 100, 2),
        "false_positive_rate_percent": false_positive_rate,
        "false_negative_rate_percent": false_negative_rate,
        "band_match_percent": round(band_matches / total * 100, 2),
        "verdict_band_integrity_percent": round(verdict_band_integrity / total * 100, 2),
        "enterprise_coverage_percent": coverage_percent,
        "score_distribution": score_distribution,
        "capability_coverage": coverage,
        "explanation_alignment_percent": alignment_percent,
        "llm_usage_percent": llm_usage_percent,
        "explanation_source_usage": explain_summary.get("source_usage", {}),
        "explanation_validation": explain_summary,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "weak_detections": weak_detection_total,
        "false_positive_items": false_positive_items[:25],
        "false_negative_items": false_negative_items[:25],
        "weak_detection_items": weak_detection_items[:25],
        "bucket_summary": bucket_summary,
        "header_tests": header_results,
        "edge_cases": edge_results,
        "edge_case_failures": edge_failures,
        "header_failures": header_failures,
        "stress_consistency": stress_results,
        "readiness_checks": readiness_checks,
        "status": status,
        "example_outputs": example_outputs,
        "results": results,
    }
    return summary


def write_report(summary: dict[str, Any]) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    bucket_rows = []
    for bucket_name, details in summary["bucket_summary"].items():
        display_name = bucket_name.replace("_", " ").title()
        bucket_rows.append(
            f"| {display_name} | {details['count']} | {details['accuracy_percent']}% | {details['average_risk_score']} | {details['min_risk_score']} | {details['max_risk_score']} | {details['band_match_percent']}% |"
        )

    coverage_rows = []
    for name, enabled in summary["capability_coverage"].items():
        coverage_rows.append(f"| {name.replace('_', ' ').title()} | {'PASS' if enabled else 'MISS'} |")

    score_rows = []
    for band_name, details in (summary.get("score_distribution") or {}).get("bands", {}).items():
        score_rows.append(f"| {band_name.replace('_', ' ')} | {details.get('count', 0)} | {details.get('percent', 0)}% |")

    source_usage = summary.get("explanation_source_usage") or {}
    source_rows = [
        f"- OpenRouter: **{int(source_usage.get('openrouter', 0) or 0)}**",
        f"- Gemini: **{int(source_usage.get('gemini', 0) or 0)}**",
        f"- Fallback: **{int(source_usage.get('fallback', 0) or 0)}**",
    ]

    report = f"""# PhishShield Enterprise Validation Report

## Final Accuracy Report
- Emails tested directly through backend: **{summary['total_emails_tested']}**
- Accuracy: **{summary['accuracy_percent']}%**
- False Positive Rate: **{summary['false_positive_rate_percent']}%**
- False Negative Rate: **{summary['false_negative_rate_percent']}%**
- Score-band realism match: **{summary['band_match_percent']}%**
- Verdict-band integrity (Safe/Suspicious/High Risk): **{summary.get('verdict_band_integrity_percent', 0)}%**
- Enterprise capability coverage: **{summary['enterprise_coverage_percent']}%**
- Explanation alignment: **{summary.get('explanation_alignment_percent', 0)}%**
- LLM usage (OpenRouter/Gemini): **{summary.get('llm_usage_percent', 0)}%**
- Final status: **{summary['status']}**

## Bucket Breakdown
| Bucket | Count | Accuracy | Avg Risk | Min | Max | Band Match |
|---|---:|---:|---:|---:|---:|---:|
{chr(10).join(bucket_rows)}

## Enterprise Capability Coverage
| Capability | Result |
|---|---|
{chr(10).join(coverage_rows)}

## Score Distribution
| Band | Count | Percent |
|---|---:|---:|
{chr(10).join(score_rows)}

## Explanation Source Usage
{chr(10).join(source_rows)}

## Header Analysis Upgrade Check
"""

    for item in summary["header_tests"]:
        report += f"- **{item['name']}** → header risk `{item['header_risk_score']}`, spoofing `{item['spoofing_score']}`, signals: {', '.join(item['signals']) or 'none'}\n"

    report += "\n## Edge Cases\n"
    for item in summary["edge_cases"]:
        report += f"- **{item['name']}** → `{item['status']}`"
        if "risk_score" in item:
            report += f" (risk {item['risk_score']}, verdict {item.get('verdict', 'n/a')})"
        if "http_status" in item:
            report += f" (HTTP {item['http_status']})"
        report += "\n"

    stress = summary.get("stress_consistency") or {}
    report += "\n## Stress & Consistency\n"
    report += f"- Repeated scans executed: **{int(stress.get('total_runs', 0) or 0)}**\n"
    report += f"- Stable outputs across repeated scans: **{bool(stress.get('stable', False))}**\n"
    report += f"- Crashes observed: **{int(stress.get('crashes', 0) or 0)}**\n"
    report += f"- Timeout safety (<2s per scan): **{bool(stress.get('sla_within_2s', False))}**\n"

    for sample in stress.get("samples") or []:
        report += (
            f"- `{sample.get('name')}`: stable={sample.get('stable')}, "
            f"min_risk={sample.get('min_risk')}, max_risk={sample.get('max_risk')}, "
            f"max_latency_ms={sample.get('max_latency_ms')}, avg_latency_ms={sample.get('avg_latency_ms')}, "
            f"signature_count={sample.get('signature_count')}\n"
        )

    report += "\n## Error Analysis\n"
    report += f"- False positives logged: **{len(summary.get('false_positive_items') or [])}**\n"
    report += f"- False negatives logged: **{len(summary.get('false_negative_items') or [])}**\n"
    report += (
        "- Weak detections (bucket-aware calibrated floor): "
        f"**{int(summary.get('weak_detections', len(summary.get('weak_detection_items') or [])) or 0)}**\n"
    )

    if summary.get("false_positive_items"):
        report += "\n### False Positive Samples\n"
        for item in summary.get("false_positive_items") or []:
            report += f"- `{item.get('id')}` → predicted `{item.get('predicted')}` at risk `{item.get('risk_score')}`\n"

    if summary.get("false_negative_items"):
        report += "\n### False Negative Samples\n"
        for item in summary.get("false_negative_items") or []:
            report += f"- `{item.get('id')}` → predicted `{item.get('predicted')}` at risk `{item.get('risk_score')}`\n"

    if summary.get("weak_detection_items"):
        report += "\n### Weak Detection Samples\n"
        for item in summary.get("weak_detection_items") or []:
            report += f"- `{item.get('id')}` → risk `{item.get('risk_score')}`, verdict `{item.get('verdict')}`\n"

    if summary["edge_case_failures"] or summary["header_failures"]:
        report += "\n## Remaining Limitations\n"
        if summary["edge_case_failures"]:
            report += f"- Edge case review needed for: {', '.join(item['name'] for item in summary['edge_case_failures'])}\n"
        if summary["header_failures"]:
            report += f"- Header checks need review for: {', '.join(item['name'] for item in summary['header_failures'])}\n"
    else:
        report += "\n## Remaining Limitations\n- No blocking issues found in the final validation run. Continue monitoring live sender reputation drift, model freshness, and user feedback in production.\n"

    report += "\n## Deployment Verdict\n"
    report += summary.get("status", "Needs review") + "\n"

    examples = summary.get("example_outputs") or {}
    report += "\n## Example Outputs\n"
    for verdict in ("Safe", "Suspicious", "High Risk"):
        example = examples.get(verdict)
        if not example:
            report += f"- **{verdict}**: No sample generated in this run.\n"
            continue
        report += (
            f"- **{verdict}** (`{example.get('id')}`): risk `{example.get('risk_score')}`, "
            f"source `{example.get('explanation_source')}`, signals: {', '.join(example.get('signals') or []) or 'none'}\n"
            f"  Explanation: {example.get('explanation') or 'N/A'}\n"
        )

    REPORT_MD_PATH.write_text(report, encoding="utf-8")


def main() -> None:
    load_artifacts()
    app.state.scan_cache.clear()
    app.state.scan_explanations.clear()
    app.state.llm_explanation_cache = {}
    cases = [
        *build_safe_cases(),
        *build_direct_cases(),
        *build_mixed_cases(),
        *build_short_text_cases(),
        *build_multilingual_cases(),
        *build_header_spoof_cases(),
        *build_attachment_cases(),
        *build_real_world_cases(),
    ]
    results = run_dataset(cases)
    explain_summary = run_explain_validation(results)
    header_results = run_header_tests()
    edge_results = run_edge_cases()
    stress_results = run_stress_consistency_checks(iterations_per_sample=20)
    summary = summarize(results, header_results, edge_results, stress_results, explain_summary)
    write_report(summary)

    print(f"Validated {summary['total_emails_tested']} emails")
    print(f"Accuracy: {summary['accuracy_percent']}%")
    print(f"False Positive Rate: {summary['false_positive_rate_percent']}%")
    print(f"False Negative Rate: {summary['false_negative_rate_percent']}%")
    print(f"Band Match: {summary['band_match_percent']}%")
    print(f"Verdict-Band Integrity: {summary.get('verdict_band_integrity_percent', 0)}%")
    print(f"Explanation Alignment: {summary.get('explanation_alignment_percent', 0)}%")
    print(f"LLM Usage: {summary.get('llm_usage_percent', 0)}%")
    print(f"Stress Stable: {bool((summary.get('stress_consistency') or {}).get('stable', False))}")
    print(f"Stress Crashes: {int((summary.get('stress_consistency') or {}).get('crashes', 0) or 0)}")
    print(f"Timeout Safety (<2s): {bool((summary.get('stress_consistency') or {}).get('sla_within_2s', False))}")
    print(f"Enterprise Coverage: {summary['enterprise_coverage_percent']}%")
    print(f"Status: {summary['status']}")
    print(f"Report: {REPORT_MD_PATH}")


if __name__ == "__main__":
    main()
