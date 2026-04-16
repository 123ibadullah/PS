import json
from datetime import datetime, timezone

from main import calculate_email_risk


CASES = [
    {
        "name": "1_safe_google_security_notice",
        "expected": "Safe",
        "email": (
            "From: Google Security <no-reply@accounts.google.com>\n"
            "Subject: New sign-in to your Google Account\n\n"
            "Your Google Account was signed in from a new Windows device. "
            "If this was you, you can ignore this email. If this wasn't you, "
            "secure your account from the official Google app."
        ),
        "headers": (
            "From: Google Security <no-reply@accounts.google.com>\n"
            "Reply-To: no-reply@accounts.google.com\n"
            "Return-Path: <no-reply@accounts.google.com>\n"
            "Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass"
        ),
    },
    {
        "name": "2_high_risk_otp_urgency_link",
        "expected": "High Risk",
        "email": (
            "URGENT: Your bank account will be suspended in 30 minutes. "
            "Reply with your OTP and password immediately and verify at "
            "http://secure-bank-verify-login.xyz/auth now."
        ),
        "headers": "",
    },
    {
        "name": "3_high_risk_bec_transfer",
        "expected": "High Risk",
        "email": (
            "Hi Finance Team, process this urgent vendor payment now. "
            "Keep this confidential and do not call me. "
            "Transfer funds to the beneficiary in the attached invoice and confirm immediately."
        ),
        "headers": "",
    },
    {
        "name": "4_suspicious_header_mismatch_no_links",
        "expected": "Suspicious",
        "email": (
            "From: Support Team <support@company-helpdesk.com>\n\n"
            "Please review your account profile details."
        ),
        "headers": (
            "From: Support Team <support@company-helpdesk.com>\n"
            "Reply-To: assist@random-mailer.net\n"
            "Return-Path: <bounce@mailer-random.net>\n"
            "Authentication-Results: mx.example.com; spf=pass dkim=none dmarc=none"
        ),
    },
    {
        "name": "5_safe_newsletter",
        "expected": "Safe",
        "email": (
            "From: LinkedIn News <news@linkedin.com>\n"
            "Subject: Weekly digest\n\n"
            "Here is your weekly professional digest. Manage notification settings or unsubscribe anytime."
        ),
        "headers": (
            "From: LinkedIn News <news@linkedin.com>\n"
            "Reply-To: news@linkedin.com\n"
            "Return-Path: <news@linkedin.com>\n"
            "Authentication-Results: mx.linkedin.com; spf=pass dkim=pass dmarc=pass"
        ),
    },
    {
        "name": "6_suspicious_link_reputation",
        "expected": "Suspicious",
        "email": (
            "Your package is delayed. Pay INR 49 now to release delivery at "
            "http://parcel-release-fee-track.top/pay."
        ),
        "headers": "",
    },
    {
        "name": "7_safe_unknown_sender_no_signals",
        "expected": "Safe",
        "email": (
            "Hello team, sharing this week's project status summary. "
            "No action required."
        ),
        "headers": (
            "From: Project PM <update@new-domain-example.org>\n"
            "Authentication-Results: mx.example.org; spf=none dkim=none dmarc=none"
        ),
    },
    {
        "name": "8_suspicious_lookalike_brand_sender",
        "expected": "Suspicious",
        "email": (
            "From: Amazon Billing <billing@amaz0n-security-support.com>\n\n"
            "Please verify your recent account activity by reviewing your account details."
        ),
        "headers": (
            "From: Amazon Billing <billing@amaz0n-security-support.com>\n"
            "Reply-To: billing@amaz0n-security-support.com\n"
            "Return-Path: <billing@amaz0n-security-support.com>\n"
            "Authentication-Results: mx.example.org; spf=pass dkim=none dmarc=none"
        ),
    },
]


def run_suite() -> None:
    print(f"Validation run started at {datetime.now(timezone.utc).isoformat()}")
    failures = 0

    for case in CASES:
        try:
            response = calculate_email_risk(case["email"], headers_text=case.get("headers") or None)
            actual = response.get("verdict")
            passed = actual == case["expected"]
            if not passed:
                failures += 1
            print(json.dumps({
                "case": case["name"],
                "expected": case["expected"],
                "actual": actual,
                "pass": passed,
                "response": response,
            }, ensure_ascii=False))
        except Exception as exc:
            failures += 1
            print(json.dumps({
                "case": case["name"],
                "expected": case["expected"],
                "actual": "ERROR",
                "pass": False,
                "error": str(exc),
            }, ensure_ascii=False))

    print(json.dumps({
        "total_cases": len(CASES),
        "failed_cases": failures,
        "passed_cases": len(CASES) - failures,
    }, ensure_ascii=False))


if __name__ == "__main__":
    run_suite()
