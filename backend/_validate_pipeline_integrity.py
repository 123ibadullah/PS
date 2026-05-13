from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from main import calculate_email_risk  # noqa: E402

CASES = [
    {
        "name": "paypal_otp_critical",
        "email": (
            "From: PayPal Security <security@paypa1-support-alerts.com>\n"
            "Subject: Urgent: Account Suspension Warning\n\n"
            "Your account will be suspended in 30 minutes. "
            "Verify immediately and provide the OTP to continue service. "
            "Use this link now: https://paypa1-login-security-verify.xyz/otp"
        ),
        "expected_verdict": "Critical",
        "score_min": 90,
        "score_max": 100,
        "confidence_min": 85,
        "confidence_max": 100,
    },
    {
        "name": "ceo_wire_no_url_high_risk",
        "email": (
            "From: CEO Office <ceo-finance@company-payroll-support.com>\n"
            "Subject: Confidential transfer request\n\n"
            "I need you to process a wire transfer of USD 48,000 to the new beneficiary today. "
            "Keep this confidential and confirm once completed."
        ),
        "expected_verdict": "High Risk",
        "score_min": 70,
        "score_max": 89,
        "confidence_min": 85,
        "confidence_max": 100,
    },
    {
        "name": "invoice_bank_update_high_risk",
        "email": (
            "From: Accounts Payable <billing@vendor-payment-support.com>\n"
            "Subject: Updated bank details for invoice #8841\n\n"
            "Continuing the same thread, invoice approval requires updated bank account details. "
            "Process payment today and confirm transfer completion."
        ),
        "expected_verdict": "High Risk",
        "score_min": 75,
        "score_max": 89,
        "confidence_min": 85,
        "confidence_max": 100,
    },
    {
        "name": "mixed_trusted_and_suspicious_links",
        "email": (
            "From: Team Updates <support@workspace-notice.com>\n"
            "Subject: Review account activity\n\n"
            "Please review your account update. Official help center: https://google.com/security. "
            "Also complete verification at http://account-security-update-check.xyz/verify"
        ),
        "expected_verdict": "Suspicious",
        "score_min": 40,
        "score_max": 60,
        "confidence_min": 65,
        "confidence_max": 80,
    },
    {
        "name": "google_notifications_safe",
        "email": (
            "From: Google Notifications <notifications@google.com>\n"
            "Subject: Security alert for your account\n\n"
            "New sign-in detected from Chrome on Windows. "
            "If this was you, no action is required. "
            "Do not share this OTP with anyone."
        ),
        "expected_verdict": "Safe",
        "score_min": 0,
        "score_max": 25,
        "confidence_min": 60,
        "confidence_max": 100,
    },
]

required_keys = {"risk_score", "verdict", "confidence", "signals", "score_components"}
required_score_components = {"language_model", "pattern_matching", "link_risk", "header_spoofing"}

results = []
failures = []

for case in CASES:
    output = calculate_email_risk(case["email"])
    score = int(output.get("risk_score", -1))
    verdict = str(output.get("verdict", ""))
    confidence = int(output.get("confidence", -1))
    signals = output.get("signals", [])
    score_components = output.get("score_components", {})

    case_failures = []

    missing = sorted(required_keys - set(output.keys()))
    if missing:
        case_failures.append(f"missing_keys={missing}")

    if verdict != case["expected_verdict"]:
        case_failures.append(f"verdict_expected={case['expected_verdict']} actual={verdict}")

    if not (case["score_min"] <= score <= case["score_max"]):
        case_failures.append(f"score_out_of_range={score} expected=[{case['score_min']},{case['score_max']}]")

    if not (case["confidence_min"] <= confidence <= case["confidence_max"]):
        case_failures.append(
            f"confidence_out_of_range={confidence} expected=[{case['confidence_min']},{case['confidence_max']}]"
        )

    if not isinstance(signals, list):
        case_failures.append("signals_not_list")

    if signals and any(str(item).strip() == "Backend flagged risk indicators" for item in signals):
        case_failures.append("generic_signal_fallback_detected")

    if not isinstance(score_components, dict):
        case_failures.append("score_components_not_dict")
    else:
        missing_components = sorted(required_score_components - set(score_components.keys()))
        if missing_components:
            case_failures.append(f"missing_score_components={missing_components}")

    results.append(
        {
            "case": case["name"],
            "risk_score": score,
            "verdict": verdict,
            "confidence": confidence,
            "signals_count": len(signals) if isinstance(signals, list) else -1,
            "score_components": score_components,
            "failures": case_failures,
        }
    )

    if case_failures:
        failures.append({"case": case["name"], "failures": case_failures})

print(json.dumps({"results": results, "failures": failures, "failure_count": len(failures)}, indent=2))
