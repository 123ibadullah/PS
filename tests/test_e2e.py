import sys
import os
import time
import json
import re
from datetime import datetime, timezone
from typing import Any

# Ensure we can import from the current directory
sys.path.insert(0, '.')
try:
    from main import calculate_email_risk_strict, detect_language_code
except ImportError as e:
    print(f"Error: Could not import calculate_email_risk_strict from main.py: {e}")
    sys.exit(1)

# === TEST CATEGORIES & CASES ===

TEST_CASES = [
    # 1. SAFE EMAILS (verdict: Safe, risk_score 0-25)
    {
        "id": "SAFE_01: Google Login Notify",
        "category": "Safe Detection",
        "email": "From: no-reply@accounts.google.com\nTo: user@gmail.com\nSubject: Security alert\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you can safely ignore this email.",
        "headers": "Authentication-Results: mx.google.com; dkim=pass header.i=@google.com; spf=pass; dmarc=pass header.from=google.com",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "SAFE_02: Amazon Order Confirm",
        "category": "Safe Detection",
        "email": "From: auto-confirm@amazon.in\nTo: customer@example.com\nSubject: Order Shipped\n\nYour Amazon order #123-456 has been shipped and will arrive tomorrow. Track here: https://amazon.in/orders/123-456",
        "headers": "Authentication-Results: mx.google.com; dkim=pass header.i=@amazon.in; spf=pass; dmarc=pass",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "SAFE_03: GitHub PR Review",
        "category": "Safe Detection",
        "email": "From: noreply@github.com\nTo: dev@company.com\nSubject: [GitHub] Review requested\n\nA teammate requested your review on PR #88. View it here: https://github.com/org/repo/pull/88",
        "headers": "Authentication-Results: mx.google.com; dkim=pass header.i=@github.com; spf=pass; dmarc=pass",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "SAFE_04: PayPal Payment confirmed",
        "category": "Safe Detection",
        "email": "From: service@paypal.com\nTo: user@example.com\nSubject: You sent a payment\n\nYou sent $15.00 USD to Netflix. This transaction will appear on your statement as PAYPAL *NETFLIX.",
        "headers": "Authentication-Results: mx.google.com; dkim=pass header.i=@paypal.com; spf=pass; dmarc=pass",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "SAFE_05: OTP Safety Notice",
        "category": "Safe Detection",
        "email": "From: security@mybank.com\nTo: customer@example.com\nSubject: Security Tip\n\nRemember: Do not share your OTP with anyone, even if they claim to be from our bank. We will never ask for your password or OTP over the phone or email.",
        "headers": "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "SAFE_06: Internal Newsletter",
        "category": "Safe Detection",
        "email": "From: news@mycompany.com\nTo: employee@mycompany.com\nSubject: Weekly Digest\n\nHere is what happened this week at the office. Don't forget the pizza party on Friday!\n\nUnsubscribe from this list.",
        "headers": "Authentication-Results: local; dkim=pass; spf=pass; dmarc=pass",
        "expected_verdict": "Safe",
        "max_risk": 25
    },

    # 2. SUSPICIOUS EMAILS (verdict: Suspicious, risk_score 26-60)
    {
        "id": "SUSP_01: Unknown sender payment mention",
        "category": "Suspicious Det.",
        "email": "From: stranger@unknown-domain.top\nTo: victim@example.com\nSubject: Regarding your payment\n\nHello, we need to discuss the payment for the services. Please check the details here: https://unknown-domain.top/payment-info",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=pass; dmarc=none",
        "expected_verdict": "Suspicious",
        "risk_range": (26, 60)
    },
    {
        "id": "SUSP_02: HR onboarding vague link",
        "category": "Suspicious Det.",
        "email": "From: hr@global-corp-onboarding.xyz\nTo: candidate@gmail.com\nSubject: Onboarding steps\n\nPlease complete your onboarding by visiting this portal: https://global-corp-onboarding.xyz/start",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=none; dmarc=none",
        "expected_verdict": "Suspicious",
        "risk_range": (26, 60)
    },

    # 3. HIGH RISK EMAILS (verdict: High Risk, risk_score 61-89)
    {
        "id": "HIGH_01: HDFC Bank OTP Phishing",
        "category": "High Risk Det.",
        "email": "From: security@hdfc-verification.xyz\nTo: user@gmail.com\nSubject: URGENT: Account Blocked\n\nYour HDFC NetBanking account is blocked. Abhi apna OTP share karein access restore karne ke liye. Verify now: https://hdfc-verification.xyz/login",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=none",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },
    {
        "id": "HIGH_02: SBI Account Suspended",
        "category": "High Risk Det.",
        "email": "From: alert@sbi-online-secure.top\nTo: user@yahoo.com\nSubject: Account Suspension Notice\n\nYour SBI account has been suspended. Please verify your KYC details immediately to avoid permanent closure. Link: https://sbi-online-secure.top/kyc",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=none",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },
    {
        "id": "HIGH_03: BEC CEO Wire Transfer",
        "category": "High Risk Det.",
        "email": "From: ceo@company-ceo-urgent.com\nTo: finance-lead@company.com\nSubject: Urgent Wire Transfer\n\nI am in a meeting and cannot be disturbed. Please process a wire transfer of $45,000 for a confidential acquisition. Send the confirmation once done.",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=fail",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },
    {
        "id": "HIGH_04: FedEx Delivery Fee Scam",
        "category": "High Risk Det.",
        "email": "From: delivery@fedex-shipping-hold.xyz\nTo: user@example.com\nSubject: Delivery Delayed\n\nYour package is on hold. A customs fee of Rs.49 is pending. Pay now to release: https://fedex-shipping-hold.xyz/pay",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=none",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },
    {
        "id": "HIGH_05: Income Tax Refund Scam",
        "category": "High Risk Det.",
        "email": "From: refund@incometax-gov-india.top\nTo: taxpayer@example.com\nSubject: Tax Refund Approved\n\nYour income tax refund of Rs.15,400 has been approved. Please verify your PAN and Bank details to receive it: https://incometax-gov-india.top/refund",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=none",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },
    {
        "id": "HIGH_06: KBC Lottery Scam",
        "category": "High Risk Det.",
        "email": "From: info@kbc-lucky-winner.xyz\nTo: user@example.com\nSubject: Congratulations! KBC Winner\n\nYou have won 25 Lakhs in KBC Lucky Draw. Contact our manager on WhatsApp +44 123456789 to claim your prize.",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=none; dmarc=none",
        "expected_verdict": "High Risk",
        "risk_range": (61, 89)
    },

    # 4. CRITICAL EMAILS (verdict: Critical / High Risk, risk_score 90-100)
    {
        "id": "CRIT_01: Multisignal Credential Phish",
        "category": "Critical Det.",
        "email": "From: security@login-verified.xyz\nTo: victim@example.com\nSubject: Security Alert: Account Compromised\n\nWe detected an unauthorized login to your account. Your account is locked. Please log in here to verify your identity and enter the OTP sent to your phone: https://login-verified.xyz/secure",
        "headers": "Authentication-Results: mx.google.com; dkim=none; spf=fail; dmarc=fail",
        "expected_verdict": ["Critical", "High Risk"],
        "min_risk": 85
    },

    # 5. EDGE CASES
    {
        "id": "EDGE_01: Very short safe",
        "category": "Edge Cases",
        "email": "Hi, are we still on for lunch?",
        "headers": "",
        "expected_verdict": "Safe",
        "max_risk": 25
    },
    {
        "id": "EDGE_02: Very short phishing",
        "category": "Edge Cases",
        "email": "Urgent: Verify your account now: https://verify-now.xyz",
        "headers": "",
        "expected_verdict": "High Risk",
        "min_risk": 61
    },
    {
        "id": "EDGE_03: Telugu Phishing",
        "category": "Edge Cases",
        "email": "à°®à±€ à°¬à± à°¯à°¾à°‚à°•à±  à°–à°¾à°¤à°¾ à°¬à± à°²à°¾à°•à±  à°šà±‡à°¯à°¬à°¡à°¿à°‚à°¦à°¿. à°¤à°¿à°°à°¿à°—à°¿ à°ªà±Šà°‚à°¦à°¡à°¾à°¨à°¿à°•à°¿ à°ˆ à°²à°¿à°‚à°•à±  à°•à± à°²à°¿à°•à±  à°šà±‡à°¯à°‚à°¡à°¿: https://bank-verify.xyz",
        "headers": "",
        "expected_verdict": "High Risk",
        "min_risk": 61
    },

    # 6. HEADER TESTS
    {
        "id": "HEAD_01: SPF/DKIM Fail",
        "category": "Header Tests",
        "email": "From: security@paypal.com\nTo: user@example.com\nSubject: Alert\n\nYour account has a problem.",
        "headers": "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail",
        "expected_verdict": ["High Risk", "Suspicious"],
        "min_risk": 40
    },
    {
        "id": "HEAD_02: Display Name Spoof",
        "category": "Header Tests",
        "email": "From: \"HDFC Bank\" <security@random-sender.xyz>\nTo: user@example.com\nSubject: Account Alert\n\nPlease check your account.",
        "headers": "Authentication-Results: mx.google.com; spf=pass; dkim=none; dmarc=none",
        "expected_verdict": ["High Risk", "Suspicious"],
        "min_risk": 30
    },
]

# Statistics trackers
results = {
    "Total Tests": 0,
    "Passed": 0,
    "Failed": 0,
    "Categories": {}
}

latencies = []

def run_test(test):
    global results, latencies
    results["Total Tests"] += 1
    cat = test["category"]
    if cat not in results["Categories"]:
        results["Categories"][cat] = {"passed": 0, "total": 0}
    results["Categories"][cat]["total"] += 1

    start_time = time.perf_counter()
    try:
        res = calculate_email_risk_strict(
            test["email"], 
            headers_text=test.get("headers", ""),
            attachments=test.get("attachments")
        )
    except Exception as e:
        print(f"[ERROR] Test {test['id']} crashed: {e}")
        results["Failed"] += 1
        return False
    
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    latencies.append(duration_ms)

    verdict = res["verdict"]
    risk_score = res["risk_score"]
    
    # Validation logic
    pass_verdict = False
    if isinstance(test["expected_verdict"], list):
        pass_verdict = verdict in test["expected_verdict"]
    else:
        pass_verdict = verdict == test["expected_verdict"]
    
    pass_risk = True
    if "max_risk" in test and risk_score > test["max_risk"]:
        pass_risk = False
    if "min_risk" in test and risk_score < test["min_risk"]:
        pass_risk = False
    if "risk_range" in test:
        low, high = test["risk_range"]
        if not (low <= risk_score <= high):
            pass_risk = False

    passed = pass_verdict and pass_risk
    
    if passed:
        results["Passed"] += 1
        results["Categories"][cat]["passed"] += 1
        # Success output is quiet by default
    else:
        results["Failed"] += 1
        print(f"[FAIL] {test['id']}")
        print(f"       Expected Verdict: {test['expected_verdict']}, Got: {verdict}")
        print(f"       Expected Risk: {test.get('max_risk') or test.get('min_risk') or test.get('risk_range')}, Got: {risk_score}")
        print(f"       Signals: {res['signals']}")
        print(f"       Explanation: {res['explanation']}")
    
    return passed

# Main Execution
print("Initiating PhishShield Production Test Suite...")
print("-" * 60)

for test in TEST_CASES:
    run_test(test)

# Determinism checks (Run SAFE_01 three times)
determinism_pass = True
det_results = []
for _ in range(3):
    res = calculate_email_risk_strict(TEST_CASES[0]["email"], headers_text=TEST_CASES[0]["headers"])
    det_results.append((res["verdict"], res["risk_score"]))

if len(set(det_results)) > 1:
    determinism_pass = False
    print(f"[FAIL] Determinism check failed: {det_results}")

# Final Report
print("\n" + "=" * 46)
print("PHISHSHIELD PRODUCTION CERTIFICATION REPORT")
print("=" * 46)
print(f"Total Tests:        {results['Total Tests']}")
print(f"Passed:             {results['Passed']}")
print(f"Failed:             {results['Failed']}")
print("-" * 45)

for cat, stats in results["Categories"].items():
    print(f"{cat:<18} [{stats['passed']}/{stats['total']} passed]")

print("-" * 45)
accuracy = (results["Passed"] / results["Total Tests"]) * 100
print(f"Accuracy:           {accuracy:.1f}%")
print(f"Determinism:        {'STABLE' if determinism_pass else 'UNSTABLE'}")
avg_time = sum(latencies) / len(latencies) if latencies else 0
max_time = max(latencies) if latencies else 0
print(f"Avg Response Time:  {avg_time:.1f}ms")
print(f"Max Response Time:  {max_time:.1f}ms")
print("-" * 45)

if accuracy == 100.0 and determinism_pass:
    print("VERDICT: [PASS] CERTIFIED FOR PRODUCTION DEPLOYMENT")
else:
    print("VERDICT: [FAIL] NOT CERTIFIED - FIX FAILURES ABOVE")
    sys.exit(1)

print("=" * 46)
