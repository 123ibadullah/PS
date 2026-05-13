"""
PhishShield 10-Case Production Validation Suite
================================================
Tests all advanced detection vectors: links, OTP, BEC, attachments,
OCR/image, QR, thread hijacking.
"""
import json
import requests
import sys

API = "http://127.0.0.1:8000/scan"

CASES = [
    {
        "id": 1,
        "name": "Phishing link (account suspended)",
        "payload": {
            "email_text": "Dear user, your account is suspended. Verify now: http://secure-login-update.xyz"
        },
        "expected": "High Risk",
    },
    {
        "id": 2,
        "name": "Safe OTP notification",
        "payload": {
            "email_text": "Your OTP is 483920. Do not share it with anyone."
        },
        "expected": "Safe",
    },
    {
        "id": 3,
        "name": "BEC transfer (no link)",
        "payload": {
            "email_text": "Hey, transfer 50000 today, don't tell anyone."
        },
        "expected": "High Risk",
    },
    {
        "id": 4,
        "name": "Attachment credential harvesting",
        "payload": {
            "email_text": "Invoice attached for your review.",
            "attachments": [{
                "filename": "invoice.pdf",
                "contentType": "application/pdf",
                "size": 45000,
                "extractedText": "login to verify password"
            }]
        },
        "expected": "High Risk",
    },
    {
        "id": 5,
        "name": "Image/QR phishing",
        "payload": {
            "email_text": "Check attached image.",
            "attachments": [{
                "filename": "scan.png",
                "contentType": "image/png",
                "size": 52000,
                "hasQrCode": True,
                "extractedText": "Scan QR to verify bank account"
            }]
        },
        "expected": "High Risk",
    },
    {
        "id": 6,
        "name": "Thread hijack payment switch",
        "payload": {
            "email_text": "Re: previous thread... change payment urgently.\n\nPlease update the payment to the new account details immediately.\nThis is urgent, do not delay.\n\n-----Original Message-----\nFrom: John <john@company.com>\nSent: Monday\nSubject: Re: Project\n\nHi team, the project is going well. Looking forward to the review.\n\nBest,\nJohn"
        },
        "expected": "High Risk",
    },
    {
        "id": 7,
        "name": "Safe GitHub welcome",
        "payload": {
            "email_text": "from: noreply@github.com\nsubject: Welcome to GitHub!\n\nWelcome to GitHub! Your account has been created successfully. You can now start exploring repositories and collaborating with developers worldwide.\n\nHappy coding!\nThe GitHub Team\n\nTo unsubscribe from these emails, visit your notification settings."
        },
        "expected": "Safe",
    },
    {
        "id": 8,
        "name": "Safe banking summary",
        "payload": {
            "email_text": "from: alerts@hdfcbank.net\nsubject: Your Weekly Banking Summary\nmailed-by: hdfcbank.net\n\nDear Customer,\n\nYour weekly banking summary is ready. You had 3 transactions this week.\n\nTotal credits: Rs. 45,000\nTotal debits: Rs. 12,500\nBalance: Rs. 1,25,000\n\nThis is an automated notification. Please do not reply.\n\nRegards,\nHDFC Bank"
        },
        "expected": "Safe",
    },
    {
        "id": 9,
        "name": "BEC casual urgency (no link)",
        "payload": {
            "email_text": "Hi bro, send me 5k urgently. Need it right now, don't tell anyone about this transfer."
        },
        "expected": "High Risk",
    },
    {
        "id": 10,
        "name": "Phishing document link",
        "payload": {
            "email_text": "Document shared: http://drive-secure-access.xyz\n\nClick here to access your shared document. Verify your identity to proceed."
        },
        "expected": "High Risk",
    },
]


def run_suite():
    print("=" * 70)
    print("  PHISHSHIELD 10-CASE PRODUCTION VALIDATION")
    print("=" * 70)
    print()

    passed = 0
    failed = 0
    results = []

    for case in CASES:
        try:
            r = requests.post(API, json=case["payload"], timeout=12)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"  [ERROR] Case {case['id']}: {case['name']} -- {e}")
            failed += 1
            results.append({"id": case["id"], "status": "ERROR", "error": str(e)})
            continue

        score = data.get("risk_score", data.get("riskScore", 0))
        verdict = data.get("verdict", "Unknown")
        signals = data.get("signals", [])
        expected = case["expected"]

        # Match logic: "High Risk" expected means verdict must NOT be "Safe"
        # "Safe" expected means verdict must be "Safe"
        if expected == "Safe":
            ok = verdict == "Safe"
        elif expected == "High Risk":
            ok = verdict in ("High Risk", "Critical")
        else:
            ok = verdict == expected

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        icon = "[PASS]" if ok else "[FAIL]"
        print(f"  {icon} Case {case['id']}: {case['name']}")
        print(f"         Expected={expected}  Got={verdict} (score={score})")
        if not ok:
            print(f"         Signals: {signals[:5]}")
        print()

        results.append({
            "id": case["id"],
            "name": case["name"],
            "expected": expected,
            "verdict": verdict,
            "score": score,
            "signals": signals[:5],
            "status": status,
        })

    print("=" * 70)
    print(f"  RESULT: {passed}/10 passed, {failed}/10 failed")
    print("=" * 70)

    if failed == 0:
        print()
        print("  >>> ALL 10/10 CASES PASS -- SYSTEM IS PRODUCTION READY <<<")
        print()

    return passed, failed, results


if __name__ == "__main__":
    p, f, _ = run_suite()
    sys.exit(0 if f == 0 else 1)
