"""
Regression test suite — 35 cases.
Run with: pytest test_regression.py -v
ALL tests must pass. A CI check should run this on every commit.
"""
import pytest
from main import calculate_email_risk, is_safe_otp_delivery, evaluate_bec_no_link


# ── Helpers ──────────────────────────────────────────────────────────────────

def scan(text, headers=None, attachments=None):
    r = calculate_email_risk(text, headers_text=headers, attachments=attachments)
    return r["verdict"], r.get("verdict_binary", "?"), int(r["risk_score"])


def assert_safe(text, **kw):
    verdict, binary, score = scan(text, **kw)
    assert verdict == "Safe",           f"Expected Safe, got {verdict} (score={score})\nText: {text[:80]}"
    assert binary  == "safe",           f"Expected binary=safe, got {binary}"
    assert score   <= 30,               f"Expected score≤30, got {score}"


def assert_phishing(text, min_score=70, **kw):
    verdict, binary, score = scan(text, **kw)
    assert verdict in ("High Risk", "Critical"), \
        f"Expected High Risk/Critical, got {verdict} (score={score})\nText: {text[:80]}"
    assert binary == "phishing",        f"Expected binary=phishing, got {binary}"
    assert score  >= min_score,         f"Expected score≥{min_score}, got {score}"


def assert_suspicious(text, **kw):
    verdict, binary, score = scan(text, **kw)
    assert verdict == "Suspicious",     f"Expected Suspicious, got {verdict} (score={score})\nText: {text[:80]}"
    assert binary  == "phishing",       f"Expected binary=phishing, got {binary}"
    assert 40 <= score <= 69,           f"Expected 40≤score≤69, got {score}"


# ── SAFE CASES (0 false positives) ──────────────────────────────────────────

def test_safe_otp_delivery():
    assert_safe("Your OTP is 483920. Do not share this with anyone.")


def test_safe_otp_colon_format():
    assert_safe("OTP: 5678. Never share your OTP with anyone.")


def test_safe_welcome_email():
    assert_safe("Welcome to PhishShield! Your account has been created successfully.")


def test_safe_order_shipped():
    assert_safe("Your Amazon order has been shipped. No action required.")


def test_safe_order_delivered():
    assert_safe("Your Amazon order has been delivered. No action is required.")


def test_safe_payment_confirmation():
    assert_safe("Payment confirmed. Thank you for your purchase. No action needed.")


def test_safe_newsletter_unsubscribe():
    assert_safe(
        "You are receiving this email because you subscribed to PhishShield Weekly. "
        "Manage notification settings or unsubscribe below."
    )


def test_safe_system_maintenance():
    assert_safe("System maintenance notice. No action is required from your side.")


def test_safe_meeting_scheduled():
    assert_safe("Meeting scheduled for tomorrow at 10am. No action required.")


def test_safe_weekly_summary():
    assert_safe("Weekly banking summary for your account. No action is required.")


def test_safe_registration_confirmed():
    assert_safe("Thank you for joining! Your registration is confirmed.")


def test_safe_subscription_renewed():
    assert_safe("Your subscription has been renewed. No action required.")


def test_safe_project_update():
    assert_safe("Project update attached for your review. Let me know if anything looks off.")


def test_safe_security_alert_no_action():
    assert_safe(
        "New sign-in detected on your account from Chrome on Windows. "
        "If this was you, no action is required."
    )


# ── PHISHING CASES (0 false negatives) ──────────────────────────────────────

def test_phishing_otp_harvest_urgency():
    assert_phishing(
        "Your SBI account will be BLOCKED. Share your OTP immediately to avoid suspension."
    )


def test_phishing_otp_harvest_with_link():
    assert_phishing(
        "Your HDFC account is at risk. Click here to verify: http://hdfc-secure.xyz/verify "
        "Enter your OTP to continue."
    )


def test_phishing_bec_no_link_explicit():
    assert_phishing(
        "Please process a quick transfer of Rs. 50000 to the new vendor. "
        "Keep this confidential. Confirm once done. Don't call anyone."
    )


def test_phishing_bec_friend_tone():
    assert_phishing(
        "Hey bro, send me Rs. 5000 urgently. I'm stuck. Don't tell anyone please."
    )


def test_phishing_malicious_url():
    assert_phishing(
        "Your account has been suspended. Click http://amaz0n-secure-login.xyz to restore access."
    )


def test_phishing_credential_harvest():
    assert_phishing(
        "Your Microsoft account will expire. Login now and provide your credentials "
        "at http://microsoft-verify.top/login"
    )


def test_phishing_lottery_scam():
    assert_phishing(
        "Congratulations! You are a lucky winner of KBC lottery. "
        "Prize money Rs. 25,00,000. Contact our WhatsApp +44-789-123-456 to claim."
    )


def test_phishing_delivery_fee_scam():
    assert_phishing(
        "Your FedEx package is on hold due to unpaid customs fee. "
        "Pay Rs. 49 at http://fedex-customs-clearance.top"
    )


def test_phishing_hindi_otp_coercion():
    assert_phishing(
        "Account block ho jayega. Abhi OTP bhejo warna permanently band ho jayega."
    )


def test_phishing_telugu_otp_coercion():
    assert_phishing("Account block ayindi. OTP ivvandi turant.")


def test_phishing_income_tax_refund():
    assert_phishing(
        "Income Tax Department: Your refund of Rs. 12,500 is pending. "
        "Verify your PAN at http://incometax-refund.xyz"
    )


def test_phishing_thread_hijack_bec():
    assert_phishing(
        "Re: Q3 Invoice\n\nAs discussed, please update the beneficiary to the new bank account. "
        "Wire the payment today. Keep this off the main thread."
    )


def test_phishing_sender_lookalike():
    assert_phishing(
        "From: support@paypa1-secure.com\n\n"
        "Your PayPal account is limited. Verify immediately at http://paypal-verify.top"
    )


def test_phishing_qr_attachment():
    assert_phishing(
        "Your KYC is incomplete. Scan the QR code in the attached document to verify your Aadhaar.",
        attachments=[{"filename": "kyc.pdf", "hasQrCode": True, "isPasswordProtected": False,
                      "contentType": "application/pdf", "size": 100000, "extractedText": ""}]
    )


def test_phishing_password_protected_attachment():
    assert_phishing(
        "Please review the attached invoice and enter your credentials to open it.",
        attachments=[{"filename": "invoice.pdf", "hasQrCode": False, "isPasswordProtected": True,
                      "contentType": "application/pdf", "size": 80000, "extractedText": ""}]
    )


def test_phishing_no_link_credential_harvest():
    assert_phishing(
        "Unusual activity detected. Confirm your login credentials by replying to this email. "
        "Account access will be restricted in 24 hours."
    )


def test_phishing_gstin_scam():
    assert_phishing(
        "GST compliance alert: Your GSTIN 27AABCU9603R1ZX is under review. "
        "Share your credentials at gst-verify.top to avoid penalty."
    )


# ── SUSPICIOUS CASES ────────────────────────────────────────────────────────

def test_suspicious_unknown_sender_request():
    assert_suspicious(
        "Kindly complete the action requested on your account by visiting our portal."
    )


def test_suspicious_mixed_links():
    assert_suspicious(
        "Review your statement at https://accounts.google.com and also check "
        "http://secure-review-portal.top for details."
    )


# ── UNIT TESTS for core helper functions ─────────────────────────────────────

def test_unit_is_safe_otp_delivery_true():
    assert is_safe_otp_delivery("Your OTP is 483920. Do not share this with anyone.") is True


def test_unit_is_safe_otp_delivery_coercive():
    assert is_safe_otp_delivery(
        "Your OTP is 1234. Do not share. Account blocked immediately."
    ) is False


def test_unit_evaluate_bec_with_links():
    is_bec, _ = evaluate_bec_no_link(
        "Wire money today. Keep confidential.",
        linked_domains=["some-domain.com"],
        action_money_requested=True, behavior_urgency=True, behavior_secrecy=True,
    )
    assert is_bec is False


def test_unit_evaluate_bec_no_link():
    is_bec, msg = evaluate_bec_no_link(
        "Quick transfer needed. Don't call. Confirm once done.",
        linked_domains=[],
        action_money_requested=True, behavior_urgency=True, behavior_secrecy=False,
    )
    assert is_bec is True
    assert "BEC" in msg
