from __future__ import annotations

import pytest

import main as backend_main

from report_generator import (
    _build_reasoning_sections,
    _collect_signal_block,
    _derive_key_findings,
    _normalize_confidence_percent,
)
from tests.multilingual_test_cases import (
    HINDI_PHISHING_CASES,
    HINGLISH_PHISHING_CASES,
    TELUGU_PHISHING_CASES,
)


pytestmark = pytest.mark.asyncio


def classify_band(score: int) -> str:
    if score <= 20:
        return "safe"
    if score >= 70:
        return "high_risk"
    return "suspicious"


def assert_scan_payload(payload: dict, *, min_score: int, max_score: int, expected_verdict: str) -> None:
    assert "risk_score" in payload
    assert "verdict" in payload

    risk_score = int(payload["risk_score"])
    verdict = str(payload["verdict"])

    assert min_score <= risk_score <= max_score
    if expected_verdict == "Safe":
        assert verdict.lower() in ["safe", "legitimate"]
    elif expected_verdict == "High Risk":
        assert verdict.lower() in ["high risk", "phishing"]
    else:
        assert verdict == expected_verdict


SAFE_CASES = [
    {
        "name": "project_update",
        "email_text": (
            "Subject: Project Update\n"
            "Hi team, sprint progress is on track. "
            "Please review the Jira board before tomorrow's standup."
        ),
    },
    {
        "name": "monthly_report",
        "email_text": (
            "Subject: Monthly Report\n"
            "Attached is the monthly performance summary for March. "
            "No action is needed, this is for your review."
        ),
    },
    {
        "name": "linkedin_digest",
        "email_text": (
            "Subject: Your LinkedIn Weekly Digest\n"
            "See new posts from your network and recent job trends on linkedin.com."
        ),
    },
    {
        "name": "otp_awareness_email",
        "email_text": (
            "Subject: Security Awareness\n"
            "Never share your OTP, PIN, or password with anyone. "
            "Our team will never ask for your verification code."
        ),
    },
]


HIGH_RISK_CASES = [
    {
        "name": "otp_scam",
        "email_text": (
            "URGENT: Your account will be blocked in 30 minutes. "
            "Reply with your OTP and PIN immediately to prevent suspension."
        ),
    },
    {
        "name": "phishing_link",
        "email_text": (
            "Security alert: unusual login detected. "
            "Verify now at https://accounts-security-check-verify.xyz/login"
        ),
    },
    {
        "name": "bec_scam",
        "email_text": (
            "I need an urgent wire transfer today. "
            "Keep this confidential and share beneficiary account details immediately."
        ),
    },
    {
        "name": "delivery_scam",
        "email_text": (
            "Delivery failed notice. "
            "Pay redelivery fee now at https://parcel-track-pay.top/confirm to avoid return."
        ),
    },
    {
        "name": "verify_account_link",
        "email_text": (
            "Final warning: verify your Microsoft account now "
            "https://microsoft-security-review-login.click/auth or it will be disabled."
        ),
    },
    {
        "name": "tax_refund_scam",
        "email_text": (
            "You are eligible for an income tax refund. "
            "Claim now at https://refund-department-gov.xyz/claim and submit bank details."
        ),
    },
]


@pytest.mark.parametrize("case", SAFE_CASES, ids=[case["name"] for case in SAFE_CASES])
async def test_safe_emails_risk_is_low(client, case) -> None:
    response = await client.post("/scan-email", json={"email_text": case["email_text"]})

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=0, max_score=20, expected_verdict="Safe")


@pytest.mark.parametrize("case", HIGH_RISK_CASES, ids=[case["name"] for case in HIGH_RISK_CASES])
async def test_high_risk_emails_flagged(client, case) -> None:
    response = await client.post("/scan-email", json={"email_text": case["email_text"]})

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=70, max_score=100, expected_verdict="High Risk")


async def test_sender_lookalike_paypal_no_url_is_high_risk(client) -> None:
    backend_main.app.state.scan_rate_limits = {}

    response = await client.post(
        "/scan-email",
        json={
            "session_id": "lookalike-paypal-regression",
            "email_text": (
                "From: paypaI-security.com\n"
                "Subject: Verify account\n"
                "Your PayPal account is limited.\n"
                "Login now to fix it."
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=70, max_score=100, expected_verdict="High Risk")


async def test_sender_domain_bank_alert_is_suspicious(client) -> None:
    backend_main.app.state.scan_rate_limits = {}

    response = await client.post(
        "/scan-email",
        json={
            "session_id": "bank-alert-domain-risk",
            "email_text": (
                "From: support@bank-alert.com\n"
                "Subject: Account notice\n"
                "Your account needs attention. Please review your details soon."
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=0, max_score=100, expected_verdict="Suspicious")
    assert any("Sender domain uses risky brand-action keyword pattern" in signal for signal in payload.get("matched_signals", []))


async def test_soft_pressure_details_request_is_suspicious(client) -> None:
    backend_main.app.state.scan_rate_limits = {}

    response = await client.post(
        "/scan-email",
        json={
            "session_id": "soft-pressure-details-request",
            "email_text": (
                "From: hr@company-careers.net\n"
                "Subject: Offer letter update\n"
                "We need you to confirm your details within 48 hours to proceed."
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=0, max_score=100, expected_verdict="Suspicious")
    assert any("Soft-pressure details confirmation request from untrusted sender" in signal for signal in payload.get("matched_signals", []))


async def test_sender_domain_hdfc_alert_detected_as_brand_lookalike(client) -> None:
    backend_main.app.state.scan_rate_limits = {}

    response = await client.post(
        "/scan-email",
        json={
            "session_id": "hdfc-alert-lookalike",
            "email_text": (
                "From: security@hdfc-alert.co\n"
                "Subject: Immediate Action Required\n"
                "Your HDFC account is locked.\n"
                "Login here: http://hdfc-secure-login.xyz"
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=70, max_score=100, expected_verdict="High Risk")
    assert any("Sender domain resembles a known brand (lookalike spoof)" in signal for signal in payload.get("matched_signals", []))


async def test_pipeline_otp_awareness_not_flagged(client) -> None:
    body = {
        "email_text": (
            "Subject: OTP Safety Reminder\n"
            "Do not share OTP or PIN with anyone. "
            "If anyone asks for OTP, report it to the security team immediately."
        )
    }
    response = await client.post("/scan-email", json=body)

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=0, max_score=20, expected_verdict="Safe")


async def test_pipeline_no_headers_not_high_risk(client) -> None:
    body = {
        "email_text": (
            "Subject: Internal Notes\n"
            "Please review the shared minutes before Friday."
        ),
        "headers": None,
    }
    response = await client.post("/scan-email", json=body)

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=0, max_score=20, expected_verdict="Safe")


async def test_pipeline_neutral_signals_not_override_safe(client) -> None:
    body = {
        "email_text": "Subject: Team Update\nPlease review the report and confirm availability."
    }
    response = await client.post("/scan-email", json=body)

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] <= 20


async def test_medium_risk_email(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "We noticed unusual login activity. Please review your account settings."},
    )

    assert response.status_code == 200
    data = response.json()
    assert 20 < data["risk_score"] < 70


async def test_pipeline_health_endpoint_works(client) -> None:
    health = await client.get("/health")
    assert health.status_code == 200

    health_payload = health.json()
    assert "status" in health_payload
    assert "model_status" in health_payload

    probe = await client.post(
        "/scan-email",
        json={"email_text": "Routine update for tomorrow's team sync and planning."},
    )
    assert probe.status_code == 200
    probe_payload = probe.json()
    assert_scan_payload(probe_payload, min_score=0, max_score=20, expected_verdict="Safe")


async def test_websocket_feed_connects(client) -> None:
    # Verify backend is reachable first; websocket handshake is optional based on dependency.
    response = await client.get("/health")
    assert response.status_code == 200

    try:
        from httpx_ws import aconnect_ws
    except Exception:
        return

    async with aconnect_ws("ws://testserver/ws/feed", client) as ws:
        msg = await ws.receive_json()
        assert msg["type"] == "connected"


async def test_recent_scans_returns_latest_items(client) -> None:
    await client.post("/scan-email", json={"email_text": "Subject: one\nPlease review this account notice."})
    await client.post("/scan-email", json={"email_text": "Subject: two\nVerify now at http://secure-login.xyz"})

    response = await client.get("/recent-scans")
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2
    assert len(data) <= 10

    first = data[0]
    assert "scan_id" in first
    assert "verdict" in first
    assert "risk_score" in first
    assert "timestamp" in first
    assert "sender_domain" in first
    assert "language" in first


async def test_send_password_to_proceed_is_suspicious(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "Please send password to proceed with account verification."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "Suspicious"
    assert int(payload["risk_score"]) >= 60
    assert 65 <= int(payload.get("confidence", 0) or 0) <= 80


async def test_enter_pin_now_is_high_risk(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "Enter your PIN now to continue verification."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "High Risk"
    assert int(payload["risk_score"]) >= 61
    assert 80 <= int(payload.get("confidence", 0) or 0) <= 95


async def test_clean_message_stays_safe(client) -> None:
    response = await client.post(
        "/scan-email",
        json={"email_text": "Subject: Team update\nPlease find the meeting notes attached for review."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict"] == "Safe"
    assert 50 <= int(payload.get("confidence", 0) or 0) <= 70


async def test_vt_reason_always_present_when_url_checked(client, monkeypatch) -> None:
    def fake_vt(url: str) -> dict:
        return {
            "url": url,
            "malicious_count": 0,
            "suspicious_count": 1,
            "harmless_count": 0,
            "trusted_domain": False,
            "risk_score": 5,
            "link_risk": 5,
            "source": "virustotal",
            "cached": False,
        }

    monkeypatch.setattr(backend_main, "check_url_virustotal", fake_vt)
    response = await client.post("/scan-email", json={"email_text": "Please review this link http://example.org"})
    assert response.status_code == 200
    payload = response.json()
    assert "VirusTotal reputation check influenced this result" in str(payload.get("explanation", {}).get("why_risky", ""))


async def test_recent_scans_filters_by_session(client) -> None:
    await client.post(
        "/scan-email",
        json={"email_text": "Session A scan http://example.org", "session_id": "session-a"},
    )
    await client.post(
        "/scan-email",
        json={"email_text": "Session B scan http://example.org", "session_id": "session-b"},
    )

    session_a = await client.get("/recent-scans", params={"session_id": "session-a"})
    assert session_a.status_code == 200
    records = session_a.json()
    assert records
    assert all(item.get("session_id") == "session-a" for item in records)


async def test_vt_malicious_forces_high_risk(client, monkeypatch) -> None:
    def fake_vt(url: str) -> dict:
        return {
            "url": url,
            "malicious_count": 4,
            "suspicious_count": 0,
            "harmless_count": 0,
            "trusted_domain": False,
            "risk_score": 80,
            "link_risk": 80,
            "source": "virustotal",
            "cached": False,
        }

    monkeypatch.setattr(backend_main, "check_url_virustotal", fake_vt)

    response = await client.post("/scan-email", json={"email_text": "Please verify at http://example.org"})
    assert response.status_code == 200

    payload = response.json()
    assert payload["verdict"] == "High Risk"
    assert int(payload["risk_score"]) >= 85
    assert "VirusTotal flagged this domain as malicious/suspicious" in payload["explanation"]["why_risky"]


async def test_vt_clean_and_no_local_risk_stays_safe(client, monkeypatch) -> None:
    def fake_vt(url: str) -> dict:
        return {
            "url": url,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 18,
            "trusted_domain": False,
            "risk_score": 0,
            "link_risk": 0,
            "source": "virustotal",
            "cached": False,
        }

    def fake_scan(email_text: str, headers_text=None, attachments=None) -> dict:
        return {
            "scan_id": "clean-vt-case",
            "verdict": "Safe",
            "risk_score": 0,
            "category": "Safe Email",
            "detectedLanguage": "EN",
            "senderDomain": "example.org",
            "links": {"all": ["http://example.org"]},
            "trust_score": 12,
            "trustScore": 12,
            "recommendation": "Allow but continue monitoring",
            "explanation": {"why_risky": ""},
        }

    monkeypatch.setattr(backend_main, "check_url_virustotal", fake_vt)
    monkeypatch.setattr(backend_main, "calculate_email_risk", fake_scan)

    response = await client.post("/scan-email", json={"email_text": "Subject: hello\nPlease review http://example.org"})
    assert response.status_code == 200

    payload = response.json()
    assert payload["verdict"] == "Safe"
    assert int(payload["risk_score"]) <= 20


async def test_local_and_vt_risky_escalates_to_high_risk(client, monkeypatch) -> None:
    def fake_vt(url: str) -> dict:
        return {
            "url": url,
            "malicious_count": 3,
            "suspicious_count": 1,
            "harmless_count": 0,
            "trusted_domain": False,
            "risk_score": 75,
            "link_risk": 75,
            "source": "virustotal",
            "cached": False,
        }

    monkeypatch.setattr(backend_main, "check_url_virustotal", fake_vt)

    response = await client.post(
        "/scan-email",
        json={"email_text": "Urgent: verify now at http://secure-login.xyz/login"},
    )
    assert response.status_code == 200

    payload = response.json()
    assert payload["verdict"] == "High Risk"
    assert int(payload["risk_score"]) >= 85
    assert "VirusTotal flagged this domain as malicious/suspicious" in payload["explanation"]["why_risky"]


async def test_trusted_domain_override_wins_over_vt(client, monkeypatch) -> None:
    def fake_vt(url: str) -> dict:
        return {
            "url": url,
            "malicious_count": 5,
            "suspicious_count": 0,
            "harmless_count": 0,
            "trusted_domain": True,
            "risk_score": 100,
            "link_risk": 100,
            "source": "trusted_allowlist",
            "cached": False,
        }

    monkeypatch.setattr(backend_main, "check_url_virustotal", fake_vt)

    response = await client.post("/scan-email", json={"email_text": "Subject: hello\nPlease review https://google.com"})
    assert response.status_code == 200

    payload = response.json()
    assert payload["verdict"] == "Safe"
    assert int(payload["risk_score"]) <= 10


async def test_metrics_endpoint(client) -> None:
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert "phishshield_scans_total" in response.text
    assert "phishshield_model_loaded" in response.text


async def test_stats_endpoint(client) -> None:
    response = await client.get("/stats")

    assert response.status_code == 200
    data = response.json()
    assert "model_active" in data
    assert "cache_entries" in data


async def test_url_check_trusted_domain(client) -> None:
    response = await client.post("/check-url", json={"url": "https://accounts.google.com/login"})

    assert response.status_code == 200
    data = response.json()
    assert data.get("trusted_domain") is True or data.get("link_risk", 100) == 0


async def test_url_check_suspicious_domain(client) -> None:
    response = await client.post("/check-url", json={"url": "http://secure-login.xyz/verify"})

    assert response.status_code == 200
    data = response.json()
    assert data.get("link_risk", 0) >= 40


async def test_url_check_empty(client) -> None:
    response = await client.post("/check-url", json={"url": ""})
    assert response.status_code in (200, 422)


async def test_vt_cache_hit(client) -> None:
    url = "http://test-phishing-site.xyz/verify"
    await client.post("/check-url", json={"url": url})
    response2 = await client.post("/check-url", json={"url": url})

    assert response2.status_code == 200
    assert response2.json().get("cached") is True


async def test_pipeline_check_headers_safe(client) -> None:
    safe_headers = (
        "From: Security Team <security@google.com>\n"
        "Reply-To: security@google.com\n"
        "Return-Path: <security@google.com>\n"
        "Authentication-Results: mx.google.com; "
        "spf=pass smtp.mailfrom=google.com; "
        "dkim=pass header.d=google.com; "
        "dmarc=pass header.from=google.com\n"
        "Received: from mail.google.com (mail.google.com [142.250.0.1]) "
        "by mx.example.com with ESMTPS id 12345;"
    )

    response = await client.post("/check-headers", json={"headers": safe_headers})

    assert response.status_code == 200
    payload = response.json()
    assert "header_risk_score" in payload
    assert "signals" in payload

    score = int(payload["header_risk_score"])
    assert 0 <= score <= 20
    assert classify_band(score) == "safe"
    assert "Display name brand spoof detected" not in payload.get("signals", [])


async def test_display_name_brand_spoof_escalates_header_scores(client) -> None:
    spoof_headers = (
        'From: "Google Security" <alerts@account-alert-security.com>\n'
        "Reply-To: alerts@account-alert-security.com\n"
        "Return-Path: <alerts@account-alert-security.com>\n"
        "Authentication-Results: mx.example.com; "
        "spf=pass smtp.mailfrom=account-alert-security.com; "
        "dkim=pass header.d=account-alert-security.com; "
        "dmarc=pass header.from=account-alert-security.com\n"
    )

    response = await client.post("/check-headers", json={"headers": spoof_headers})

    assert response.status_code == 200
    payload = response.json()
    assert int(payload.get("spoofing_score", 0)) >= 70
    assert int(payload.get("header_risk_score", 0)) >= 60
    assert "Display name brand spoof detected" in payload.get("signals", [])


async def test_display_name_brand_spoof_classified_suspicious_or_high_risk(client) -> None:
    response = await client.post(
        "/scan-email",
        json={
            "session_id": "display-name-brand-spoof-regression",
            "email_text": (
                'From: "HDFC Alerts" <notify@bank-secure-action.com>\n'
                "Reply-To: notify@bank-secure-action.com\n"
                "Return-Path: <notify@bank-secure-action.com>\n"
                "Authentication-Results: mx.example.com; "
                "spf=pass smtp.mailfrom=bank-secure-action.com; "
                "dkim=pass header.d=bank-secure-action.com; "
                "dmarc=pass header.from=bank-secure-action.com\n"
                "Subject: Secure your account\n"
                "Please verify your account details immediately."
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert str(payload.get("verdict", "")).lower() in {"suspicious", "high risk", "phishing"}


async def test_empty_headers_safe(client) -> None:
    response = await client.post("/check-headers", json={"headers": ""})
    if response.status_code == 422:
        response = await client.post("/check-headers", json={"headers": " "})
    assert response.status_code == 200


async def test_pipeline_same_input_same_output(client) -> None:
    email_text = (
        "Please verify your payroll details at "
        "https://employee-payroll-review.top/login before end of day."
    )

    first = await client.post("/scan-email", json={"email_text": email_text})
    second = await client.post("/scan-email", json={"email_text": email_text})

    assert first.status_code == 200
    assert second.status_code == 200

    first_payload = first.json()
    second_payload = second.json()

    assert "risk_score" in first_payload and "risk_score" in second_payload
    assert "verdict" in first_payload and "verdict" in second_payload
    assert int(first_payload["risk_score"]) == int(second_payload["risk_score"])
    assert str(first_payload["verdict"]) == str(second_payload["verdict"])


@pytest.mark.parametrize(
    "payload",
    [
        {"email_text": ""},
        {"email_text": "   "},
    ],
    ids=["empty_string", "whitespace_only"],
)
async def test_pipeline_empty_input_rejected(client, payload) -> None:
    response = await client.post("/scan-email", json=payload)

    assert response.status_code in {400, 422}


async def test_multilingual_hindi_phishing(client) -> None:
    hindi_email = (
        "तुरंत ध्यान दें: आपका बैंक खाता बंद किया जाएगा। "
        "अपना OTP और PIN अभी साझा करें और लिंक पर जाएं "
        "https://sbi-login-check.top/verify"
    )
    response = await client.post("/scan-email", json={"email_text": hindi_email})

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=70, max_score=100, expected_verdict="High Risk")


async def test_multilingual_hinglish_phishing(client) -> None:
    hinglish_email = (
        "Urgent hai, account suspend ho jayega. "
        "OTP abhi bhejo aur verify karo: https://secure-wallet-restore.xyz/login"
    )
    response = await client.post("/scan-email", json={"email_text": hinglish_email})

    assert response.status_code == 200
    payload = response.json()
    assert_scan_payload(payload, min_score=70, max_score=100, expected_verdict="High Risk")


async def test_malformed_request(client) -> None:
    response = await client.post("/scan-email", json={"wrong_key": "test"})
    assert response.status_code in [400, 422]


async def test_otp_advisory_english_is_safe(client) -> None:
    response = await client.post(
        "/scan-email",
        json={
            "email_text": "Your OTP is 123456. Do not share it with anyone. This is an automated message from your bank.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] <= 25
    assert str(data["verdict"]).lower() in {"safe", "legitimate"}


async def test_otp_advisory_hinglish_is_safe(client) -> None:
    response = await client.post(
        "/scan-email",
        json={
            "email_text": "Dear user, please update your details. OTP kisi ke saath share na karein. Visit our official website.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] <= 25
    assert str(data["verdict"]).lower() in {"safe", "legitimate"}


async def test_otp_neutral_verification_is_suspicious(client) -> None:
    response = await client.post(
        "/scan-email",
        json={
            "email_text": "Your OTP is 123456. Use it to continue verification.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert 26 <= int(data["risk_score"]) <= 60
    assert str(data["verdict"]).lower() == "suspicious"


async def test_otp_login_prompt_is_suspicious(client) -> None:
    response = await client.post(
        "/scan-email",
        json={
            "email_text": "OTP: 123456. Login to your account.",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert 26 <= int(data["risk_score"]) <= 60
    assert str(data["verdict"]).lower() == "suspicious"


async def test_report_missing_scan_id_returns_404(client) -> None:
    response = await client.get("/report/does-not-exist")
    assert response.status_code == 404


async def test_report_endpoint_returns_pdf(client) -> None:
    scan_response = await client.post(
        "/scan-email",
        json={
            "email_text": (
                "Subject: Security alert\n"
                "Verify your account immediately at https://secure-login-review.xyz/auth "
                "to avoid suspension."
            )
        },
    )

    assert scan_response.status_code == 200
    scan_payload = scan_response.json()
    scan_id = scan_payload.get("scan_id")
    assert isinstance(scan_id, str) and scan_id

    report_response = await client.get(f"/report/{scan_id}")
    assert report_response.status_code == 200
    assert report_response.headers.get("content-type", "").startswith("application/pdf")
    assert "attachment; filename=phishshield-report-" in report_response.headers.get("content-disposition", "")
    assert report_response.content.startswith(b"%PDF")


async def test_pdf_confidence_uses_exact_scan_value() -> None:
    assert _normalize_confidence_percent(0.78, risk_score=23) == "78%"
    assert _normalize_confidence_percent(78, risk_score=23) == "78%"
    assert _normalize_confidence_percent("78%", risk_score=23) == "78%"


async def test_pdf_signal_block_and_findings_are_signal_driven() -> None:
    scan_data = {
        "email_text": "Please verify your account and enter the OTP to continue.",
        "signals": ["OTP request detected", "Credential verification intent detected"],
        "safe_signals": [],
    }

    risk_signals, safe_signals, detection_text = _collect_signal_block(scan_data)
    key_findings = _derive_key_findings(risk_signals, safe_signals, detection_text)
    primary, secondary, details = _build_reasoning_sections(risk_signals, safe_signals)

    assert "OTP request detected" in risk_signals
    assert "Credential verification intent detected" in risk_signals
    assert "No malicious link detected" in safe_signals
    assert "No urgency language detected" in safe_signals
    assert key_findings[:3] == [
        "OTP request detected",
        "Credential intent detected",
        "No malicious link detected",
    ]
    assert primary != details
    assert "OTP request" in primary
    assert "credential usage intent" in details.lower()
    assert "No malicious link detected" in secondary


async def test_pdf_key_findings_include_link_and_urgency() -> None:
    scan_data = {
        "email_text": "Jaldi verify karo warna account band ho jayega. Visit https://secure-check.example/login",
        "signals": ["Credential verification intent detected", "Link included in message", "Urgency language"],
        "safe_signals": [],
    }

    risk_signals, safe_signals, detection_text = _collect_signal_block(scan_data)
    key_findings = _derive_key_findings(risk_signals, safe_signals, detection_text)
    _, secondary, details = _build_reasoning_sections(risk_signals, safe_signals)

    assert "Suspicious link detected" in key_findings
    assert "Urgency or pressure language detected" in key_findings
    assert "no urgency" not in secondary.lower()
    assert "without a visible link" not in details.lower()


async def test_pdf_filters_low_value_signals_and_keeps_high_value_safe_signals() -> None:
    scan_data = {
        "email_text": "Routine message with no links.",
        "signals": ["No attachments detected", "Attachment present - scan recommended", "Credential verification intent detected"],
        "safe_signals": ["No attachments detected", "Known sender history looks normal", "Trusted domain correctly verified"],
        "domainTrust": {"status": "trusted", "domain": "google.com"},
    }

    risk_signals, safe_signals, _ = _collect_signal_block(scan_data)

    assert "No attachments detected" not in risk_signals
    assert "Attachment present - scan recommended" not in risk_signals
    assert "Credential verification intent detected" in risk_signals
    assert safe_signals == [
        "No malicious link detected",
        "No urgency language detected",
        "Trusted domain detected",
    ]


@pytest.mark.parametrize("case", HINDI_PHISHING_CASES)
async def test_hindi_cases(client, case) -> None:
    response = await client.post(
        "/scan",
        json={"email_text": case["email"]},
    )
    assert response.status_code == 200
    data = response.json()
    detected_language = data.get("detectedLanguage") or data.get("language")
    assert detected_language == case["language"]
    if case["expected_verdict"] == "phishing":
        assert data["risk_score"] >= case["expected_min_risk"], f"FAIL {case['name']}: risk={data['risk_score']} < {case['expected_min_risk']}"
    else:
        assert data["risk_score"] <= case["expected_max_risk"], f"FAIL {case['name']}: risk={data['risk_score']} > {case['expected_max_risk']}"


@pytest.mark.parametrize("case", TELUGU_PHISHING_CASES)
async def test_telugu_cases(client, case) -> None:
    response = await client.post(
        "/scan",
        json={"email_text": case["email"]},
    )
    assert response.status_code == 200
    data = response.json()
    detected_language = data.get("detectedLanguage") or data.get("language")
    assert detected_language == case["language"]
    if case["expected_verdict"] == "phishing":
        assert data["risk_score"] >= case["expected_min_risk"]
    else:
        assert data["risk_score"] <= case["expected_max_risk"]


@pytest.mark.parametrize("case", HINGLISH_PHISHING_CASES)
async def test_hinglish_cases(client, case) -> None:
    response = await client.post(
        "/scan",
        json={"email_text": case["email"]},
    )
    assert response.status_code == 200
    data = response.json()
    detected_language = data.get("detectedLanguage") or data.get("language")
    assert detected_language == case["language"]
    if case["expected_verdict"] == "phishing":
        assert data["risk_score"] >= case["expected_min_risk"]
    else:
        assert data["risk_score"] <= case["expected_max_risk"]
