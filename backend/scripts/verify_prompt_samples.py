from __future__ import annotations

import json
from dataclasses import dataclass
import urllib.request


API_URL = "http://127.0.0.1:8000/scan-email"


def scan(text: str) -> dict:
    # Use a unique session_id per call to avoid local rate limiting (10/min per client key).
    # This script is for local regression verification (May 2026 hardening pack).
    scan_id = str(abs(hash(text)))[:10]
    req = urllib.request.Request(
        API_URL,
        data=json.dumps({"email_text": text, "session_id": f"verify-{scan_id}"}, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass(frozen=True)
class Expectation:
    verdict: str
    min_score: int
    max_score: int


def main() -> int:
    cases: list[tuple[str, str, Expectation]] = [
        ("S71_amazon_typosquat", "Am4zon order... http://am4z0n-india.com", Expectation("High Risk", 75, 100)),
        ("S56_hindi_otp", "आपका बैंक खाता बंद हो जाएगा। अभी अपना OTP शेयर करें: +91-9876543210", Expectation("High Risk", 75, 100)),
        ("S59_telugu_aadhaar", "మీ ఆధార్ కార్డు లో సమస్య ఉంది. వెంటనే మీ వివరాలు ఇవ్వండి: +91-7777777777", Expectation("High Risk", 70, 100)),
        ("S60_hindi_newsletter_regression", "नमस्ते! यह इस सप्ताह का न्यूज़लेटर है। नए लेख और अपडेट पढ़ें। धन्यवाद।", Expectation("Safe", 0, 25)),
        ("S66_cyrillic_amazon", "аmazon account suspended", Expectation("High Risk", 80, 100)),
        ("S95_unicode_obfuscation", "Ÿ0ür ÄCC0ÛNT ïs SÜSPËNDËD", Expectation("High Risk", 75, 100)),
        ("S73_romance_advance_fee", "Dr. James Williams from UK. I have $2 million to transfer. This is confidential. I want to share together as partners. Reply to proceed.", Expectation("High Risk", 72, 100)),
        ("S76_sextortion", "I recorded you via webcam. I will share the video with your contacts. Pay Rs.50,000 in Bitcoin within 24 hours.", Expectation("High Risk", 85, 100)),
        ("S79_nigerian_419", "barrister Emmanuel Okafor, Lagos. Deceased client died without a will. $15.5 million inheritance transfer requires next of kin. Commission percentage will be shared. Reply urgently.", Expectation("High Risk", 75, 100)),
        ("S51_airtel_refund", "Airtel notice: unclaimed refund pending. To receive refund, share Aadhaar and mobile number immediately.", Expectation("High Risk", 78, 100)),
        ("S52_bescom_disconnect", "BESCOM electricity bill unpaid. Connection will be disconnected today. Pay now at http://bescom-payment.xyz", Expectation("High Risk", 80, 100)),
        ("S54_crypto_guaranteed", "Crypto investment offer: 100% guaranteed returns. Join our WhatsApp group for trading tips.", Expectation("High Risk", 78, 100)),
        ("S75_tech_support", "Microsoft Support: your PC is infected with Trojan malware. Call 1800-FAKE-MS for remote access support.", Expectation("High Risk", 80, 100)),
        ("S64_hinglish_legit", "Hi Rahul bhai, aaj ki meeting ke baad mujhe invoice bhejna. Amount Rs.45,000... NEFT karo by Friday to our regular account.", Expectation("Safe", 0, 25)),
        ("S72_techcrunch_newsletter", "TechCrunch Daily: Top stories today. Read more at https://techcrunch.com. Unsubscribe here: https://techcrunch.com/unsubscribe", Expectation("Safe", 0, 25)),
        ("S77_google_alert", "Google Security Alert: A new sign-in on your account. If this was you, no action needed. Review activity at https://myaccount.google.com/security", Expectation("Safe", 0, 25)),
        (
            "S92_career_webinar_fp",
            "USD Career Development Session with Alexander Lo, Assistant Director. Explore career pathways, internships, register here 8:00-9:00 PM IST. Build meaningful connections.",
            Expectation("Safe", 0, 40),
        ),
        ("S89_security_report", "Vulnerability Report #VR-2024-089: phishing campaign targeting SBI. IOC list and mitigation guidance included. This is for research only.", Expectation("Suspicious", 26, 60)),
        ("S90_it_temp_password", "temporary password for your new employee account: TempPass@2024! Please change it on first login at https://company.okta.com", Expectation("Safe", 0, 25)),
        ("S84_emoji_prize", "🎉🎊 CONGRATULATIONS!! You've WON Rs.1,00,000!! Click NOW 👉 http://win-prize.xyz Share your Aadhaar + Bank details", Expectation("High Risk", 80, 100)),
        ("S57_hinglish_no_url", "Bhai aapka account band hone wala hai. Abhi call karo 1800-FAKE-NUM pe aur apna PIN share karo", Expectation("High Risk", 75, 100)),
        ("S61_hinglish_lottery_fee", "Congratulations! Aapne Rs.10,00,000 jeet liya hai... Rs.1,000 processing fee bhejein UPI se", Expectation("High Risk", 80, 100)),
        ("REG_phish_reply_password", "Reply with your current password to confirm your account access.", Expectation("High Risk", 61, 100)),
        ("REG_phish_account_verification", "Account verification required. Please share your password and OTP to continue.", Expectation("High Risk", 61, 100)),
    ]

    passed = 0
    failed = 0
    rows: list[dict[str, str]] = []

    for cid, text, expect in cases:
        try:
            result = scan(text)
            verdict = str(result.get("verdict") or "").strip()
            score = int(result.get("risk_score", 0) or 0)
            ok = verdict == expect.verdict and expect.min_score <= score <= expect.max_score
            if ok:
                passed += 1
            else:
                failed += 1
            rows.append(
                {
                    "status": "PASS" if ok else "FAIL",
                    "id": cid,
                    "expected": f"{expect.verdict} {expect.min_score}-{expect.max_score}",
                    "got": f"{verdict} {score}",
                }
            )
        except Exception as exc:
            failed += 1
            rows.append(
                {
                    "status": "FAIL",
                    "id": cid,
                    "expected": f"{expect.verdict} {expect.min_score}-{expect.max_score}",
                    "got": f"ERROR {exc}",
                }
            )

    print("=== PhishShield May 2026 regression pack ===")
    for row in rows:
        print(f"{row['status']:4} | {row['id']:<28} | exp={row['expected']:<18} | got={row['got']}")
    print(f"\nTOTAL: {len(rows)} | PASS: {passed} | FAIL: {failed}")

    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())

