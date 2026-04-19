"""PhishShield certification: 35 cases, score bands, dataset sample accuracy."""
from __future__ import annotations

import sys
import time
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as m  # noqa: E402
import pandas as pd  # noqa: E402

CLEANED_CSV = ROOT.parent / "Phishing_Email_cleaned.csv"

CERT_CASES: list[tuple[str, str]] = [
    # PHISHING (20)
    ("Dear Customer, your SBI account is suspended. Share OTP immediately at http://sbi-verify.net", "phishing"),
    ("Aapka UPI PIN expire ho gaya hai. Turant yahan click karein: http://upi-renew.co", "phishing"),
    ("Your HDFC account shows suspicious activity. Verify Aadhaar now: http://hdfc-kyc.xyz", "phishing"),
    ("Income Tax refund of Rs.18,400 pending. Submit PAN details: http://incometax-refund.in", "phishing"),
    ("Dear Sir, wire transfer of $85,000 must be processed urgently. Keep this confidential. — CEO", "phishing"),
    ("GST portal notice: Your GSTIN has been deactivated. Login immediately to restore.", "phishing"),
    ("Congratulations! You won Rs.25 lakh in KBC Lucky Draw. WhatsApp 9876543210 to claim.", "phishing"),
    ("Your IRCTC account is locked. Verify KYC within 24 hours or account will be deleted.", "phishing"),
    ("FedEx: Your parcel is held at customs. Pay Rs.499 delivery fee: http://fedex-india-delivery.net", "phishing"),
    ("Urgent: Share your net banking password to complete 2FA upgrade. — ICICI Security Team", "phishing"),
    ("आपका बैंक खाता बंद हो जाएगा। अभी OTP साझा करें।", "phishing"),
    ("మీ SBI ఖాతా నిలిపివేయబడింది. వెంటనే OTP పంచుకోండి.", "phishing"),
    ("ALERT: Rs.9,999 debited from your HDFC a/c. Not you? Call 1800-XXX to reverse.", "phishing"),
    ("Dear vendor, please update your bank account to the new details below for next payment.", "phishing"),
    ("Your PAN card is linked to suspicious transactions. Verify at http://pan-verify.in now.", "phishing"),
    ("HR Update: Submit your Aadhaar and PAN copy to new-hr-portal.xyz for salary revision.", "phishing"),
    ("Lucky Winner! Your mobile number selected for Rs.50,000 prize. Reply with name and address.", "phishing"),
    ("Payroll team: Please change my salary account to XXXX bank. Sending details separately.", "phishing"),
    ("This is DHL India. Your package requires customs clearance fee of Rs.299. Pay here.", "phishing"),
    ("Verify your Aadhaar-linked mobile number immediately or service will be discontinued.", "phishing"),
    # SAFE (15) — 35 total
    ("Hi Team, please find the meeting agenda for tomorrow's standup attached.", "safe"),
    ("Your Amazon order #402-XXXXXX has been shipped. Expected delivery: Friday.", "safe"),
    ("GitHub notification: A new pull request was opened in your repository.", "safe"),
    ("Your monthly Airtel bill of Rs.399 is due on 25th April. Pay via My Airtel app.", "safe"),
    ("Newsletter: This week in Python — top articles, tutorials, and job posts.", "safe"),
    ("Meeting rescheduled to 3pm IST tomorrow. Please update your calendar.", "safe"),
    ("Your Swiggy order is on the way! Track here: [tracking link]", "safe"),
    ("SELECT * FROM users WHERE email = 'test@example.com'; — DB admin query log", "safe"),
    ("OTP for your Zepto login is 847291. Valid for 10 minutes. Do not share.", "safe"),
    ("Dear subscriber, your IRCTC e-ticket for Train 12345 is confirmed. PNR: XXXXXXXX", "safe"),
    ("Hi Rahul, attached is the invoice for last month's consulting work. Please process.", "safe"),
    ("Your Google account was signed in from Chrome on Windows. Was this you?", "safe"),
    ("Reminder: Your LIC premium of Rs.4,200 is due next week.", "safe"),
    ("Weekly digest: Top cybersecurity news — ransomware trends, patch updates.", "safe"),
    ("Team lunch at 1pm today at the usual place. Let me know if you can't make it.", "safe"),
]


def _init_app_state() -> None:
    m.app.state.scan_explanations = OrderedDict()
    m.app.state.scan_cache = OrderedDict()
    m.app.state.sender_profiles = {}
    m.app.state.threat_intel = m.load_threat_intel_feed()
    m.app.state.feedback_memory = {}
    m.app.state.scan_rate_limits = {}
    m.load_artifacts()


def run_certification_tests() -> tuple[int, int, int, list[dict], float]:
    _init_app_state()
    fp = fn = 0
    rows: list[dict] = []
    max_ms = 0.0
    for i, (text, exp) in enumerate(CERT_CASES, 1):
        t0 = time.perf_counter()
        r = m.calculate_email_risk(text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        max_ms = max(max_ms, elapsed_ms)
        sc = int(r.get("risk_score", 0) or 0)
        verdict = str(r.get("verdict", ""))
        if exp == "phishing":
            ok = sc >= 70
            if not ok:
                fn += 1
        else:
            ok = sc <= 30
            if not ok:
                fp += 1
        status = "PASS" if ok else "FAIL"
        rows.append(
            {
                "case": i,
                "expected": exp,
                "score": sc,
                "verdict": verdict,
                "status": status,
                "ms": round(elapsed_ms, 1),
            }
        )
        print(f"Case #{i} | expected={exp} | verdict={verdict} | score={sc} | {status} | {elapsed_ms:.0f}ms")
    return fp, fn, len(CERT_CASES), rows, max_ms


def run_dataset_sample_accuracy(csv_path: Path, n: int = 100, seed: int = 42) -> tuple[float, int, int, int]:
    if not csv_path.exists():
        return 0.0, 0, 0, 0
    df = pd.read_csv(csv_path)
    if len(df) == 0:
        return 0.0, 0, 0, 0
    sample = df.sample(n=min(n, len(df)), random_state=seed)
    correct = 0
    _init_app_state()
    fp = fn = 0
    slow = 0
    for _, row in sample.iterrows():
        text = str(row.get("email_text", "") or "")
        label = str(row.get("label", "") or "").strip().lower()
        if label not in ("safe", "phishing"):
            continue
        t0 = time.perf_counter()
        r = m.calculate_email_risk(text)
        if (time.perf_counter() - t0) > 2.0:
            slow += 1
        sc = int(r.get("risk_score", 0) or 0)
        pred_phish = sc >= 70
        true_phish = label == "phishing"
        if pred_phish == true_phish:
            correct += 1
        elif pred_phish and not true_phish:
            fp += 1
        else:
            fn += 1
    acc = 100.0 * correct / len(sample) if len(sample) else 0.0
    return acc, fp, fn, slow


def main() -> None:
    print("=== PhishShield certification (35 cases) ===\n")
    fp, fn, n_cases, _rows, max_ms = run_certification_tests()
    print()

    acc, dfp, dfn, slow = run_dataset_sample_accuracy(CLEANED_CSV, n=100, seed=42)
    cleaned_rows = 0
    if CLEANED_CSV.exists():
        cleaned_rows = len(pd.read_csv(CLEANED_CSV))

    perf_ok = max_ms < 2000
    acc_ok = acc >= 95.0
    tests_ok = fp == 0 and fn == 0
    production_ready = tests_ok and acc_ok and perf_ok and slow == 0

    print("SYSTEM CERTIFICATION REPORT:")
    print(f"  dataset cleaned rows: {cleaned_rows} ({CLEANED_CSV.name})")
    print("  duplicates removed: run certify_dataset.py (exact + TF-IDF cosine >0.90 near-dup)")
    print(f"  sample accuracy (n=100, score>=70 phishing / <=30 safe): {acc:.2f}%")
    print(f"  certification tests: {n_cases - fp - fn}/{n_cases} pass | FP={fp} | FN={fn}")
    print(f"  performance: max case latency {max_ms:.0f}ms (target <2000ms) - {'OK' if perf_ok else 'NEEDS FIX'}")
    print(f"  sample rows over 2s: {slow}")
    print(f"  final verdict: {'Production Ready' if production_ready else 'Needs Fix'}")


if __name__ == "__main__":
    main()
