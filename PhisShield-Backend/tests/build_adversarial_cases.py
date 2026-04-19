"""Generate PhisShield-Backend/tests/adversarial_cases.json (60 cases A-F). Run: python build_adversarial_cases.py"""
from __future__ import annotations

import json
from pathlib import Path

out = Path(__file__).resolve().parent / "adversarial_cases.json"

cases: list[dict] = []

# A: leet / unicode obfuscation phishing (expect score >= 70 for 9/10)
a_bodies = [
    "From: nоtification@paypa1-security.ru\nVerify your аccount now: http://evil-login.xyz/verify",
    "Your bаnk аccount is l0cked. L0gin: http://secure-bank.ml/auth",
    "Urgent: c0nfirm your emаil at http://amaz0n-verify.tk/otp",
    "SBI: your UPI is exp1red. http://sbi-upi-renew.xyz",
    "HDFC аlert: suspici0us login http://hdfc-kyc.ml",
    "GSTIN deаctivated — rest0re at http://gst-portal.xyz",
    "Income tаx refund pending http://it-refund.in",
    "Your Pаypal is limited http://paypa1-support.ml",
    "Gоogle security: sign in from Russia http://g00gle-verify.tk",
    "Netfl1x payment failed http://netf1ix-billing.xyz",
]
for i, t in enumerate(a_bodies, 1):
    cases.append({"id": f"A{i:02d}", "category": "A", "email_text": t, "expect": {"min_score": 70}})

# B: safe context with phishing keywords (<=30)
b_bodies = [
    "Security awareness training covers phishing, OTP scams, and credential theft. No links required.",
    "Our policy: we never ask for your password or OTP by email. Regards, IT Security Team.",
    "Newsletter: how to spot phishing and report suspicious messages to abuse@company.com.",
    "Reminder: do not share OTP or PIN with anyone, including callers claiming to be the bank.",
    "This is a simulated phishing exercise for staff education only. No action needed.",
    "HR: mandatory cybersecurity module explains spear phishing and wire fraud scenarios.",
    "IT bulletin: examples of fake bank SMS and OTP harvesting for awareness only.",
    "Compliance: definitions of phishing, vishing, and smishing for the employee handbook.",
    "Training deck attached: password policies and why we never request OTP via email.",
    "Quarterly security digest discusses credential stuffing — purely informational.",
]
for i, t in enumerate(b_bodies, 1):
    cases.append({"id": f"B{i:02d}", "category": "B", "email_text": t, "expect": {"max_score": 30}})

# C: tone disguise phishing (>=70)
c_bodies = [
    "Bhai jaldi se OTP bhejo warna account band ho jayega http://fake-upi.xyz",
    "Mee SBI account block avutundi. OTP ippude pampinchu http://sbi-fake.ml",
    "Sir plz share net banking password for verification http://bank-help.tk",
    "URGENT!!! wire $50,000 today confidential do not tell anyone — CFO (spoofed)",
    "yo bro im stuck send me rs 5000 on this upi id pls urgent http://pay-scam.xyz",
    "Kindly remit funds per attached invoice; treat as strictly confidential wire today.",
    "SMS style: UR ACCT BLOCKED. TAP LINK NOW http://short.tk/x",
    "Formal: We require immediate verification of credentials to avoid service suspension http://verify-now.ml",
    "Casual: hey can u send me the otp u got? need it for the app thing http://evil.co",
    "Hinglish mix: turant OTP share karein otherwise aaj hi account suspend http://phish.xyz",
]
for i, t in enumerate(c_bodies, 1):
    cases.append({"id": f"C{i:02d}", "category": "C", "email_text": t, "expect": {"min_score": 70}})

# D: multi-signal conflicts (5 phish >=70, 5 safe <=30)
d_bodies = [
    ("D01", "Amazon shipped your order #123. Tracking: https://www.amazon.in/gp/css/order-history — ignore any other links.", {"max_score": 30}),
    ("D02", "Meeting notes attached for your review. Please confirm if everything looks fine.", {"max_score": 30}),
    ("D03", "Your Airtel bill is due on 25th April. Pay via My Airtel app only.", {"max_score": 30}),
    ("D04", "GitHub notification: a new pull request was opened in your repository.", {"max_score": 30}),
    ("D05", "Weekly digest: Python articles. Contains the word password in a benign context only.", {"max_score": 30}),
    ("D06", "Urgent: verify your account now http://secure-login.xyz and share OTP to avoid lockout.", {"min_score": 70}),
    ("D07", "Your bank account is suspended. Click http://hdfc-kyc.ml immediately with OTP.", {"min_score": 70}),
    ("D08", "CEO wire $85000 confidential today http://evil-wire.tk", {"min_score": 70}),
    ("D09", "Prize winner! Claim Rs 50000 at http://prize-spam.xyz now with OTP.", {"min_score": 70}),
    ("D10", "GSTIN deactivated login restore http://gst-fake.in urgent", {"min_score": 70}),
]
for cid, t, exp in d_bodies:
    cases.append({"id": cid, "category": "D", "email_text": t, "expect": exp})

# E: BEC no URL (>=70)
e_bodies = [
    "Wire $92000 to the new account today. Keep this confidential — CEO",
    "Process urgent wire transfer confidentially. Do not discuss with finance.",
    "Payroll team: change my salary account to the new bank details I will send separately.",
    "Vendor: please update bank account to new details below for next payment.",
    "Gift cards worth $5000 needed urgently for client meeting — reimburse later.",
    "I am in a conference; wire funds now per earlier discussion. Secret.",
    "Transfer INR 450000 today only. Don't call me, I am in meetings.",
    "Confirm once done with the wire. Don't inform anyone in the office.",
    "New beneficiary added — approve wire of $120000 immediately. Confidential.",
    "Urgent: send corporate tax payment via wire using attached instructions (no link).",
]
for i, t in enumerate(e_bodies, 1):
    cases.append({"id": f"E{i:02d}", "category": "E", "email_text": t, "expect": {"min_score": 70}})

# F: resilience (no crash, score 0-100)
f_bodies = [
    ("F01", "hello"),
    ("F02", "x" * 8000),
    ("F03", "'; DROP TABLE users; -- is in the subject line as text only"),
    ("F04", "http://a.com " * 80),
    ("F05", "\n\n\nminimal body zzz"),
    ("F06", "Normal short text hello"),
    ("F07", "UTF8: \u200b\u200c\u200d zero width mix"),
    ("F08", "A" * 10000 + " verify OTP http://x.tk"),
    ("F09", "JSON blob {\"otp\":123} in body"),
    ("F10", "stress " + ("Z" * 12000)),
]
for fid, t in f_bodies:
    cases.append({"id": fid, "category": "F", "email_text": t, "expect": {}})

out.write_text(json.dumps({"description": "Adversarial suite A-F", "cases": cases}, indent=2), encoding="utf-8")
print("Wrote", out, len(cases))
