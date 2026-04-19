#!/usr/bin/env python3
"""
Phase 1: Load, audit, clean, normalize Phishing_Email.csv → Phishing_Email_cleaned.csv
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

ROOT = Path(__file__).resolve().parent
CSV_IN = ROOT / "Phishing_Email.csv"
CSV_OUT = ROOT / "Phishing_Email_cleaned.csv"

NON_EMAIL_RE = re.compile(r"^[^a-zA-Z]*$")
_URL_LINE = re.compile(r"^https?://\S+$", re.I)


def normalize_obfuscation_and_lower(text: str) -> str:
    if not isinstance(text, str):
        return ""
    s = text.lower()
    s = re.sub(r"\b[o0](?:\s*[-_.]\s*)?t(?:\s*[-_.]\s*)?p\b", " otp ", s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def audit_and_clean_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    stats: dict[str, int | float | str] = {}
    original = len(df)
    stats["total_rows_raw"] = original

    df = df.rename(columns={c: c.strip().lower() for c in df.columns})
    if "email_text" not in df.columns or "label" not in df.columns:
        raise SystemExit("CSV must have email_text and label columns")

    # Exact duplicates
    before = len(df)
    df = df.drop_duplicates(subset=["email_text"])
    stats["exact_duplicates_removed"] = before - len(df)

    # Empty / short / non-string
    def bad_text(x: object) -> bool:
        if pd.isna(x) or not isinstance(x, str):
            return True
        return len(x.strip()) < 10

    bad = df["email_text"].apply(bad_text)
    stats["empty_short_removed"] = int(bad.sum())
    df = df[~bad]

    # Labels
    def fix_label(v: object) -> str | None:
        if not isinstance(v, str):
            return None
        t = v.strip().lower()
        if t in ("phishing", "safe"):
            return t
        if t in ("phishing email", "1", "malicious"):
            return "phishing"
        if t in ("safe email", "0", "legitimate", "benign"):
            return "safe"
        return None

    df["label"] = df["label"].apply(fix_label)
    stats["invalid_label_removed"] = int(df["label"].isna().sum())
    df = df[df["label"].notna()]

    # Noise: no letters after stripping html/url
    def is_noise(text: object) -> bool:
        if not isinstance(text, str):
            return True
        t = re.sub(r"<[^>]+>", "", text)
        t = re.sub(r"https?://\S+|www\.\S+", "", t)
        if NON_EMAIL_RE.match(t.strip()):
            return True
        if _URL_LINE.match(text.strip()) and len(text.strip()) < 30:
            return True
        return not re.search(r"[a-zA-Z]", t)

    noise = df["email_text"].apply(is_noise)
    stats["noise_removed"] = int(noise.sum())
    df = df[~noise]

    # Normalize text column for modeling (lowercase + OTP obfuscation)
    df["email_text"] = df["email_text"].astype(str).map(normalize_obfuscation_and_lower)

    # Label fixes (on normalized text)
    otp_share_safe = df["email_text"].str.contains(
        r"\botp\b", regex=True, na=False
    ) & df["email_text"].str.contains(
        r"\b(do not share|don'?t share|never share)\b", regex=True, na=False
    ) & ~df["email_text"].str.contains(
        r"\b(share\s+(?:your\s+)?otp|otp\s+share|bhejo|साझा|పంచుకో|urgent|blocked|suspended)\b",
        regex=True,
        na=False,
    )
    df.loc[otp_share_safe, "label"] = "safe"

    bec_pat = re.compile(
        r"\b(wire transfer|urgent payment|keep this confidential|strictly confidential|"
        r"vendor payment|new vendor account|beneficiary account|process before end of day|"
        r"don'?t\s+call|do\s+not\s+call|confirm once done|board meeting)\b",
        re.I,
    )
    df.loc[df["email_text"].str.contains(bec_pat, regex=True, na=False), "label"] = "phishing"

    cred_link = df["email_text"].str.contains(r"https?://\S+", regex=True, na=False) & df[
        "email_text"
    ].str.contains(
        r"\b(verify|login|sign\s*in|password|credential|update\s+your\s+account|kyc|otp)\b",
        regex=True,
        na=False,
    )
    df.loc[cred_link, "label"] = "phishing"

    stats["phishing_count"] = int((df["label"] == "phishing").sum())
    stats["safe_count"] = int((df["label"] == "safe").sum())

    return df.reset_index(drop=True), stats


def near_duplicate_mask(texts: list[str], threshold: float = 0.90) -> np.ndarray:
    """Return boolean mask: True = row to DROP (duplicate of earlier row)."""
    n = len(texts)
    if n <= 1:
        return np.zeros(n, dtype=bool)
    vectorizer = TfidfVectorizer(max_features=8000, ngram_range=(1, 2), min_df=1)
    X = vectorizer.fit_transform(texts)
    nn = NearestNeighbors(metric="cosine", n_neighbors=min(30, n), algorithm="brute")
    nn.fit(X)
    dist, idx = nn.kneighbors(X, return_distance=True)
    drop = np.zeros(n, dtype=bool)
    sim = 1.0 - dist
    for i in range(n):
        if drop[i]:
            continue
        for j_pos in range(1, idx.shape[1]):
            j = int(idx[i, j_pos])
            if j <= i:
                continue
            if sim[i, j_pos] > threshold:
                drop[j] = True
    return drop


def ensure_diversity(df: pd.DataFrame) -> pd.DataFrame:
    """Add minimal synthetic rows only for missing thematic buckets."""
    col = df["email_text"].str.lower()

    def has(rx: str) -> bool:
        return bool(col.str.contains(rx, regex=True, na=False).any())

    synth: list[tuple[str, str, str]] = [
        (
            "otp_hi",
            r"\byour otp is\b.*\bdo not share\b",
            "subject: login code\nyour otp is 482193. valid 5 minutes. do not share this code.",
        ),
        (
            "bec_nl",
            r"wire transfer.*confidential",
            "subject: urgent\ni am in meetings — please wire $12,400 to the new vendor today. keep this confidential. do not call.",
        ),
        (
            "link_phish",
            r"http.*verify.*account",
            "subject: verify\nyour account is locked. verify now: http://secure-verify-login.xyz/update",
        ),
        (
            "job_scam",
            r"job offer.*fee",
            "subject: offer letter\ncongratulations — you are selected. pay rs. 4,999 registration fee to hrdesk-jobportal.cc to receive offer.",
        ),
        (
            "delivery_scam",
            r"customs.*pay.*http",
            "subject: dhl\nparcel held at customs. pay rs. 799 fee: http://dhl-customs-pay.xyz",
        ),
        (
            "aadhaar",
            r"aadhaar.*kyc.*http",
            "subject: uidai\nlink aadhaar kyc now or sim will block: http://uidai-kyc-update.in",
        ),
        (
            "invoice_fraud",
            r"invoice.*bank details",
            "subject: invoice\nupdated bank details for invoice #8891 — please process payment to new account today.",
        ),
        (
            "qr_phish",
            r"scan the qr",
            "subject: payment\nscan the qr code in the attachment to authorize refund to your wallet.",
        ),
        (
            "newsletter",
            r"unsubscribe.*digest",
            "subject: weekly digest\nthis week in devops — top posts. unsubscribe | manage preferences.",
        ),
        (
            "login_alert",
            r"new sign-in.*was this you",
            "subject: security alert\nyour google account had a new sign-in from windows. was this you? no action required if it was you.",
        ),
        (
            "payment_ok",
            r"payment (successful|confirmed)",
            "subject: receipt\nyour payment of rs. 1,200 was successful on 10 apr 2026. transaction id: 998877.",
        ),
    ]
    fixed_rows: list[dict[str, str]] = []
    for key, pat, text in synth:
        if not has(pat):
            lab = "safe" if key in ("otp_hi", "newsletter", "login_alert", "payment_ok") else "phishing"
            fixed_rows.append({"email_text": normalize_obfuscation_and_lower(text), "label": lab})
    if fixed_rows:
        df = pd.concat([df, pd.DataFrame(fixed_rows)], ignore_index=True)
    return df


def main() -> None:
    if not CSV_IN.exists():
        print(f"Missing input: {CSV_IN}", file=sys.stderr)
        sys.exit(1)
    df = pd.read_csv(CSV_IN)
    df, stats = audit_and_clean_frame(df)
    texts = df["email_text"].astype(str).tolist()
    drop = near_duplicate_mask(texts, 0.90)
    stats["near_duplicate_rows_removed"] = int(drop.sum())
    df = df[~drop].reset_index(drop=True)

    df = ensure_diversity(df)

    stats["final_row_count"] = len(df)
    stats["final_phishing"] = int((df["label"] == "phishing").sum())
    stats["final_safe"] = int((df["label"] == "safe").sum())

    df.to_csv(CSV_OUT, index=False)
    print("=== PHASE 1 DATASET AUDIT ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"Saved: {CSV_OUT}")


if __name__ == "__main__":
    main()
