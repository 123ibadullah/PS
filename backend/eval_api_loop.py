from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import requests

from main import calculate_email_risk, load_artifacts

BASE_DIR = Path(__file__).resolve().parent
API_URL_DEFAULT = "http://localhost:8000/scan-email"


def normalize_predicted_label(payload: dict[str, Any]) -> str:
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict == "safe":
        return "safe"
    return "phishing"


def categorize_failure(text: str, expected: str, predicted: str) -> str:
    t = text.lower()
    if expected == "safe" and predicted == "phishing" and "otp" in t and ("do not share" in t or "never share" in t):
        return "safe_otp_context_false_positive"
    if any(token in t for token in ("o t p", "o-t-p", "otp")):
        return "otp_handling"
    if any(token in t for token in ("bhai", "bro", "yaar", "paise", "bhejo", "karo", "ivvandi")):
        return "multilingual_or_hinglish"
    if any(token in t for token in ("click", "verify", "reset password", "credentials", "unlock account")):
        return "clean_phishing_or_social_engineering"
    if any(token in t for token in ("urgent", "don't tell anyone", "confidential", "transfer funds")):
        return "social_engineering_bec"
    return "context_misunderstanding"


def run_dataset(dataset_path: Path, api_url: str, *, timeout_s: float, use_local: bool) -> dict[str, Any]:
    data = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for idx, item in enumerate(data, start=1):
        text = str(item.get("text") or "")
        expected = str(item.get("label") or "").strip().lower()
        try:
            if use_local:
                payload = calculate_email_risk(text)
            else:
                response = requests.post(api_url, json={"email_text": text}, timeout=timeout_s)
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001
            errors.append({"id": f"{dataset_path.stem}-{idx:04d}", "text": text, "error": f"{type(exc).__name__}: {exc}"})
            continue

        predicted = normalize_predicted_label(payload)
        risk_score = int(payload.get("risk_score", 0) or 0)
        verdict = str(payload.get("verdict") or "")
        row = {
            "id": f"{dataset_path.stem}-{idx:04d}",
            "text": text,
            "expected": expected,
            "predicted": predicted,
            "risk_score": risk_score,
            "verdict": verdict,
            "matched_signals": list(payload.get("matched_signals") or payload.get("signals") or []),
        }
        rows.append(row)
        if expected != predicted:
            mismatches.append({**row, "failure_category": categorize_failure(text, expected, predicted)})
        if idx % 100 == 0:
            print(f"[{dataset_path.name}] processed {idx}/{len(data)}", flush=True)

    total = len(rows)
    correct = sum(1 for r in rows if r["expected"] == r["predicted"])
    accuracy = round((correct / total * 100) if total else 0.0, 2)
    failure_patterns = dict(Counter(m["failure_category"] for m in mismatches))
    return {
        "dataset": dataset_path.name,
        "dataset_size": total,
        "accuracy_percent": accuracy,
        "correct": correct,
        "mismatch_count": len(mismatches),
        "failure_patterns": failure_patterns,
        "errors": errors,
        "mismatches": mismatches,
        "results": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate live API against datasets.")
    parser.add_argument("--api-url", default=API_URL_DEFAULT)
    parser.add_argument("--dataset", default=str(BASE_DIR / "elite_emails_1000.json"))
    parser.add_argument("--adversarial", default=str(BASE_DIR / "adversarial_20.json"))
    parser.add_argument("--out", default=str(BASE_DIR / "reports" / "verification" / "elite_api_eval.json"))
    parser.add_argument("--timeout-s", type=float, default=5.0)
    parser.add_argument("--local", action="store_true", help="Evaluate via local calculate_email_risk instead of HTTP API")
    args = parser.parse_args()

    if args.local:
        load_artifacts()
    dataset_report = run_dataset(Path(args.dataset), args.api_url, timeout_s=float(args.timeout_s), use_local=bool(args.local))
    adversarial_report = run_dataset(Path(args.adversarial), args.api_url, timeout_s=float(args.timeout_s), use_local=bool(args.local))
    combined = {
        "api_url": args.api_url,
        "main_dataset": dataset_report,
        "adversarial_dataset": adversarial_report,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Main dataset: {dataset_report['dataset_size']} | accuracy={dataset_report['accuracy_percent']}% | mismatches={dataset_report['mismatch_count']}")
    print(f"Adversarial: {adversarial_report['dataset_size']} | accuracy={adversarial_report['accuracy_percent']}% | mismatches={adversarial_report['mismatch_count']}")
    print(f"Report: {out_path}")


if __name__ == "__main__":
    main()
