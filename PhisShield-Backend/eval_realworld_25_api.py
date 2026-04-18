from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests


API_URL = "http://localhost:8000/scan-email"
OUT_PATH = Path("reports/verification/realworld_25_api_eval.json")


@dataclass
class Case:
    id: int
    bucket: str
    text: str


CASES: list[Case] = [
    Case(1, "high_risk", "Dear user, your SBI account has been temporarily suspended. Verify immediately: http://sbi-secure-alert-login.xyz"),
    Case(2, "high_risk", "Your account shows unusual activity. Please confirm your login credentials now to avoid restriction."),
    Case(3, "high_risk", "Hi, I need you to process an urgent vendor payment today. I’m in a meeting, don’t call."),
    Case(4, "high_risk", "Income Tax Department: Refund pending. Submit PAN and bank details to receive."),
    Case(5, "high_risk", "Your Paytm account will be blocked. Update KYC here: http://paytm-verification-secure.xyz"),
    Case(6, "high_risk", "OTP bhejo jaldi warna account block ho jayega abhi ke abhi"),
    Case(7, "high_risk", "Hello, we noticed a login from a new device. Confirm your password immediately."),
    Case(8, "high_risk", "Bro I’m stuck, can you send 10k now? I’ll return tonight."),
    Case(9, "high_risk", "Click here to download your invoice: http://secure-invoice-download.xyz"),
    Case(10, "high_risk", "Your bank account is locked. Share OTP to unlock immediately."),
    Case(11, "high_risk", "Dear employee, please review attached payroll changes and confirm login credentials."),
    Case(12, "high_risk", "Your Netflix account payment failed. Update billing info now: http://netflix-secure-update.xyz"),
    Case(13, "suspicious", "Hi, please review the attached document and confirm."),
    Case(14, "suspicious", "Following up on previous request, kindly complete the action."),
    Case(15, "suspicious", "Urgent: Please respond as soon as possible."),
    Case(16, "suspicious", "Your account may need verification. Contact support."),
    Case(17, "suspicious", "Please confirm your identity for security reasons."),
    Case(18, "suspicious", "A document has been shared with you. Access it here: http://drive-secure-access.xyz"),
    Case(19, "safe", "Your OTP is 482991. Do not share it with anyone."),
    Case(20, "safe", "Your Amazon order has been delivered successfully."),
    Case(21, "safe", "Payment of ₹5,000 received successfully."),
    Case(22, "safe", "Meeting scheduled tomorrow at 10 AM."),
    Case(23, "safe", "Invoice attached for your review."),
    Case(24, "safe", "Your account statement is ready."),
    Case(25, "safe", "Welcome to our platform! Your account setup is complete."),
]


def verdict_to_label(verdict: str) -> str:
    return "safe" if verdict.strip().lower() == "safe" else "flagged"


def is_pass(bucket: str, verdict: str) -> bool:
    normalized = verdict.strip().lower()
    if bucket == "safe":
        return normalized == "safe"
    return normalized != "safe"


def main() -> None:
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    api_errors: list[dict[str, Any]] = []
    for case in CASES:
        payload: dict[str, Any] | None = None
        last_error = ""
        for _attempt in range(2):
            try:
                response = requests.post(API_URL, json={"email_text": case.text}, timeout=8)
                if response.status_code == 429:
                    last_error = "HTTPError: 429 Too Many Requests"
                    time.sleep(0.8)
                    continue
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.4)
        if payload is None:
            api_errors.append({"id": case.id, "text": case.text, "error": last_error})
            failures.append(
                {
                    "id": case.id,
                    "bucket": case.bucket,
                    "text": case.text,
                    "risk_score": -1,
                    "verdict": "API_ERROR",
                    "label": "unknown",
                    "passed": False,
                }
            )
            continue
        time.sleep(0.2)
        verdict = str(payload.get("verdict") or "")
        risk_score = int(payload.get("risk_score", 0) or 0)
        passed = is_pass(case.bucket, verdict)
        row = {
            "id": case.id,
            "bucket": case.bucket,
            "text": case.text,
            "risk_score": risk_score,
            "verdict": verdict,
            "label": verdict_to_label(verdict),
            "passed": passed,
        }
        results.append(row)
        if not passed:
            failures.append(row)

    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "accuracy_percent": round((sum(1 for r in results if r["passed"]) / len(results) * 100), 2) if results else 0.0,
        "api_errors": api_errors,
        "failures": failures,
        "results": results,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Evaluated: {summary['total']}")
    print(f"Passed: {summary['passed']}")
    print(f"Accuracy: {summary['accuracy_percent']}%")
    print(f"Failures: {len(failures)}")
    print(f"API errors: {len(api_errors)}")
    print(f"Report: {OUT_PATH}")
    print("--- Results ---")
    for row in results:
        print(f"{row['id']:02d}. [{row['bucket']}] risk={row['risk_score']:3d} verdict={row['verdict']}")


if __name__ == "__main__":
    main()
