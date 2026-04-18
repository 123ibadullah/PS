from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from main import calculate_email_risk, load_artifacts


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset_100.json"
OUT_PATH = BASE_DIR / "reports" / "verification" / "dataset_100_eval.json"


def _normalize_predicted_label(result: dict[str, Any]) -> str:
    verdict = str(result.get("verdict") or "").strip().lower()
    if verdict == "safe":
        return "safe"
    return "phishing"


def _failure_category(item: dict[str, Any], result: dict[str, Any]) -> str:
    text = str(item.get("text") or "").lower()
    signals = " ".join(str(s).lower() for s in (result.get("matched_signals") or []))
    if any(token in text for token in ("bhai", "bhejo", "karo", "jaldi", "warna")):
        return "multilingual_or_hinglish"
    if any(token in text for token in ("o t p", "o-t-p")):
        return "obfuscation"
    if any(token in text for token in ("urgent", "immediately", "don't inform", "click", "verify")):
        return "social_engineering_or_clean_phishing"
    if "otp" in text and "do not share" in text:
        return "safe_context_misread"
    if "sender authenticity" in signals:
        return "sender_domain_intel_bias"
    return "context_intent_misunderstanding"


def main() -> None:
    load_artifacts()
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []

    for idx, item in enumerate(dataset, start=1):
        text = str(item.get("text") or "")
        expected = str(item.get("label") or "").strip().lower()
        result = calculate_email_risk(text)
        predicted = _normalize_predicted_label(result)
        risk_score = int(result.get("risk_score", 0) or 0)
        verdict = str(result.get("verdict") or "")
        matched_signals = list(result.get("matched_signals") or result.get("signals") or [])

        row = {
            "id": f"ITEM-{idx:03d}",
            "text": text,
            "expected": expected,
            "predicted": predicted,
            "risk_score": risk_score,
            "verdict": verdict,
            "matched_signals": matched_signals,
        }
        rows.append(row)
        if expected != predicted:
            mismatches.append(
                {
                    **row,
                    "failure_category": _failure_category(item, result),
                }
            )

    total = len(rows)
    correct = sum(1 for r in rows if r["expected"] == r["predicted"])
    accuracy = round((correct / total * 100) if total else 0.0, 2)
    category_counter = Counter(m["failure_category"] for m in mismatches)

    output = {
        "dataset_size": total,
        "accuracy_percent": accuracy,
        "correct": correct,
        "mismatches_count": len(mismatches),
        "mismatch_categories": dict(category_counter),
        "mismatches": mismatches,
        "results": rows,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Dataset size: {total}")
    print(f"Accuracy: {accuracy}%")
    print(f"Mismatches: {len(mismatches)}")
    if mismatches:
        print("Top mismatch categories:")
        for category, count in category_counter.most_common():
            print(f"- {category}: {count}")
    print(f"Report: {OUT_PATH}")


if __name__ == "__main__":
    main()
