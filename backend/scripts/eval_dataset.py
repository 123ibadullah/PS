from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
import sys


Label = Literal["safe", "phishing"]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                continue
            text = str(obj.get("text", "") or "").strip()
            label = str(obj.get("label", "") or "").strip().lower()
            if not text or label not in ("safe", "phishing"):
                continue
            items.append({"text": text, "label": label})
    return items


def _predict_label(result: dict[str, Any]) -> Label:
    verdict = str(result.get("verdict", "") or "")
    score = int(result.get("risk_score", 0) or 0)
    if verdict.strip().lower() == "safe" and score <= 25:
        return "safe"
    return "phishing"


@dataclass
class Metrics:
    total: int
    accuracy: float
    precision_phish: float
    recall_phish: float
    fpr: float
    fn: int
    fp: int
    tn: int
    tp: int
    unstable: int
    avg_ms: float


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate PhishShield risk function against a JSONL dataset.")
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="Write JSON report here")
    ap.add_argument("--limit", default=0, type=int, help="Optional limit for quick runs")
    args = ap.parse_args()

    # Ensure backend root is importable when running from scripts/.
    backend_root = Path(__file__).resolve().parents[1]
    if str(backend_root) not in sys.path:
        sys.path.insert(0, str(backend_root))

    # Import late so this script can be used as a smoke test even if deps are heavy.
    from main import calculate_email_risk  # type: ignore

    items = _load_jsonl(args.dataset)
    if args.limit and args.limit > 0:
        items = items[: args.limit]

    tp = tn = fp = fn = 0
    unstable = 0
    lat_ms: list[float] = []
    false_negatives: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    unstable_samples: list[dict[str, Any]] = []

    for idx, it in enumerate(items):
        text = it["text"]
        true_label: Label = it["label"]

        t0 = time.perf_counter()
        r1 = calculate_email_risk(text, headers_text="")
        t1 = time.perf_counter()
        r2 = calculate_email_risk(text, headers_text="")
        t2 = time.perf_counter()

        lat_ms.append((t1 - t0) * 1000.0)

        pred1 = _predict_label(r1)
        pred2 = _predict_label(r2)
        if (r1.get("verdict"), r1.get("risk_score")) != (r2.get("verdict"), r2.get("risk_score")) or pred1 != pred2:
            unstable += 1
            if len(unstable_samples) < 10:
                unstable_samples.append(
                    {
                        "verdict_1": r1.get("verdict"),
                        "risk_score_1": r1.get("risk_score"),
                        "verdict_2": r2.get("verdict"),
                        "risk_score_2": r2.get("risk_score"),
                        "text": text[:500],
                    }
                )

        pred = pred1
        if true_label == "phishing" and pred == "phishing":
            tp += 1
        elif true_label == "safe" and pred == "safe":
            tn += 1
        elif true_label == "safe" and pred == "phishing":
            fp += 1
            if len(false_positives) < 20:
                false_positives.append(
                    {"risk_score": r1.get("risk_score"), "verdict": r1.get("verdict"), "text": text[:500]}
                )
        elif true_label == "phishing" and pred == "safe":
            fn += 1
            if len(false_negatives) < 20:
                false_negatives.append(
                    {"risk_score": r1.get("risk_score"), "verdict": r1.get("verdict"), "text": text[:500]}
                )

        if (idx + 1) % 50 == 0:
            # lightweight progress output
            pass

    total = max(1, (tp + tn + fp + fn))
    accuracy = (tp + tn) / total
    precision_phish = tp / max(1, (tp + fp))
    recall_phish = tp / max(1, (tp + fn))
    fpr = fp / max(1, (fp + tn))
    avg_ms = sum(lat_ms) / max(1, len(lat_ms))

    metrics = Metrics(
        total=total,
        accuracy=accuracy,
        precision_phish=precision_phish,
        recall_phish=recall_phish,
        fpr=fpr,
        fn=fn,
        fp=fp,
        tn=tn,
        tp=tp,
        unstable=unstable,
        avg_ms=avg_ms,
    )

    report = {
        "dataset": str(args.dataset),
        "metrics": metrics.__dict__,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "unstable_samples": unstable_samples,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

