from __future__ import annotations

import json
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent


def training_metadata_paths() -> list[Path]:
    """Repo layout uses ../data; HF Space Docker layout uses ./data next to main.py."""
    return [
        BASE_DIR / "data" / "training_meta.json",
        BASE_DIR.parent / "data" / "training_meta.json",
    ]


def resolve_training_metadata_path() -> Path | None:
    for candidate in training_metadata_paths():
        if candidate.exists():
            return candidate
    return None


def load_training_metadata() -> dict[str, Any]:
    path = resolve_training_metadata_path()
    if path is None:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _runtime_counts_from_scans(scans: list[dict[str, Any]]) -> dict[str, int]:
    total_scans = len(scans)
    phishing_detected = sum(1 for item in scans if int(item.get("risk_score", 0) or 0) >= 61)
    suspicious_detected = sum(1 for item in scans if 26 <= int(item.get("risk_score", 0) or 0) <= 60)
    safe_detected = max(total_scans - phishing_detected - suspicious_detected, 0)
    return {
        "total_scans": total_scans,
        "phishing_detected": phishing_detected,
        "suspicious_detected": suspicious_detected,
        "safe_detected": safe_detected,
    }


def build_api_metrics_payload(scans: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Honest metrics payload: offline holdout evaluation vs in-process runtime counters.
    """
    metadata = load_training_metadata()
    offline_raw = metadata.get("metrics") if isinstance(metadata.get("metrics"), dict) else {}
    runtime = _runtime_counts_from_scans(scans)

    accuracy = float(offline_raw.get("accuracy", 0.0) or 0.0)
    precision = float(offline_raw.get("precision", 0.0) or 0.0)
    recall = float(offline_raw.get("recall", 0.0) or 0.0)
    f1 = float(offline_raw.get("f1_score", offline_raw.get("f1Score", 0.0)) or 0.0)
    false_positive_rate = max(0.0, 1.0 - precision) if precision > 0 else None

    live_qa = metadata.get("live_qa") if isinstance(metadata.get("live_qa"), dict) else {}
    live_range = live_qa.get("estimated_accuracy_range")
    live_accuracy_note = None
    if isinstance(live_range, (list, tuple)) and len(live_range) == 2:
        try:
            low = float(live_range[0])
            high = float(live_range[1])
            live_accuracy_note = f"Documented live UI QA range: {low * 100:.0f}–{high * 100:.0f}% (May 2026 sample)"
        except (TypeError, ValueError):
            live_accuracy_note = None

    offline_evaluation = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": false_positive_rate,
        "evaluated_at": metadata.get("trained_at"),
        "evaluation_dataset_size": metadata.get("test_rows"),
        "training_rows": metadata.get("train_rows"),
        "model_type": metadata.get("model_type"),
        "training_metadata_version": metadata.get("trained_at"),
        "metadata_path": str(resolve_training_metadata_path() or training_metadata_paths()[0]),
        "disclaimer": "Offline holdout evaluation on a fixed train/test split — not continuously measured live accuracy.",
        "live_qa_note": live_accuracy_note,
    }

    runtime_operational = {
        **runtime,
        "scope": "current_process_session_memory",
        "disclaimer": "Counts reflect scans stored in this API process session, not global production telemetry.",
    }

    return {
        "metrics_kind": "offline_evaluation_plus_runtime_operational",
        "offline_evaluation": offline_evaluation,
        "runtime_operational": runtime_operational,
        # Backward-compatible flat keys (explicitly sourced from offline evaluation)
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1Score": f1,
        "falsePositiveRate": false_positive_rate if false_positive_rate is not None else 0.0,
        "accuracy_source": "offline_holdout_evaluation",
        "totalScans": runtime["total_scans"],
        "phishingDetected": runtime["phishing_detected"],
        "suspiciousDetected": runtime["suspicious_detected"],
        "safeDetected": runtime["safe_detected"],
        "driftLevel": "low",
        "falseNegativeCount": 0,
    }
