"""
Comprehensive Test Harness for PhishShield backend.
Tests against the /scan endpoint with all datasets.
Identifies: missed phishing, false positives, instability.
Outputs detailed failure reports.
"""

import json
import sys
import time
import hashlib
import requests
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).resolve().parent
API_BASE = "http://127.0.0.1:8000"
SCAN_URL = f"{API_BASE}/scan"

# Load combined dataset
dataset_path = DATA_DIR / "combined_test_dataset.json"
with open(dataset_path, 'r', encoding='utf-8') as f:
    dataset = json.load(f)

print(f"Loaded {len(dataset)} test cases")
print(f"  Safe:     {sum(1 for x in dataset if x['label'] == 'safe')}")
print(f"  Phishing: {sum(1 for x in dataset if x['label'] == 'phishing')}")
print()

# ---- Test Runner ----

results = {
    "total": 0,
    "correct": 0,
    "missed_phishing": [],       # FN: phishing labeled safe
    "false_positive": [],        # FP: safe labeled phishing
    "errors": [],
    "by_source": defaultdict(lambda: {"total": 0, "correct": 0, "missed": 0, "fp": 0}),
}

BATCH_SIZE = 50  # Print progress every N

def classify_verdict(verdict: str) -> str:
    """Map API verdict to safe/phishing binary."""
    v = verdict.lower().strip()
    if v in ("safe", "low risk"):
        return "safe"
    elif v in ("suspicious", "high risk", "critical"):
        return "phishing"
    return "phishing"  # Default to phishing for unknown

def scan_email(text: str, timeout: float = 30.0) -> dict:
    """Send email text to /scan endpoint."""
    try:
        resp = requests.post(
            SCAN_URL,
            json={"email_text": text},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.exceptions.Timeout:
        return {"error": "TIMEOUT"}
    except requests.exceptions.ConnectionError:
        return {"error": "CONNECTION_REFUSED"}
    except Exception as e:
        return {"error": str(e)[:200]}


def run_test(item: dict, index: int) -> dict:
    """Run a single test case."""
    text = item["text"]
    expected = item["label"]
    source = item.get("source", "unknown")
    
    result = scan_email(text)
    
    if "error" in result:
        return {
            "index": index,
            "status": "error",
            "error": result["error"],
            "expected": expected,
            "source": source,
            "text_preview": text[:100],
        }
    
    verdict = result.get("verdict", result.get("classification", "unknown"))
    risk_score = result.get("risk_score", result.get("riskScore", 0))
    predicted = classify_verdict(verdict)
    
    correct = (predicted == expected)
    
    return {
        "index": index,
        "status": "correct" if correct else "wrong",
        "expected": expected,
        "predicted": predicted,
        "verdict": verdict,
        "risk_score": risk_score,
        "source": source,
        "correct": correct,
        "text_preview": text[:150],
        "signals": result.get("signals", [])[:5],
    }


# ---- Main Test Loop ----

print("=" * 70)
print("  PHISHSHIELD COMPREHENSIVE TEST SUITE")
print("=" * 70)
print()

start_time = time.time()
failed_cases = []

for i, item in enumerate(dataset):
    result = run_test(item, i)
    results["total"] += 1
    source = result["source"]
    results["by_source"][source]["total"] += 1
    
    if result["status"] == "error":
        results["errors"].append(result)
        # Print progress marker
        if (i + 1) % BATCH_SIZE == 0 or i == len(dataset) - 1:
            elapsed = time.time() - start_time
            print(f"  [{i+1}/{len(dataset)}] {elapsed:.1f}s - Errors: {len(results['errors'])}", flush=True)
        continue
    
    if result["correct"]:
        results["correct"] += 1
        results["by_source"][source]["correct"] += 1
    else:
        if result["expected"] == "phishing" and result["predicted"] == "safe":
            results["missed_phishing"].append(result)
            results["by_source"][source]["missed"] += 1
        elif result["expected"] == "safe" and result["predicted"] == "phishing":
            results["false_positive"].append(result)
            results["by_source"][source]["fp"] += 1
        failed_cases.append(result)
    
    # Progress
    if (i + 1) % BATCH_SIZE == 0 or i == len(dataset) - 1:
        elapsed = time.time() - start_time
        acc = results["correct"] / results["total"] * 100 if results["total"] else 0
        missed = len(results["missed_phishing"])
        fps = len(results["false_positive"])
        errs = len(results["errors"])
        print(f"  [{i+1}/{len(dataset)}] {elapsed:.1f}s  Acc={acc:.1f}%  Missed={missed}  FP={fps}  Err={errs}", flush=True)

elapsed = time.time() - start_time

# ---- Results Summary ----

print()
print("=" * 70)
print("  RESULTS SUMMARY")
print("=" * 70)

total = results["total"]
correct = results["correct"]
testable = total - len(results["errors"])
accuracy = correct / testable * 100 if testable else 0

print(f"\n  Total tested:     {total}")
print(f"  Testable:         {testable}")
print(f"  Correct:          {correct}")
print(f"  Accuracy:         {accuracy:.2f}%")
print(f"  Missed Phishing:  {len(results['missed_phishing'])}  (CRITICAL)")
print(f"  False Positives:  {len(results['false_positive'])}")
print(f"  API Errors:       {len(results['errors'])}")
print(f"  Time:             {elapsed:.1f}s")

# Per-source breakdown
print(f"\n  --- Per Source ---")
for source, stats in sorted(results["by_source"].items()):
    src_testable = stats["total"]
    src_acc = stats["correct"] / src_testable * 100 if src_testable else 0
    print(f"  {source:20s}: {stats['correct']}/{src_testable} ({src_acc:.1f}%)  missed={stats['missed']}  fp={stats['fp']}")

# Critical failures detail
if results["missed_phishing"]:
    print(f"\n  --- MISSED PHISHING (Critical) ---")
    for r in results["missed_phishing"][:30]:
        print(f"  [{r['index']}] [{r['source']}] verdict={r['verdict']} score={r['risk_score']}")
        print(f"       {r['text_preview'][:120].encode('ascii', 'replace').decode('ascii')}")
        print()

if results["false_positive"]:
    print(f"\n  --- FALSE POSITIVES ---")
    for r in results["false_positive"][:30]:
        print(f"  [{r['index']}] [{r['source']}] verdict={r['verdict']} score={r['risk_score']}")
        print(f"       {r['text_preview'][:120].encode('ascii', 'replace').decode('ascii')}")
        if r.get("signals"):
            print(f"       signals: {r['signals'][:3]}")
        print()

if results["errors"]:
    print(f"\n  --- API ERRORS ---")
    for r in results["errors"][:10]:
        print(f"  [{r['index']}] {r['error']}")

# Save full report
report = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "total": total,
    "testable": testable,
    "correct": correct,
    "accuracy": accuracy,
    "missed_phishing_count": len(results["missed_phishing"]),
    "false_positive_count": len(results["false_positive"]),
    "error_count": len(results["errors"]),
    "elapsed_seconds": elapsed,
    "missed_phishing": results["missed_phishing"][:50],
    "false_positives": results["false_positive"][:50],
    "errors": results["errors"][:20],
    "by_source": {k: dict(v) for k, v in results["by_source"].items()},
}

report_path = DATA_DIR / "test_report.json"
with open(report_path, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
print(f"\n  Report saved: {report_path}")

# Exit code
if len(results["missed_phishing"]) == 0 and len(results["false_positive"]) == 0:
    print("\n  [PASS] ALL TESTS PASSED - System is production-ready!")
    sys.exit(0)
else:
    print(f"\n  [FAIL] Issues remain: {len(results['missed_phishing'])} missed phishing, {len(results['false_positive'])} false positives")
    sys.exit(1)
