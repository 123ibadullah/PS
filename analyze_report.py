import json

r = json.load(open("data_2/test_report.json", encoding="utf-8"))
print(f"ACCURACY: {r['accuracy']:.2f}%")
print(f"MISSED PHISHING: {r['missed_phishing_count']}")
print(f"FALSE POSITIVES: {r['false_positive_count']}")
print()
print("BY SOURCE:")
for k, v in r["by_source"].items():
    print(f"  {k}: {v}")

print("\n=== SAMPLE MISSED PHISHING ===")
for x in r["missed_phishing"][:20]:
    print(f"  [{x['index']}] verdict={x['verdict']} score={x['risk_score']} src={x['source']}")
    print(f"    {x['text_preview'][:120]}")

print("\n=== SAMPLE FALSE POSITIVES (safe tagged as phishing) ===")
for x in r["false_positives"][:20]:
    print(f"  [{x['index']}] verdict={x['verdict']} score={x['risk_score']} src={x['source']}")
    print(f"    {x['text_preview'][:120]}")
