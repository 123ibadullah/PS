from main import derive_domain_trust
import json

tests = [
    {"sender": "icicibank.com", "brand": "icici", "urls": []},
    {"sender": "google.com", "brand": "google", "urls": []},
    {"sender": "amazon-secure.xyz", "brand": "amazon", "urls": []},
    {"sender": "axisbank.com", "brand": "axisbank", "urls": []},
    {"sender": "sbi.co.in", "brand": "sbi", "urls": []},
]

for t in tests:
    res = derive_domain_trust(
        sender_domain=t["sender"],
        linked_domains=t["urls"],
        header_scan={},
        detected_brand=t["brand"],
        has_lookalike_domain=(t["sender"] == "amazon-secure.xyz")
    )
    print(f"{t['sender']:<20} -> {res['trust']} ({res['status']})")
