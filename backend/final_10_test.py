import requests
import json
import time

CASES = [
    {
        "id": "1",
        "name": "Bank phishing (link + urgency)",
        "content": "Dear Customer,\nYour SBI account has been temporarily suspended due to suspicious activity.\nPlease verify immediately to avoid permanent block:\nhttp://sbi-secure-login.co.in.verify-now.xyz",
        "expected": "High Risk"
    },
    {
        "id": "2",
        "name": "OTP phishing (obfuscated)",
        "content": "Dear user,\nYour account will be blocked. Share your 0 T P immediately to continue.",
        "expected": "High Risk"
    },
    {
        "id": "3",
        "name": "BEC (no link, pressure)",
        "content": "Hey,\nNeed you to transfer 75000 today.\nI’m in a meeting, don’t call. Just confirm once done.",
        "expected": "High Risk"
    },
    {
        "id": "4",
        "name": "Attachment phishing",
        "content": "Hello,\nInvoice attached. Please review and login to confirm your details.",
        "attachments": [{"filename": "invoice.pdf", "extractedText": "Enter your username and password to verify invoice."}],
        "expected": "High Risk"
    },
    {
        "id": "5",
        "name": "Image/QR phishing",
        "content": "Hi,\nScan the QR code in attached image to verify your bank account.",
        "attachments": [{"filename": "qr.jpg", "hasQrCode": True}],
        "expected": "High Risk"
    },
    {
        "id": "6",
        "name": "Thread hijack",
        "content": "Re: Payment discussion\n\nPlease update payment to this new account urgently.\nPrevious one is no longer valid.",
        "expected": "High Risk"
    },
    {
        "id": "7",
        "name": "Fake cloud link",
        "content": "Hi,\nYour document has been shared with you.\nAccess it here:\nhttp://drive-secure-access.xyz",
        "expected": "High Risk"
    },
    {
        "id": "8",
        "name": "Real safe OTP",
        "content": "Your OTP for login is 483920. Do not share it with anyone.",
        "expected": "Safe"
    },
    {
        "id": "9",
        "name": "Real welcome email",
        "content": "Welcome to GitHub!\n\nYour account has been successfully created.\nYou can now start using GitHub.",
        "expected": "Safe"
    },
    {
        "id": "10",
        "name": "Real notification",
        "content": "Hello,\nYour weekly banking summary is now available.\nNo action is required.",
        "expected": "Safe"
    }
]

def run_tests():
    passed = 0
    failed_details = []
    
    print(f"{'='*60}")
    print(f"RUNNING FINAL REAL EMAIL TEST (10 CASES)")
    print(f"{'='*60}\n")
    
    for case in CASES:
        payload = {
            "email_text": case["content"]
        }
        if "attachments" in case:
            payload["attachments"] = case["attachments"]
            
        try:
            resp = requests.post("http://127.0.0.1:8000/scan-email", json=payload, timeout=30)
            data = resp.json()
            verdict = data.get("classification", data.get("verdict", "Unknown"))
            
            # Map "phishing" to "High Risk" for comparison if API returns "phishing"
            norm_verdict = "High Risk" if verdict.lower() in ["phishing", "high risk", "high_risk"] else verdict
            norm_expected = "High Risk" if case["expected"].lower() in ["phishing", "high risk", "high_risk"] else case["expected"]
            
            # For safe cases, sometimes API returns Suspicious instead of Safe
            if norm_expected.lower() == "safe" and verdict.lower() == "safe":
                norm_verdict = "Safe"
            elif norm_expected.lower() == "safe" and verdict.lower() == "suspicious":
                norm_verdict = "Suspicious"
                
            is_pass = norm_verdict.lower() == norm_expected.lower()
            
            if is_pass:
                passed += 1
                print(f"[PASS] {case['name']} (Expected: {case['expected']}, Got: {verdict})")
            else:
                print(f"[FAIL] {case['name']} (Expected: {case['expected']}, Got: {verdict})")
                failed_details.append({
                    "name": case["name"],
                    "expected": case["expected"],
                    "got": verdict,
                    "reasons": data.get("reasons", [])
                })
        except Exception as e:
            print(f"[ERROR] on {case['name']}: {str(e)}")
            failed_details.append({
                "name": case["name"],
                "error": str(e)
            })
            
    print(f"\n{'-'*60}")
    print(f"RESULTS: {passed}/10 PASSED")
    print(f"{'-'*60}")
    
    if failed_details:
        print("\nFAILURE DETAILS:")
        for fd in failed_details:
            print(f"\n[{fd.get('name')}]")
            if "error" in fd:
                print(f"  Error: {fd['error']}")
            else:
                print(f"  Expected: {fd['expected']} | Got: {fd['got']}")
                print("  Reasons flagged by backend:")
                for r in fd.get("reasons", []):
                    print(f"    - [{r.get('category')}] {r.get('description')}")
                    
if __name__ == '__main__':
    run_tests()
