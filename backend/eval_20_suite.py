import requests
import json
import time

TEST_CASES = [
    # --- PHISHING (10) ---
    {
        "id": "1",
        "name": "Bank KYC Phishing",
        "content": "Dear Customer, Your HDFC account requires mandatory KYC update. Please verify at http://hdfc-bank-kyc-update.xyz. Failure will result in account suspension.",
        "expected": "High Risk"
    },
    {
        "id": "2",
        "name": "PayPal Fake Order",
        "content": "You've successfully authorized a payment of $899.99 for Apple iPhone 14 to eBay. If you did not make this purchase, click here instantly to dispute: http://paypal-dispute-resolution.ml",
        "expected": "High Risk"
    },
    {
        "id": "3",
        "name": "HR Policy Update BEC",
        "content": "All Employees, kindly review the attached revised company policy regarding payroll changes immediately. Login to your employee portal below to acknowledge.",
        "attachments": [{"filename": "HR_Policy.pdf", "extractedText": "Enter Microsoft credentials to view policy"}],
        "expected": "High Risk"
    },
    {
        "id": "4",
        "name": "Urgent Vendor Payment (No Link BEC)",
        "content": "Hi finance, I need an urgent wire transfer of 23,000 USD to a new vendor. Please process it right now and keep it confidential until we announce the partnership. Reply once done.",
        "expected": "High Risk"
    },
    {
        "id": "5",
        "name": "Fake Netflix Subscription",
        "content": "Your Netflix subscription has expired today. Update your payment details immediately at http://netflix.support-renew.xyz to prevent service interruption.",
        "expected": "High Risk"
    },
    {
        "id": "6",
        "name": "Obfuscated OTP Scam",
        "content": "Dear user, suspicious login attempt on your account from Kolkata. Share your O.T.P. here immediately to block the attacker.",
        "expected": "High Risk"
    },
    {
        "id": "7",
        "name": "Fake Google Drive",
        "content": "Someone shared a secure document with you on Google Drive. View Document: http://gdrive-auth-file-id-5231.tk",
        "expected": "High Risk"
    },
    {
        "id": "8",
        "name": "Thread Hijack Payment",
        "content": "Re: Invoice 10444\nHi, regarding the previous thread, our banking details have changed. Please redirect the payment to the attached new account rather than the old one today.",
        "expected": "High Risk"
    },
    {
        "id": "9",
        "name": "Income Tax Refund",
        "content": "Govt of India IT dept notification: You have an outstanding tax refund of INR 45,900. Claim it immediately click http://incometax-refunds-india.xyz",
        "expected": "High Risk"
    },
    {
        "id": "10",
        "name": "QR Code Payroll",
        "content": "Scan the QR code below using your banking app to authenticate your monthly salary slip.",
        "attachments": [{"filename": "qr.jpg", "hasQrCode": True}],
        "expected": "High Risk"
    },

    # --- SAFE (10) ---
    {
        "id": "11",
        "name": "GitHub Welcome",
        "content": "Welcome to GitHub! Your account has been successfully created. Start contributing to repositories and exploring the community.",
        "expected": "Safe"
    },
    {
        "id": "12",
        "name": "Amazon Order Shipped",
        "content": "Your Amazon.in order #412-1249912 has been shipped. Arriving on Thursday. Track your package on your Amazon account.",
        "expected": "Safe"
    },
    {
        "id": "13",
        "name": "True OTP",
        "content": "Your login OTP is 559190. It is valid for 10 minutes. Do not share this code with anyone.",
        "expected": "Safe"
    },
    {
        "id": "14",
        "name": "Team Newsletter",
        "content": "Hi team, attached is the weekly newsletter and performance indicators. Have a great weekend!",
        "expected": "Safe"
    },
    {
        "id": "15",
        "name": "Payment Confirmation",
        "content": "We have successfully received your payment of Rs 1,499 for your broadband bill. Thank you for choosing Airtel.",
        "expected": "Safe"
    },
    {
        "id": "16",
        "name": "SBI Weekly Summary",
        "content": "Dear customer, your weekly banking summary is now available in your SBI online portal. No action is required.",
        "expected": "Safe"
    },
    {
        "id": "17",
        "name": "Calendly Invite",
        "content": "New Event: John / Jane Sync. Time: 4 PM EST. Joining link via Google Meet. No action required unless you need to reschedule.",
        "expected": "Safe"
    },
    {
        "id": "18",
        "name": "Security Alert New Device",
        "content": "A new sign-in to your Google Account from Chrome on Windows. If this was you, you don't need to do anything.",
        "expected": "Safe"
    },
    {
        "id": "19",
        "name": "Internal Jira Notify",
        "content": "[JIRA] User assigned issue PROJ-102: Update landing page UI. View task in our board.",
        "expected": "Safe"
    },
    {
        "id": "20",
        "name": "Password Reset Info",
        "content": "You recently requested to reset your password for your Dropbox account. Use the code 44929 in the app. If you didn't request this, you can safely ignore this email.",
        "expected": "Safe"
    }
]

def run_suite():
    passed = 0
    failures = []
    
    print("="*60)
    print("RUNNING 20 CYBERSECURITY VALIDATION EMAILS")
    print("="*60 + "\n")
    
    for case in TEST_CASES:
        payload = {"email_text": case["content"]}
        if "attachments" in case:
            payload["attachments"] = case["attachments"]
            
        try:
            resp = requests.post("http://127.0.0.1:8000/scan-email", json=payload, timeout=20)
            data = resp.json()
            verdict = data.get("classification", data.get("verdict", "Unknown"))
            
            # Map equivalents
            norm_verdict = verdict
            if verdict.lower() in ["phishing", "high risk", "high_risk"]:
                norm_verdict = "High Risk"
            
            if norm_verdict == case["expected"]:
                passed += 1
                print(f"[PASS] {case['name']} (Got: {norm_verdict})")
            else:
                print(f"[FAIL] {case['name']} -> Expected: {case['expected']} | Got: {norm_verdict} (Score: {data.get('risk_score')})")
                failures.append({
                    "name": case["name"],
                    "expected": case["expected"],
                    "got": norm_verdict,
                    "reasons": data.get("reasons", []),
                    "score": data.get("risk_score")
                })
        except Exception as e:
            print(f"[ERROR] {case['name']}: {str(e)}")
            failures.append({"name": case["name"], "error": str(e)})

    print("\n" + "-"*60)
    print(f"FINAL ACCURACY: {passed}/{len(TEST_CASES)} ({(passed/len(TEST_CASES))*100}%)\n")
    
    if failures:
        print("FAILURE DETAILS TO FIX:")
        for f in failures:
            if "error" in f:
                print(f"- {f['name']}: Exception - {f['error']}")
            else:
                print(f"- {f['name']}: Wanted {f['expected']}, Got {f['got']} (Score: {f['score']})")
                for r in f.get('reasons', []):
                    print(f"  * {r.get('category')}: {r.get('description')}")
    else:
        print("SYSTEM STABLE AND RELIABLE. 100% CORRECT.")

if __name__ == "__main__":
    run_suite()
