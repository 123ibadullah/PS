import requests

ENDPOINT = "http://localhost:8000/scan-email"

TEST_CASES = [
    # PHISHING CASES
    ("Dear Customer, your SBI account is suspended. Share OTP immediately at http://sbi-verify.net", "phishing"),
    ("Aapka UPI PIN expire ho gaya hai. Turant yahan click karein: http://upi-renew.co", "phishing"),
    ("Your HDFC account shows suspicious activity. Verify Aadhaar now: http://hdfc-kyc.xyz", "phishing"),
    ("Income Tax refund of Rs.18,400 pending. Submit PAN details: http://incometax-refund.in", "phishing"),
    ("Dear Sir, wire transfer of $85,000 must be processed urgently. Keep this confidential. — CEO", "phishing"),
    ("GST portal notice: Your GSTIN has been deactivated. Login immediately to restore.", "phishing"),
    ("Congratulations! You won Rs.25 lakh in KBC Lucky Draw. WhatsApp 9876543210 to claim.", "phishing"),
    ("Your IRCTC account is locked. Verify KYC within 24 hours or account will be deleted.", "phishing"),
    ("FedEx: Your parcel is held at customs. Pay Rs.499 delivery fee: http://fedex-india-delivery.net", "phishing"),
    ("Urgent: Share your net banking password to complete 2FA upgrade. — ICICI Security Team", "phishing"),
    ("आपका बैंक खाता बंद हो जाएगा। अभी OTP साझा करें।", "phishing"),
    ("మీ SBI ఖాతా నిలిపివేయబడింది. వెంటనే OTP పంచుకోండి.", "phishing"),
    ("ALERT: Rs.9,999 debited from your HDFC a/c. Not you? Call 1800-XXX to reverse.", "phishing"),
    ("Dear vendor, please update your bank account to the new details below for next payment.", "phishing"),
    ("Your PAN card is linked to suspicious transactions. Verify at http://pan-verify.in now.", "phishing"),
    ("HR Update: Submit your Aadhaar and PAN copy to new-hr-portal.xyz for salary revision.", "phishing"),
    ("Lucky Winner! Your mobile number selected for Rs.50,000 prize. Reply with name and address.", "phishing"),
    ("Payroll team: Please change my salary account to XXXX bank. Sending details separately.", "phishing"),
    ("This is DHL India. Your package requires customs clearance fee of Rs.299. Pay here.", "phishing"),
    ("Verify your Aadhaar-linked mobile number immediately or service will be discontinued.", "phishing"),
    # SAFE CASES
    ("Hi Team, please find the meeting agenda for tomorrow's standup attached.", "safe"),
    ("Your Amazon order #402-XXXXXX has been shipped. Expected delivery: Friday.", "safe"),
    ("GitHub notification: A new pull request was opened in your repository.", "safe"),
    ("Your monthly Airtel bill of Rs.399 is due on 25th April. Pay via My Airtel app.", "safe"),
    ("Newsletter: This week in Python — top articles, tutorials, and job posts.", "safe"),
    ("Meeting rescheduled to 3pm IST tomorrow. Please update your calendar.", "safe"),
    ("Your Swiggy order is on the way! Track here: [tracking link]", "safe"),
    ("SELECT * FROM users WHERE email = 'test@example.com'; — DB admin query log", "safe"),
    ("OTP for your Zepto login is 847291. Valid for 10 minutes. Do not share.", "safe"),
    ("Dear subscriber, your IRCTC e-ticket for Train 12345 is confirmed. PNR: XXXXXXXX", "safe"),
    ("Hi Rahul, attached is the invoice for last month's consulting work. Please process.", "safe"),
    ("Your Google account was signed in from Chrome on Windows. Was this you?", "safe"),
    ("Reminder: Your LIC premium of Rs.4,200 is due next week.", "safe"),
    ("Weekly digest: Top cybersecurity news — ransomware trends, patch updates.", "safe"),
    ("Team lunch at 1pm today at the usual place. Let me know if you can't make it.", "safe"),
]

def get_verdict(text):
    try:
        resp = requests.post(ENDPOINT, json={"email_text": text}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # Accept 'phishing' or 'safe' (case-insensitive)
        verdict = data.get('verdict', '').strip().lower()
        return verdict
    except Exception as e:
        return f"error: {e}"

def main():
    results = []
    total_pass = 0
    first_fail_response = None
    for i, (text, expected) in enumerate(TEST_CASES, 1):
        try:
            resp = requests.post(ENDPOINT, json={"email_text": text}, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            got = data.get('verdict', '').strip().lower()
        except Exception as e:
            got = f"error: {e}"
            data = None
        score = 1 if got == expected else 0
        status = "PASS" if score else "FAIL"
        if status == "PASS":
            total_pass += 1
        results.append((i, expected, got, score, status))
        print(f"Case #{i} | Expected: {expected} | Got: {got} | Score: {score} | {status}")
        if status == "FAIL" and not first_fail_response and data:
            print(f"\n--- FULL API RESPONSE FOR FIRST FAIL (Case #{i}) ---\n{data}\n--- END RESPONSE ---\n")
            first_fail_response = data
    print(f"\nTotal PASS: {total_pass}")
    print(f"Total FAIL: {len(TEST_CASES) - total_pass}")
    return results

if __name__ == "__main__":
    main()
