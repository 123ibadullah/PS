from main import calculate_email_risk
import json

test_cases = [
    {
        "name": "Google safe email",
        "text": "Your Google account password was changed recently. If this was you, ignore this email.",
        "headers": "From: no-reply@accounts.google.com"
    },
    {
        "name": "ICICI awareness",
        "text": "ICICI Bank safety tip: Never share your OTP or password with anyone, even bank officials. Stay safe.",
        "headers": "From: alerts@icicibank.com"
    },
    {
        "name": "OTP short",
        "text": "Verify account now: send OTP to 9988776655 immediately for refund.",
        "headers": "From: support@hdfc-verify.com"
    },
    {
        "name": "BEC",
        "text": "Urgent wire transfer needed for vendor payment. Discuss details on call later. Release today.",
        "headers": "From: ceo@company.com"
    },
    {
        "name": "Phishing link",
        "text": "Your Netflix account is suspended. Update payment now: http://netflix-update.xyz/login",
        "headers": "From: billing@netflix.com"
    },
    {
        "name": "Mixed",
        "text": "Check your official Amazon orders at http://amazon.in. Also verify your prime bonus here: http://amazon-bonus.tk/claim",
        "headers": "From: info@amazon.in"
    },
    {
        "name": "Normal email",
        "text": "Hi Team, let's meet at 5 PM today for the project sync. Thanks.",
        "headers": "From: colleague@work.com"
    }
]

print("="*80)
print(f"{'TEST CASE':<25} | {'VERDICT':<10} | {'SCORE':<5} | {'TRUST':<5} | {'SIGNAL COUNT'}")
print("-" * 80)

for case in test_cases:
    res = calculate_email_risk(case['text'], headers_text=case['headers'])
    name = case['name']
    verdict = res['verdict']
    score = res['risk_score']
    trust = res['trust_score']
    signals = len(res.get('signals', []))
    
    noisy = []
    if verdict == 'Safe':
        forbidden = ["authenticity", "urgent", "sensitive", "impersonation"]
        for s in res.get('signals', []):
            if any(f in s.lower() for f in forbidden):
                noisy.append(s)
    
    noisy_str = f" (Noisy: {noisy})" if noisy else ""
    print(f"{name:<25} | {verdict:<10} | {score:<5} | {trust:<5} | {signals}{noisy_str}")
    
    # Print Top Words
    top_words = [tw['word'] for tw in res.get('explanation', {}).get('top_words', [])]
    if top_words:
        print(f"   - Top Words: {top_words}")
    
    # Print Links
    exp_links = res.get('explanation', {}).get('links', {})
    if exp_links.get('trusted') or exp_links.get('suspicious'):
        print(f"   - Links: {exp_links}")

print("="*80)
