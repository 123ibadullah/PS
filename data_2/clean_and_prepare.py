"""
Phase 1: Clean FINAL_ELITE_DATASET.raw.json and prepare all datasets for testing.

This script:
1. Cleans FINAL_ELITE_DATASET.raw.json - fixes wrong labels, removes SMS/chat noise,
   keeps only email-like content, removes duplicates
2. Parses real_gmail.txt into structured test cases  
3. Loads phishtank_dataset.json as-is
4. Outputs: cleaned_elite_dataset.json, gmail_dataset.json, combined_test_dataset.json
"""

import json
import re
import os
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent

# ---- Helpers ----

def is_sms_or_chat(text: str) -> bool:
    """Aggressively detect SMS/chat-style messages that are NOT emails.
    
    PhishShield is an EMAIL scanner. Any text lacking email structure 
    (headers, from/to, URLs, formal signatures) should be excluded.
    """
    text_lower = text.lower().strip()
    word_count = len(text_lower.split())
    
    # Very short messages are always SMS/chat
    if word_count < 10:
        return True
    
    # Email structure indicators - things that make something look like an email
    email_structure_indicators = [
        r'(from|to|subject|date|reply-to|mailed-by|signed by):\s*\S',  # email headers
        r'(dear\s+\w+|hi\s+\w+,|hello\s+\w+,)',  # formal email greetings
        r'(regards,|sincerely,|best wishes,|best regards|kind regards)',  # email closings
        r'(unsubscribe|privacy policy|terms\s*(and|&)\s*conditions|terms apply)',  # email footer
        r'https?://\S{10,}',  # URLs (at least 10 chars)
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # proper email addresses
        r'\b(account|password|verify|click here|log\s*in|sign\s*in)\b',  # email action words
        r'\b(invoice|receipt|order|confirmation|payment|transaction)\b',  # transactional
        r'\b(notification|alert|update|reminder|notice)\b',  # notification style
        r'(copyright|©|\d{4}\s+\w+\s+(inc|llc|ltd|corp))',  # corporate footer
    ]
    
    email_score = sum(1 for p in email_structure_indicators 
                      if re.search(p, text_lower, re.IGNORECASE))
    
    # For texts under 60 words without ANY email structure, it's SMS/chat
    # Even if it has phishing-like words — PhishShield is an EMAIL scanner,
    # not an SMS scanner. SMS phishing (smishing) is a different problem.
    if word_count < 60 and email_score == 0:
        return True
    
    # SMS/chat specific patterns
    sms_patterns = [
        r'\b\d{3}p\s*(per|/)\s*(min|msg|message)\b',  # pricing
        r'\b(lol|omg|brb|ttyl|idk|tbh|nvm|smh)\b',  # chat slang
        r'\b(haha|hehe|lmao|rofl)\b',  # laughing
        r'\b(bro|dude|fam|homie)\b',  # chat address
        r'\b(wanna|gonna|gotta|lemme|gimme|ima|imma)\b',  # text speak
        r'\b(lor|leh|hor|lah|meh|sia)\b',  # Singlish particles
    ]
    sms_score = sum(1 for p in sms_patterns if re.search(p, text_lower))
    
    if word_count < 40 and sms_score >= 1 and email_score == 0:
        return True
    
    return False


def fix_label(text: str, label: str) -> str:
    """Fix obviously wrong labels using heuristic analysis."""
    text_lower = text.lower().strip()
    
    # ---- SMS premium/scam that should ALWAYS be "phishing" ----
    sms_scam_indicators = [
        r'\b(txt|text)\s+\w+\s+to\s+\d{4,6}\b',  # "txt CHAT to 86688"
        r'\b\d{3}p\s*(per|/)\s*(msg|min|message|txt)\b',  # "150p/msg"
        r'\bcall\s+(now\s+)?0[89]\d{8,}\b',  # premium rate numbers
        r'\b(txt|text)\s+(stop|end|quit)\s+\w*\s*to\s+\d{4,5}\b',  # "txt stop to 12345"
        r'\bfreephone\s+0800\b',  # freephone scam
        r'\b(ringtone|polyphonic|caller\s*tune)\b.*\b(free|order)\b',  # ringtone scam
        r'\bwap\.\w+\.com\b',  # WAP site scams
        r'\b18\+\b.*\b(xxx|sex|adult|naked)\b',  # adult SMS scam
        r'\b(xxx|sex|naked|adult)\b.*\b18\+\b',  # adult SMS scam reverse
        r'\b(txt|text)\s+\w+\s*to\s*\d{5}\b',  # short code scam
        r'\bwin\s+(vip\s+)?tickets\b',  # win tickets scam
        r'\bclaim\s*a?\s*\d+\s*(shopping|cash|pound|dollar|\$|gbp)\b',  # "claim a 200 shopping spree"
        r'\b(missed\s+call\s+alert|voicemail)\b.*\b0\d{9,}\b',  # missed call scam
    ]
    
    sms_scam_score = sum(1 for p in sms_scam_indicators 
                         if re.search(p, text_lower, re.IGNORECASE))
    
    if sms_scam_score >= 1:
        return "phishing"  # SMS scams are phishing regardless of original label
    
    # ---- Items labeled "phishing" that are actually SAFE ----
    safe_false_positives = [
        # Casual conversation / personal messages
        r'^(yeah|yes|no|ok|okay|sure|fine|cool|nice|great|good)[\s.,!?]',
        r"^(i'll|i will|i am|i'm|i think|i hope|i love|i want|i miss|i need)\b",
        r'^(have a lovely|have a great|good morning|good night)\b',
        r'^(he\'s really|she\'s really|they\'re really|it\'s fine)\b',
        r'^(do you realize|do you ever notice|do you want)\b',
        r'^(where are you|when are you|what time|how long)\b',
        r'^(sorry|hello|hey|hi |hmm|huh|oh|ah|wow|lol)\b',
        r'^(the wine|the evo|said kiss|bloody hell)\b',
        r'\b(I\'m going to try|just joking|see you tomorrow)\b',
        r'\b(merry christmas|happy new year|happy birthday)\b',
        # Additional conversational patterns
        r'^(sir|madam|dear),?\s',  # Polite address without phishing context
        r'^(perhaps|maybe|probably)\b',  # Tentative language
        r'\b(xmas|christmas|tree burning|stars here)\b',  # Holiday talk
        r'\b(dad fetching|mom|mum|brother|sister)\b.*\b(home|now|here)\b',  # Family talk
        r'^(when|where|what|how|why)\b.*\b(login|dat time|fetching)\b',  # Chat questions
        r'\b(you will receive|you will get)\b.*\b(sorry for the delay)\b',  # Business courtesy
        r'\b(great .* update|can totally see)\b',  # Update/observation
    ]
    
    if label == "phishing":
        for pattern in safe_false_positives:
            if re.search(pattern, text_lower, re.IGNORECASE):
                # Double-check: does it ALSO have STRONG phishing indicators?
                phishing_indicators = [
                    r'\b(verify|suspended|blocked|account locked|claim|prize|winner|won)\b',
                    r'\bcall\s+\d{8,}\b',
                    r'\b(otp|pin|password|passcode)\b.*\b(share|send|enter)\b',
                    r'https?://\S*(verify|login|secure|update|claim)\S*',
                    r'\b(txt|text)\s+\w+\s+to\s+\d{4,5}\b',  # SMS premium
                ]
                has_phishing = any(re.search(p, text_lower) for p in phishing_indicators)
                if not has_phishing:
                    return "safe"
    
    # ---- Items labeled "safe" that are actually PHISHING ----
    phishing_indicators_strong = [
        r'\b(you have won|you\'ve won|congratulations.*prize|awarded.*\d+)\b',
        r'\bcall\s+(now\s+)?0[89]\d{8,}\b',  # premium numbers
        r'\b(claim|collect).*\b(prize|award|cash|gift)\b',
        r'\b(txt|text)\s+\w+\s+to\s+\d{4,5}\b',  # SMS premium
        r'\baccount.*\b(suspend|block|lock|verify immediately)\b',
        r'\b(share|send|provide).*\b(otp|pin|password|banking)\b',
    ]
    
    if label == "safe":
        phish_score = sum(1 for p in phishing_indicators_strong if re.search(p, text_lower))
        if phish_score >= 1:  # lowered from 2 to 1 -- any strong indicator is enough
            return "phishing"
    
    return label


def text_hash(text: str) -> str:
    """Create a hash for dedup."""
    normalized = re.sub(r'\s+', ' ', text.lower().strip())
    return hashlib.md5(normalized.encode()).hexdigest()


# ---- Phase 1: Clean FINAL_ELITE_DATASET ----
print("=" * 60)
print("PHASE 1: Cleaning FINAL_ELITE_DATASET.raw.json")
print("=" * 60)

raw_path = ROOT / "FINAL_ELITE_DATASET.raw.json"
if not raw_path.exists():
    print(f"ERROR: {raw_path} not found!")
    exit(1)

with open(raw_path, 'r', encoding='utf-8') as f:
    raw_data = json.load(f)

print(f"Raw entries: {len(raw_data)}")

# Stats tracking
stats = {
    "total_raw": len(raw_data),
    "removed_sms_chat": 0,
    "label_fixed_to_safe": 0,
    "label_fixed_to_phishing": 0,
    "duplicates_removed": 0,
    "empty_removed": 0,
}

seen_hashes = set()
cleaned = []

for item in raw_data:
    text = str(item.get("text", "")).strip()
    label = str(item.get("label", "")).strip().lower()
    
    # Skip empty
    if not text or len(text) < 5:
        stats["empty_removed"] += 1
        continue
    
    # Normalize label
    if label not in ("safe", "phishing"):
        label = "safe" if label in ("ham", "legitimate", "benign") else "phishing"
    
    # Remove SMS/chat noise  
    if is_sms_or_chat(text):
        stats["removed_sms_chat"] += 1
        continue
    
    # Fix wrong labels
    new_label = fix_label(text, label)
    if new_label != label:
        if new_label == "safe":
            stats["label_fixed_to_safe"] += 1
        else:
            stats["label_fixed_to_phishing"] += 1
        label = new_label
    
    # Dedup
    h = text_hash(text)
    if h in seen_hashes:
        stats["duplicates_removed"] += 1
        continue
    seen_hashes.add(h)
    
    cleaned.append({"text": text, "label": label})

# Check balance
safe_count = sum(1 for x in cleaned if x["label"] == "safe")
phish_count = sum(1 for x in cleaned if x["label"] == "phishing")

print(f"\nCleaning Results:")
print(f"  Removed SMS/chat:        {stats['removed_sms_chat']}")
print(f"  Label fixed -> safe:      {stats['label_fixed_to_safe']}")
print(f"  Label fixed -> phishing:  {stats['label_fixed_to_phishing']}")
print(f"  Duplicates removed:      {stats['duplicates_removed']}")
print(f"  Empty removed:           {stats['empty_removed']}")
print(f"  Final count:             {len(cleaned)}")
print(f"  Safe:                    {safe_count}")
print(f"  Phishing:                {phish_count}")
print(f"  Balance ratio:           {safe_count/(phish_count+0.001):.2f}")

# Save cleaned
cleaned_path = DATA_DIR / "cleaned_elite_dataset.json"
with open(cleaned_path, 'w', encoding='utf-8') as f:
    json.dump(cleaned, f, indent=2, ensure_ascii=False)
print(f"\nSaved: {cleaned_path}")


# ---- Phase 2: Parse real_gmail.txt ----
print("\n" + "=" * 60)
print("PHASE 2: Parsing real_gmail.txt into structured test cases")
print("=" * 60)

gmail_path = ROOT / "real_gmail.txt"
gmail_text = gmail_path.read_text(encoding='utf-8')

# Split by "Skip to content" markers
email_blocks = re.split(r'Skip to content\s*\n\s*Using Gmail with screen readers', gmail_text)

gmail_dataset = []
for block in email_blocks:
    block = block.strip()
    if not block or len(block) < 50:
        continue
    
    # Extract key fields
    subject_match = re.search(r'subject:\s*(.+)', block, re.IGNORECASE)
    from_match = re.search(r'from:\s*(.+)', block, re.IGNORECASE)
    to_match = re.search(r'to:\s*(.+)', block, re.IGNORECASE)
    mailed_by_match = re.search(r'mailed-by:\s*(.+)', block, re.IGNORECASE)
    signed_by_match = re.search(r'Signed by:\s*(.+)', block, re.IGNORECASE)
    
    subject = subject_match.group(1).strip() if subject_match else ""
    from_addr = from_match.group(1).strip() if from_match else ""
    mailed_by = mailed_by_match.group(1).strip() if mailed_by_match else ""
    signed_by = signed_by_match.group(1).strip() if signed_by_match else ""
    
    # Build email text (the actual content after headers)
    # Find where headers end and body begins
    lines = block.split('\n')
    body_lines = []
    header_done = False
    for line in lines:
        line_stripped = line.strip()
        if header_done:
            body_lines.append(line_stripped)
        elif line_stripped and not re.match(r'^(from|to|subject|date|reply-to|mailed-by|Signed by|security|mailing list|unsubscribe):', line_stripped, re.IGNORECASE):
            if not re.match(r'^\d+ of \d+$', line_stripped) and line_stripped not in ('Inbox', ''):
                header_done = True
                body_lines.append(line_stripped)
    
    body = '\n'.join(body_lines).strip()
    if not body or len(body) < 20:
        continue
    
    # Construct a full email text for the API
    headers_text = ""
    if from_addr:
        headers_text += f"from: {from_addr}\n"
    if subject:
        headers_text += f"subject: {subject}\n"
    if mailed_by:
        headers_text += f"mailed-by: {mailed_by}\n"
    if signed_by:
        headers_text += f"Signed by: {signed_by}\n"
    
    full_email = f"{headers_text}\n{body}" if headers_text else body
    
    gmail_dataset.append({
        "text": full_email,
        "label": "safe",  # All real Gmail inbox emails are legitimate
        "source": "real_gmail",
        "subject": subject,
        "sender": from_addr,
    })

print(f"Parsed {len(gmail_dataset)} emails from real_gmail.txt")

gmail_out_path = DATA_DIR / "gmail_dataset.json"
with open(gmail_out_path, 'w', encoding='utf-8') as f:
    json.dump(gmail_dataset, f, indent=2, ensure_ascii=False)
print(f"Saved: {gmail_out_path}")


# ---- Phase 2B: Parse LAST.TXT (second Gmail inbox) ----
print("\n" + "=" * 60)
print("PHASE 2B: Parsing LAST.TXT into structured test cases")
print("=" * 60)

last_path = ROOT / "LAST.TXT"
last_dataset = []
if last_path.exists():
    last_text = last_path.read_text(encoding='utf-8')
    last_blocks = re.split(r'Skip to content\s*\n\s*Using Gmail with screen readers', last_text)
    
    for block in last_blocks:
        block = block.strip()
        if not block or len(block) < 50:
            continue
        
        # Detect if this is a spam-folder email
        is_spam_folder = bool(re.search(r'in:spam|Why is this message in spam\?', block, re.IGNORECASE))
        
        # Extract key fields
        subject_match = re.search(r'subject:\s*(.+)', block, re.IGNORECASE)
        from_match = re.search(r'from:\s*(.+)', block, re.IGNORECASE)
        mailed_by_match = re.search(r'mailed-by:\s*(.+)', block, re.IGNORECASE)
        signed_by_match = re.search(r'Signed by:\s*(.+)', block, re.IGNORECASE)
        
        subject = subject_match.group(1).strip() if subject_match else ""
        from_addr = from_match.group(1).strip() if from_match else ""
        mailed_by = mailed_by_match.group(1).strip() if mailed_by_match else ""
        signed_by = signed_by_match.group(1).strip() if signed_by_match else ""
        
        lines = block.split('\n')
        body_lines = []
        header_done = False
        for line in lines:
            line_stripped = line.strip()
            if header_done:
                body_lines.append(line_stripped)
            elif line_stripped and not re.match(r'^(from|to|subject|date|reply-to|mailed-by|Signed by|security|mailing list|unsubscribe):', line_stripped, re.IGNORECASE):
                if not re.match(r'^\d+ of [\d,]+$', line_stripped) and line_stripped not in ('Inbox', 'Spam', '', 'None selected'):
                    if not re.match(r'^in:spam$', line_stripped):
                        header_done = True
                        body_lines.append(line_stripped)
        
        body = '\n'.join(body_lines).strip()
        if not body or len(body) < 20:
            continue
        
        headers_text = ""
        if from_addr:
            headers_text += f"from: {from_addr}\n"
        if subject:
            headers_text += f"subject: {subject}\n"
        if mailed_by:
            headers_text += f"mailed-by: {mailed_by}\n"
        if signed_by:
            headers_text += f"Signed by: {signed_by}\n"
        
        full_email = f"{headers_text}\n{body}" if headers_text else body
        
        # Spam folder emails are still "safe" (they're marketing/promotions, not phishing)
        # but we tag them differently for analysis
        last_dataset.append({
            "text": full_email,
            "label": "safe",  
            "source": "last_txt_spam" if is_spam_folder else "last_txt_inbox",
            "subject": subject,
            "sender": from_addr,
        })
    
    print(f"Parsed {len(last_dataset)} emails from LAST.TXT")
    inbox_count = sum(1 for x in last_dataset if x['source'] == 'last_txt_inbox')
    spam_count = sum(1 for x in last_dataset if x['source'] == 'last_txt_spam')
    print(f"  Inbox emails: {inbox_count}")
    print(f"  Spam-folder:  {spam_count}")
    
    last_out_path = DATA_DIR / "last_txt_dataset.json"
    with open(last_out_path, 'w', encoding='utf-8') as f:
        json.dump(last_dataset, f, indent=2, ensure_ascii=False)
    print(f"Saved: {last_out_path}")
else:
    print("LAST.TXT not found, skipping")


# ---- Phase 3: Load phishtank ----
print("\n" + "=" * 60)
print("PHASE 3: Loading phishtank_dataset.json")
print("=" * 60)

phishtank_path = ROOT / "phishtank_dataset.json"
with open(phishtank_path, 'r', encoding='utf-8') as f:
    phishtank_data = json.load(f)

print(f"PhishTank entries: {len(phishtank_data)}")

# Validate all are phishing
for item in phishtank_data:
    item["label"] = "phishing"
    item["source"] = "phishtank"

phishtank_out = DATA_DIR / "phishtank_dataset.json"
with open(phishtank_out, 'w', encoding='utf-8') as f:
    json.dump(phishtank_data, f, indent=2, ensure_ascii=False)


# ---- Phase 4: Build combined test dataset ----
print("\n" + "=" * 60)
print("PHASE 4: Building combined test dataset")
print("=" * 60)

combined = []

# Add cleaned elite (with source tag)
for item in cleaned:
    combined.append({
        "text": item["text"],
        "label": item["label"],
        "source": "elite_cleaned",
    })

# Add Gmail  
for item in gmail_dataset:
    combined.append({
        "text": item["text"],
        "label": item["label"],
        "source": "real_gmail",
    })

# Add LAST.TXT (second Gmail inbox + spam folder)
for item in last_dataset:
    combined.append({
        "text": item["text"],
        "label": item["label"],
        "source": item["source"],
    })

# Add PhishTank
for item in phishtank_data:
    combined.append({
        "text": item["text"],
        "label": "phishing",
        "source": "phishtank",
    })

# Final dedup across combined
final_hashes = set()
final_combined = []
for item in combined:
    h = text_hash(item["text"])
    if h not in final_hashes:
        final_hashes.add(h)
        final_combined.append(item)

safe_total = sum(1 for x in final_combined if x["label"] == "safe")
phish_total = sum(1 for x in final_combined if x["label"] == "phishing")

print(f"\nCombined Dataset Summary:")
print(f"  Total entries:   {len(final_combined)}")
print(f"  Safe:            {safe_total}")
print(f"  Phishing:        {phish_total}")
print(f"  From elite:      {sum(1 for x in final_combined if x['source'] == 'elite_cleaned')}")
print(f"  From Gmail:      {sum(1 for x in final_combined if x['source'] == 'real_gmail')}")
print(f"  From LAST inbox: {sum(1 for x in final_combined if x['source'] == 'last_txt_inbox')}")
print(f"  From LAST spam:  {sum(1 for x in final_combined if x['source'] == 'last_txt_spam')}")
print(f"  From PhishTank:  {sum(1 for x in final_combined if x['source'] == 'phishtank')}")

combined_path = DATA_DIR / "combined_test_dataset.json"
with open(combined_path, 'w', encoding='utf-8') as f:
    json.dump(final_combined, f, indent=2, ensure_ascii=False)

print(f"\nSaved: {combined_path}")
print("\n[OK] DATA PREPARATION COMPLETE")
