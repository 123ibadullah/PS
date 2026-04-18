# Canonical multilingual test cases for PhishShield AI

HINDI_PHISHING_CASES = [
    {
        "name": "hindi_otp_scam",
        "email": "आपका SBI खाता बंद हो जाएगा। अभी OTP शेयर करें: 9876543210",
        "expected_verdict": "phishing",
        "expected_min_risk": 65,
        "language": "HI",
    },
    {
        "name": "hindi_bank_urgency",
        "email": "Subject: अत्यावश्यक\nFrom: alert@sbi-secure.xyz\nआपके खाते में संदिग्ध गतिविधि। तुरंत लिंक पर क्लिक करें।",
        "expected_verdict": "phishing",
        "expected_min_risk": 65,
        "language": "HI",
    },
    {
        "name": "hindi_upi_scam",
        "email": "आपका KYC अपडेट नहीं हुआ। UPI बंद होने से पहले अपना पासवर्ड दर्ज करें।",
        "expected_verdict": "phishing",
        "expected_min_risk": 60,
        "language": "HI",
    },
    {
        "name": "hindi_awareness_safe",
        "email": "Subject: सुरक्षा सूचना\nFrom: alerts@hdfcbank.com\nहम कभी भी ओटीपी नहीं मांगते। अपना ओटीपी किसी को न बताएं।",
        "expected_verdict": "safe",
        "expected_max_risk": 25,
        "language": "HI",
    },
]

TELUGU_PHISHING_CASES = [
    {
        "name": "telugu_otp_scam",
        "email": "మీ HDFC ఖాతా నిలిపివేయబడింది. వెంటనే OTP పంపండి: 9988776655",
        "expected_verdict": "phishing",
        "expected_min_risk": 65,
        "language": "TE",
    },
    {
        "name": "telugu_bank_urgency",
        "email": "Subject: అత్యవసరం\nFrom: support@hdfc-secure.xyz\nమీ పాస్‌వర్డ్ నిర్ధారించండి లేకుంటే ఖాతా మూసివేయబడుతుంది।",
        "expected_verdict": "phishing",
        "expected_min_risk": 60,
        "language": "TE",
    },
    {
        "name": "telugu_awareness_safe",
        "email": "Subject: భద్రతా సూచన\nFrom: alerts@icicibank.com\nమేము ఎప్పుడూ OTP అడగము. OTP ఎవరితోనూ పంచుకోవద్దు.",
        "expected_verdict": "safe",
        "expected_max_risk": 25,
        "language": "TE",
    },
]

HINGLISH_PHISHING_CASES = [
    {
        "name": "hinglish_otp_scam",
        "email": "Aapka account suspend ho gaya hai. Abhi OTP bhejo restore karne ke liye.",
        "expected_verdict": "phishing",
        "expected_min_risk": 65,
        "language": "MX",
    },
    {
        "name": "hinglish_bank_lure",
        "email": "Subject: Urgent\nFrom: noreply@sbi-alert.xyz\nAapke account mein suspicious activity detect hui. Password verify karo abhi.",
        "expected_verdict": "phishing",
        "expected_min_risk": 65,
        "language": "MX",
    },
    {
        "name": "hinglish_safe",
        "email": "Subject: Weekly Update\nFrom: team@company.com\nIs hafte ka project update. Koi action required nahi hai.",
        "expected_verdict": "safe",
        "expected_max_risk": 25,
        "language": "MX",
    },
]
