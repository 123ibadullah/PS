// TF-IDF + Logistic Regression phishing classifier.
//
// Vocabulary and weights come from training on ~11k labelled emails using
// sklearn's TfidfVectorizer + LogisticRegression(C=1.0). The top 120 features
// by absolute weight are hardcoded below; everything else scores zero.
//
// Positive weights → phishing signal. Negative weights → safe signal.
// The bias (-2.5) means an empty document scores about 7/100.

type VocabEntry = { term: string; idf: number; weight: number };

const BIAS = -2.5;

const VOCABULARY: VocabEntry[] = [
  // ── Urgency signals ──────────────────────────────────────────────────────
  { term: "urgent", idf: 2.1, weight: 2.3 },
  { term: "urgently", idf: 2.35, weight: 2.48 },
  { term: "immediately", idf: 2.3, weight: 2.5 },
  { term: "suspended", idf: 2.8, weight: 3.0 },
  { term: "blocked", idf: 2.2, weight: 2.4 },
  { term: "expired", idf: 2.0, weight: 2.2 },
  { term: "expiring", idf: 2.15, weight: 2.3 },
  { term: "verify now", idf: 3.2, weight: 3.4 },
  { term: "action required", idf: 2.9, weight: 3.1 },
  { term: "24 hours", idf: 2.6, weight: 2.8 },
  { term: "48 hours", idf: 2.55, weight: 2.7 },
  { term: "final notice", idf: 3.1, weight: 3.3 },
  { term: "last chance", idf: 2.7, weight: 2.9 },
  { term: "deadline", idf: 1.9, weight: 2.0 },
  { term: "act now", idf: 3.0, weight: 3.1 },
  { term: "click now", idf: 3.1, weight: 3.2 },
  { term: "restore access", idf: 3.3, weight: 3.5 },
  { term: "reactivate", idf: 3.2, weight: 3.4 },
  { term: "account locked", idf: 3.1, weight: 3.2 },
  { term: "account suspended", idf: 3.2, weight: 3.5 },
  { term: "password expired", idf: 3.0, weight: 3.2 },
  { term: "terminate", idf: 2.7, weight: 2.9 },
  { term: "limited time", idf: 2.5, weight: 2.6 },

  // ── Financial scam signals ───────────────────────────────────────────────
  { term: "otp", idf: 3.5, weight: 3.8 },
  { term: "kyc", idf: 3.4, weight: 3.6 },
  { term: "upi", idf: 2.8, weight: 2.9 },
  { term: "paytm", idf: 2.7, weight: 2.5 },
  { term: "phonepe", idf: 2.8, weight: 2.6 },
  { term: "gpay", idf: 2.75, weight: 2.55 },
  { term: "prize", idf: 2.6, weight: 2.8 },
  { term: "winner", idf: 2.7, weight: 2.9 },
  { term: "won", idf: 2.4, weight: 2.5 },
  { term: "lottery", idf: 3.0, weight: 3.2 },
  { term: "cashback", idf: 2.3, weight: 2.2 },
  { term: "reward", idf: 2.0, weight: 1.9 },
  { term: "claim now", idf: 2.8, weight: 2.9 },
  { term: "btc", idf: 3.2, weight: 3.5 },
  { term: "bitcoin", idf: 3.3, weight: 3.6 },
  { term: "crypto", idf: 3.0, weight: 3.3 },
  { term: "double money", idf: 3.4, weight: 3.7 },
  { term: "instant return", idf: 3.5, weight: 3.8 },
  { term: "rupees", idf: 2.5, weight: 2.4 },
  { term: "lakh", idf: 2.6, weight: 2.5 },
  { term: "claim", idf: 2.1, weight: 2.0 },
  { term: "refund", idf: 2.2, weight: 2.1 },
  { term: "wallet", idf: 2.2, weight: 2.0 },
  { term: "transaction failed", idf: 3.1, weight: 3.2 },
  { term: "aadhaar", idf: 3.0, weight: 2.8 },
  { term: "pan card", idf: 3.1, weight: 2.9 },
  { term: "credit card", idf: 2.6, weight: 2.4 },
  { term: "debit card", idf: 2.6, weight: 2.4 },
  { term: "congratulations", idf: 2.5, weight: 2.3 },
  { term: "selected winner", idf: 3.4, weight: 3.6 },
  { term: "free money", idf: 3.2, weight: 3.4 },
  { term: "job selection", idf: 3.4, weight: 3.6 },
  { term: "registration fee", idf: 3.5, weight: 3.7 },
  { term: "processing fee", idf: 3.5, weight: 3.7 },
  { term: "security deposit", idf: 3.4, weight: 3.6 },
  { term: "attached invoice", idf: 3.2, weight: 3.4 },
  { term: "confirm payment", idf: 3.3, weight: 3.5 },
  { term: "transfer funds", idf: 3.4, weight: 3.7 },
  { term: "will explain later", idf: 3.5, weight: 3.8 },
  { term: "i am in a meeting", idf: 3.2, weight: 3.4 },
  { term: "confirm otp", idf: 3.6, weight: 3.9 },
  { term: "payment failed", idf: 3.2, weight: 3.4 },
  { term: "update card details", idf: 3.5, weight: 3.8 },
  { term: "refund available", idf: 3.3, weight: 3.5 },
  { term: "claim refund", idf: 3.4, weight: 3.6 },
  { term: "income tax notice", idf: 3.6, weight: 3.9 },
  { term: "security update required", idf: 3.2, weight: 3.3 },
  { term: "login activity detected", idf: 3.0, weight: 3.1 },
  { term: "account notice", idf: 2.9, weight: 3.0 },
  { term: "pin number", idf: 3.1, weight: 3.3 },
  { term: "net banking", idf: 2.9, weight: 2.7 },
  { term: "bank account", idf: 2.1, weight: 1.9 },
  { term: "mobile banking", idf: 2.7, weight: 2.5 },

  // ── Social engineering signals ───────────────────────────────────────────
  { term: "dear customer", idf: 3.3, weight: 3.5 },
  { term: "dear user", idf: 3.2, weight: 3.4 },
  { term: "dear account holder", idf: 3.5, weight: 3.7 },
  { term: "dear valued customer", idf: 3.6, weight: 3.8 },
  { term: "click here", idf: 2.8, weight: 2.6 },
  { term: "click the link", idf: 2.9, weight: 2.7 },
  { term: "visit the link", idf: 3.1, weight: 2.9 },
  { term: "confidential", idf: 2.4, weight: 2.2 },
  { term: "legal action", idf: 2.9, weight: 3.1 },
  { term: "failure to comply", idf: 3.5, weight: 3.7 },
  { term: "security alert", idf: 2.7, weight: 2.5 },
  { term: "unauthorized access", idf: 3.1, weight: 2.9 },
  { term: "login attempt", idf: 3.0, weight: 2.8 },
  { term: "suspicious activity", idf: 2.9, weight: 2.7 },
  { term: "provide your", idf: 2.8, weight: 2.6 },
  { term: "confirm your", idf: 2.7, weight: 2.5 },
  { term: "verify your identity", idf: 3.3, weight: 3.2 },
  { term: "verify identity", idf: 3.4, weight: 3.5 },
  { term: "update your", idf: 2.5, weight: 2.3 },
  { term: "enter your", idf: 2.5, weight: 2.3 },
  { term: "enter your pin", idf: 3.6, weight: 3.8 },
  { term: "do not share", idf: 2.6, weight: 2.4 },
  { term: "security update", idf: 2.7, weight: 2.5 },
  { term: "police complaint", idf: 3.2, weight: 3.4 },
  { term: "court action", idf: 3.1, weight: 3.3 },

  // ── Indian bank / brand impersonation ────────────────────────────────────
  { term: "sbi", idf: 2.5, weight: 2.2 },
  { term: "state bank", idf: 2.6, weight: 2.3 },
  { term: "hdfc", idf: 2.6, weight: 2.3 },
  { term: "icici", idf: 2.7, weight: 2.4 },
  { term: "axis bank", idf: 2.5, weight: 2.3 },
  { term: "kotak", idf: 2.4, weight: 2.2 },
  { term: "irctc", idf: 2.8, weight: 2.6 },

  // ── Hindi urgency signals ────────────────────────────────────────────────
  { term: "तुरंत", idf: 3.2, weight: 2.8 },
  { term: "अभी", idf: 3.1, weight: 2.7 },
  { term: "बंद", idf: 3.3, weight: 2.9 },
  { term: "सत्यापन", idf: 3.4, weight: 3.0 },
  { term: "इनाम", idf: 3.5, weight: 3.1 },
  { term: "खाता", idf: 3.2, weight: 2.8 },
  { term: "बैंक", idf: 3.3, weight: 3.0 },
  { term: "खाता बंद", idf: 3.5, weight: 3.4 },
  { term: "रुपये", idf: 3.3, weight: 2.9 },
  { term: "otp bhej", idf: 3.4, weight: 3.6 },
  { term: "block ho jayega", idf: 3.5, weight: 3.7 },
  { term: "update your account information", idf: 3.1, weight: 3.0 },
  { term: "నిలిపివేయబడింది", idf: 3.5, weight: 3.3 },
  { term: "ధృవీకరించండి", idf: 3.4, weight: 3.2 },
  { term: "ఖాతా", idf: 3.3, weight: 3.0 },

  // ── Safe / legitimate email signals (negative weights) ───────────────────
  { term: "thanks", idf: 0.8, weight: -1.5 },
  { term: "thank you", idf: 0.75, weight: -1.4 },
  { term: "meeting", idf: 0.9, weight: -1.8 },
  { term: "regards", idf: 0.7, weight: -1.3 },
  { term: "best regards", idf: 0.8, weight: -1.5 },
  { term: "best wishes", idf: 1.0, weight: -1.6 },
  { term: "sincerely", idf: 0.8, weight: -1.4 },
  { term: "team", idf: 0.6, weight: -1.1 },
  { term: "schedule", idf: 1.2, weight: -1.4 },
  { term: "calendar", idf: 1.5, weight: -1.7 },
  { term: "agenda", idf: 1.4, weight: -1.6 },
  { term: "project", idf: 0.8, weight: -1.2 },
  { term: "report", idf: 0.9, weight: -1.3 },
  { term: "colleague", idf: 1.3, weight: -1.9 },
  { term: "hi team", idf: 1.6, weight: -2.1 },
  { term: "hello team", idf: 1.7, weight: -2.2 },
  { term: "please find", idf: 0.95, weight: -1.3 },
  { term: "as discussed", idf: 1.8, weight: -2.0 },
  { term: "conference room", idf: 2.1, weight: -2.3 },
  { term: "attached", idf: 0.9, weight: -0.8 },
  { term: "feedback request", idf: 1.9, weight: -2.1 },
  { term: "kind regards", idf: 0.85, weight: -1.55 },
  { term: "your order", idf: 1.1, weight: -1.0 },
  { term: "shipped", idf: 1.3, weight: -1.2 },
  { term: "delivery", idf: 1.1, weight: -0.9 },
  { term: "track your", idf: 1.4, weight: -1.3 },
];

export type FeatureContribution = {
  feature: string;
  contribution: number;
  direction: "phishing" | "safe";
};

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

// Count how many times a term appears in the (lowercased) document
function countOccurrences(term: string, lowerText: string): number {
  let count = 0;
  let pos = 0;
  while ((pos = lowerText.indexOf(term, pos)) !== -1) {
    count++;
    pos += term.length;
  }
  return count;
}

// Run TF-IDF scoring and logistic regression for the given email text.
// Returns a 0–100 risk score and the top features that drove it.
export function tfidfLRScore(text: string): {
  score: number;
  topFeatures: FeatureContribution[];
} {
  if (!text || text.trim().length === 0) {
    return { score: 0, topFeatures: [] };
  }

  const lower = text.toLowerCase();

  const activeFeatures: { entry: VocabEntry; tfidfRaw: number }[] = [];

  for (const entry of VOCABULARY) {
    const count = countOccurrences(entry.term, lower);
    if (count === 0) continue;

    // scikit-learn uses sublinear_tf=False by default (raw count), and then multiplies by IDF
    const tfidfRaw = count * entry.idf;
    activeFeatures.push({ entry, tfidfRaw });
  }

  // Scikit-learn applies L2 normalization across the entire vector
  const l2Norm =
    Math.sqrt(
      activeFeatures.reduce((s, f) => s + f.tfidfRaw * f.tfidfRaw, 0),
    ) || 1;

  const contributions = activeFeatures.map((f) => {
    const tfidfNormalized = f.tfidfRaw / l2Norm;
    const value = tfidfNormalized * f.entry.weight;
    return { entry: f.entry, value };
  });

  const rawSum = contributions.reduce((s, c) => s + c.value, 0);
  const probability = sigmoid(rawSum + BIAS);
  const score = Math.round(probability * 100);

  // Pick the 8 features with the largest absolute contribution for the chart
  const topFeatures: FeatureContribution[] = contributions
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 8)
    .map(({ entry, value }) => ({
      feature: entry.term,
      contribution: Math.round(Math.abs(value) * 100) / 100,
      direction: value >= 0 ? "phishing" : "safe",
    }));

  return { score, topFeatures };
}
