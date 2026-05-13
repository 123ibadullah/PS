import { Router, type IRouter } from "express";

const router: IRouter = Router();

const SUSPICIOUS_TLDS = [
  ".xyz",
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".pw",
  ".top",
  ".club",
  ".online",
  ".site",
  ".icu",
  ".work",
  ".loan",
  ".click",
  ".link",
  ".biz",
];

const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "short.io",
  "rebrand.ly",
  "cutt.ly",
  "tiny.cc",
  "bl.ink",
  "clk.sh",
  "is.gd",
  "v.gd",
];

const BRAND_SHORTENERS = ["c.gle", "lnkd.in"];

const LOOKALIKE_PATTERNS: [RegExp, string][] = [
  [/paypa[l1]|payp4l/i, "PayPal lookalike domain"],
  [/g00gle|g0ogle|gooogle/i, "Google lookalike domain"],
  [/amaz0n|am4zon|amazzon/i, "Amazon lookalike domain"],
  [/faceb00k|f4cebook|faceb0ok/i, "Facebook lookalike domain"],
  [/sb[i1]-|sb[i1]\.|sbi-online|sbi_online/i, "SBI lookalike domain"],
  [/hdf[c0]-|hdfcbank-/i, "HDFC lookalike domain"],
  [/icic[i1]-|icicibankk/i, "ICICI lookalike domain"],
  [/payt[m0]-|paytrn/i, "Paytm lookalike domain"],
  [/ph0nepe|phonep3/i, "PhonePe lookalike domain"],
  [/[a-z]+-secure-|secure-[a-z]+\./i, "Fake 'secure' domain pattern"],
  [/[a-z]+-update\./i, "Fake 'update' domain pattern"],
  [/[a-z]+-verify\./i, "Fake 'verify' domain pattern"],
  [/[a-z]+-alert\./i, "Fake 'alert' domain pattern"],
  [/[a-z]+-kyc\./i, "Fake 'KYC' domain pattern"],
  [/[a-z]+-reward\./i, "Fake 'reward' domain pattern"],
  [/[a-z]+-claim\./i, "Fake 'claim' domain pattern"],
];

const INDIA_BANKS = [
  "sbi",
  "hdfc",
  "icici",
  "axisbank",
  "pnb",
  "kotak",
  "yesbank",
  "indusind",
  "bankofbaroda",
  "canarabank",
  "unionbank",
];

const INDIA_SERVICES = [
  "paytm",
  "phonepe",
  "gpay",
  "bhimupi",
  "irctc",
  "uidai",
  "aadhaar",
  "incometax",
  "epfo",
  "nsdl",
  "cibil",
];

function extractDomain(url: string): string {
  try {
    const normalized = url.startsWith("http") ? url : "https://" + url;
    return new URL(normalized).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase() : url;
  }
}

router.post("/check-url", (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string" || url.trim().length === 0) {
      res
        .status(400)
        .json({
          error: "url_required",
          message: "Please provide a valid URL string.",
        });
      return;
    }

    const domain = extractDomain(url.trim());
    const flags: string[] = [];
    const reasons: string[] = [];
    let score = 0;

    const tld = "." + domain.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      flags.push(`Suspicious TLD: ${tld}`);
      reasons.push(
        `This site uses the "${tld}" domain, which is commonly associated with phishing and spam.`,
      );
      score += 30;
    }

    if (URL_SHORTENERS.some((s) => domain.includes(s))) {
      flags.push("URL shortener detected");
      reasons.push(
        "A link shortener hides the real destination — the site you end up at could be anything.",
      );
      score += 25;
    } else if (BRAND_SHORTENERS.some((s) => domain.includes(s))) {
      flags.push("Official brand shortener detected");
      reasons.push("This is an official shortener used by a trusted brand, but still masks the final destination.");
      score += 5;
    }

    let lookalikMatched = false;
    for (const [pattern, label] of LOOKALIKE_PATTERNS) {
      if (pattern.test(domain)) {
        flags.push(label);
        reasons.push(
          `"${domain}" is imitating a trusted brand (${label}). This is a classic phishing tactic.`,
        );
        score += 45;
        lookalikMatched = true;
        break;
      }
    }

    if (domain.split(".").length > 3) {
      flags.push("Complex subdomain structure");
      reasons.push(
        "Fake sites often nest themselves deep in subdomains to look like part of a real website.",
      );
      score += 15;
    }

    if (/[0-9]/.test(domain.split(".")[0])) {
      flags.push("Numbers in domain name");
      reasons.push(
        "Legitimate brands rarely put numbers in their domain name. This is a common sign of a spoofed site.",
      );
      score += 10;
    }

    if (url.length > 100) {
      flags.push("Unusually long URL");
      reasons.push(
        "Phishing links are often deliberately long and complex to discourage inspection.",
      );
      score += 10;
    }

    if (/token=|session=|verify=|otp=|password=|pin=/i.test(url)) {
      flags.push("Sensitive parameters in URL");
      reasons.push(
        "The URL contains sensitive fields (like OTP, token, or password) passed as parameters — a red flag for credential theft.",
      );
      score += 20;
    }

    if (
      /secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(
        domain,
      )
    ) {
      flags.push("Deceptive keyword in domain");
      reasons.push(
        `The domain uses a word like "secure", "login", or "kyc" to appear trustworthy. Real banks don't need to do this.`,
      );
      score += 15;
    }

    // Indian banking/payment context
    const domainStripped = domain.toLowerCase().replace(/[-_.]/g, "");
    const matchedBank = INDIA_BANKS.find((b) => domainStripped.includes(b));
    const matchedService = INDIA_SERVICES.find((s) =>
      domainStripped.includes(s),
    );
    const isIndianBankingRelated = !!(matchedBank || matchedService);

    // Only flag banking impersonation when there are already other risk signals
    if (isIndianBankingRelated && score > 15) {
      const brandName =
        matchedBank?.toUpperCase() ?? matchedService?.toUpperCase();
      reasons.push(
        matchedBank
          ? `This looks like a fake ${brandName} banking page. Real banks will NEVER ask for your OTP, PIN, or password through a link.`
          : `This appears to impersonate ${brandName}. Never enter your UPI PIN, Aadhaar, or PAN details on suspicious sites.`,
      );
      score = Math.min(score + 20, 100);
    }

    const finalScore = Math.min(score, 100);
    const classification =
      finalScore >= 71 ? "phishing" : finalScore >= 31 ? "suspicious" : "safe";

    // Highlight the suspicious parts of the URL for the extension UI
    const suspiciousParts: { part: string; reason: string }[] = [];
    if (SUSPICIOUS_TLDS.includes(tld)) {
      suspiciousParts.push({ part: tld, reason: "Suspicious TLD" });
    }
    if (lookalikMatched) {
      suspiciousParts.push({ part: domain, reason: "Lookalike domain" });
    }
    if (
      /secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(
        domain,
      )
    ) {
      const match = domain.match(
        /secure|login|verify|account|update|confirm|kyc|claim|reward/i,
      );
      if (match)
        suspiciousParts.push({ part: match[0], reason: "Deceptive keyword" });
    }

    res.json({
      url,
      domain,
      riskScore: finalScore,
      classification,
      flags,
      reasons,
      isIndianBankingRelated,
      suspiciousParts,
    });
  } catch (err) {
    console.error("Error in /check-url:", err);
    res
      .status(500)
      .json({
        error: "check_failed",
        message: "URL check failed. Please try again.",
      });
  }
});

export default router;
