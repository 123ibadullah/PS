export const HIGH_RISK_TLDS = [
  ".tk",
  ".xyz",
  ".ml",
  ".cf",
  ".gq",
  ".ga",
  ".top",
  ".click",
  ".work",
] as const;

export const TRUSTED_BRAND_DOMAIN_MAP: Record<string, string[]> = {
  amazon: ["amazon.in", "amazon.com", "amazon.co.uk", "amazonaws.com", "amazonses.com"],
  hdfc: ["hdfcbank.com"],
  sbi: ["sbi.co.in"],
  google: ["accounts.google.com", "google.com", "pay.google.com", "googleapis.com"],
  incometax: ["incometax.gov.in"],
  microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"],
  paytm: ["paytm.com", "paytm.in"],
  phonepe: ["phonepe.com"],
  icici: ["icicibank.com"],
  netflix: ["netflix.com", "mailer.netflix.com"],
  linkedin: ["linkedin.com"],
  irctc: ["irctc.co.in"],
};

const BRAND_PATTERNS: Array<{ brand: string; pattern: RegExp }> = [
  { brand: "amazon", pattern: /\bamazon\b/i },
  { brand: "hdfc", pattern: /\bhdfc\b/i },
  { brand: "sbi", pattern: /\b(?:sbi|state bank of india)\b/i },
  { brand: "google", pattern: /\b(?:google|gmail|google pay|gpay)\b/i },
  { brand: "incometax", pattern: /\b(?:income tax|incometax|itr|refund)\b/i },
  { brand: "microsoft", pattern: /\b(?:microsoft|office 365|outlook|sharepoint)\b/i },
  { brand: "paytm", pattern: /\bpaytm\b/i },
  { brand: "phonepe", pattern: /\bphonepe\b/i },
  { brand: "icici", pattern: /\bicici\b/i },
  { brand: "netflix", pattern: /\bnetflix\b/i },
  { brand: "linkedin", pattern: /\blinkedin\b/i },
  { brand: "irctc", pattern: /\birctc\b/i },
];

export function normalizeDomainForComparison(value: string): string {
  return String(value || "")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/0/g, "o")
    .replace(/[1!|]/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/_/g, "-")
    .trim();
}

export function hasRiskyTld(domain: string): boolean {
  const normalized = normalizeDomainForComparison(domain);
  return HIGH_RISK_TLDS.some((tld) => normalized.endsWith(tld));
}

export function isDomainTrustedForBrand(domain: string, brand?: string | null): boolean {
  const normalizedDomain = normalizeDomainForComparison(domain);
  const trustedDomains = brand ? TRUSTED_BRAND_DOMAIN_MAP[brand] ?? [] : [];
  return trustedDomains.some(
    (trusted) =>
      normalizedDomain === trusted || normalizedDomain.endsWith(`.${trusted}`),
  );
}

export function detectBrandFromText(text: string, domains: string[] = []): string | null {
  const haystack = `${text}\n${domains.join("\n")}`;
  const normalizedHaystack = normalizeDomainForComparison(haystack);

  for (const { brand, pattern } of BRAND_PATTERNS) {
    if (pattern.test(haystack) || normalizedHaystack.includes(brand)) {
      return brand;
    }
  }

  return null;
}

export function domainMatchesAnyTrustedBrand(domain: string): boolean {
  const normalizedDomain = normalizeDomainForComparison(domain);
  return Object.values(TRUSTED_BRAND_DOMAIN_MAP).some((trustedDomains) =>
    trustedDomains.some(
      (trusted) =>
        normalizedDomain === trusted || normalizedDomain.endsWith(`.${trusted}`),
    ),
  );
}

export function areDomainsSameFamily(left: string, right: string): boolean {
  const normalizedLeft = normalizeDomainForComparison(left);
  const normalizedRight = normalizeDomainForComparison(right);

  if (!normalizedLeft || !normalizedRight) return false;
  return (
    normalizedLeft === normalizedRight ||
    normalizedLeft.endsWith(`.${normalizedRight}`) ||
    normalizedRight.endsWith(`.${normalizedLeft}`)
  );
}
