import { logger } from "./logger.js";

export interface FrontierReviewContext {
  localScore: number;
  urlScore: number;
  headerScore: number;
  suspiciousUrlCount: number;
  spoofingRisk?: string;
  detectedSignals?: string[];
  classification?: "safe" | "uncertain" | "phishing";
}

export interface FrontierReview {
  provider: string;
  model: string;
  score: number;
  confidence: number;
  classification: "safe" | "uncertain" | "phishing";
  finalLabel: "safe" | "uncertain" | "phishing";
  explanation: string;
  riskLevel: "low" | "medium" | "high";
  attackType: string;
  reasons: string[];
}

type FrontierConfig = {
  provider: string;
  model: string;
  url: string;
  headers: Record<string, string>;
  timeoutMs: number;
  mode: "chat" | "native";
};

const reviewCache = new Map<string, FrontierReview>();
const DEFAULT_LLM_FALLBACK_PROMPT =
  "You are a cybersecurity phishing detection expert. Analyze the email and determine if it is phishing. Explain clearly.";

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function parseJsonHeaders(raw?: string): Record<string, string> {
  if (!raw?.trim()) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }

    return Object.fromEntries(
      Object.entries(parsed)
        .filter((entry): entry is [string, string | number | boolean] => Boolean(entry[0]))
        .map(([key, value]) => [key, String(value)]),
    );
  } catch (error) {
    logger.warn("Invalid PHISHSHIELD_LLM_HEADERS_JSON; ignoring custom headers", {
      error: error instanceof Error ? error.message : String(error),
    });
    return {};
  }
}

function getFrontierConfig(): FrontierConfig | null {
  const timeoutMs = Number(
    process.env.PHISHSHIELD_LLM_TIMEOUT_MS ??
      process.env.PHISHSHIELD_FRONTIER_TIMEOUT_MS ??
      "6000",
  );

  const url =
    process.env.PHISHSHIELD_LLM_API_URL ??
    process.env.PHISHSHIELD_FRONTIER_URL ??
    process.env.PHISHSHIELD_LOCAL_MODEL_URL;

  if (!url) {
    return null;
  }

  const provider =
    process.env.PHISHSHIELD_LLM_PROVIDER ??
    process.env.PHISHSHIELD_FRONTIER_PROVIDER ??
    (url === process.env.PHISHSHIELD_LOCAL_MODEL_URL ? "phishshield-local" : "generic-llm");

  const model =
    process.env.PHISHSHIELD_LLM_MODEL ??
    process.env.PHISHSHIELD_FRONTIER_MODEL ??
    process.env.PHISHSHIELD_LOCAL_MODEL_NAME ??
    "phishshield-llm-fallback";

  const modeValue = (
    process.env.PHISHSHIELD_LLM_API_MODE ??
    process.env.PHISHSHIELD_FRONTIER_API_MODE ??
    (url === process.env.PHISHSHIELD_LOCAL_MODEL_URL ? "native" : "chat")
  ).toLowerCase();
  const mode: "chat" | "native" = modeValue === "native" ? "native" : "chat";

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...parseJsonHeaders(
      process.env.PHISHSHIELD_LLM_HEADERS_JSON ??
        process.env.PHISHSHIELD_FRONTIER_HEADERS_JSON,
    ),
  };

  const apiKey =
    process.env.PHISHSHIELD_LLM_API_KEY ??
    process.env.PHISHSHIELD_FRONTIER_API_KEY;
  if (apiKey) {
    const headerName =
      process.env.PHISHSHIELD_LLM_API_KEY_HEADER ??
      process.env.PHISHSHIELD_FRONTIER_API_KEY_HEADER ??
      "Authorization";
    const authScheme =
      process.env.PHISHSHIELD_LLM_API_KEY_SCHEME ??
      process.env.PHISHSHIELD_FRONTIER_API_KEY_SCHEME ??
      "Bearer";

    headers[headerName] =
      headerName.toLowerCase() === "authorization" && authScheme
        ? `${authScheme} ${apiKey}`
        : apiKey;
  }

  return {
    provider,
    model,
    url,
    headers,
    timeoutMs,
    mode,
  };
}

function buildRequestBody(
  config: FrontierConfig,
  emailText: string,
  context: FrontierReviewContext,
) {
  const prompt = process.env.PHISHSHIELD_LLM_PROMPT ?? DEFAULT_LLM_FALLBACK_PROMPT;
  const emailPayload = emailText.slice(0, 8000);
  const localSignals = {
    currentScore: context.localScore,
    urlScore: context.urlScore,
    headerScore: context.headerScore,
    suspiciousUrlCount: context.suspiciousUrlCount,
    spoofingRisk: context.spoofingRisk ?? "none",
    detectedSignals: context.detectedSignals ?? [],
    currentClassification: context.classification ?? "uncertain",
  };

  if (config.mode === "native") {
    return {
      model: config.model,
      prompt,
      emailText: emailPayload,
      detectedSignals: localSignals.detectedSignals,
      context: localSignals,
      outputSchema: {
        final_label: ["safe", "uncertain", "phishing"],
        explanation: "string",
        risk_level: ["low", "medium", "high"],
      },
    };
  }

  return {
    model: config.model,
    temperature: 0,
    max_tokens: 260,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content:
          `${prompt} Return ONLY valid JSON with keys final_label, explanation, risk_level. final_label must be one of safe, uncertain, phishing. risk_level must be one of low, medium, high.`,
      },
      {
        role: "user",
        content: JSON.stringify({
          emailText: emailPayload,
          detectedSignals: localSignals,
        }),
      },
    ],
  };
}

function extractMessageContent(payload: any): string | null {
  const content = payload?.choices?.[0]?.message?.content;

  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {
    const textParts = content
      .map((item) => (typeof item?.text === "string" ? item.text : ""))
      .filter(Boolean);

    return textParts.length > 0 ? textParts.join("\n") : null;
  }

  return null;
}

function extractJsonObject(raw: string): string {
  const match = raw.match(/\{[\s\S]*\}/);
  return match ? match[0] : raw;
}

function normalizeReview(
  parsed: any,
  config: FrontierConfig,
): FrontierReview | null {
  const label =
    parsed?.final_label ?? parsed?.finalLabel ?? parsed?.classification ?? parsed?.label;
  const classification = ["safe", "uncertain", "phishing"].includes(label)
    ? (label as "safe" | "uncertain" | "phishing")
    : null;

  if (!classification) {
    return null;
  }

  const explanation =
    typeof parsed?.explanation === "string" && parsed.explanation.trim().length > 0
      ? parsed.explanation.trim()
      : Array.isArray(parsed?.reasons)
        ? parsed.reasons
            .filter((item: unknown): item is string => typeof item === "string")
            .join(" ")
        : `Fallback review marked this email as ${classification}.`;

  const rawRiskLevel = String(
    parsed?.risk_level ??
      parsed?.riskLevel ??
      (classification === "phishing"
        ? "high"
        : classification === "safe"
          ? "low"
          : "medium"),
  ).toLowerCase();

  const riskLevel: "low" | "medium" | "high" =
    rawRiskLevel === "high" || rawRiskLevel === "low" || rawRiskLevel === "medium"
      ? rawRiskLevel
      : classification === "phishing"
        ? "high"
        : classification === "safe"
          ? "low"
          : "medium";

  const defaultScore =
    classification === "phishing" ? 85 : classification === "safe" ? 15 : 50;
  const score = clamp(Number(parsed?.score ?? parsed?.riskScore ?? defaultScore), 0, 100);
  const confidence = clamp(
    Number(
      parsed?.confidence ??
        (riskLevel === "high" ? 0.9 : riskLevel === "medium" ? 0.75 : 0.65),
    ),
    0.4,
    0.99,
  );
  const attackType =
    typeof parsed?.attackType === "string" && parsed.attackType.trim().length > 0
      ? parsed.attackType.trim()
      : classification === "safe"
        ? "Safe / Informational"
        : "Social Engineering";

  const reasons = Array.isArray(parsed?.reasons)
    ? parsed.reasons
        .filter((item: unknown): item is string => typeof item === "string")
        .slice(0, 4)
    : [explanation];

  return {
    provider: config.provider,
    model:
      typeof parsed?.model === "string" && parsed.model.trim().length > 0
        ? parsed.model.trim()
        : config.model,
    score,
    confidence,
    classification,
    finalLabel: classification,
    explanation,
    riskLevel,
    attackType,
    reasons,
  };
}

export async function reviewWithFrontierModel(
  emailText: string,
  context: FrontierReviewContext,
): Promise<FrontierReview | null> {
  const config = getFrontierConfig();

  if (!config || !emailText?.trim()) {
    return null;
  }

  const cacheKey = `${config.provider}:${config.model}:${context.localScore}:${emailText.slice(0, 600)}`;
  const cached = reviewCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

  try {
    const response = await fetch(config.url, {
      method: "POST",
      headers: config.headers,
      body: JSON.stringify(buildRequestBody(config, emailText, context)),
      signal: controller.signal,
    });

    if (!response.ok) {
      logger.warn("Frontier review request failed", {
        provider: config.provider,
        status: response.status,
      });
      return null;
    }

    const payload = await response.json();

    const directReview = normalizeReview(payload, config);
    if (directReview) {
      reviewCache.set(cacheKey, directReview);
      return directReview;
    }

    const rawContent = extractMessageContent(payload);

    if (!rawContent) {
      return null;
    }

    const parsed = JSON.parse(extractJsonObject(rawContent));
    const review = normalizeReview(parsed, config);

    if (review) {
      reviewCache.set(cacheKey, review);
    }

    return review;
  } catch (error) {
    const err = error as Error;
    if (err.name !== "AbortError") {
      logger.warn("LLM fallback unavailable; continuing with local ensemble", {
        provider: config.provider,
        error: err.message,
      });
    }
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
