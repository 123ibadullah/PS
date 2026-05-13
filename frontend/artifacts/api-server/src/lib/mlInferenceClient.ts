import axios from "axios";
import { logger } from "./logger.js";
import type {
  InferenceLabel,
  MlInferenceFailure,
  MlInferenceRequest,
  MlInferenceResult,
  MlProviderId,
} from "./mlInferenceContracts.js";

type ProviderResponse = {
  label?: InferenceLabel;
  score?: number;
  verdict?: string;
  risk_score?: number;
  riskScore?: number;
  providers_used?: string[];
  degraded?: boolean;
  provider_count?: number;
  fallback_mode?: boolean;
  metadata?: Record<string, unknown>;
};

type ProviderConfig = {
  provider: MlProviderId;
  source: "local" | "python-internal";
  url?: string;
  timeoutMs: number;
};

type CircuitState = {
  failures: number;
  openedAt: number | null;
  halfOpenProbeInFlight: boolean;
};

const DEFAULT_TIMEOUT_MS = Number(process.env.PHISHSHIELD_ML_TIMEOUT_MS ?? "5000");
const CIRCUIT_FAILURE_THRESHOLD = Number(
  process.env.PHISHSHIELD_ML_CIRCUIT_FAILURE_THRESHOLD ?? "3",
);
const CIRCUIT_OPEN_MS = Number(process.env.PHISHSHIELD_ML_CIRCUIT_OPEN_MS ?? "30000");
const INTERNAL_API_KEY = process.env.PHISHSHIELD_INTERNAL_API_KEY?.trim() ?? "";

const providerCircuitState = new Map<MlProviderId, CircuitState>();

function getCircuitState(provider: MlProviderId): CircuitState {
  const existing = providerCircuitState.get(provider);
  if (existing) return existing;
  const created: CircuitState = {
    failures: 0,
    openedAt: null,
    halfOpenProbeInFlight: false,
  };
  providerCircuitState.set(provider, created);
  return created;
}

function providerConfig(provider: MlProviderId): ProviderConfig {
  const transformerBaseUrl =
    process.env.PHISHSHIELD_TRANSFORMER_URL?.trim() || "http://127.0.0.1:8001";
  const normalizeAnalyzeUrl = (value?: string): string | undefined => {
    const raw = value?.trim();
    if (!raw) return undefined;
    if (/\/analyze\/?$/i.test(raw)) return raw.replace(/\/+$/, "");
    return `${raw.replace(/\/+$/, "")}/analyze`;
  };

  switch (provider) {
    case "tfidf":
      return {
        provider,
        source: "local",
        timeoutMs: DEFAULT_TIMEOUT_MS,
      };
    case "indicbert":
      return {
        provider,
        source: "python-internal",
        url: normalizeAnalyzeUrl(transformerBaseUrl),
        timeoutMs: Number(process.env.PHISHSHIELD_TRANSFORMER_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS),
      };
    case "securebert":
      return {
        provider,
        source: "python-internal",
        url: process.env.PHISHSHIELD_SECUREBERT_URL?.trim(),
        timeoutMs: Number(process.env.PHISHSHIELD_SECUREBERT_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS),
      };
    case "muril":
      return {
        provider,
        source: "python-internal",
        url: process.env.PHISHSHIELD_MURIL_URL?.trim(),
        timeoutMs: Number(process.env.PHISHSHIELD_MURIL_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS),
      };
  }
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function failureFromReason(
  provider: MlProviderId,
  reason: MlInferenceFailure["reason"],
  message: string,
  latencyMs: number,
  retryable: boolean,
  statusCode?: number,
  metadata?: Record<string, unknown>,
): MlInferenceFailure {
  return {
    provider,
    reason,
    message,
    retryable,
    latencyMs,
    statusCode,
    metadata,
  };
}

function isCircuitOpen(provider: MlProviderId, now: number): boolean {
  const state = getCircuitState(provider);
  if (!state.openedAt) return false;
  if (now - state.openedAt >= CIRCUIT_OPEN_MS) return false;
  return true;
}

function enterOpenCircuit(provider: MlProviderId): void {
  const state = getCircuitState(provider);
  state.openedAt = Date.now();
  state.halfOpenProbeInFlight = false;
}

function onProviderSuccess(provider: MlProviderId): void {
  const state = getCircuitState(provider);
  state.failures = 0;
  state.openedAt = null;
  state.halfOpenProbeInFlight = false;
}

function onProviderFailure(provider: MlProviderId): void {
  const state = getCircuitState(provider);
  state.failures += 1;
  if (state.failures >= CIRCUIT_FAILURE_THRESHOLD) {
    enterOpenCircuit(provider);
  }
}

function toResult(
  provider: MlProviderId,
  source: "local" | "python-internal",
  label: InferenceLabel,
  confidence: number,
  latencyMs: number,
  degraded: boolean,
  metadata?: Record<string, unknown>,
): MlInferenceResult {
  return {
    provider,
    source,
    label,
    confidence: clamp(confidence, 0, 1),
    latencyMs,
    degraded,
    metadata,
  };
}

async function callPythonProvider(
  config: ProviderConfig,
  request: MlInferenceRequest,
): Promise<MlInferenceResult | MlInferenceFailure> {
  const start = Date.now();
  const timeoutMs = request.timeoutMs ?? config.timeoutMs;
  if (!config.url) {
    return failureFromReason(
      config.provider,
      config.provider === "indicbert" ? "not_configured" : "provider_unavailable",
      config.provider === "indicbert"
        ? "SecureBERT/MuRIL provider URL is not configured."
        : `${config.provider} provider is declared but not integrated yet.`,
      Date.now() - start,
      false,
    );
  }

  const payload =
    config.provider === "indicbert"
      ? {
        text: request.emailText.slice(0, 20000),
      }
      : {
        email_text: request.emailText.slice(0, 20000),
        provider: config.provider,
      };

  try {
    const response = await axios.post<ProviderResponse>(
      config.url,
      payload,
      {
        timeout: timeoutMs,
        headers: {
          "Content-Type": "application/json",
          ...(INTERNAL_API_KEY ? { "x-internal-api-key": INTERNAL_API_KEY } : {}),
        },
      },
    );

    const rawLabel = response.data?.label ?? response.data?.verdict;
    const label = String(rawLabel).toLowerCase() === "phishing" ? "phishing" : "safe";
    const directScore = Number(response.data?.score);
    const hasDirectScore = Number.isFinite(directScore);
    const riskScore = Number(response.data?.risk_score ?? response.data?.riskScore);
    const hasRiskScore = Number.isFinite(riskScore);
    if (!hasDirectScore && !hasRiskScore) {
      return failureFromReason(
        config.provider,
        "invalid_response",
        "Provider response did not include score or risk_score.",
        Date.now() - start,
        true,
        response.status,
      );
    }
    const confidence = hasDirectScore
      ? clamp(directScore, 0, 1)
      : label === "phishing"
        ? clamp(riskScore / 100, 0, 1)
        : clamp(1 - riskScore / 100, 0, 1);
    return toResult(
      config.provider,
      "python-internal",
      label,
      confidence,
      Date.now() - start,
      Boolean(response.data?.degraded),
      {
        statusCode: response.status,
        providersUsed: Array.isArray(response.data?.providers_used)
          ? response.data.providers_used
          : undefined,
        providerCount: Number.isFinite(Number(response.data?.provider_count))
          ? Number(response.data?.provider_count)
          : undefined,
        fallbackMode: Boolean(response.data?.fallback_mode),
        ...(response.data?.metadata ?? {}),
      },
    );
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      const isTimeout = error.code === "ECONNABORTED";
      const reason: MlInferenceFailure["reason"] = isTimeout
        ? "timeout"
        : status
          ? "service_error"
          : "network_error";
      return failureFromReason(
        config.provider,
        reason,
        error.message,
        Date.now() - start,
        isTimeout || !status || status >= 500,
        status,
      );
    }
    return failureFromReason(
      config.provider,
      "service_error",
      (error as Error).message,
      Date.now() - start,
      true,
    );
  }
}

export async function inferWithProvider(
  request: MlInferenceRequest,
): Promise<MlInferenceResult | MlInferenceFailure> {
  const provider = request.provider;
  const config = providerConfig(provider);
  const now = Date.now();
  const state = getCircuitState(provider);

  if (isCircuitOpen(provider, now)) {
    logger.warn("ML provider circuit open; using fallback path", {
      provider,
      failures: state.failures,
      circuitOpenMs: now - (state.openedAt ?? now),
    }, request.correlationId);
    return failureFromReason(
      provider,
      "circuit_open",
      "ML provider circuit breaker is open.",
      0,
      true,
    );
  }

  if (state.openedAt && now - state.openedAt >= CIRCUIT_OPEN_MS) {
    if (state.halfOpenProbeInFlight) {
      return failureFromReason(
        provider,
        "circuit_open",
        "ML provider circuit breaker probe in progress.",
        0,
        true,
      );
    }
    state.halfOpenProbeInFlight = true;
  }

  if (provider === "tfidf") {
    state.halfOpenProbeInFlight = false;
    return toResult("tfidf", "local", "safe", 0, 0, false, {
      note: "tfidf is evaluated in-process by local scorer.",
    });
  }

  const response = await callPythonProvider(config, request);
  const failed = "reason" in response;
  state.halfOpenProbeInFlight = false;

  if (failed) {
    onProviderFailure(provider);
    const latestState = getCircuitState(provider);
    logger.warn("ML provider inference failed", {
      provider,
      reason: response.reason,
      retryable: response.retryable,
      statusCode: response.statusCode,
      latencyMs: response.latencyMs,
      failures: latestState.failures,
      circuitOpen: Boolean(latestState.openedAt),
    }, request.correlationId);
    return response;
  }

  onProviderSuccess(provider);
  const providerCount = Number((response.metadata as { providerCount?: number } | undefined)?.providerCount ?? 0);
  const fallbackMode = Boolean((response.metadata as { fallbackMode?: boolean } | undefined)?.fallbackMode);
  logger.info(`Inference complete: providers=${providerCount}, fallback=${fallbackMode}`, {
    provider,
    source: response.source,
    latencyMs: response.latencyMs,
    confidence: response.confidence,
    providerCount,
    fallbackMode,
  }, request.correlationId);
  return response;
}
