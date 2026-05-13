export type MlProviderId = "tfidf" | "indicbert" | "securebert" | "muril";

export type InferenceLabel = "phishing" | "safe";

export type MlInferenceRequest = {
  provider: MlProviderId;
  emailText: string;
  timeoutMs?: number;
  correlationId?: string;
};

export type MlInferenceResult = {
  provider: MlProviderId;
  label: InferenceLabel;
  confidence: number;
  latencyMs: number;
  source: "local" | "python-internal";
  degraded: boolean;
  metadata?: Record<string, unknown>;
};

export type MlFailureReason =
  | "not_configured"
  | "provider_unavailable"
  | "timeout"
  | "network_error"
  | "service_error"
  | "circuit_open"
  | "invalid_response";

export type MlInferenceFailure = {
  provider: MlProviderId;
  reason: MlFailureReason;
  message: string;
  retryable: boolean;
  latencyMs: number;
  statusCode?: number;
  metadata?: Record<string, unknown>;
};
