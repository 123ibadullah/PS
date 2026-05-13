import { Router, type IRouter } from "express";
import { HealthCheckResponse } from "@workspace/api-zod";

interface ProviderHealthResponse {
  status: string;
  providers?: Record<
    string,
    {
      status: string;
      device: string;
      reason: string | null | undefined;
    }
  >;
}

const router: IRouter = Router();

router.get("/healthz", (_req, res) => {
  const data = HealthCheckResponse.parse({ status: "ok" });
  res.json(data);
});

router.get("/health", async (_req, res) => {
  const transformerUrl = (process.env.PHISHSHIELD_TRANSFORMER_URL ?? "").trim();
  let mlHealthUrl = "";
  if (transformerUrl) {
    try {
      const parsed = new URL(transformerUrl);
      parsed.pathname = "/health";
      parsed.search = "";
      mlHealthUrl = parsed.toString();
    } catch {
      mlHealthUrl = "";
    }
  }

  try {
    let mlHealth: ProviderHealthResponse | null = null;
    if (mlHealthUrl) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      mlHealth = await fetch(mlHealthUrl, { signal: controller.signal })
        .then(async (r) => (r.ok ? (await r.json()) as Promise<ProviderHealthResponse> : null))
        .catch(() => null)
        .finally(() => clearTimeout(timeout));
    }
    res.status(200).json({
      status: "ok",
      api: "express",
      ml_service: mlHealth?.status ?? "unreachable",
      providers: mlHealth?.providers ?? null,
      timestamp: new Date().toISOString(),
    });
  } catch {
    res.status(200).json({
      status: "degraded",
      api: "express",
      ml_service: "unreachable",
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;
