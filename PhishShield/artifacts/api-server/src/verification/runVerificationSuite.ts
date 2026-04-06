import { performance } from "node:perf_hooks";
import path from "node:path";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { detectLlmUsage, normalizeClassification, summarizeForConsole, validateAnalyzeResult } from "./assertions.js";
import { writeVerificationReports, computeMetrics, evaluateThresholds, summarizeSuites, DEFAULT_THRESHOLDS } from "./reporting.js";
import { generateVerificationCases, getConsistencyCases, getIntegrationSmokeCases, getLlmFallbackCase, getPerformanceCases } from "./testDataEngine.js";
import type { PerformanceSummary, TestExecutionResult, VerificationCase, VerificationReport } from "./types.js";

process.env.PHISHSHIELD_FRONTIER_MODE ??= "off";
process.env.PHISHSHIELD_TRANSFORMER_URL ??= "http://127.0.0.1:6553/predict";
process.env.PHISHSHIELD_TRANSFORMER_TIMEOUT_MS ??= "150";

async function withTemporaryEnv<T>(
  overrides: Record<string, string | undefined>,
  work: () => Promise<T>,
): Promise<T> {
  const previousEntries = Object.entries(overrides).map(([key, value]) => [key, process.env[key], value] as const);

  for (const [key, _oldValue, nextValue] of previousEntries) {
    if (typeof nextValue === "undefined") delete process.env[key];
    else process.env[key] = nextValue;
  }

  try {
    return await work();
  } finally {
    for (const [key, oldValue] of previousEntries) {
      if (typeof oldValue === "undefined") delete process.env[key];
      else process.env[key] = oldValue;
    }
  }
}

async function startJsonServer(
  handler: (body: string, reqUrl: string) => { status?: number; body: unknown; delayMs?: number },
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    const response = handler(Buffer.concat(chunks).toString("utf-8"), req.url ?? "/");
    if (response.delayMs && response.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, response.delayMs));
    }

    res.writeHead(response.status ?? 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(response.body));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}

async function runDirectCase(
  analyzeEmail: (emailText: string, headersText?: string, id?: string, attachments?: any[]) => Promise<any>,
  testCase: VerificationCase,
): Promise<TestExecutionResult> {
  const start = performance.now();

  try {
    const result = await analyzeEmail(testCase.emailText, testCase.headersText, `verify-${testCase.id}`, testCase.attachments ?? []);
    const issues = validateAnalyzeResult(testCase, result);
    return {
      caseId: testCase.id,
      suite: testCase.suite,
      name: testCase.name,
      passed: issues.length === 0,
      latencyMs: performance.now() - start,
      expectedClassification: testCase.expected.expectedClassification,
      actualClassification: normalizeClassification(result.classification),
      riskScore: result.riskScore,
      confidence: result.confidence,
      llmUsed: detectLlmUsage(result),
      issues,
    };
  } catch (error) {
    return {
      caseId: testCase.id,
      suite: testCase.suite,
      name: testCase.name,
      passed: false,
      latencyMs: performance.now() - start,
      expectedClassification: testCase.expected.expectedClassification,
      issues: ["Unhandled exception during analysis."],
      error: error instanceof Error ? error.stack ?? error.message : String(error),
    };
  }
}

async function runLlmFallbackScenario(
  analyzeEmail: (emailText: string, headersText?: string, id?: string, attachments?: any[]) => Promise<any>,
): Promise<TestExecutionResult> {
  const testCase = getLlmFallbackCase();
  const stub = await startJsonServer(() => ({
    body: {
      final_label: "phishing",
      explanation: "The email combines an account alert with manual verification pressure and should be escalated.",
      risk_level: "high",
      score: 88,
      confidence: 0.93,
      reasons: ["manual verification pressure", "account access concern"],
    },
  }));

  try {
    return await withTemporaryEnv(
      {
        PHISHSHIELD_LLM_API_URL: stub.url,
        PHISHSHIELD_LLM_API_MODE: "native",
        PHISHSHIELD_LLM_TIMEOUT_MS: "300",
        PHISHSHIELD_FRONTIER_MODE: "smart",
      },
      async () => runDirectCase(analyzeEmail, testCase),
    );
  } finally {
    await stub.close();
  }
}

async function runIntegrationSuite(): Promise<TestExecutionResult[]> {
  const { default: app } = await import("../app.js");
  const server = app.listen(0, "127.0.0.1");

  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  const baseUrl = `http://127.0.0.1:${port}`;
  const headers = {
    Authorization: "Bearer dev-sandbox-key",
    "Content-Type": "application/json",
  };

  const integrationCases = getIntegrationSmokeCases();
  const results: TestExecutionResult[] = [];

  try {
    for (const testCase of integrationCases) {
      const start = performance.now();
      try {
        const response = await fetch(`${baseUrl}/api/analyze`, {
          method: "POST",
          headers,
          body: JSON.stringify({ emailText: testCase.emailText, headers: testCase.headersText }),
        });
        const result = (await response.json()) as any;
        const issues = response.ok ? validateAnalyzeResult(testCase, result) : [`HTTP ${response.status} returned from /api/analyze`];
        results.push({
          caseId: testCase.id,
          suite: "integration",
          name: testCase.name,
          passed: response.ok && issues.length === 0,
          latencyMs: performance.now() - start,
          expectedClassification: testCase.expected.expectedClassification,
          actualClassification: response.ok ? normalizeClassification(result.classification) : undefined,
          riskScore: response.ok ? result.riskScore : undefined,
          confidence: response.ok ? result.confidence : undefined,
          llmUsed: response.ok ? detectLlmUsage(result) : false,
          issues,
          error: response.ok ? undefined : JSON.stringify(result),
        });
      } catch (error) {
        results.push({
          caseId: testCase.id,
          suite: "integration",
          name: testCase.name,
          passed: false,
          latencyMs: performance.now() - start,
          expectedClassification: testCase.expected.expectedClassification,
          issues: ["Integration request threw an exception."],
          error: error instanceof Error ? error.stack ?? error.message : String(error),
        });
      }
    }

    const feedbackStart = performance.now();
    const emailId = `integration-feedback-${Date.now()}`;
    const feedbackResponse = await fetch(`${baseUrl}/api/feedback`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        emailId,
        userFeedback: "incorrect",
        correctedClassification: "phishing",
        feedbackSource: "user",
        notes: "<script>alert('xss')</script> urgent vendor transfer requires verification",
        emailText: "Please process the vendor transfer and keep this confidential.",
        emailPreview: "Urgent vendor transfer request",
        predictedClassification: "safe",
        riskScore: 12,
        confidence: 0.42,
        attackType: "Social Engineering",
        reasons: ["Urgent transfer request", "<b>keep this confidential</b>"],
      }),
    });
    const exportResponse = await fetch(`${baseUrl}/api/feedback/export`, {
      method: "GET",
      headers: { Authorization: headers.Authorization },
    });
    const exported = await exportResponse.json();

    const exportIssues: string[] = [];
    if (!feedbackResponse.ok) {
      exportIssues.push(`Feedback submission returned HTTP ${feedbackResponse.status}.`);
    }
    if (!exportResponse.ok) {
      exportIssues.push(`Feedback export returned HTTP ${exportResponse.status}.`);
    }
    if (!Array.isArray(exported)) {
      exportIssues.push("Feedback export did not return an array.");
    }

    const matchingFeedback = Array.isArray(exported)
      ? exported.find((item) => item?.scanId === emailId)
      : undefined;

    if (!matchingFeedback) {
      exportIssues.push("The newly submitted feedback sample was not present in the export.");
    }

    if (typeof matchingFeedback?.feedbackNotes === "string") {
      if (/<script|<b>/i.test(matchingFeedback.feedbackNotes)) {
        exportIssues.push("Feedback notes were not sanitized before export.");
      }
      if (!/urgent vendor transfer requires verification/i.test(matchingFeedback.feedbackNotes)) {
        exportIssues.push("Feedback notes lost the analyst context after sanitization.");
      }
    }

    results.push({
      caseId: "integration-feedback-export",
      suite: "integration",
      name: "Feedback submission and export endpoint",
      passed: exportIssues.length === 0,
      latencyMs: performance.now() - feedbackStart,
      expectedClassification: "safe",
      actualClassification: "safe",
      issues: exportIssues,
    });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }

  return results;
}

function runChildProcessTest(name: string, code: string, env: Record<string, string>): TestExecutionResult {
  const start = performance.now();
  const child = spawnSync(process.execPath, ["--import", "tsx", "-e", code], {
    cwd: path.resolve(import.meta.dirname, "..", ".."),
    env: { ...process.env, ...env },
    encoding: "utf-8",
  });

  const latencyMs = performance.now() - start;
  const issues: string[] = [];

  if (child.error) {
    issues.push(`Child process failed to start: ${child.error.message}`);
  }

  if (child.status !== 0) {
    issues.push(`Child process exited with code ${child.status ?? -1}.`);
  }

  const output = `${child.stdout ?? ""}\n${child.stderr ?? ""}`.trim();
  if (!/classification=|status=ok|feedback=/.test(output)) {
    issues.push("Expected success marker was not found in child process output.");
  }

  return {
    caseId: `failure-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    suite: "failure-handling",
    name,
    passed: issues.length === 0,
    latencyMs,
    expectedClassification: "safe",
    actualClassification: issues.length === 0 ? "safe" : undefined,
    issues,
    error: issues.length === 0 ? undefined : output,
  };
}

async function runFailureHandlingSuite(): Promise<TestExecutionResult[]> {
  const backendFailureStart = performance.now();
  const { default: app } = await import("../app.js");
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  const invalidResponse = await fetch(`http://127.0.0.1:${port}/api/analyze`, {
    method: "POST",
    headers: {
      Authorization: "Bearer dev-sandbox-key",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ emailText: 12345 }),
  });
  const invalidBody = (await invalidResponse.json().catch(() => ({}))) as Record<string, unknown>;
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));

  const backendFailureResult: TestExecutionResult = {
    caseId: "failure-backend-invalid-body",
    suite: "failure-handling",
    name: "Backend validation failure returns a structured error",
    passed:
      (invalidResponse.status === 400 || invalidResponse.status === 422) &&
      (typeof invalidBody?.message === "string" ||
        typeof (invalidBody as any)?.error?.message === "string"),
    latencyMs: performance.now() - backendFailureStart,
    expectedClassification: "safe",
    actualClassification: "safe",
    issues:
      invalidResponse.status === 400 || invalidResponse.status === 422
        ? typeof invalidBody?.message === "string" ||
          typeof (invalidBody as any)?.error?.message === "string"
          ? []
          : ["Backend error response was not structured JSON."]
        : [`Unexpected backend status code ${invalidResponse.status}.`],
    error: JSON.stringify(invalidBody),
  };

  const mlFailure = runChildProcessTest(
    "ML model failure falls back safely",
    `Math.exp = (() => { throw new Error('Simulated TF-IDF outage'); }) as typeof Math.exp; const { analyzeEmail } = await import('./src/lib/phishingDetector.ts'); const result = await analyzeEmail('Urgent payroll verification required today. Confirm the beneficiary details immediately.'); console.log('classification=' + result.classification + ' score=' + result.riskScore);`,
    {
      PHISHSHIELD_FRONTIER_MODE: "off",
      PHISHSHIELD_TRANSFORMER_URL: "http://127.0.0.1:6554/predict",
    },
  );

  const transformerFailure = runChildProcessTest(
    "Transformer API outage does not crash analysis",
    `const { analyzeEmail } = await import('./src/lib/phishingDetector.ts'); const result = await analyzeEmail('Urgent: verify your account via http://secure-account-reset.xyz/login now.'); console.log('classification=' + result.classification + ' score=' + result.riskScore);`,
    {
      PHISHSHIELD_FRONTIER_MODE: "off",
      PHISHSHIELD_TRANSFORMER_URL: "http://127.0.0.1:6555/predict",
      PHISHSHIELD_TRANSFORMER_TIMEOUT_MS: "80",
    },
  );

  const llmTimeoutServer = await startJsonServer(() => ({
    delayMs: 250,
    body: {
      final_label: "phishing",
      explanation: "Delayed response",
      risk_level: "high",
    },
  }));

  let llmTimeoutResult: TestExecutionResult;
  try {
    const { analyzeEmail } = await import("../lib/phishingDetector.js");
    const llmCase = {
      id: "failure-llm-timeout",
      suite: "failure-handling" as const,
      name: "LLM timeout falls back to a valid local verdict",
      emailText:
        "Subject: Security notice\n\nWe noticed unusual activity on your mailbox. Please contact support to review this alert.",
      expected: {
        expectedClassification: "uncertain" as const,
        minScore: 30,
        maxScore: 70,
        requiresExplanation: true,
      },
    };

    llmTimeoutResult = await withTemporaryEnv(
      {
        PHISHSHIELD_LLM_API_URL: llmTimeoutServer.url,
        PHISHSHIELD_LLM_API_MODE: "native",
        PHISHSHIELD_LLM_TIMEOUT_MS: "50",
        PHISHSHIELD_FRONTIER_MODE: "smart",
      },
      async () => runDirectCase(analyzeEmail, llmCase),
    );
    llmTimeoutResult.suite = "failure-handling";
  } finally {
    await llmTimeoutServer.close();
  }

  return [backendFailureResult, mlFailure, transformerFailure, llmTimeoutResult];
}

async function runConsistencySuite(
  analyzeEmail: (emailText: string, headersText?: string, id?: string, attachments?: any[]) => Promise<any>,
): Promise<TestExecutionResult[]> {
  const consistencyCases = getConsistencyCases();
  const results: TestExecutionResult[] = [];

  for (const testCase of consistencyCases) {
    const startedAt = performance.now();
    const runs = [] as Array<{ classification: string; riskScore: number; confidence: number; issues: string[] }>;

    for (let attempt = 0; attempt < 3; attempt++) {
      const result = await analyzeEmail(testCase.emailText, testCase.headersText, `consistency-${testCase.id}-${attempt}`, testCase.attachments ?? []);
      runs.push({
        classification: normalizeClassification(result.classification),
        riskScore: result.riskScore,
        confidence: result.confidence,
        issues: validateAnalyzeResult(testCase, result),
      });
    }

    const issues = runs.flatMap((run) => run.issues);
    const classifications = [...new Set(runs.map((run) => run.classification))];
    const minScore = Math.min(...runs.map((run) => run.riskScore));
    const maxScore = Math.max(...runs.map((run) => run.riskScore));

    if (classifications.length > 1) {
      issues.push(`Inconsistent classification across repeated runs: ${classifications.join(", ")}.`);
    }

    if (maxScore - minScore > 2) {
      issues.push(`Risk score drifted across repeated runs: ${minScore}-${maxScore}.`);
    }

    results.push({
      caseId: testCase.id,
      suite: "consistency",
      name: testCase.name,
      passed: issues.length === 0,
      latencyMs: performance.now() - startedAt,
      expectedClassification: testCase.expected.expectedClassification,
      actualClassification: normalizeClassification(runs[0]?.classification),
      riskScore: runs[0]?.riskScore,
      confidence: runs[0]?.confidence,
      issues,
    });
  }

  return results;
}

async function runPerformanceSuite(
  analyzeEmail: (emailText: string, headersText?: string, id?: string, attachments?: any[]) => Promise<any>,
): Promise<{ summary: PerformanceSummary; result: TestExecutionResult }> {
  const cases = getPerformanceCases(20260403, 120);
  const latencies: number[] = [];
  const startMem = process.memoryUsage().heapUsed;
  const startedAt = performance.now();
  let failures = 0;

  for (const testCase of cases) {
    const start = performance.now();
    try {
      const result = await analyzeEmail(testCase.emailText, testCase.headersText, `perf-${testCase.id}`, testCase.attachments ?? []);
      const issues = validateAnalyzeResult(testCase, result);
      if (issues.length > 0) {
        failures += 1;
      }
    } catch {
      failures += 1;
    }
    latencies.push(performance.now() - start);
  }

  const totalDurationMs = performance.now() - startedAt;
  const sortedLatencies = [...latencies].sort((a, b) => a - b);
  const averageLatencyMs = latencies.reduce((sum, value) => sum + value, 0) / Math.max(latencies.length, 1);
  const p95Index = Math.min(sortedLatencies.length - 1, Math.floor(sortedLatencies.length * 0.95));
  const p95LatencyMs = sortedLatencies[p95Index] ?? 0;
  const maxLatencyMs = sortedLatencies[sortedLatencies.length - 1] ?? 0;
  const memoryDeltaMb = (process.memoryUsage().heapUsed - startMem) / (1024 * 1024);
  const throughputPerSecond = cases.length / Math.max(totalDurationMs / 1000, 0.001);
  const passed = failures === 0 && averageLatencyMs <= DEFAULT_THRESHOLDS.averageLatencyMs && p95LatencyMs <= DEFAULT_THRESHOLDS.p95LatencyMs;

  const summary: PerformanceSummary = {
    batchSize: cases.length,
    averageLatencyMs,
    p95LatencyMs,
    maxLatencyMs,
    throughputPerSecond,
    memoryDeltaMb,
    passed,
  };

  const result: TestExecutionResult = {
    caseId: "performance-batch",
    suite: "performance",
    name: `Batch performance and stability over ${cases.length} emails`,
    passed,
    latencyMs: totalDurationMs,
    expectedClassification: "safe",
    actualClassification: "safe",
    issues: failures > 0 ? [`${failures} case(s) failed during the performance batch.`] : [],
  };

  return { summary, result };
}

async function main() {
  const seed = 20260403;
  const { analyzeEmail } = await import("../lib/phishingDetector.js");
  const directCases = generateVerificationCases(seed);

  const directResults: TestExecutionResult[] = [];
  for (const testCase of directCases) {
    const result = await runDirectCase(analyzeEmail, testCase);
    directResults.push(result);
    console.log(summarizeForConsole(result));
  }

  const llmFallbackResult = await runLlmFallbackScenario(analyzeEmail);
  console.log(summarizeForConsole(llmFallbackResult));

  const integrationResults = await runIntegrationSuite();
  for (const result of integrationResults) {
    console.log(summarizeForConsole(result));
  }

  const failureResults = await runFailureHandlingSuite();
  for (const result of failureResults) {
    console.log(summarizeForConsole(result));
  }

  const consistencyResults = await runConsistencySuite(analyzeEmail);
  for (const result of consistencyResults) {
    console.log(summarizeForConsole(result));
  }

  const { summary: performanceSummary, result: performanceResult } = await runPerformanceSuite(analyzeEmail);
  console.log(summarizeForConsole(performanceResult));

  const allResults = [
    ...directResults,
    llmFallbackResult,
    ...integrationResults,
    ...failureResults,
    ...consistencyResults,
    performanceResult,
  ];

  const metrics = computeMetrics(directResults);
  const suites = summarizeSuites(allResults);
  const thresholdFailures = evaluateThresholds(metrics, performanceSummary, DEFAULT_THRESHOLDS);
  const reportBase: Omit<VerificationReport, "artifacts"> = {
    generatedAt: new Date().toISOString(),
    seed,
    summary: {
      total: allResults.length,
      passed: allResults.filter((result) => result.passed).length,
      failed: allResults.filter((result) => !result.passed).length,
    },
    suites,
    metrics,
    performance: performanceSummary,
    thresholds: DEFAULT_THRESHOLDS,
    thresholdFailures,
    failures: allResults.filter((result) => !result.passed),
    results: allResults,
  };

  const reportDir = path.resolve(import.meta.dirname, "..", "..", "reports", "verification");
  const report = await writeVerificationReports(reportDir, reportBase);

  console.log("\n=== PHISHSHIELD VERIFICATION SUMMARY ===");
  console.log(`Passed: ${report.summary.passed}/${report.summary.total}`);
  console.log(`Accuracy: ${(report.metrics.accuracy * 100).toFixed(2)}%`);
  console.log(`Precision: ${(report.metrics.precision * 100).toFixed(2)}%`);
  console.log(`Recall: ${(report.metrics.recall * 100).toFixed(2)}%`);
  console.log(`F1 Score: ${(report.metrics.f1Score * 100).toFixed(2)}%`);
  console.log(`False Positive Rate: ${(report.metrics.falsePositiveRate * 100).toFixed(2)}%`);
  console.log(`False Negative Rate: ${(report.metrics.falseNegativeRate * 100).toFixed(2)}%`);
  console.log(`Average Latency: ${report.performance.averageLatencyMs.toFixed(2)}ms`);
  console.log(`P95 Latency: ${report.performance.p95LatencyMs.toFixed(2)}ms`);
  console.log(`JSON Report: ${report.artifacts.jsonReportPath}`);
  console.log(`HTML Report: ${report.artifacts.htmlReportPath}`);

  if (report.failures.length > 0) {
    console.log("\nFailed cases:");
    for (const failure of report.failures.slice(0, 20)) {
      console.log(` - ${failure.name}: ${failure.issues.join("; ") || failure.error || "Unknown failure"}`);
    }
  }

  if (report.thresholdFailures.length > 0 || report.failures.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("Verification suite crashed:", error);
  process.exitCode = 1;
});
