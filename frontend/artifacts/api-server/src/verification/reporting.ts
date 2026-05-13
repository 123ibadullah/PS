import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  MetricsSummary,
  PerformanceSummary,
  SuiteSummary,
  TestExecutionResult,
  ThresholdConfig,
  VerificationReport,
} from "./types.js";

export const DEFAULT_THRESHOLDS: ThresholdConfig = {
  accuracy: 0.9,
  phishingRecall: 0.95,
  precision: 0.9,
  falsePositiveRate: 0.1,
  falseNegativeRate: 0.1,
  averageLatencyMs: 500,
  p95LatencyMs: 1500,
};

export function computeMetrics(results: TestExecutionResult[]): MetricsSummary {
  const classified = results.filter((result) => !result.error);
  const binaryClassified = classified.filter(
    (result) =>
      result.expectedClassification !== "uncertain" &&
      result.actualClassification !== "uncertain",
  );

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const passedCount = classified.filter((result) => result.passed).length;

  for (const result of binaryClassified) {
    const predictedPositive = result.actualClassification === "phishing";
    const expectedPositive = result.expectedClassification === "phishing";

    if (expectedPositive && predictedPositive) tp += 1;
    else if (!expectedPositive && predictedPositive) fp += 1;
    else if (!expectedPositive && !predictedPositive) tn += 1;
    else if (expectedPositive && !predictedPositive) fn += 1;
  }

  const totalCases = classified.length || 1;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1Score = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const falsePositiveRate = fp + tn === 0 ? 0 : fp / (fp + tn);
  const falseNegativeRate = fn + tp === 0 ? 0 : fn / (fn + tp);

  return {
    totalCases: classified.length,
    accuracy: passedCount / totalCases,
    precision,
    recall,
    f1Score,
    falsePositiveRate,
    falseNegativeRate,
    tp,
    fp,
    tn,
    fn,
  };
}

export function summarizeSuites(results: TestExecutionResult[]): SuiteSummary[] {
  const grouped = new Map<string, TestExecutionResult[]>();

  for (const result of results) {
    const current = grouped.get(result.suite) ?? [];
    current.push(result);
    grouped.set(result.suite, current);
  }

  return [...grouped.entries()].map(([suite, suiteResults]) => {
    const total = suiteResults.length;
    const passed = suiteResults.filter((result) => result.passed).length;
    const avgLatencyMs =
      suiteResults.reduce((sum, result) => sum + result.latencyMs, 0) / Math.max(total, 1);

    return {
      suite: suite as SuiteSummary["suite"],
      total,
      passed,
      failed: total - passed,
      avgLatencyMs: Math.round(avgLatencyMs * 100) / 100,
    };
  });
}

export function evaluateThresholds(
  metrics: MetricsSummary,
  performance: PerformanceSummary,
  thresholds: ThresholdConfig = DEFAULT_THRESHOLDS,
): string[] {
  const failures: string[] = [];

  if (metrics.accuracy < thresholds.accuracy) {
    failures.push(`Accuracy below threshold: ${(metrics.accuracy * 100).toFixed(2)}% < ${(thresholds.accuracy * 100).toFixed(2)}%`);
  }
  if (metrics.recall < thresholds.phishingRecall) {
    failures.push(`Phishing recall below threshold: ${(metrics.recall * 100).toFixed(2)}% < ${(thresholds.phishingRecall * 100).toFixed(2)}%`);
  }
  if (metrics.precision < thresholds.precision) {
    failures.push(`Precision below threshold: ${(metrics.precision * 100).toFixed(2)}% < ${(thresholds.precision * 100).toFixed(2)}%`);
  }
  if (metrics.falsePositiveRate > thresholds.falsePositiveRate) {
    failures.push(`False positive rate too high: ${(metrics.falsePositiveRate * 100).toFixed(2)}% > ${(thresholds.falsePositiveRate * 100).toFixed(2)}%`);
  }
  if (metrics.falseNegativeRate > thresholds.falseNegativeRate) {
    failures.push(`False negative rate too high: ${(metrics.falseNegativeRate * 100).toFixed(2)}% > ${(thresholds.falseNegativeRate * 100).toFixed(2)}%`);
  }
  if (performance.averageLatencyMs > thresholds.averageLatencyMs) {
    failures.push(`Average latency too high: ${performance.averageLatencyMs.toFixed(1)}ms > ${thresholds.averageLatencyMs}ms`);
  }
  if (performance.p95LatencyMs > thresholds.p95LatencyMs) {
    failures.push(`P95 latency too high: ${performance.p95LatencyMs.toFixed(1)}ms > ${thresholds.p95LatencyMs}ms`);
  }

  return failures;
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function buildHtmlReport(report: VerificationReport): string {
  const failureRows = report.failures
    .map(
      (failure) => `
        <tr>
          <td>${failure.suite}</td>
          <td>${failure.name}</td>
          <td>${failure.expectedClassification}</td>
          <td>${failure.actualClassification ?? "error"}</td>
          <td>${failure.riskScore ?? "-"}</td>
          <td>${failure.issues.join("; ") || failure.error || "-"}</td>
        </tr>`,
    )
    .join("\n");

  const suiteCards = report.suites
    .map(
      (suite) => `
        <div class="card">
          <h3>${suite.suite}</h3>
          <p><strong>${suite.passed}/${suite.total}</strong> passed</p>
          <p>${suite.failed} failed · avg latency ${suite.avgLatencyMs.toFixed(1)}ms</p>
        </div>`,
    )
    .join("\n");

  const thresholdBlock =
    report.thresholdFailures.length === 0
      ? `<div class="ok">All configured thresholds passed.</div>`
      : `<div class="fail"><strong>Threshold failures:</strong><ul>${report.thresholdFailures
          .map((failure) => `<li>${failure}</li>`)
          .join("")}</ul></div>`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>PhishShield Verification Report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0b1220; color: #e5eefc; }
    h1, h2, h3 { margin: 0 0 12px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 20px 0; }
    .card { background: #131d32; border: 1px solid #263452; border-radius: 12px; padding: 16px; }
    .ok { background: #123222; border: 1px solid #2b8a57; padding: 12px; border-radius: 10px; }
    .fail { background: #3a1d24; border: 1px solid #d65567; padding: 12px; border-radius: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; background: #131d32; }
    th, td { padding: 10px; border: 1px solid #263452; text-align: left; vertical-align: top; }
    th { background: #1b2942; }
    code { background: #09101d; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>PhishShield AI Verification Report</h1>
  <p>Generated at <code>${report.generatedAt}</code> with seed <code>${report.seed}</code>.</p>

  <div class="grid">
    <div class="card"><h3>Overall</h3><p><strong>${report.summary.passed}/${report.summary.total}</strong> tests passed</p><p>${report.summary.failed} failed</p></div>
    <div class="card"><h3>Accuracy</h3><p>${formatPercent(report.metrics.accuracy)}</p><p>Precision ${formatPercent(report.metrics.precision)} · Recall ${formatPercent(report.metrics.recall)}</p></div>
    <div class="card"><h3>F1 / Error Rates</h3><p>F1 ${formatPercent(report.metrics.f1Score)}</p><p>FP ${formatPercent(report.metrics.falsePositiveRate)} · FN ${formatPercent(report.metrics.falseNegativeRate)}</p></div>
    <div class="card"><h3>Performance</h3><p>Avg ${report.performance.averageLatencyMs.toFixed(1)}ms · P95 ${report.performance.p95LatencyMs.toFixed(1)}ms</p><p>Throughput ${report.performance.throughputPerSecond.toFixed(2)}/sec</p></div>
  </div>

  <h2>Threshold status</h2>
  ${thresholdBlock}

  <h2>Suite breakdown</h2>
  <div class="grid">${suiteCards}</div>

  <h2>Failed cases</h2>
  <table>
    <thead>
      <tr><th>Suite</th><th>Case</th><th>Expected</th><th>Actual</th><th>Score</th><th>Reason</th></tr>
    </thead>
    <tbody>
      ${failureRows || '<tr><td colspan="6">No failures 🎉</td></tr>'}
    </tbody>
  </table>
</body>
</html>`;
}

export async function writeVerificationReports(
  reportDir: string,
  report: Omit<VerificationReport, "artifacts">,
): Promise<VerificationReport> {
  await mkdir(reportDir, { recursive: true });

  const timestamp = report.generatedAt.replace(/[:.]/g, "-");
  const jsonReportPath = path.join(reportDir, `verification-report-${timestamp}.json`);
  const htmlReportPath = path.join(reportDir, `verification-report-${timestamp}.html`);
  const latestJsonPath = path.join(reportDir, "verification-report-latest.json");
  const latestHtmlPath = path.join(reportDir, "verification-report-latest.html");

  const completedReport: VerificationReport = {
    ...report,
    artifacts: {
      jsonReportPath,
      htmlReportPath,
    },
  };

  const jsonBody = JSON.stringify(completedReport, null, 2);
  const htmlBody = buildHtmlReport(completedReport);

  await Promise.all([
    writeFile(jsonReportPath, jsonBody, "utf-8"),
    writeFile(htmlReportPath, htmlBody, "utf-8"),
    writeFile(latestJsonPath, jsonBody, "utf-8"),
    writeFile(latestHtmlPath, htmlBody, "utf-8"),
  ]);

  return completedReport;
}
