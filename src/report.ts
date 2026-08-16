import { ScanResult, Severity } from "./types";
import { astLabelsForRule } from "./ast10";

const SEVERITY_ICON: Record<Severity, string> = {
  info: "  ",
  low: " ⚠",
  medium: " ⚠",
  high: " ✗",
  critical: "‼️",
};

export function formatReport(results: ScanResult[]): string {
  const lines: string[] = [];
  const clean = results.filter((r) => r.findings.length === 0 || r.findings.every((f) => f.suppressed));
  const flagged = results.filter((r) => r.findings.some((f) => !f.suppressed));

  const totalActive = results.reduce((n, r) => n + r.findings.filter((f) => !f.suppressed).length, 0);
  const totalSuppressed = results.reduce((n, r) => n + r.findings.filter((f) => f.suppressed).length, 0);

  lines.push(
    `Scanned ${results.length} tool(s): ${clean.length} clean, ${flagged.length} flagged.` +
      (totalSuppressed ? ` (${totalSuppressed} finding(s) suppressed as known false positives)` : "") +
      "\n"
  );

  for (const result of flagged) {
    lines.push(`${SEVERITY_ICON[result.overallSeverity]} ${result.toolName}  [${result.sourceFile}]  — overall: ${result.overallSeverity.toUpperCase()}`);
    for (const f of result.findings) {
      if (f.suppressed) {
        lines.push(`    - [SUPPRESSED] ${f.ruleId} — previously marked false positive`);
        continue;
      }
      const pct = Math.round(f.confidence * 100);
      lines.push(`    - [${f.severity.toUpperCase()}] ${f.ruleId} (confidence: ${pct}%): ${f.message}`);
      if (f.evidence) lines.push(`        evidence: ${f.evidence}`);
      const ast = astLabelsForRule(f.ruleId);
      if (ast) lines.push(`        OWASP AST10: ${ast}`);
      lines.push(`        why this confidence: ${f.confidenceReason}`);
      lines.push(`        not a real issue? re-run with: --mark-false-positive ${f.ruleId} "${f.toolName}"`);
    }
    lines.push("");
  }

  if (clean.length) {
    lines.push(`Clean: ${clean.map((r) => r.toolName).join(", ")}`);
  }

  return lines.join("\n");
}
