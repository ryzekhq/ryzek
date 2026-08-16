import { ScanResult, Severity } from "./types";
import { allRules } from "./rules";
import { RULE_TO_AST, AST_CATEGORIES } from "./ast10";
import { VERSION } from "./version";

/**
 * SARIF 2.1.0 output.
 *
 * SARIF is the format GitHub Code Scanning ingests, so emitting it is what
 * makes ryzek findings appear in a repo's Security tab alongside CodeQL
 * and Dependabot alerts, rather than being buried in CI log text that nobody
 * reads. This is pure ecosystem integration — it adds no detection ability,
 * but it's the difference between findings that get seen and findings that
 * don't.
 */

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  info: "note",
  low: "note",
  medium: "warning",
  high: "error",
  critical: "error",
};

/** GitHub uses security-severity (a CVSS-like 0-10 number) to sort and filter alerts. */
const SEVERITY_TO_SCORE: Record<Severity, string> = {
  info: "0.0",
  low: "3.0",
  medium: "5.5",
  high: "7.5",
  critical: "9.0",
};

export function formatSarif(results: ScanResult[], version = VERSION): string {
  // Build the rule metadata catalogue (SARIF "rules"), including the
  // manifest-drift pseudo-rule which lives in scanner.ts rather than rules.ts.
  const ruleDescriptors = [
    ...allRules.map((r) => ({ id: r.id, description: r.description })),
    {
      id: "manifest-drift",
      description:
        "Flags tools whose definition changed since the last scan — the core mechanic behind MCP rug-pull / tool-poisoning attacks.",
    },
  ].map((r) => {
    const astIds = RULE_TO_AST[r.id] ?? [];
    const tags = ["security", "agent-skills", ...astIds];
    return {
      id: r.id,
      name: r.id,
      shortDescription: { text: r.description },
      fullDescription: {
        text:
          r.description +
          (astIds.length
            ? ` Maps to OWASP AST10: ${astIds
                .map((id) => `${id} (${AST_CATEGORIES[id]?.name})`)
                .join(", ")}.`
            : ""),
      },
      properties: { tags },
    };
  });

  const sarifResults = results.flatMap((result) =>
    result.findings
      .filter((f) => !f.suppressed)
      .map((f) => {
        const astIds = RULE_TO_AST[f.ruleId] ?? [];
        return {
          ruleId: f.ruleId,
          level: SEVERITY_TO_SARIF_LEVEL[f.severity],
          message: {
            text:
              `${f.message}\n\nConfidence: ${Math.round(f.confidence * 100)}% — ${f.confidenceReason}` +
              (f.evidence ? `\n\nEvidence: ${f.evidence}` : "") +
              (astIds.length ? `\n\nOWASP AST10: ${astIds.join(", ")}` : ""),
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.sourceFile },
                // Manifest findings are file-level; SARIF requires a region,
                // so line 1 is used as the anchor rather than a fake precise line.
                region: { startLine: 1 },
              },
              logicalLocations: [{ name: f.toolName, kind: "member" }],
            },
          ],
          properties: {
            confidence: f.confidence,
            toolName: f.toolName,
            "security-severity": SEVERITY_TO_SCORE[f.severity],
          },
        };
      })
  );

  // Suppressed findings are emitted with SARIF's own suppression mechanism so
  // GitHub shows them as dismissed rather than silently dropping the history.
  const suppressedResults = results.flatMap((result) =>
    result.findings
      .filter((f) => f.suppressed)
      .map((f) => ({
        ruleId: f.ruleId,
        level: SEVERITY_TO_SARIF_LEVEL[f.severity],
        message: { text: f.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.sourceFile },
              region: { startLine: 1 },
            },
            logicalLocations: [{ name: f.toolName, kind: "member" }],
          },
        ],
        suppressions: [
          { kind: "external", justification: "Marked as a false positive by the team via ryzek feedback." },
        ],
      }))
  );

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "ryzek",
            version,
            informationUri: "https://github.com/ryzekhq/ryzek",
            rules: ruleDescriptors,
          },
        },
        results: [...sarifResults, ...suppressedResults],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
