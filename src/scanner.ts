import { Finding, Rule, ScanResult, Severity, ToolManifest } from "./types";
import { FeedbackStore, isKnownFalsePositive } from "./feedback";
import { BaselineStore, computeHash, toolKey } from "./baseline";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Compares a tool against its recorded baseline (if any) and returns a
 * finding if the security-relevant fields have changed since it was last
 * scanned. Returns null for tools with no baseline yet (first sighting —
 * the caller records a new baseline instead of flagging) or tools whose
 * hash still matches.
 */
export function checkDrift(tool: ToolManifest, baseline?: BaselineStore): Finding | null {
  if (!baseline) return null;
  const prev = baseline.tools[toolKey(tool)];
  if (!prev) return null;

  const currentHash = computeHash(tool);
  if (currentHash === prev.hash) return null;

  const prevPerms = new Set(prev.permissions);
  const currPerms = new Set(tool.permissions ?? []);
  const addedPerms = [...currPerms].filter((p) => !prevPerms.has(p));
  const removedPerms = [...prevPerms].filter((p) => !currPerms.has(p));

  const changes: string[] = [];
  if (addedPerms.length) changes.push(`permissions added: ${addedPerms.join(", ")}`);
  if (removedPerms.length) changes.push(`permissions removed: ${removedPerms.join(", ")}`);
  if (prev.descriptionPreview !== tool.description.slice(0, 80)) changes.push("description text changed");
  if (changes.length === 0) changes.push("parameters changed");

  return {
    ruleId: "manifest-drift",
    severity: addedPerms.length > 0 ? "critical" : "high",
    confidence: 0.9,
    confidenceReason: `Direct hash comparison against the exact version of this tool last scanned on ${prev.recordedAt.slice(
      0,
      10
    )} — not a heuristic guess, a verified diff.`,
    message: `This tool's definition changed since it was last scanned (${changes.join(
      "; "
    )}). This is the core mechanic behind MCP "rug pull" / tool-poisoning attacks: a tool looks safe when a human reviews and approves it, then its description or permissions change afterward while the agent keeps trusting the original approval. If this change was intentional, re-run with --update-baseline "${tool.name}".`,
    toolName: tool.name,
    sourceFile: tool.sourceFile,
    evidence: changes.join("; "),
  };
}

function worstSeverity(findings: Finding[]): Severity {
  // Suppressed findings don't count toward overall severity — a user-confirmed
  // false positive shouldn't still fail a CI build.
  const active = findings.filter((f) => !f.suppressed);
  if (active.length === 0) return "info";
  return active.reduce<Severity>((worst, f) => {
    return SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(worst) ? f.severity : worst;
  }, "info");
}

export function scanTool(
  tool: ToolManifest,
  rules: Rule[],
  feedback?: FeedbackStore,
  baseline?: BaselineStore
): ScanResult {
  const findings = rules.flatMap((rule) => rule.check(tool));

  const drift = checkDrift(tool, baseline);
  if (drift) findings.push(drift);

  if (feedback) {
    for (const f of findings) {
      if (isKnownFalsePositive(feedback, f.ruleId, f.toolName, f.sourceFile)) {
        f.suppressed = true;
      }
    }
  }
  return {
    toolName: tool.name,
    sourceFile: tool.sourceFile,
    findings,
    overallSeverity: worstSeverity(findings),
  };
}

export function scanTools(
  tools: ToolManifest[],
  rules: Rule[],
  feedback?: FeedbackStore,
  baseline?: BaselineStore
): ScanResult[] {
  return tools.map((tool) => scanTool(tool, rules, feedback, baseline));
}
