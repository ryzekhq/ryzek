/**
 * ryzek-rules — everything new, wired into one export.
 *
 * Drop this folder's files into src/ and add two lines to rules.ts. The 39 new
 * rules land in allRules alongside your existing 11.
 *
 *   import { newRules } from "./ryzek-rules-index";
 *   ...
 *   export const allRules: Rule[] = [ ...existing, ...newRules ];
 *
 * The three stateful rules and the shadow scan need more than one tool at a
 * time, so they are exported separately — see statefulRulesFor() and
 * shadowMcpFindings() below and the scanner.ts step in the guide.
 */

import { Rule, ToolManifest, Finding } from "./types";
import { compileAll, RuleSpec, rulesForProfile, PROFILES } from "./rule-spec";

import { mcpRules } from "./mcp-rules";
import { tier1Specs } from "./tier1-rules";
import { agentSpecs } from "./agent-rules";
import { remainderSpecs } from "./remainder-rules";
import { complianceSpecs } from "./compliance-rules";
import {
  statefulRules,
  shadowMcpFindings,
  BaselineEntry,
  toolFingerprint,
} from "./stateful-rules";

// ---------------------------------------------------------------------------
// Every declarative spec in one place
// ---------------------------------------------------------------------------

export const allSpecs: RuleSpec[] = [
  ...tier1Specs,      // 19-24
  ...agentSpecs,      // 33-40
  ...remainderSpecs,  // 25-32, 41-43, 46-48, 50
  ...complianceSpecs, // 51-53
];

/**
 * The 36 rules that work on a single tool. Add these to allRules.
 * (7 MCP, hand-written + 29 compiled from specs.)
 */
export const newRules: Rule[] = [...mcpRules, ...compileAll(allSpecs)];

// ---------------------------------------------------------------------------
// The ones that need the whole set
// ---------------------------------------------------------------------------

/**
 * homoglyph-tool-name, duplicate-tool-name, toolset-mutation.
 * Call once you have every manifest loaded, then run over each tool.
 */
export function statefulRulesFor(
  tools: ToolManifest[],
  baseline: BaselineEntry[] = []
): Rule[] {
  return statefulRules(tools, baseline);
}

/** Build a baseline to compare against on later runs. */
export function buildBaseline(tools: ToolManifest[]): BaselineEntry[] {
  return tools.map((t) => ({ name: t.name, hash: toolFingerprint(t) }));
}

/** shadow-mcp-discovery. Reports on the machine, not on a tool. */
export { shadowMcpFindings };
export { RULE_TO_OWASP, OWASP_MCP, owaspCoverage, rulesForOwasp } from "./compliance-rules";

// ---------------------------------------------------------------------------
// Focus profiles
// ---------------------------------------------------------------------------

export { PROFILES };

/** Rule ids belonging to a named focus profile. */
export function ruleIdsForProfile(profile: string): string[] {
  if (profile === "audit") return newRules.map((r) => r.id);
  return rulesForProfile(allSpecs, profile).map((s) => s.id);
}

/**
 * Split findings into the three zones focus mode renders.
 * Criticals outside the focus are promoted, never hidden.
 */
export function applyFocus(
  findings: Finding[],
  profile?: string
): { inFocus: Finding[]; promoted: Finding[]; other: Finding[] } {
  if (!profile || profile === "audit") {
    return { inFocus: findings, promoted: [], other: [] };
  }
  const ids = new Set(ruleIdsForProfile(profile));
  const inFocus: Finding[] = [];
  const promoted: Finding[] = [];
  const other: Finding[] = [];
  for (const f of findings) {
    if (ids.has(f.ruleId)) inFocus.push(f);
    else if (f.severity === "critical") promoted.push(f);
    else other.push(f);
  }
  return { inFocus, promoted, other };
}

// ---------------------------------------------------------------------------
// Counts, so the CLI and the site can't drift apart
// ---------------------------------------------------------------------------

export const RULE_COUNTS = {
  existing: 11,
  mcp: mcpRules.length,
  declarative: allSpecs.length,
  stateful: 3,
  machineLevel: 1, // shadow-mcp-discovery
  get total(): number {
    return (
      this.existing +
      this.mcp +
      this.declarative +
      this.stateful +
      this.machineLevel
    );
  },
};
