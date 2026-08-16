/**
 * OWASP Agentic Skills Top 10 (AST10) mapping.
 *
 * AST10 v1.0-2026 is the first dedicated security framework for agent skills
 * (OWASP Incubator project, published March 2026). Mapping findings to it
 * matters for one practical reason: it's the rubric an auditor or security
 * reviewer is increasingly likely to already be asking about, so a finding
 * that names its AST category is far easier to act on and to report upward
 * than one that only names a ryzek rule id.
 *
 * Honest scope note: ryzek covers SOME of AST10, not all of it. Several
 * categories (weak isolation, governance, supply-chain provenance) are
 * runtime or process concerns that a static manifest scanner structurally
 * cannot assess. `AST10_COVERAGE` below states that explicitly rather than
 * implying full-framework coverage.
 */

export interface AstCategory {
  id: string;
  name: string;
}

export const AST_CATEGORIES: Record<string, AstCategory> = {
  AST01: { id: "AST01", name: "Malicious Skills" },
  AST02: { id: "AST02", name: "Supply Chain Compromise" },
  AST03: { id: "AST03", name: "Over-Privileged Skills" },
  AST04: { id: "AST04", name: "Insecure Metadata" },
  AST05: { id: "AST05", name: "Untrusted External Instructions" },
  AST06: { id: "AST06", name: "Weak Isolation" },
  AST07: { id: "AST07", name: "Update Drift" },
  AST08: { id: "AST08", name: "Poor Scanning" },
  AST09: { id: "AST09", name: "No Governance" },
  AST10: { id: "AST10", name: "Cross-Platform Reuse" },
};

/** Maps each ryzek rule to the AST10 category (or categories) it addresses. */
export const RULE_TO_AST: Record<string, string[]> = {
  "excessive-permissions": ["AST03"],
  "prompt-injection-payload": ["AST01", "AST04"],
  "exfiltration-pattern": ["AST01", "AST03"],
  "hardcoded-secret": ["AST04"],
  "dynamic-execution": ["AST01"],
  "description-capability-mismatch": ["AST04"],
  "unicode-obfuscation": ["AST04"],
  "loose-parameter-schema": ["AST03", "AST04"],
  "manifest-drift": ["AST07", "AST02"],
  "untrusted-external-install": ["AST05", "AST01"],
  "concealed-instruction": ["AST04", "AST01"],
  "opaque-payload": ["AST02", "AST01"],
};

/**
 * Which AST10 categories this scanner can and cannot speak to. Stated
 * explicitly so a compliance report built on ryzek output doesn't
 * silently imply coverage that doesn't exist.
 */
export const AST10_COVERAGE: Record<string, { covered: boolean; note: string }> = {
  AST01: { covered: true, note: "Partial — detects known malicious patterns in manifests; cannot detect novel behavioral payloads." },
  AST02: { covered: true, note: "Partial — drift detection catches post-approval changes; no registry provenance or signature verification." },
  AST03: { covered: true, note: "Covered — permission breadth and unconstrained parameter checks." },
  AST04: { covered: true, note: "Covered — secrets, hidden Unicode, description/capability mismatch, loose schemas." },
  AST05: { covered: true, note: "Partial — flags prose instructing download/execution from anonymous hosts (untrusted-external-install). Does not yet resolve or continuously re-scan external instruction URLs referenced by a skill." },
  AST06: { covered: false, note: "Not covered — isolation/sandboxing is a runtime property; static manifest analysis cannot assess it." },
  AST07: { covered: true, note: "Covered — manifest-drift detection with hash baselines." },
  AST08: { covered: false, note: "Not applicable as a finding — this is the category describing scanner quality itself. ryzek's confidence scores and false-positive feedback loop are its answer to it." },
  AST09: { covered: false, note: "Not covered — governance, inventory, and audit logging are organizational processes outside a CLI scanner's scope." },
  AST10: { covered: false, note: "Not covered — cross-platform permission-model comparison is not yet implemented." },
};

export function astLabelsForRule(ruleId: string): string {
  const ids = RULE_TO_AST[ruleId];
  if (!ids || ids.length === 0) return "";
  return ids.map((id) => `${id} ${AST_CATEGORIES[id]?.name ?? ""}`.trim()).join(", ");
}
