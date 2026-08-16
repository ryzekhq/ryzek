export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** A normalized representation of one agent tool/skill, regardless of source format. */
export interface ToolManifest {
  name: string;
  description: string;
  sourceFile: string;
  parameters?: Record<string, any>;
  permissions?: string[]; // e.g. ["filesystem:read", "filesystem:write", "network:*", "shell:exec"]
  raw: any;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  /** 0-1: how confident the rule is that this is a real issue, not a false positive. */
  confidence: number;
  message: string;
  /** Short, human-readable reason the confidence is what it is (e.g. "exact secret-format match"). */
  confidenceReason: string;
  toolName: string;
  sourceFile: string;
  evidence?: string;
  /** True if a user has previously marked this exact ruleId+toolName combo as a false positive. */
  suppressed?: boolean;
}

export interface ScanResult {
  toolName: string;
  sourceFile: string;
  findings: Finding[];
  overallSeverity: Severity;
}

export interface Rule {
  id: string;
  description: string;
  check: (tool: ToolManifest) => Finding[];
}
