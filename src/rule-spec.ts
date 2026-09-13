/**
 * Declarative rule engine.
 *
 * A RuleSpec is data. compileRule() turns it into the same Rule object that
 * rules.ts already exports, so scanner.ts, report.ts, sarif.ts and suppression
 * keep working untouched.
 *
 * Rules that need real logic (AST walks, cross-field comparison, decoding)
 * stay hand-written and sit alongside these in allRules.
 */

import { Finding, Rule, Severity, ToolManifest } from "./types";

// ---------------------------------------------------------------------------
// Fields a matcher can look at
// ---------------------------------------------------------------------------

export type Field =
  | "name"
  | "description"
  | "permissions"
  | "parameters"
  | "sourceText"
  | "command"
  | "env"
  | "raw";

/** Flatten a manifest field to searchable text. */
export function fieldText(tool: ToolManifest, field: Field): string {
  const raw: any = tool.raw ?? {};
  switch (field) {
    case "name":
      return tool.name ?? "";
    case "description":
      return tool.description ?? "";
    case "permissions":
      return (tool.permissions ?? []).join(" ");
    case "parameters":
      return safeJson(tool.parameters);
    case "command":
      return [raw.command ?? "", ...(Array.isArray(raw.args) ? raw.args : [])]
        .join(" ")
        .trim();
    case "env":
      return safeJson(raw.env);
    case "raw":
      return safeJson(raw);
    case "sourceText":
    default:
      // Everything a reviewer would have in front of them.
      return [
        tool.name ?? "",
        tool.description ?? "",
        (tool.permissions ?? []).join(" "),
        safeJson(tool.parameters),
        safeJson(raw),
      ].join("\n");
  }
}

function safeJson(v: unknown): string {
  return flatten(v);
}

/**
 * Flatten a value to readable text.
 *
 * Deliberately NOT JSON.stringify: that escapes quotes to \" and collapses
 * everything onto one line, which breaks any pattern anchored to a line start
 * or matching a quoted attribute. Rules are written against what a reviewer
 * would see, so the text they match has to look like what a reviewer sees.
 */
function flatten(v: unknown, depth = 0): string {
  if (v == null) return "";
  if (depth > 6) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.map((x) => flatten(x, depth + 1)).join("\n");
  if (typeof v === "object") {
    return Object.entries(v as Record<string, unknown>)
      .map(([k, val]) => `${k}: ${flatten(val, depth + 1)}`)
      .join("\n");
  }
  return String(v);
}

// ---------------------------------------------------------------------------
// Matchers
// ---------------------------------------------------------------------------

export type Matcher =
  | { kind: "regex"; field: Field; pattern: string; flags?: string }
  | { kind: "anyOf"; field: Field; values: string[]; caseSensitive?: boolean }
  | { kind: "codepointRange"; field: Field; from: number; to: number }
  | { kind: "entropyAbove"; field: Field; pattern: string; threshold: number }
  | { kind: "isMcp" }
  | { kind: "all"; of: Matcher[] }
  | { kind: "any"; of: Matcher[] }
  | { kind: "not"; of: Matcher };

export interface MatchHit {
  matched: boolean;
  /** The exact text that triggered it — becomes Finding.evidence. */
  evidence?: string;
}

export function evaluate(m: Matcher, tool: ToolManifest): MatchHit {
  switch (m.kind) {
    case "isMcp":
      return { matched: !!(tool.raw as any)?.__mcp };

    case "regex": {
      const re = new RegExp(m.pattern, m.flags ?? "");
      const hit = fieldText(tool, m.field).match(re);
      return hit ? { matched: true, evidence: clip(hit[0]) } : { matched: false };
    }

    case "anyOf": {
      const hay = fieldText(tool, m.field);
      const cmp = m.caseSensitive ? hay : hay.toLowerCase();
      for (const v of m.values) {
        const needle = m.caseSensitive ? v : v.toLowerCase();
        if (cmp.includes(needle)) return { matched: true, evidence: clip(v) };
      }
      return { matched: false };
    }

    case "codepointRange": {
      const text = fieldText(tool, m.field);
      const found: string[] = [];
      for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        if (cp >= m.from && cp <= m.to) {
          const tag = "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
          if (!found.includes(tag)) found.push(tag);
        }
      }
      return found.length
        ? { matched: true, evidence: `${found.length} hidden codepoint(s): ${found.slice(0, 4).join(", ")}` }
        : { matched: false };
    }

    case "entropyAbove": {
      const re = new RegExp(m.pattern, "g");
      const text = fieldText(tool, m.field);
      let hit: RegExpExecArray | null;
      while ((hit = re.exec(text)) !== null) {
        const candidate = hit[1] ?? hit[0];
        if (shannon(candidate) >= m.threshold) {
          return {
            matched: true,
            evidence: `${clip(candidate)} (entropy ${shannon(candidate).toFixed(2)})`,
          };
        }
      }
      return { matched: false };
    }

    case "all": {
      const ev: string[] = [];
      for (const sub of m.of) {
        const r = evaluate(sub, tool);
        if (!r.matched) return { matched: false };
        if (r.evidence) ev.push(r.evidence);
      }
      return { matched: true, evidence: ev.join(" + ") || undefined };
    }

    case "any": {
      for (const sub of m.of) {
        const r = evaluate(sub, tool);
        if (r.matched) return r;
      }
      return { matched: false };
    }

    case "not":
      return { matched: !evaluate(m.of, tool).matched };
  }
}

function clip(s: string, n = 90): string {
  const one = s.replace(/\s+/g, " ").trim();
  return one.length > n ? one.slice(0, n - 1) + "\u2026" : one;
}

export function shannon(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ---------------------------------------------------------------------------
// The spec
// ---------------------------------------------------------------------------

export interface RuleSpec {
  id: string;
  description: string;
  severity: Severity;
  /** 0..1, matching the numeric confidence already used in rules.ts */
  confidence: number;
  confidenceReason: string;
  message: string;
  /** Focus profiles this rule belongs to. */
  profiles: string[];
  match: Matcher;
  /** Suppresses the finding entirely — the false-positive killer. */
  unless?: Matcher;
  /** Context-aware softening rather than suppression. */
  downgradeWhen?: {
    match: Matcher;
    severity: Severity;
    confidence: number;
    confidenceReason: string;
  };
}

export function compileRule(spec: RuleSpec): Rule {
  return {
    id: spec.id,
    description: spec.description,
    check(tool: ToolManifest): Finding[] {
      const hit = evaluate(spec.match, tool);
      if (!hit.matched) return [];
      if (spec.unless && evaluate(spec.unless, tool).matched) return [];

      let severity = spec.severity;
      let confidence = spec.confidence;
      let confidenceReason = spec.confidenceReason;

      if (spec.downgradeWhen && evaluate(spec.downgradeWhen.match, tool).matched) {
        severity = spec.downgradeWhen.severity;
        confidence = spec.downgradeWhen.confidence;
        confidenceReason = spec.downgradeWhen.confidenceReason;
      }

      return [
        {
          ruleId: spec.id,
          severity,
          confidence,
          confidenceReason,
          message: spec.message,
          toolName: tool.name,
          sourceFile: tool.sourceFile,
          evidence: hit.evidence,
        },
      ];
    },
  };
}

export function compileAll(specs: RuleSpec[]): Rule[] {
  return specs.map(compileRule);
}

/** Focus profiles, resolved from the profiles field on each spec. */
export const PROFILES: Record<string, string> = {
  credentials: "Secrets, credential paths, tokens in config or logs",
  exfiltration: "Any route by which data leaves the machine",
  "supply-chain": "Where the code came from and whether it can change",
  "agent-safety": "Attacks aimed at the agent rather than the code",
  execution: "Code execution, escalation, persistence",
  "pre-commit": "Fast, high-confidence subset for a git hook",
  "ci-gate": "Critical and high only, for a build gate",
  audit: "Everything",
};

export function rulesForProfile(specs: RuleSpec[], profile: string): RuleSpec[] {
  if (profile === "audit") return specs;
  return specs.filter((s) => s.profiles.includes(profile));
}
