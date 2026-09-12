/**
 * Rules 41, 44, 45, 49 — the ones a RuleSpec can't express.
 *
 * A RuleSpec sees one tool at a time. These need either the whole manifest set
 * (duplicate names, homoglyph collisions), a stored baseline (mutation), or the
 * filesystem (shadow discovery). So they are hand-written Rules.
 */

import { Finding, Rule, ToolManifest } from "./types";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

function finding(
  ruleId: string,
  severity: Finding["severity"],
  confidence: number,
  confidenceReason: string,
  message: string,
  tool: ToolManifest,
  evidence?: string
): Finding {
  return {
    ruleId, severity, confidence, confidenceReason, message,
    toolName: tool.name, sourceFile: tool.sourceFile, evidence,
  };
}

// ---------------------------------------------------------------------------
// 44 — homoglyph-tool-name
// A name that looks like another name but is not.
// ---------------------------------------------------------------------------

/** Characters commonly substituted to make a name look identical. */
const CONFUSABLES: Record<string, string> = {
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
  "\u0445": "x", "\u0443": "y", "\u04bb": "h", "\u0456": "i", "\u0458": "j",
  "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u0131": "i", "\u2010": "-",
  "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u00ad": "",
};

export function skeleton(name: string): string {
  let out = "";
  for (const ch of name) {
    out += CONFUSABLES[ch] ?? ch;
  }
  // Case-fold and collapse the classic l/I/1 and O/0 confusions.
  return out.toLowerCase().replace(/[l1|]/g, "i").replace(/0/g, "o");
}

export function homoglyphToolName(all: ToolManifest[]): Rule {
  return {
    id: "homoglyph-tool-name",
    description: "Tool name that renders like another tool's name",
    check(tool) {
      const mine = skeleton(tool.name);
      const clashes = all.filter(
        (t) => t.name !== tool.name && skeleton(t.name) === mine
      );
      if (!clashes.length) return [];

      // Non-ASCII in the name makes it deliberate rather than coincidental.
      const hasNonAscii = /[^\x00-\x7F]/.test(tool.name);
      return [
        finding(
          "homoglyph-tool-name",
          "high",
          hasNonAscii ? 0.94 : 0.72,
          hasNonAscii
            ? "name contains non-ASCII characters that render as ASCII ones"
            : "name differs from another tool only by visually similar characters",
          `Renders identically to ${clashes.map((c) => `"${c.name}"`).join(", ")}. ` +
            `Whichever the agent resolves first is the one that runs.`,
          tool,
          `"${tool.name}" vs "${clashes[0].name}"`
        ),
      ];
    },
  };
}

// ---------------------------------------------------------------------------
// 45 — duplicate-tool-name
// Same name, two sources. Load order decides which wins.
// ---------------------------------------------------------------------------

export function duplicateToolName(all: ToolManifest[]): Rule {
  return {
    id: "duplicate-tool-name",
    description: "Two tools registered under the same name",
    check(tool) {
      const dupes = all.filter(
        (t) => t.name === tool.name && t.sourceFile !== tool.sourceFile
      );
      if (!dupes.length) return [];
      return [
        finding(
          "duplicate-tool-name",
          "medium",
          0.9,
          "identical name declared in more than one source file",
          `Also declared in ${dupes.map((d) => d.sourceFile).join(", ")}. ` +
            `Load order decides which definition the agent uses, and load order is ` +
            `not something you control.`,
          tool,
          `${tool.name} in ${[tool.sourceFile, ...dupes.map((d) => d.sourceFile)].join(" + ")}`
        ),
      ];
    },
  };
}

// ---------------------------------------------------------------------------
// 41 — toolset-mutation
// Compare against an approved baseline. The rug-pull check.
// ---------------------------------------------------------------------------

export interface BaselineEntry {
  name: string;
  hash: string;
}

/** Stable hash of everything the agent actually reads about a tool. */
export function toolFingerprint(tool: ToolManifest): string {
  const material = [
    tool.name,
    tool.description ?? "",
    JSON.stringify(tool.parameters ?? {}),
    (tool.permissions ?? []).slice().sort().join(","),
  ].join("\u0000");
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < material.length; i++) {
    const c = material.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 + c, 0x85ebca6b) >>> 0;
  }
  return (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0"));
}

export function toolsetMutation(baseline: BaselineEntry[]): Rule {
  const byName = new Map(baseline.map((b) => [b.name, b.hash]));
  return {
    id: "toolset-mutation",
    description: "Tool definition changed since it was approved",
    check(tool) {
      const known = byName.get(tool.name);
      if (known === undefined) {
        if (baseline.length === 0) return [];
        return [
          finding(
            "toolset-mutation", "medium", 0.85,
            "tool is present now and absent from the approved baseline",
            `Appeared since the baseline was taken. It has not been reviewed.`,
            tool, `new tool: ${tool.name}`
          ),
        ];
      }
      const now = toolFingerprint(tool);
      if (now === known) return [];
      return [
        finding(
          "toolset-mutation", "high", 0.97,
          "fingerprint of the description, schema or permissions has changed",
          `Definition has changed since it was approved. A server that behaves during ` +
            `review and differently afterwards is the rug-pull pattern.`,
          tool, `${known.slice(0, 8)} \u2192 ${now.slice(0, 8)}`
        ),
      ];
    },
  };
}

// ---------------------------------------------------------------------------
// 49 — shadow-mcp-discovery
// Config files and running servers the user did not declare.
// ---------------------------------------------------------------------------

export const CLIENT_CONFIG_PATHS: string[] = [
  "Library/Application Support/Claude/claude_desktop_config.json",
  ".config/Claude/claude_desktop_config.json",
  "AppData/Roaming/Claude/claude_desktop_config.json",
  ".cursor/mcp.json",
  ".codeium/windsurf/mcp_config.json",
  ".config/windsurf/mcp_config.json",
  "Library/Application Support/Code/User/settings.json",
  ".vscode/mcp.json",
  ".config/zed/settings.json",
  ".continue/config.json",
  ".aider.conf.yml",
  ".config/cline/mcp_settings.json",
  "Library/Application Support/Claude Code/config.json",
  ".claude/settings.json",
  ".mcp.json",
  ".config/mcp/config.json",
];

export interface ShadowResult {
  path: string;
  servers: string[];
  declared: boolean;
}

/**
 * Walk every known client config location plus the project directory.
 * `declared` lists paths the user has told us about; anything else is shadow.
 */
export function findMcpConfigs(
  projectDir: string = process.cwd(),
  declared: string[] = []
): ShadowResult[] {
  const home = os.homedir();
  const seen = new Set<string>();
  const out: ShadowResult[] = [];

  const candidates = [
    ...CLIENT_CONFIG_PATHS.map((p) => path.join(home, p)),
    ...CLIENT_CONFIG_PATHS.map((p) => path.join(projectDir, p)),
  ];

  for (const file of candidates) {
    if (seen.has(file)) continue;
    seen.add(file);
    let text: string;
    try {
      if (!fs.existsSync(file)) continue;
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    let servers: string[] = [];
    try {
      const parsed = JSON.parse(text);
      const block =
        parsed.mcpServers ?? parsed.servers ?? parsed["mcp.servers"] ?? {};
      servers = Object.keys(block);
    } catch {
      // Non-JSON config (yaml, jsonc). Still worth reporting that it exists.
      servers = [];
    }
    if (!servers.length && !/mcp/i.test(text)) continue;
    out.push({
      path: file,
      servers,
      declared: declared.some((d) => path.resolve(d) === path.resolve(file)),
    });
  }
  return out;
}

/**
 * Build the finding set. Not a per-tool Rule — this one reports on the machine,
 * so the scanner calls it once and appends the results.
 */
export function shadowMcpFindings(
  projectDir: string = process.cwd(),
  declared: string[] = []
): Finding[] {
  const results = findMcpConfigs(projectDir, declared);
  const shadow = results.filter((r) => !r.declared);
  if (!shadow.length) return [];

  const totalServers = shadow.reduce((n, r) => n + r.servers.length, 0);
  return shadow.map((r) => ({
    ruleId: "shadow-mcp-discovery",
    severity: r.servers.length ? ("high" as const) : ("low" as const),
    confidence: r.servers.length ? 0.92 : 0.5,
    confidenceReason: r.servers.length
      ? "config file with declared servers, not covered by this scan's inputs"
      : "file matches a known MCP config location but declares no servers",
    message: r.servers.length
      ? `${r.servers.length} MCP server(s) configured here and not included in what ` +
        `you asked to scan: ${r.servers.join(", ")}. Across this machine, ` +
        `${totalServers} server(s) are configured outside your declared set.`
      : `A known MCP config location exists here but could not be parsed. ` +
        `Worth a look by hand.`,
    toolName: path.basename(r.path),
    sourceFile: r.path,
    evidence: r.servers.slice(0, 6).join(", ") || "(unparsed)",
  }));
}

export function statefulRules(
  all: ToolManifest[],
  baseline: BaselineEntry[] = []
): Rule[] {
  return [
    homoglyphToolName(all),
    duplicateToolName(all),
    toolsetMutation(baseline),
  ];
}
