/**
 * MCP server configuration rules.
 *
 * These follow the same shape as everything in rules.ts: a Rule takes a
 * normalised ToolManifest and returns Findings. MCP servers map onto
 * ToolManifest cleanly — a server is a tool, its launch command and env are
 * its definition, and the config file it came from is its sourceFile.
 *
 * The loader in mcp-loader.ts does that normalisation, so these rules never
 * need to know what an MCP config file looks like.
 */

import { Finding, Rule, ToolManifest } from "./types";

/** Same helper shape as rules.ts, kept local so this file stands alone. */
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
    ruleId,
    severity,
    confidence,
    confidenceReason,
    message,
    toolName: tool.name,
    sourceFile: tool.sourceFile,
    evidence,
  };
}

/** Pull the launch command out of a normalised MCP tool. */
function launchCommand(tool: ToolManifest): string {
  const raw = tool.raw ?? {};
  return [raw.command ?? "", ...(raw.args ?? [])].join(" ").trim();
}

function isMcpServer(tool: ToolManifest): boolean {
  return !!tool.raw?.__mcp;
}

// ---------------------------------------------------------------------------
// mcp-auto-approve
// ---------------------------------------------------------------------------

const SENSITIVE_TOOL_PATTERNS = [
  /exec/i, /shell/i, /bash/i, /command/i, /run_/i,
  /write/i, /delete/i, /remove/i, /rm_/i,
  /credential/i, /secret/i, /token/i, /key/i,
  /http/i, /fetch/i, /request/i, /curl/i,
];

export const mcpAutoApprove: Rule = {
  id: "mcp-auto-approve",
  description:
    "MCP server configured to run tools without user confirmation",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const raw = tool.raw ?? {};
    const auto: string[] = [
      ...(raw.autoApprove ?? []),
      ...(raw.alwaysAllow ?? []),
    ];
    if (auto.length === 0) return [];

    if (auto.some((t: string) => t === "*" || t === "all")) {
      return [
        finding(
          "mcp-auto-approve",
          "critical",
          0.95,
          "explicit wildcard in autoApprove",
          "Auto-approves every tool this server exposes, with no confirmation " +
            "prompt. That includes tools added by future updates you have not " +
            "reviewed.",
          tool,
          `autoApprove: ${JSON.stringify(auto)}`
        ),
      ];
    }

    const risky = auto.filter((t: string) =>
      SENSITIVE_TOOL_PATTERNS.some((p) => p.test(t))
    );
    if (risky.length === 0) return [];

    return [
      finding(
        "mcp-auto-approve",
        "high",
        0.88,
        "tool names indicate side effects",
        `Auto-approves ${risky.length} tool(s) whose names indicate execution, ` +
          `writes, or credential access: ${risky.join(", ")}. These skip the ` +
          `confirmation that would otherwise surface them.`,
        tool,
        `autoApprove: ${JSON.stringify(risky)}`
      ),
    ];
  },
};

// ---------------------------------------------------------------------------
// mcp-unpinned-server
// ---------------------------------------------------------------------------

export const mcpUnpinnedServer: Rule = {
  id: "mcp-unpinned-server",
  description: "MCP server pulled from a package registry with no version pin",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const findings: Finding[] = [];
    const cmd = launchCommand(tool);
    const args: string[] = tool.raw?.args ?? [];

    if (/\b(npx|uvx|pipx|bunx)\b/.test(cmd)) {
      const pkg = args.find((a) => !a.startsWith("-") && a.length > 0);
      const pinned = pkg ? /@\d|@\^|@~|==\d/.test(pkg) : false;
      if (!pinned) {
        findings.push(
          finding(
            "mcp-unpinned-server",
            "high",
            0.84,
            "package runner with no version specifier",
            "Fetches the latest published version on every start, so a " +
              "compromised or maliciously updated release runs automatically " +
              "with no review step.",
            tool,
            cmd
          )
        );
      }
    }

    const url: string | undefined = tool.raw?.url;
    if (url && /^http:\/\//i.test(url)) {
      findings.push(
        finding(
          "mcp-unpinned-server",
          "critical",
          0.93,
          "endpoint scheme is plain http",
          "Server endpoint uses unencrypted HTTP. Tool definitions and every " +
            "argument passed to them — routinely including file contents and " +
            "credentials — travel in cleartext and can be modified in transit.",
          tool,
          url
        )
      );
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// mcp-credential-in-config
// ---------------------------------------------------------------------------

const SECRET_KEY_PATTERNS = [
  /token/i, /secret/i, /password/i, /passwd/i, /api[_-]?key/i,
  /access[_-]?key/i, /private[_-]?key/i, /credential/i, /auth/i,
];

const LITERAL_SECRET_SHAPES = [
  /^sk-[A-Za-z0-9_-]{16,}$/,
  /^ghp_[A-Za-z0-9]{20,}$/,
  /^github_pat_[A-Za-z0-9_]{20,}$/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/,
  /^AKIA[0-9A-Z]{16}$/,
  /^[A-Za-z0-9+/]{40,}={0,2}$/,
];

export const mcpCredentialInConfig: Rule = {
  id: "mcp-credential-in-config",
  description: "Literal credential stored in an MCP server config",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const env: Record<string, unknown> = tool.raw?.env ?? {};
    const findings: Finding[] = [];

    for (const [k, v] of Object.entries(env)) {
      if (typeof v !== "string") continue;

      // ${VAR} / $VAR indirection is the correct pattern, not a finding.
      if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v.trim())) continue;

      const keyLooksSecret = SECRET_KEY_PATTERNS.some((p) => p.test(k));
      if (!keyLooksSecret || v.trim().length <= 8) continue;

      const valueLooksSecret = LITERAL_SECRET_SHAPES.some((p) =>
        p.test(v.trim())
      );

      findings.push(
        finding(
          "mcp-credential-in-config",
          valueLooksSecret ? "critical" : "high",
          valueLooksSecret ? 0.96 : 0.79,
          valueLooksSecret
            ? "value matches a known credential format"
            : "key name indicates a secret and value is a literal",
          `Environment key "${k}" holds a literal value rather than a reference ` +
            `to an environment variable. MCP config files are commonly synced, ` +
            `backed up, and committed, so a secret here leaks with the file.`,
          tool,
          `${k}=${v.slice(0, 6)}…(${v.length} chars)`
        )
      );
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// mcp-overbroad-command
// ---------------------------------------------------------------------------

const DANGEROUS_COMMAND_PATTERNS: Array<[RegExp, string]> = [
  [/\bsudo\b/, "runs with elevated privileges"],
  [/\bcurl\b[^|]*\|\s*(sh|bash)/, "pipes remote content directly into a shell"],
  [/\bwget\b[^|]*\|\s*(sh|bash)/, "pipes remote content directly into a shell"],
  [/\beval\b/, "evaluates dynamically constructed code"],
  [/--no-sandbox/, "explicitly disables sandboxing"],
  [/--allow-all/, "requests unrestricted permissions"],
  [/\/dev\/tcp\//, "opens a raw network socket via shell redirection"],
];

export const mcpOverbroadCommand: Rule = {
  id: "mcp-overbroad-command",
  description: "MCP server launch command requests more capability than needed",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const cmd = launchCommand(tool);
    if (!cmd) return [];

    for (const [pattern, why] of DANGEROUS_COMMAND_PATTERNS) {
      if (pattern.test(cmd)) {
        return [
          finding(
            "mcp-overbroad-command",
            "critical",
            0.91,
            "launch command matches a known dangerous pattern",
            `Launch command ${why}. This grants the server more capability than ` +
              `exposing tools requires, and the agent has no visibility into what ` +
              `it does at startup.`,
            tool,
            cmd
          ),
        ];
      }
    }
    return [];
  },
};

// ---------------------------------------------------------------------------
// mcp-stdio-injection-surface
// ---------------------------------------------------------------------------

const UNTRUSTED_CONFIG_SIGNALS: Array<[RegExp, string]> = [
  [/\$\{[^}]*\}/, "interpolates a variable at launch time"],
  [/\$\(/, "contains command substitution, which executes before the server starts"],
  [/`[^`]+`/, "contains backtick substitution, which executes before the server starts"],
  [/\bnpx\b[^|]*\s-c\b/, "uses npx -c, the documented bypass for command allowlists"],
  [/;|\|\||&&/, "chains multiple commands with a shell operator"],
  [/\bsh\s+-c\b|\bbash\s+-c\b/, "invokes a shell with an inline command string"],
];

export const mcpStdioInjectionSurface: Rule = {
  id: "mcp-stdio-injection-surface",
  description:
    "MCP STDIO transport passes config values into subprocess execution",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const raw = tool.raw ?? {};

    // Non-stdio transports don't route through the vulnerable path.
    const declared = String(raw.transport ?? raw.type ?? "").toLowerCase();
    if (declared === "sse" || declared === "http" || declared === "streamable-http") {
      return [];
    }
    if (!raw.command || raw.url) return [];

    const cmd = launchCommand(tool);
    if (!cmd) return [];

    const matched = UNTRUSTED_CONFIG_SIGNALS.filter(([p]) => p.test(cmd)).map(
      ([, why]) => why
    );

    if (matched.length === 0) {
      return [
        finding(
          "mcp-stdio-injection-surface",
          "low",
          0.6,
          "stdio transport in use, but this command is a literal string",
          "Uses MCP STDIO transport, where configuration values are passed to " +
            "subprocess execution without sanitisation by the SDK. This command " +
            "is literal, so there is no injection path visible here — but anything " +
            "able to write to this config file can substitute an arbitrary command. " +
            "Anthropic has stated this is by design and will not be patched, so the " +
            "available control is restricting write access to the config file itself.",
          tool,
          cmd.slice(0, 120)
        ),
      ];
    }

    const isBypass = /npx -c|sh -c|bash -c/.test(cmd);
    return [
      finding(
        "mcp-stdio-injection-surface",
        isBypass ? "critical" : "high",
        isBypass ? 0.92 : 0.85,
        isBypass
          ? "command form is the documented allowlist bypass"
          : "config value reaches the command line dynamically",
        `MCP STDIO transport executes configuration values as a subprocess ` +
          `without sanitisation, and this entry ${matched.join("; ")}. That turns ` +
          `a config value into a command execution path on the host.` +
          (isBypass
            ? " This form also defeats command allowlisting, which is why " +
              "filtering commands is not sufficient on its own."
            : ""),
        tool,
        cmd.slice(0, 160)
      ),
    ];
  },
};

// ---------------------------------------------------------------------------
// mcp-known-vulnerable-version
// ---------------------------------------------------------------------------

interface Advisory {
  cve: string;
  product: string;
  match: RegExp;
  fixedIn: string | null;
  severity: Finding["severity"];
  summary: string;
  note?: string;
}

/**
 * Hand-verified advisory set. Deliberately small: a wrong entry produces a
 * false accusation against a real package, which is worse than a miss.
 * Shipped with the package and checked on release — never fetched at scan
 * time, so this stays offline.
 */
export const KNOWN_VULNERABILITIES: Advisory[] = [
  {
    cve: "CVE-2026-30623",
    product: "litellm",
    match: /\blitellm\b/i,
    fixedIn: "1.83.7",
    severity: "high",
    summary:
      "Command injection via MCP stdio transport: the command field was passed " +
      "straight to StdioServerParameters and executed on the proxy host.",
    note:
      "Required a valid API key — not exploitable unauthenticated. " +
      "v1.83.7-stable is the first stable release with the fix.",
  },
  {
    cve: "CVE-2025-49596",
    product: "mcp-inspector",
    match: /@modelcontextprotocol\/inspector|\bmcp-inspector\b/i,
    fixedIn: "0.14.1",
    severity: "critical",
    summary:
      "Versions below 0.14.1 lacked authentication between the Inspector client " +
      "and its proxy, allowing unauthenticated requests to launch MCP commands.",
  },
  {
    cve: "CVE-2026-30615",
    product: "windsurf",
    match: /\bwindsurf\b/i,
    fixedIn: null,
    severity: "critical",
    summary:
      "Prompt injection leading to local remote code execution, reported " +
      "against Windsurf 1.9544.26.",
    note: "Exploitation required zero user interaction. Check the vendor advisory.",
  },
  {
    cve: "CVE-2026-33252",
    product: "mcp-go-sdk",
    match: /modelcontextprotocol\/go-sdk/i,
    fixedIn: null,
    severity: "high",
    summary:
      "Cross-site tool execution for HTTP servers without authorisation: a " +
      "malicious site could POST into MCP message handling without a preflight.",
  },
];

export function compareVersions(a: string, b: string): number {
  const norm = (v: string) =>
    v.replace(/^v/, "").split(/[.\-+]/).map((p) => (/^\d+$/.test(p) ? parseInt(p, 10) : p));
  const pa = norm(a), pb = norm(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i], y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === "number" && typeof y === "number") {
      if (x !== y) return x < y ? -1 : 1;
    } else if (String(x) !== String(y)) {
      return String(x) < String(y) ? -1 : 1;
    }
  }
  return 0;
}

export function extractVersion(spec: string): string | null {
  return spec.match(/[@=]{1,2}(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)/)?.[1] ?? null;
}

export const mcpKnownVulnerableVersion: Rule = {
  id: "mcp-known-vulnerable-version",
  description: "MCP server pinned to a version with a published advisory",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const full = [launchCommand(tool), tool.raw?.url ?? ""].join(" ");
    if (!full.trim()) return [];

    const findings: Finding[] = [];

    for (const adv of KNOWN_VULNERABILITIES) {
      if (!adv.match.test(full)) continue;
      const version = extractVersion(full);

      if (!version) {
        findings.push(
          finding(
            "mcp-known-vulnerable-version",
            "medium",
            0.55,
            "product matches an advisory but no version is pinned",
            `References ${adv.product}, which has a published advisory (${adv.cve}), ` +
              `but no version is pinned so this cannot be confirmed. ${adv.summary}` +
              (adv.fixedIn ? ` Fixed in ${adv.fixedIn} and later.` : "") +
              ` Pinning a version would give a definite answer.`,
            tool,
            `${adv.product}, version unpinned`
          )
        );
        continue;
      }

      if (adv.fixedIn && compareVersions(version, adv.fixedIn) >= 0) continue;

      findings.push(
        finding(
          "mcp-known-vulnerable-version",
          adv.severity,
          0.94,
          "pinned version is below the published fix",
          `${adv.product} ${version} is affected by ${adv.cve}. ${adv.summary}` +
            (adv.note ? ` ${adv.note}` : "") +
            (adv.fixedIn
              ? ` Upgrade to ${adv.fixedIn} or later.`
              : " No fixed version published at time of writing."),
          tool,
          `${adv.product}@${version} < ${adv.fixedIn ?? "no fix"}`
        )
      );
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// mcp-package-impersonation
// ---------------------------------------------------------------------------

export const KNOWN_PACKAGES: string[] = [
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-gitlab",
  "@modelcontextprotocol/server-slack",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-sqlite",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-memory",
  "@modelcontextprotocol/inspector",
  "@modelcontextprotocol/sdk",
  "mcp-remote",
  "litellm",
  "postmark-mcp",
];

export function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const d: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

function normalisePkg(name: string): string {
  return name
    .toLowerCase()
    .replace(/[-_.]/g, "")
    .replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s")
    .replace(/rn/g, "m");
}

export const mcpPackageImpersonation: Rule = {
  id: "mcp-package-impersonation",
  description: "MCP server package name closely resembles a widely used package",
  check(tool) {
    if (!isMcpServer(tool)) return [];
    const args: string[] = tool.raw?.args ?? [];
    const all = [tool.raw?.command ?? "", ...args];
    const runnerIdx = all.findIndex((a) => /^(npx|uvx|pipx|bunx)$/i.test(a));
    if (runnerIdx === -1) return [];

    const spec = all.slice(runnerIdx + 1).find((a) => !a.startsWith("-"));
    if (!spec) return [];

    const clean = spec.replace(/@[\d.^~><=\s]+.*$/, "").trim();
    if (!clean) return [];
    if (KNOWN_PACKAGES.some((k) => k.toLowerCase() === clean.toLowerCase())) return [];

    const normSuspect = normalisePkg(clean);

    for (const known of KNOWN_PACKAGES) {
      const normKnown = normalisePkg(known);
      if (normSuspect === normKnown) {
        return [
          finding(
            "mcp-package-impersonation",
            "high",
            0.86,
            "identical once separators and lookalike characters are normalised",
            `"${clean}" is identical to "${known}" once hyphens, underscores and ` +
              `lookalike characters are ignored. Typosquatted packages have been ` +
              `used to get fake MCP servers installed, and a substituted server ` +
              `inherits whatever credentials the real one would have had.\n\n` +
              `This is a prompt to verify, not a verdict — check the publisher and ` +
              `repository before deciding.`,
            tool,
            `"${clean}" vs "${known}"`
          ),
        ];
      }

      const dist = editDistance(normSuspect, normKnown);
      const threshold = normKnown.length > 10 ? 2 : 1;
      if (dist > 0 && dist <= threshold) {
        return [
          finding(
            "mcp-package-impersonation",
            "medium",
            dist === 1 ? 0.74 : 0.62,
            `differs by ${dist} character(s) from a widely used package`,
            `"${clean}" closely resembles "${known}". Verify the publisher and ` +
              `repository before trusting it. Legitimate forks often have similar ` +
              `names, so this is a check rather than an accusation.`,
            tool,
            `"${clean}" vs "${known}" (distance ${dist})`
          ),
        ];
      }
    }

    return [];
  },
};

// ---------------------------------------------------------------------------

/** Add these to allRules in rules.ts. */
export const mcpRules: Rule[] = [
  mcpAutoApprove,
  mcpUnpinnedServer,
  mcpCredentialInConfig,
  mcpOverbroadCommand,
  mcpStdioInjectionSurface,
  mcpKnownVulnerableVersion,
  mcpPackageImpersonation,
];
