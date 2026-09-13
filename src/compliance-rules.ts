/**
 * Rules 51-53 and the OWASP MCP Top 10 mapping.
 *
 * Categories are MCP01:2025 - MCP10:2025, from the OWASP MCP Top 10 project
 * (Phase 3 beta, project lead Vandana Verma Sehgal). Stable enough to cite;
 * re-check owasp.org/www-project-mcp-top-10 before quoting wording in audit
 * material, and note the framework is CC BY-NC-SA 4.0.
 */

import { RuleSpec } from "./rule-spec";

// ---------------------------------------------------------------------------
// The categories
// ---------------------------------------------------------------------------

export const OWASP_MCP = {
  MCP01: "Token Mismanagement & Secret Exposure",
  MCP02: "Privilege Escalation via Scope Creep",
  MCP03: "Tool Poisoning",
  MCP04: "Software Supply Chain Attacks & Dependency Tampering",
  MCP05: "Command Injection & Execution",
  MCP06: "Intent Flow Subversion",
  MCP07: "Insufficient Authentication & Authorization",
  MCP08: "Lack of Audit and Telemetry",
  MCP09: "Shadow MCP Servers",
  MCP10: "Context Injection & Over-Sharing",
} as const;

export type OwaspId = keyof typeof OWASP_MCP;

// ---------------------------------------------------------------------------
// 51 — oauth-misconfiguration          MCP07
// ---------------------------------------------------------------------------

export const oauthMisconfiguration: RuleSpec = {
  id: "oauth-misconfiguration",
  description: "OAuth configuration that weakens the authorization boundary",
  severity: "high",
  confidence: 0.84,
  confidenceReason: "OAuth block present with a wildcard scope, implicit flow, or open redirect",
  message:
    "OAuth is configured in a way that widens access beyond what the server needs. " +
    "Wildcard scopes, the implicit flow, and wildcard redirect URIs each remove a " +
    "control the MCP authorization spec relies on.",
  profiles: ["credentials", "supply-chain", "ci-gate"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(oauth|authorization_endpoint|token_endpoint|client_id|response_type|redirect_uri)",
        flags: "i",
      },
      {
        kind: "any",
        of: [
          // wildcard or admin-wide scope
          { kind: "regex", field: "sourceText",
            pattern: "\"?scopes?\"?\\s*[:=]\\s*\\[?\\s*[\"'](\\*|.*\\badmin\\b.*|.*\\bfull_access\\b.*|.*\\ball\\b.*)[\"']",
            flags: "i" },
          // implicit flow — deprecated, leaks the token in the URL
          { kind: "regex", field: "sourceText",
            pattern: "response_type\\s*[:=]\\s*[\"']?(token|id_token token)",
            flags: "i" },
          // wildcard or scheme-less redirect
          { kind: "regex", field: "sourceText",
            pattern: "redirect_uris?\\s*[:=]\\s*\\[?\\s*[\"'][^\"']*(\\*|localhost:\\*|https?://\\*)",
            flags: "i" },
          // PKCE explicitly disabled
          { kind: "regex", field: "sourceText",
            pattern: "(pkce|code_challenge)\\s*[:=]\\s*(false|\"none\"|'none'|null)",
            flags: "i" },
        ],
      },
    ],
  },
};

// ---------------------------------------------------------------------------
// 52 — permissive-cors                 MCP07
// ---------------------------------------------------------------------------

export const permissiveCors: RuleSpec = {
  id: "permissive-cors",
  description: "CORS policy that allows any origin with credentials",
  severity: "high",
  confidence: 0.88,
  confidenceReason: "wildcard allowed origin on an HTTP-transport server",
  message:
    "Allows requests from any origin. On an HTTP-transport MCP server this lets a " +
    "page the user merely visits call tools on their behalf.",
  profiles: ["credentials", "execution", "ci-gate"],
  match: {
    kind: "any",
    of: [
      { kind: "regex", field: "sourceText",
        pattern: "(Access-Control-Allow-Origin|allowedOrigins?|cors\\.origin)[\"']?\\s*[,:=]\\s*[\"'`]?\\*",
        flags: "i" },
      { kind: "regex", field: "sourceText",
        pattern: "cors\\s*\\(\\s*\\{[^}]*origin\\s*:\\s*true",
        flags: "i" },
      { kind: "all", of: [
        { kind: "regex", field: "sourceText",
          pattern: "Access-Control-Allow-Credentials\\s*[:=]\\s*[\"']?true", flags: "i" },
        { kind: "regex", field: "sourceText",
          pattern: "Access-Control-Allow-Origin\\s*[:=]\\s*[\"'`]?(\\*|.*\\$\\{)", flags: "i" },
      ]},
    ],
  },
};

// ---------------------------------------------------------------------------
// 53 — missing-provenance              MCP04
// ---------------------------------------------------------------------------

export const missingProvenance: RuleSpec = {
  id: "missing-provenance",
  description: "Package installed without any provenance or integrity check",
  severity: "medium",
  confidence: 0.71,
  confidenceReason: "install step with integrity checking explicitly disabled or absent",
  message:
    "Installs a package with no signature, checksum or provenance attestation, " +
    "or with integrity checking switched off. You cannot tell whether what you " +
    "installed is what the maintainer published.",
  profiles: ["supply-chain", "ci-gate"],
  match: {
    kind: "any",
    of: [
      // integrity explicitly disabled
      { kind: "regex", field: "sourceText",
        pattern: "(--no-verify|--no-check-certificate|--insecure|NODE_TLS_REJECT_UNAUTHORIZED\\s*[:=]\\s*[\"']?0|--trusted-host|strict-ssl\\s*[:=]\\s*false|GIT_SSL_NO_VERIFY)",
        flags: "i" },
      // fetch-and-run a binary with no checksum anywhere nearby
      { kind: "all", of: [
        { kind: "regex", field: "sourceText",
          pattern: "(curl|wget|Invoke-WebRequest|iwr)[^\\n]{0,120}\\.(sh|py|exe|bin|tar\\.gz|zip|deb|pkg)",
          flags: "i" },
        { kind: "not", of: { kind: "regex", field: "sourceText",
          pattern: "(sha256|sha512|checksum|integrity|gpg --verify|cosign|sigstore|slsa|minisign)",
          flags: "i" } },
      ]},
    ],
  },
};

export const complianceSpecs: RuleSpec[] = [
  oauthMisconfiguration,
  permissiveCors,
  missingProvenance,
];

// ---------------------------------------------------------------------------
// The mapping — every rule to its OWASP category
// ---------------------------------------------------------------------------

export const RULE_TO_OWASP: Record<string, OwaspId[]> = {
  // --- your original 11 ---
  "excessive-permissions":        ["MCP02"],
  "prompt-injection":             ["MCP06", "MCP03"],
  "exfiltration-pattern":         ["MCP10", "MCP01"],
  "hardcoded-secrets":            ["MCP01"],
  "dynamic-execution":            ["MCP05"],
  "description-mismatch":         ["MCP03"],
  "unicode-obfuscation":          ["MCP03", "MCP06"],
  "loose-parameter-schema":       ["MCP05"],
  "untrusted-external-install":   ["MCP04"],
  "concealed-instruction":        ["MCP06", "MCP03"],
  "opaque-payload":               ["MCP04", "MCP05"],

  // --- MCP config, 12-18 ---
  "mcp-auto-approve":             ["MCP02"],
  "mcp-unpinned-server":          ["MCP04"],
  "mcp-credential-in-config":     ["MCP01"],
  "mcp-overbroad-command":        ["MCP05", "MCP02"],
  "mcp-stdio-injection-surface":  ["MCP06"],
  "mcp-known-vulnerable-version": ["MCP04"],
  "mcp-package-impersonation":    ["MCP04"],

  // --- tier 1, 19-24 ---
  "webhook-sink":                 ["MCP10"],
  "credential-path-access":       ["MCP01"],
  "cloud-metadata-access":        ["MCP01"],
  "install-script-hook":          ["MCP04"],
  "persistence-mechanism":        ["MCP05"],
  "dns-exfiltration":             ["MCP10"],

  // --- tier 2 and group 5, 25-32 ---
  "tool-shadowing":               ["MCP03"],
  "sandbox-escape-hint":          ["MCP05", "MCP02"],
  "string-reassembly":            ["MCP05"],
  "dependency-confusion":         ["MCP04"],
  "permission-escalation-request":["MCP02"],
  "history-file-access":          ["MCP01"],
  "schema-injection":             ["MCP03", "MCP06"],
  "unicode-tag-smuggling":        ["MCP03", "MCP06"],

  // --- agent layer, 33-40 ---
  "markdown-image-beacon":        ["MCP10"],
  "tool-result-forgery":          ["MCP06"],
  "memory-poisoning":             ["MCP06", "MCP10"],
  "deferred-trigger":             ["MCP03", "MCP04"],
  "agent-chain-injection":        ["MCP06"],
  "confused-deputy":              ["MCP02", "MCP07"],
  "system-prompt-extraction":     ["MCP10"],
  "context-history-access":       ["MCP10"],

  // --- bench and parity, 41-50 ---
  "toolset-mutation":             ["MCP03", "MCP04"],
  "toxic-capability-flow":        ["MCP10", "MCP02"],
  "vulnerable-dependency":        ["MCP04"],
  "homoglyph-tool-name":          ["MCP03", "MCP04"],
  "duplicate-tool-name":          ["MCP03"],
  "prompt-in-error-message":      ["MCP06"],
  "network-in-declared-offline":  ["MCP10", "MCP03"],
  "sensitive-data-in-logs":       ["MCP01", "MCP08"],
  "shadow-mcp-discovery":         ["MCP09"],
  "command-injection-surface":    ["MCP05"],

  // --- compliance, 51-53 ---
  "oauth-misconfiguration":       ["MCP07"],
  "permissive-cors":              ["MCP07"],
  "missing-provenance":           ["MCP04"],
};

/** Rules covering a category. */
export function rulesForOwasp(id: OwaspId): string[] {
  return Object.entries(RULE_TO_OWASP)
    .filter(([, ids]) => ids.includes(id))
    .map(([rule]) => rule);
}

/** Coverage table for the site and for security questionnaires. */
export function owaspCoverage(): Array<{
  id: OwaspId; category: string; rules: string[]; count: number;
}> {
  return (Object.keys(OWASP_MCP) as OwaspId[]).map((id) => {
    const rules = rulesForOwasp(id);
    return { id, category: OWASP_MCP[id], rules, count: rules.length };
  });
}
