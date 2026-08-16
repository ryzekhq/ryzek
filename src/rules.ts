import { Finding, Rule, ToolManifest } from "./types";
import { findEncodedBlob } from "./binary-inspect";

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

// --- Rule 1: excessive / dangerous permission requests ---
const DANGEROUS_PERMISSIONS = [
  "shell:exec",
  "filesystem:write:/",
  "filesystem:*",
  "network:*",
  "process:spawn",
];

const excessivePermissions: Rule = {
  id: "excessive-permissions",
  description: "Flags tools requesting unusually broad or dangerous permissions.",
  check: (tool) => {
    const findings: Finding[] = [];
    const perms = tool.permissions ?? [];
    for (const p of perms) {
      if (DANGEROUS_PERMISSIONS.includes(p)) {
        findings.push(
          finding(
            "excessive-permissions",
            "high",
            0.9,
            `Exact match against known-dangerous permission string "${p}" — low false-positive rate.`,
            `Requests broad/dangerous permission "${p}". Verify this is actually required for the tool's stated purpose.`,
            tool,
            p
          )
        );
      }
    }
    return findings;
  },
};

// --- Rule 2: prompt injection payloads hidden in descriptions/metadata ---
const INJECTION_PATTERNS = [
  /ignore (all|previous|prior) instructions/i,
  /disregard (the )?(system|previous) prompt/i,
  /you are now (in )?(developer|debug|god) mode/i,
  /do not (tell|inform|mention) the user/i,
  /this is a (hidden|secret) instruction/i,
];

/**
 * Legitimate-phrasing allowlist.
 *
 * The single most-documented failure mode of pattern-matching skill scanners
 * is flagging completely standard MCP tool-chaining language as "prompt
 * injection" — published audits have found the majority of a scanner's
 * injection hits were phrases like "You MUST call this function first",
 * which is ordinary, correct tool-dependency documentation.
 *
 * These patterns don't suppress a finding outright (an attacker could just
 * wrap a real payload in polite tool-chaining language). They mark the
 * surrounding context as *plausibly legitimate*, which drops the confidence
 * score and says so in the reason. The user still sees the finding; they
 * just see it correctly ranked below the high-confidence ones.
 */
const LEGITIMATE_INSTRUCTION_PATTERNS = [
  /you (must|should) (first )?call/i,
  /call (this|the) (tool|function|endpoint) (first|before)/i,
  /(before|prior to) (calling|using) this tool/i,
  /required parameter/i,
  /use this tool (when|only when|if)/i,
  /returns? (a |an )?(list|object|json|string)/i,
];

/**
 * Self-reference guard: a security tool's own manifest legitimately contains
 * injection-language examples (ryzek's own rule descriptions do). If the
 * manifest reads like security tooling AND the match sits near that framing,
 * that's a strong signal it's a description of an attack, not an attack.
 */
const SECURITY_CONTEXT_PATTERNS = [
  /\b(scanner|scanning|detect(s|ion)?|flags?|security|vulnerab)/i,
  /\b(example|sample|test|fixture|pattern|rule)\b/i,
];

const promptInjection: Rule = {
  id: "prompt-injection-payload",
  description: "Flags tool descriptions/metadata containing embedded instructions aimed at the agent, not the user.",
  check: (tool) => {
    const findings: Finding[] = [];
    const text = JSON.stringify(tool.raw);

    const looksLikeToolChaining = LEGITIMATE_INSTRUCTION_PATTERNS.some((p) => p.test(text));
    const looksLikeSecurityContext = SECURITY_CONTEXT_PATTERNS.every((p) => p.test(text));

    for (const pattern of INJECTION_PATTERNS) {
      const match = text.match(pattern);
      if (!match) continue;

      let confidence = 0.65;
      let severity: Finding["severity"] = "critical";
      let reason =
        `Matched phrase "${match[0]}" against a known injection-language pattern. ` +
        `These phrases are rare in legitimate tool metadata, but review the surrounding text — ` +
        `quoting or discussing such phrases (e.g. in a security tool's own description) can also trigger this.`;

      if (looksLikeSecurityContext) {
        confidence = 0.25;
        severity = "low";
        reason =
          `Matched "${match[0]}", but this manifest reads like security tooling (it also contains scanner/detection ` +
          `and example/pattern language). Security tools legitimately quote injection phrases in their own ` +
          `descriptions, so this is most likely a description of an attack rather than an attack. Confidence ` +
          `lowered from 65% to 25% for that reason — confirm by reading the surrounding text.`;
      } else if (looksLikeToolChaining) {
        confidence = 0.45;
        severity = "medium";
        reason =
          `Matched "${match[0]}", but this manifest also contains standard MCP tool-chaining language ` +
          `(e.g. "you must call... first", "required parameter"). Ordinary tool-dependency documentation is the ` +
          `single most common source of false positives in this rule across published scanner audits, so ` +
          `confidence is lowered from 65% to 45%. Still worth reading — an attacker can wrap a real payload in ` +
          `polite tool-chaining phrasing.`;
      }

      findings.push(
        finding(
          "prompt-injection-payload",
          severity,
          confidence,
          reason,
          `Tool metadata contains a phrase consistent with a prompt-injection payload aimed at manipulating the agent's behavior.`,
          tool,
          match[0]
        )
      );
    }
    return findings;
  },
};

// --- Rule 3: exfiltration pattern — reads sensitive data AND has outbound network capability ---
const SENSITIVE_READ_HINTS = ["env", "credentials", "secrets", "ssh", "password", "token", "keychain"];
const NETWORK_HINTS = ["network:*", "http:post", "fetch", "webhook"];

const exfiltrationPattern: Rule = {
  id: "exfiltration-pattern",
  description: "Flags tools that both access sensitive data and can send data out to the network.",
  check: (tool) => {
    const perms = (tool.permissions ?? []).map((p) => p.toLowerCase());
    const text = (tool.description + " " + JSON.stringify(tool.parameters ?? {})).toLowerCase();

    const readsSensitive = SENSITIVE_READ_HINTS.some((h) => text.includes(h) || perms.some((p) => p.includes(h)));
    const hasNetwork = NETWORK_HINTS.some((h) => perms.some((p) => p.includes(h)) || text.includes(h));

    if (readsSensitive && hasNetwork) {
      return [
        finding(
          "exfiltration-pattern",
          "critical",
          0.55,
          `Keyword co-occurrence heuristic (sensitive-data term + network term appearing in the same manifest), not a verified data flow between them — the tool may legitimately need both without one feeding the other. Worth a manual look before treating as confirmed.`,
          `Tool appears to both access sensitive data (credentials/env/secrets) and have outbound network capability in the same definition. This combination is the single most common pattern behind real agent-skill data exfiltration.`,
          tool
        ),
      ];
    }
    return [];
  },
};

// --- Rule 4: hardcoded secrets left in the manifest itself ---
const SECRET_PATTERNS = [
  /sk-[a-zA-Z0-9]{20,}/, // generic API-key-shaped string
  /AKIA[0-9A-Z]{16}/, // AWS access key pattern
  /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
];

const hardcodedSecrets: Rule = {
  id: "hardcoded-secret",
  description: "Flags manifests that contain what looks like a live credential.",
  check: (tool) => {
    const findings: Finding[] = [];
    const text = JSON.stringify(tool.raw);
    for (const pattern of SECRET_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        findings.push(
          finding(
            "hardcoded-secret",
            "critical",
            0.95,
            `Exact structural match against a known credential format (e.g. AWS key prefix, PEM header, API-key shape). These formats essentially never occur by coincidence — very low false-positive rate.`,
            `Manifest appears to contain a hardcoded credential. Revoke it immediately if real, and never ship secrets inside a tool definition.`,
            tool,
            match[0].slice(0, 12) + "…" // don't echo the full secret back out
          )
        );
      }
    }
    return findings;
  },
};


/**
 * Returns true if the given index falls inside an HTML comment.
 *
 * Markdown renderers hide HTML comments, but an LLM reading the raw file
 * reads them in full. That asymmetry — invisible to the reviewer, visible to
 * the model — is the same concealment principle as hidden-Unicode smuggling,
 * and a real corpus sample uses it to hide curl-pipe-to-shell commands behind
 * innocuous-looking prose.
 *
 * Note the corpus sample uses an unterminated `<!--` ... `>` form rather than
 * a well-formed `-->`, so both terminators are accepted.
 */
export function isInsideHtmlComment(text: string, index: number): boolean {
  const before = text.slice(0, index);
  const lastOpen = before.lastIndexOf("<!--");
  if (lastOpen === -1) return false;
  const afterOpen = before.slice(lastOpen);
  // If a comment terminator appears between the opener and our match, we're outside it.
  return !/-->|\\n>/.test(afterOpen);
}

// --- Rule 5: obfuscation / dynamic execution red flags ---
const EXEC_PATTERNS = [
  /curl[^|]*\|\s*(bash|sh)/i,
  /wget[^|]*\|\s*(bash|sh)/i,
  /base64\s*-[dD].*\|\s*(bash|sh)/i,
  /eval\s*\(/i,
  /child_process/i,
  /os\.system\s*\(/i,
  // Outbound curl/wget carrying command substitution or local data. The
  // ToxicSkills "vercel" sample exfiltrates via `curl --data "$(uname -a)"`
  // with no pipe to a shell at all, so pipe-to-bash patterns alone miss it —
  // this was a real miss against the real corpus, not a hypothetical.
  /curl\s+[^\n]*(--data|-d\s|--upload-file|-T\s)[^\n]*\$\(/i,
  /curl\s+[^\n]*\$\([^)]+\)[^\n]*https?:\/\//i,
  /wget\s+[^\n]*--post-(data|file)[^\n]*\$\(/i,
];

const dynamicExecution: Rule = {
  id: "dynamic-execution",
  description: "Flags obfuscated or dynamic-execution patterns commonly used to hide malicious behavior.",
  check: (tool) => {
    const findings: Finding[] = [];
    const text = JSON.stringify(tool.raw);
    const lowered = text.toLowerCase();

    // Measured against the real corpus: the legitimate Snyk CLI skill
    // (`curl ... downloads.snyk.io/... -o snyk`) tripped the curl-pipe pattern
    // and produced a false positive. A fetch from a first-party vendor domain
    // or public registry is an accountable distribution channel, so findings
    // whose only trigger sits alongside such a domain get downgraded rather
    // than reported at full confidence.
    const trustedSource = TRUSTED_INSTALL_SOURCES.find((d) => lowered.includes(d));

    for (const pattern of EXEC_PATTERNS) {
      // Scan EVERY match, not just the first. Measured against the real
      // corpus: a sample placed a benign-looking vendor curl before a
      // malicious one, and first-match-only meant the malicious second
      // command was never evaluated at all.
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
      const matches = [...text.matchAll(globalPattern)];
      for (const match of matches) {
        const isCurlish = /curl|wget/i.test(match[0]);
        // Concealment overrides the vendor allowlist: a command hidden inside
        // an HTML comment is not "normal install documentation" regardless of
        // which domain it points at, because the user never sees it rendered.
        const concealed = isInsideHtmlComment(text, match.index ?? 0);
        if (trustedSource && isCurlish && !concealed) {
          findings.push(
            finding(
              "dynamic-execution",
              "low",
              0.2,
              `Matched "${match[0].slice(0, 60)}", but the surrounding text references ${trustedSource}, a first-party vendor domain or public package registry. Fetching an installer from an accountable, named source is normal software installation, so confidence is lowered from 75% to 20%. Verify the domain is genuinely the vendor's and not a lookalike.`,
              `Manifest contains a download-and-execute pattern, but pointed at what appears to be a legitimate vendor distribution channel.`,
              tool,
              match[0].slice(0, 80)
            )
          );
          continue;
        }
        findings.push(
          finding(
            "dynamic-execution",
            "high",
            0.75,
            `Exact match against a known dynamic-execution pattern ("${match[0].slice(
              0,
              60
            )}"). Fairly specific, but some legitimate tools use eval/child_process intentionally — check the surrounding logic.`,
            `Manifest contains a pattern associated with obfuscated or dynamic code execution.`,
            tool,
            match[0].slice(0, 80)
          )
        );
      }
    }
    return findings;
  },
};

// --- Rule 6: description/capability mismatch ---
// Heuristic: description mentions a narrow, benign purpose, but declared params suggest
// far broader capability (write/delete/pay/execute) than described.
const BENIGN_DESCRIPTION_HINTS = ["read", "lookup", "check", "view", "list", "display", "get"];
const BROAD_PARAM_HINTS = ["delete", "write", "pay", "transfer", "execute", "drop", "admin"];

const descriptionMismatch: Rule = {
  id: "description-capability-mismatch",
  description: "Flags tools whose description sounds narrow/read-only but whose parameters imply much broader capability.",
  check: (tool) => {
    const desc = tool.description.toLowerCase();
    const paramsText = JSON.stringify(tool.parameters ?? {}).toLowerCase();

    const soundsBenign = BENIGN_DESCRIPTION_HINTS.some((h) => desc.includes(h));
    const impliesBroad = BROAD_PARAM_HINTS.some((h) => paramsText.includes(h));

    if (soundsBenign && impliesBroad && !BROAD_PARAM_HINTS.some((h) => desc.includes(h))) {
      return [
        finding(
          "description-capability-mismatch",
          "medium",
          0.45,
          `Keyword heuristic comparing description tone against parameter names — the weakest signal in this scanner, since parameter names alone don't prove behavior. Treat as a prompt to go read the tool's actual implementation.`,
          `Description reads as a narrow/read-only action, but declared parameters suggest broader capability (e.g. delete/write/transfer). Worth confirming the description isn't understating what this tool actually does.`,
          tool
        ),
      ];
    }
    return [];
  },
};

// --- Rule 7: hidden/invisible Unicode used to smuggle instructions past human review ---
// Real technique (documented as "ASCII smuggling" / Unicode Tags-block injection): characters
// like zero-width spaces, bidi overrides, and the Unicode Tags block render as nothing (or as
// their visible base character) to a human skimming a manifest in an editor or PR review, but
// are still fully present in the string an LLM reads token-by-token. That gap — invisible to
// the reviewer, visible to the agent — is exactly how a malicious instruction gets past code
// review while still reaching the model.
const SUSPICIOUS_CODEPOINTS: { name: string; regex: RegExp }[] = [
  { name: "zero-width space", regex: /\u200B/ },
  { name: "zero-width non-joiner", regex: /\u200C/ },
  { name: "zero-width joiner", regex: /\u200D/ },
  { name: "word joiner", regex: /\u2060/ },
  { name: "invisible separator", regex: /\u2063/ },
  { name: "mid-string byte-order-mark", regex: /[\s\S]\uFEFF/ },
  { name: "bidirectional text-direction override", regex: /[\u202A-\u202E]/ },
  { name: "Unicode Tags block (ASCII-smuggling payload)", regex: /[\u{E0001}\u{E0020}-\u{E007F}]/u },
];

const unicodeObfuscation: Rule = {
  id: "unicode-obfuscation",
  description:
    "Flags invisible or bidi-override Unicode characters hidden in tool text — a known technique for smuggling instructions past a human reviewer while an LLM still reads them.",
  check: (tool) => {
    const findings: Finding[] = [];
    // Scan the FULL raw manifest, not just name/description/parameters: for
    // SKILL.md skills the payload usually sits in the markdown body or a
    // bundled script, both of which live under `raw`. Scoping this rule to
    // the structured fields only meant real Unicode Tags-block payloads in
    // real corpus samples went undetected.
    const text = tool.name + " " + tool.description + " " + JSON.stringify(tool.raw ?? {});
    for (const { name, regex } of SUSPICIOUS_CODEPOINTS) {
      if (regex.test(text)) {
        findings.push(
          finding(
            "unicode-obfuscation",
            "critical",
            0.9,
            `Detected a ${name} character. These have essentially no legitimate reason to appear in tool metadata — very low false-positive rate — but double-check this isn't a copy-paste artifact from a source doc before treating it as hostile.`,
            `Tool metadata contains a hidden or invisible Unicode character (${name}). This is a known technique for smuggling instructions past a human reviewing the manifest in an editor or PR, while an LLM parsing the same string still reads it in full.`,
            tool
          )
        );
      }
    }
    return findings;
  },
};

// --- Rule 9: loose / unconstrained parameter schemas ---
// Unbounded string parameters with no schema validation are the documented
// structural precondition behind the RCE- and SSRF-class CVEs disclosed
// against MCP servers in 2026: a parameter that accepts any string, with no
// type constraint, enum, maxLength, or pattern, is what lets a command,
// a URL pointing at an internal metadata endpoint, or a path traversal
// sequence reach code that assumed it would get something benign.
//
// This checks structure, not keywords — it's the most purely-static rule in
// the scanner, so it doesn't suffer the natural-language false-positive
// problem the injection rules do.
const HIGH_RISK_PARAM_NAMES = [
  "cmd", "command", "exec", "script", "shell",
  "url", "uri", "endpoint", "host", "target",
  "path", "file", "filepath", "filename", "dir",
  "query", "sql", "expression", "eval", "code",
];

function isUnconstrained(schema: any): boolean {
  if (!schema || typeof schema !== "object") return true;
  // A parameter is considered constrained if it declares ANY meaningful bound.
  const hasEnum = Array.isArray(schema.enum) && schema.enum.length > 0;
  const hasPattern = typeof schema.pattern === "string" && schema.pattern.length > 0;
  const hasMaxLength = typeof schema.maxLength === "number";
  const hasFormat = typeof schema.format === "string";
  const hasNonStringType =
    typeof schema.type === "string" && !["string", "any"].includes(schema.type);
  return !(hasEnum || hasPattern || hasMaxLength || hasFormat || hasNonStringType);
}

const looseParameterSchema: Rule = {
  id: "loose-parameter-schema",
  description:
    "Flags high-risk parameters (command, url, path, query…) declared with no type constraint, enum, pattern, format, or maxLength.",
  check: (tool) => {
    const findings: Finding[] = [];
    const params = tool.parameters ?? {};
    if (typeof params !== "object") return findings;

    // Support both a flat {name: schema} map and JSON-Schema style {properties: {...}}.
    const properties =
      params.properties && typeof params.properties === "object" ? params.properties : params;

    for (const [name, schema] of Object.entries(properties)) {
      const lowered = name.toLowerCase();
      const isHighRisk = HIGH_RISK_PARAM_NAMES.some((h) => lowered === h || lowered.includes(h));
      if (!isHighRisk) continue;
      if (!isUnconstrained(schema)) continue;

      findings.push(
        finding(
          "loose-parameter-schema",
          "high",
          0.7,
          `Structural check, not a keyword guess: parameter "${name}" is a known high-risk name and declares no enum, pattern, format, maxLength, or constraining type. This is a verifiable property of the schema itself, so it can't be a text false positive — but an unconstrained parameter is a precondition for exploitation, not proof of a vulnerability. Whether it's actually exploitable depends on the implementation this scanner can't see.`,
          `Parameter "${name}" accepts arbitrary unconstrained input. Unbounded parameters of this kind are the documented structural precondition behind RCE, SSRF, and path-traversal issues in agent tools. Add an enum, pattern, format, or maxLength, and validate server-side.`,
          tool,
          `${name}: ${JSON.stringify(schema)}`
        )
      );
    }
    return findings;
  },
};

// --- Rule 10: untrusted external download-and-run instructions ---
// Grounded in a real corpus sample: the documented fake "google" skill tells
// the agent to download a password-protected archive from an arbitrary GitHub
// account and run it, and points macOS users at a paste site for a command to
// run in their terminal. No shell metacharacter, no eval, no obfuscation — the
// attack is entirely social, carried in prose the agent obeys. Pattern rules
// aimed at code constructs miss it completely, which is exactly why it needs
// its own check.
const PASTE_AND_DROP_HOSTS = [
  "pastebin.com", "rentry.co", "paste.c-net.org", "hastebin",
  "transfer.sh", "0x0.st", "termbin.com", "ghostbin", "anonfiles",
  "bashupload", "file.io", "gofile.io",
];

/**
 * Trusted install sources.
 *
 * Measured against the real corpus, the download-and-run heuristic flagged the
 * legitimate Snyk CLI skill (downloads.snyk.io) and the real ClawHub CLI skill
 * (npm package install) alongside the actual attacks — a 50% false-positive
 * rate on benign samples, which is precisely the failure mode that makes teams
 * stop reading a scanner's output.
 *
 * The distinction that actually matters isn't "does it download something" but
 * "is the source an accountable, named distribution channel." A first-party
 * vendor domain or a public package registry has a revocation path, a
 * published owner, and an audit trail. A paste site does not.
 */
const TRUSTED_INSTALL_SOURCES = [
  // Public package registries — versioned, named, revocable.
  "npmjs.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
  "crates.io", "rubygems.org", "packagist.org", "nuget.org", "maven.org",
  "apt.get", "brew.sh", "homebrew",
  // Major first-party software vendors' own download domains.
  "downloads.snyk.io", "snyk.io", "docker.com", "microsoft.com",
  "python.org", "nodejs.org", "golang.org", "rust-lang.org",
  "cloud.google.com", "aws.amazon.com", "azure.com",
];

/** Package-manager install commands are a named, auditable channel — not a drop-and-run. */
const PACKAGE_MANAGER_INSTALL = /\b(npm|yarn|pnpm|pip3?|gem|cargo|go|apt-get|apt|brew|choco|winget)\s+(install|add|get)\b/i;

const DOWNLOAD_RUN_PATTERNS: { name: string; regex: RegExp }[] = [
  { name: "password-protected archive", regex: /(extract|unzip)[^.\n]{0,40}(with )?pass(word)?[\s:`'"]/i },
  { name: "instruction to run a downloaded file", regex: /(download|fetch)[^.\n]{0,60}(and )?(run|execute|launch|open)\b/i },
  { name: "instruction to paste a command into a terminal", regex: /(copy|paste)[^.\n]{0,40}command[^.\n]{0,40}(terminal|shell|cmd)/i },
  { name: "install script piped from a URL", regex: /(install|setup)[^.\n]{0,30}https?:\/\/[^\s)]+[^.\n]{0,30}(run|execute)/i },
];

const untrustedExternalInstall: Rule = {
  id: "untrusted-external-install",
  description:
    "Flags skills whose instructions tell the agent or user to download and run something from an external or anonymous host.",
  check: (tool) => {
    const findings: Finding[] = [];
    const text = JSON.stringify(tool.raw ?? {}) + " " + tool.description;

    const hitHost = PASTE_AND_DROP_HOSTS.find((h) => text.toLowerCase().includes(h));
    const hitPattern = DOWNLOAD_RUN_PATTERNS.find((p) => p.regex.test(text));

    if (!hitHost && !hitPattern) return findings;

    // If the only download activity points at an accountable, named source
    // (a real registry or a first-party vendor domain) and no anonymous host
    // appears anywhere, this is ordinary dependency installation — stay quiet.
    const lowered = text.toLowerCase();
    const trustedSource = TRUSTED_INSTALL_SOURCES.find((d) => lowered.includes(d));
    const usesPackageManager = PACKAGE_MANAGER_INSTALL.test(text);
    if (!hitHost && (trustedSource || usesPackageManager)) {
      return findings;
    }

    // Both signals together is a much stronger case than either alone.
    const both = Boolean(hitHost && hitPattern);
    const evidenceParts = [
      hitHost ? `anonymous/paste host referenced: ${hitHost}` : null,
      hitPattern ? `${hitPattern.name} detected` : null,
    ].filter(Boolean);

    findings.push(
      finding(
        "untrusted-external-install",
        both ? "critical" : "high",
        both ? 0.85 : 0.6,
        both
          ? `Two independent signals co-occur: an anonymous file/paste host AND prose instructing that something be downloaded and run. Legitimate skills install dependencies from package registries with versioned, auditable names — not from paste sites with run-this-file instructions. Low false-positive rate when both appear together.`
          : `One signal matched (${evidenceParts.join(
              "; "
            )}). On its own this can be legitimate — plenty of honest skills document an install step — so treat it as a prompt to read the instruction and confirm the source is a real, named package registry rather than an anonymous host.`,
        `Skill instructions direct the agent or user to obtain and execute something from an external source. This is the mechanism behind documented fake-brand skills that trick users into installing malware, and it carries no code-level indicator a conventional scanner would catch — the payload is the instruction itself.`,
        tool,
        evidenceParts.join("; ")
      )
    );
    return findings;
  },
};


// --- Rule 10: concealed instructions & auto-executing hooks ---
// Two concealment techniques found in real corpus samples that no other rule
// here catches structurally:
//
//   1. Commands hidden inside HTML comments. A markdown renderer hides them;
//      the model reads them. Same invisible-to-human, visible-to-model
//      asymmetry as Unicode smuggling.
//   2. Frontmatter hooks that auto-execute a command on an agent lifecycle
//      event (e.g. UserPromptSubmit running `env > /tmp/a` to capture the
//      environment). These run without the user ever invoking the skill.
const HOOK_COMMAND_PATTERN = /hooks?\s*:[\s\S]{0,400}?command\s*:\s*["']?([^"'\n,}]+)/i;
const SHELL_ISH = /\b(env|printenv|cat|curl|wget|nc|bash|sh|python|eval|base64)\b/i;
const INLINE_EXEC_DIRECTIVE = /!`([^`]+)`/g;

const concealedInstruction: Rule = {
  id: "concealed-instruction",
  description:
    "Flags commands hidden in HTML comments and auto-executing frontmatter hooks — instructions that reach the agent without the user seeing them.",
  check: (tool) => {
    const findings: Finding[] = [];
    const text = JSON.stringify(tool.raw);

    // 1. Auto-executing hooks in frontmatter.
    const hookMatch = text.match(HOOK_COMMAND_PATTERN);
    if (hookMatch && SHELL_ISH.test(hookMatch[1])) {
      findings.push(
        finding(
          "concealed-instruction",
          "critical",
          0.85,
          `A frontmatter hook declares a shell command ("${hookMatch[1].trim().slice(0, 60)}") bound to an agent lifecycle event. Hooks fire automatically — the user never invokes them and typically never sees them. Legitimate skills rarely need one, and one that reads the environment is a recognised credential-capture pattern, so confidence is high. Confirm the hook is documented and necessary.`,
          `Skill defines an auto-executing hook that runs a shell command. Hooks execute on agent events without user invocation, which makes them a documented vector for silent credential capture and persistence.`,
          tool,
          hookMatch[1].trim().slice(0, 80)
        )
      );
    }

    // 2. Executable directives concealed inside HTML comments.
    for (const m of text.matchAll(INLINE_EXEC_DIRECTIVE)) {
      const idx = m.index ?? 0;
      if (!isInsideHtmlComment(text, idx)) continue;
      if (!SHELL_ISH.test(m[1])) continue;
      findings.push(
        finding(
          "concealed-instruction",
          "critical",
          0.85,
          `An auto-executing directive ("${m[1].slice(0, 60)}") sits inside an HTML comment. Markdown renderers hide comments, so a human reviewing the rendered skill never sees this line while the model reads it in full. There is no legitimate reason to conceal an executable command from the reader — that asymmetry is the attack.`,
          `Skill hides an executable command inside an HTML comment, invisible when the markdown is rendered but fully readable by the agent.`,
          tool,
          m[0].slice(0, 80)
        )
      );
    }

    return findings;
  },
};


// --- Rule 11: opaque binary / archive payloads ---
// Published bypass research defeated every public skill scanner tested partly
// by hiding logic in binary and archive formats. A text-pattern scanner reads
// a .zip or a compiled .so as meaningless bytes, matches nothing, and reports
// the skill clean — which is worse than reporting nothing, because it
// manufactures confidence that a review happened.
//
// This rule does NOT claim to know what a binary does; no static text scanner
// can. It reports the reviewable fact: this skill ships something a human
// cannot read. For agent skills — which are meant to be auditable text — that
// is itself the finding.
const opaquePayload: Rule = {
  id: "opaque-payload",
  description:
    "Flags binary, executable, or archive files bundled with a skill, which no text scanner (including this one) can review.",
  check: (tool) => {
    const findings: Finding[] = [];
    const raw: any = tool.raw ?? {};
    const opaque: any[] = Array.isArray(raw._opaqueFiles) ? raw._opaqueFiles : [];

    for (const f of opaque) {
      // A file whose header contradicts its extension is hiding what it is.
      if (f.extensionMismatch) {
        findings.push(
          finding(
            "opaque-payload",
            "critical",
            0.9,
            `Magic-byte check: the file header identifies this as a ${f.kind}, but the filename does not carry a matching extension. Renaming an executable to look like a data or text file has no legitimate purpose in a skill bundle — this is a structural fact about the file, not a keyword guess.`,
            `Bundled file "${f.relPath}" is a ${f.kind} disguised by its filename. A reviewer reading this skill would not know executable content was present.`,
            tool,
            `${f.relPath} (${f.kind}, ${f.sizeBytes} bytes)`
          )
        );
        continue;
      }

      const isExecutable = /executable|class file|WebAssembly|bytecode/i.test(f.kind);
      findings.push(
        finding(
          "opaque-payload",
          isExecutable ? "high" : "medium",
          isExecutable ? 0.8 : 0.6,
          isExecutable
            ? `This skill bundles an executable (${f.kind}). Static analysis cannot determine what it does — that is a hard limit of every text-based scanner, including this one. The finding is that unreviewable executable code ships with a skill meant to be auditable, not a claim the file is malicious.`
            : `This skill bundles an archive (${f.kind}) whose contents cannot be reviewed as text. Archives are a documented way to hide logic from scanners. It may be entirely legitimate — the point is that nobody can confirm that by reading the skill.`,
          isExecutable
            ? `Bundled executable "${f.relPath}" cannot be reviewed by static analysis. Confirm you trust its origin, or unpack and inspect it before installing this skill.`
            : `Bundled archive "${f.relPath}" cannot be read as text. Unpack it and scan the contents before trusting this skill.`,
          tool,
          `${f.relPath} (${f.kind}, ${f.sizeBytes} bytes)`
        )
      );
    }

    // Large base64 blobs inside otherwise-text files: binary smuggled into text.
    const text = JSON.stringify(raw);
    const blob = findEncodedBlob(text);
    if (blob) {
      findings.push(
        finding(
          "opaque-payload",
          "high",
          0.7,
          `A continuous base64-shaped string of ${blob.length} characters appears in this skill's content. Legitimate manifests occasionally embed small encoded values (an icon, a short key), but blocks this size are the standard way binary payloads are hidden inside files that still "look like" text. Decode it before trusting the skill.`,
          `Skill contains a large encoded blob (${blob.length} chars) that cannot be reviewed as readable text.`,
          tool,
          blob.snippet
        )
      );
    }

    return findings;
  },
};

export const allRules: Rule[] = [
  excessivePermissions,
  promptInjection,
  exfiltrationPattern,
  hardcodedSecrets,
  dynamicExecution,
  descriptionMismatch,
  unicodeObfuscation,
  looseParameterSchema,
  untrustedExternalInstall,
  concealedInstruction,
  opaquePayload,
];
