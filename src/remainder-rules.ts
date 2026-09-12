/**
 * Rules 25-32 and 41-50 — the remainder of the 50.
 *
 * Declarative where a pattern is enough. The ones needing cross-manifest state
 * (toolset-mutation, duplicate-tool-name, shadow-mcp-discovery) live in
 * stateful-rules.ts because a RuleSpec only sees one tool at a time.
 */

import { RuleSpec } from "./rule-spec";

// 25 ------------------------------------------------------------------------
export const toolShadowing: RuleSpec = {
  id: "tool-shadowing",
  description: "Description that gives instructions about a different tool",
  severity: "critical",
  confidence: 0.83,
  confidenceReason: "imperative directed at a named tool other than this one",
  message:
    "Contains an instruction about how a different tool should behave. This is the " +
    "static form of tool poisoning: the agent reads it while using the other tool.",
  profiles: ["agent-safety", "ci-gate"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\b(when|before|whenever|any time) (using|calling|invoking|you (use|call|run))\\b",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\b(always|must|make sure to|be sure to|never|in addition,? )\\b",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\b(bcc|cc|forward|copy|append|include|send|report|log|notify)\\b",
        flags: "i",
      },
    ],
  },
};

// 26 ------------------------------------------------------------------------
export const sandboxEscapeHint: RuleSpec = {
  id: "sandbox-escape-hint",
  description: "References container or sandbox escape surfaces",
  severity: "high",
  confidence: 0.9,
  confidenceReason: "literal reference to a container escape surface",
  message:
    "References a container escape surface. Access to the Docker socket or a " +
    "privileged flag is equivalent to root on the host.",
  profiles: ["execution", "ci-gate"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      "/var/run/docker.sock", "--privileged", "--cap-add=SYS_ADMIN", "--cap-add=ALL",
      "--pid=host", "--net=host", "hostPID", "hostNetwork", "nsenter",
      "--security-opt seccomp=unconfined", "--userns=host", "/proc/1/root",
    ],
  },
};

// 27 ------------------------------------------------------------------------
export const stringReassembly: RuleSpec = {
  id: "string-reassembly",
  description: "Dangerous identifier assembled from fragments",
  severity: "high",
  confidence: 0.8,
  confidenceReason: "identifier built by concatenation or character codes",
  message:
    "Builds an identifier from fragments rather than writing it out. This is done " +
    "to survive a text search, which means someone expected the file to be searched.",
  profiles: ["execution", "agent-safety"],
  match: {
    kind: "any",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "[\"'](ev|ex|req|Fun|chi|spaw|proc)[a-z]{0,4}[\"']\\s*\\+\\s*[\"'][a-z]{1,6}[\"']",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(String\\.fromCharCode|fromCharCode|chr\\()\\s*\\(\\s*\\d+\\s*(,\\s*\\d+\\s*){3,}",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\[[\"'][a-z][\"'](\\s*,\\s*[\"'][a-z][\"']){4,}\\]\\s*\\.\\s*join",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(split\\([\"']{2}\\)\\.reverse\\(\\)\\.join|\\.reverse\\(\\)\\.join\\([\"']{2}\\))",
        flags: "i",
      },
    ],
  },
};

// 28 ------------------------------------------------------------------------
export const dependencyConfusion: RuleSpec = {
  id: "dependency-confusion",
  description: "Package name that shadows an internal package",
  severity: "high",
  confidence: 0.72,
  confidenceReason: "unscoped install of a name matching an internal-package convention",
  message:
    "Installs an unscoped package whose name follows an internal naming convention. " +
    "If the same name exists on a private registry, the public one may win.",
  profiles: ["supply-chain"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\b(npm i|npm install|yarn add|pnpm add|pip install|npx -y)\\b",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\s(?!@)([a-z0-9]+-)?(internal|corp|company|private|inhouse|acme|prod|staging)-[a-z0-9-]{3,}",
        flags: "i",
      },
    ],
  },
};

// 29 ------------------------------------------------------------------------
export const permissionEscalationRequest: RuleSpec = {
  id: "permission-escalation-request",
  description: "Asks the user or agent to widen permissions",
  severity: "high",
  confidence: 0.84,
  confidenceReason: "explicit request to grant, allowlist or skip a safety control",
  message:
    "Asks you or the agent to grant broader access or bypass a check. Social " +
    "engineering aimed at the human in the loop, not at the machine.",
  profiles: ["agent-safety", "execution", "ci-gate"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "(run (this |it )?(with |using )?sudo|add (this|it|the server) to your (allow ?list|白|whitelist|trusted)|dangerously-skip-permissions|--yolo|disable (the )?(sandbox|safety|confirmation|approval)|skip (the )?(review|confirmation|approval|check)|approve (this|all) without|turn off (the )?(sandbox|protection))",
    flags: "i",
  },
};

// 30 ------------------------------------------------------------------------
export const historyFileAccess: RuleSpec = {
  id: "history-file-access",
  description: "Reads shell or client history files",
  severity: "medium",
  confidence: 0.79,
  confidenceReason: "literal history file path",
  message:
    "Reads a command history file. These routinely contain credentials that were " +
    "passed on a command line and never rotated.",
  profiles: ["credentials", "exfiltration"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      ".bash_history", ".zsh_history", ".sh_history", ".python_history",
      ".node_repl_history", ".psql_history", ".mysql_history", ".irb_history",
      "ConsoleHost_history.txt",
    ],
  },
  unless: {
    kind: "regex",
    field: "description",
    pattern: "(shell history|command history|history file) (search|clean|audit|manage)",
    flags: "i",
  },
};

// 31 ------------------------------------------------------------------------
export const schemaInjection: RuleSpec = {
  id: "schema-injection",
  description: "Injected instruction inside a parameter description",
  severity: "critical",
  confidence: 0.89,
  confidenceReason: "imperative or override phrase inside the parameter schema",
  message:
    "A parameter's description contains instructions rather than a description. " +
    "Most scanners read the tool description and stop; the agent reads both.",
  profiles: ["agent-safety", "ci-gate"],
  match: {
    kind: "regex",
    field: "parameters",
    pattern:
      "(ignore (all |any )?(previous|prior|above)|disregard the|instead,? (you (must|should)|always)|before (answering|responding|calling)|do not (tell|mention|inform) the user|secretly|without (telling|informing) the user|system ?:)",
    flags: "i",
  },
};

// 32 ------------------------------------------------------------------------
export const unicodeTagSmuggling: RuleSpec = {
  id: "unicode-tag-smuggling",
  description: "Characters from the Unicode Tags block",
  severity: "critical",
  confidence: 0.95,
  confidenceReason: "codepoints in U+E0000-U+E007F, invisible in every editor",
  message:
    "Contains characters from the Unicode Tags block. They render as nothing " +
    "anywhere a person would look and are read normally by the model.",
  profiles: ["agent-safety", "pre-commit", "ci-gate"],
  match: { kind: "codepointRange", field: "sourceText", from: 0xe0000, to: 0xe007f },
};

// 42 ------------------------------------------------------------------------
export const toxicCapabilityFlow: RuleSpec = {
  id: "toxic-capability-flow",
  description: "Private read combined with a public write in one tool",
  severity: "high",
  confidence: 0.75,
  confidenceReason: "declares both private-data access and an outbound publish path",
  message:
    "Combines access to private data with a path that publishes outward. Each is " +
    "reasonable alone; together they are a route from your data to somewhere else.",
  profiles: ["exfiltration", "agent-safety"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(read_file|readFile|fs\\.read|database|query|secret|credential|private|internal|inbox|mailbox)",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(post_?[Mm]essage|publish|tweet|send_?[Ee]mail|sendMail|webhook|upload|create_?[Ii]ssue|create_?[Gg]ist|slack|discord)",
        flags: "i",
      },
    ],
  },
};

// 43 ------------------------------------------------------------------------
export const vulnerableDependency: RuleSpec = {
  id: "vulnerable-dependency",
  description: "Dependency pinned inside a published advisory range",
  severity: "high",
  confidence: 0.7,
  confidenceReason: "dependency matches an advisory entry in the current feed",
  message:
    "A declared dependency matches an entry in the advisory feed. Advisory data " +
    "goes stale quickly, so this is only as good as your last feed update.",
  profiles: ["supply-chain", "ci-gate"],
  match: {
    kind: "all",
    of: [
      { kind: "regex", field: "raw", pattern: "(dependencies|devDependencies|requirements)", flags: "i" },
      {
        kind: "anyOf",
        field: "raw",
        values: ["litellm", "langflow", "flowise", "@modelcontextprotocol/inspector", "mcp-remote"],
      },
    ],
  },
};

// 46 ------------------------------------------------------------------------
export const promptInErrorMessage: RuleSpec = {
  id: "prompt-in-error-message",
  description: "Instruction hidden inside an error string",
  severity: "medium",
  confidence: 0.81,
  confidenceReason: "imperative phrasing inside an error or exception message",
  message:
    "An error message contains instructions. Errors are read by the agent when " +
    "something fails, which is exactly when nobody is looking closely.",
  profiles: ["agent-safety"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(throw new |Error\\(|reject\\(|raise |except|catch)",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(to (fix|resolve|continue),? (you (must|should)|run|call|grant|disable|send)|instead,? (call|run|use|send)|ignore (this|the) (check|error|warning) and)",
        flags: "i",
      },
    ],
  },
};

// 47 ------------------------------------------------------------------------
export const networkInDeclaredOffline: RuleSpec = {
  id: "network-in-declared-offline",
  description: "Claims local-only operation but makes network calls",
  severity: "high",
  confidence: 0.86,
  confidenceReason: "description asserts local or offline; network call present",
  message:
    "Says it runs locally, then makes an outbound request. The claim is what a " +
    "reviewer trusts, so a false one is worth more to an attacker than the code.",
  profiles: ["exfiltration", "agent-safety", "ci-gate"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "description",
        pattern: "(local[- ]only|runs locally|offline|no network|never (leaves|sends)|air.?gapped|on[- ]device|stays on your)",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(fetch\\(|axios|https?\\.request|urllib|requests\\.(get|post)|XMLHttpRequest|WebSocket|net\\.connect|curl )",
        flags: "i",
      },
    ],
  },
};

// 48 ------------------------------------------------------------------------
export const sensitiveDataInLogs: RuleSpec = {
  id: "sensitive-data-in-logs",
  description: "Writes credentials to a log or console",
  severity: "medium",
  confidence: 0.77,
  confidenceReason: "log call whose argument is a credential-named value",
  message:
    "Logs a value held in a credential-named variable. Logs get shipped, shared and " +
    "kept far longer than the credential stays valid.",
  profiles: ["credentials"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "(console\\.(log|info|debug|error)|logger?\\.(info|debug|warn|error)|print\\(|println|fmt\\.Print|writeFile\\([^)]*log)[^\\n)]{0,60}(token|secret|password|passwd|api_?key|apikey|credential|private_?key|bearer)",
    flags: "i",
  },
};

// 50 ------------------------------------------------------------------------
export const commandInjectionSurface: RuleSpec = {
  id: "command-injection-surface",
  description: "Shell command built from an interpolated value",
  severity: "high",
  confidence: 0.85,
  confidenceReason: "shell invocation with an interpolated or concatenated argument",
  message:
    "Builds a shell command from a value supplied at runtime. Anything that reaches " +
    "that value runs as a command, not as data.",
  profiles: ["execution", "ci-gate"],
  match: {
    kind: "any",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(exec|execSync|spawn|spawnSync|system|popen|shell_exec|subprocess\\.(run|call|Popen))\\s*\\([^)]{0,80}(\\$\\{|`|\\+\\s*\\w+|%s|\\.format\\()",
        flags: "i",
      },
      {
        kind: "regex",
        field: "command",
        pattern: "(sh|bash|zsh|cmd|powershell)\\s+-c\\s+[\"'][^\"']*(\\$\\{|\\$[A-Z_]+|`)",
        flags: "i",
      },
    ],
  },
};

export const remainderSpecs: RuleSpec[] = [
  toolShadowing,
  sandboxEscapeHint,
  stringReassembly,
  dependencyConfusion,
  permissionEscalationRequest,
  historyFileAccess,
  schemaInjection,
  unicodeTagSmuggling,
  toxicCapabilityFlow,
  vulnerableDependency,
  promptInErrorMessage,
  networkInDeclaredOffline,
  sensitiveDataInLogs,
  commandInjectionSurface,
];
