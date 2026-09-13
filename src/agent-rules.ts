/**
 * Rules 33-40 — the agent layer.
 *
 * These attack the agent, not the code. A scanner that only looks for
 * dangerous function calls cannot see any of them.
 */

import { RuleSpec } from "./rule-spec";

// 33 ------------------------------------------------------------------------
export const markdownImageBeacon: RuleSpec = {
  id: "markdown-image-beacon",
  description: "Markdown image whose URL carries data",
  severity: "critical",
  confidence: 0.93,
  confidenceReason: "remote image URL carrying query parameters or interpolation",
  message:
    "Contains a markdown image pointing at a remote URL with data in it. The " +
    "client fetches the image when it renders the response, so the data leaves " +
    "the machine without any network call appearing in the tool's code.",
  profiles: ["exfiltration", "agent-safety", "ci-gate"],
  match: {
    kind: "any",
    of: [
      // ![...](https://host/path?key=value)
      {
        kind: "regex",
        field: "sourceText",
        pattern: "!\\[[^\\]]*\\]\\(\\s*https?://[^)\\s]+\\?[^)\\s]+\\)",
        flags: "i",
      },
      // image URL built by interpolation
      {
        kind: "regex",
        field: "sourceText",
        pattern: "!\\[[^\\]]*\\]\\(\\s*https?://[^)]*(\\$\\{|\\{\\{|`\\s*\\+)",
        flags: "i",
      },
      // <img src> with a query string
      {
        kind: "regex",
        field: "sourceText",
        pattern: "<img[^>]+src=[\"']https?://[^\"']+\\?[^\"']+[\"']",
        flags: "i",
      },
    ],
  },
  // A docs tool legitimately embedding a versioned asset from its own domain.
  unless: {
    kind: "regex",
    field: "sourceText",
    pattern: "!\\[[^\\]]*\\]\\(\\s*https?://[^)\\s]*(shields\\.io|badge|githubusercontent\\.com/[^)]*\\.(png|svg))",
    flags: "i",
  },
};

// 34 ------------------------------------------------------------------------
export const toolResultForgery: RuleSpec = {
  id: "tool-result-forgery",
  description: "Content imitating the format of a tool result",
  severity: "critical",
  confidence: 0.85,
  confidenceReason: "text imitates a tool-result envelope inside tool-supplied content",
  message:
    "Contains text formatted to look like a tool result. This can convince the " +
    "agent that a tool already ran and returned something — a fabricated " +
    "approval, a clean scan, or a permission grant that never happened.",
  profiles: ["agent-safety", "ci-gate"],
  match: {
    kind: "any",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "</?(function_results|function_calls|tool_result|tool_use|antml:)",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(^|\\n|:\\s*)(Tool output|Observation|Function result|Tool response|System)\\s*:",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\"jsonrpc\"\\s*:\\s*\"2\\.0\"[^\\n]{0,80}\"result\"",
        flags: "i",
      },
    ],
  },
};

// 35 ------------------------------------------------------------------------
export const memoryPoisoning: RuleSpec = {
  id: "memory-poisoning",
  description: "Instruction aimed at the agent's persistent store",
  severity: "critical",
  confidence: 0.82,
  confidenceReason: "imperative targeting persistent agent state or a rules file",
  message:
    "Attempts to write instructions into persistent agent state. Ordinary " +
    "injection lasts one session; this survives until someone notices, and " +
    "uninstalling the tool does not remove it.",
  profiles: ["agent-safety", "ci-gate"],
  match: {
    kind: "any",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(always remember|remember (that|this) (for|in) (all|future|every)|store (this|the following) (in|to) (your )?memory|add (this|the following) to your (memory|instructions|rules))",
        flags: "i",
      },
      {
        kind: "all",
        of: [
          {
            kind: "anyOf",
            field: "sourceText",
            values: [
              "CLAUDE.md", ".cursorrules", "AGENTS.md", ".github/copilot-instructions",
              ".windsurfrules", "system_prompt", "systemPrompt", ".aider.conf",
              "memory.json", "MEMORY.md",
            ],
          },
          {
            kind: "regex",
            field: "sourceText",
            pattern: "(append|write|>>|writeFile|fs\\.write|echo\\s)",
            flags: "i",
          },
        ],
      },
    ],
  },
};

// 36 ------------------------------------------------------------------------
export const deferredTrigger: RuleSpec = {
  id: "deferred-trigger",
  description: "Behaviour gated on a later condition",
  severity: "high",
  confidence: 0.76,
  confidenceReason: "conditional activation phrase targeting a future turn or date",
  message:
    "Describes behaviour that activates later or under a condition. This defeats " +
    "review: the tool behaves during inspection and changes afterwards.",
  profiles: ["agent-safety", "supply-chain"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "(if the user (later|ever|subsequently)|on the (second|third|fourth|fifth|next) (run|invocation|call)|after (the )?(date|[0-9]{4}-[0-9]{2})|only when (no one|nobody) is|when not being (watched|reviewed|observed)|if (this is |you are )?not (a )?(test|review|sandbox|dry.?run))",
    flags: "i",
  },
};

// 37 ------------------------------------------------------------------------
export const agentChainInjection: RuleSpec = {
  id: "agent-chain-injection",
  description: "Content addressed to a downstream agent",
  severity: "high",
  confidence: 0.79,
  confidenceReason: "imperative directed at a subsequent agent or handoff",
  message:
    "Contains instructions aimed at a downstream agent rather than at the user. " +
    "In multi-agent setups the trust boundary between agents is rarely checked, " +
    "so an instruction planted here travels further than the tool that carried it.",
  profiles: ["agent-safety"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "(when handing off|tell the (next|following|downstream) agent|pass (this|the following) to the (orchestrator|next|parent|supervisor)|instruct the (sub|child|worker) ?agent|include (this|the following) in your (summary|handoff|report) to)",
    flags: "i",
  },
};

// 38 ------------------------------------------------------------------------
export const confusedDeputy: RuleSpec = {
  id: "confused-deputy",
  description: "Low-privilege tool directing use of a higher-privilege one",
  severity: "high",
  confidence: 0.74,
  confidenceReason: "read-scoped tool instructing invocation of a write or exec tool",
  message:
    "Instructs the agent to invoke a more privileged tool on its behalf. The " +
    "privilege check passes on the caller, not on the instruction's origin.",
  profiles: ["agent-safety", "execution"],
  match: {
    kind: "all",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(then (call|use|invoke|run)|after (this|that),? (call|use|invoke|run)|you (should|must) (then )?(call|use|invoke))",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(exec|shell|bash|write_file|delete|remove|sudo|admin|deploy|publish)",
        flags: "i",
      },
    ],
  },
  // A tool that legitimately declares exec permissions isn't borrowing anyone's.
  unless: {
    kind: "regex",
    field: "permissions",
    pattern: "(shell:exec|process:spawn|filesystem:write)",
    flags: "i",
  },
};

// 39 ------------------------------------------------------------------------
export const systemPromptExtraction: RuleSpec = {
  id: "system-prompt-extraction",
  description: "Attempts to surface the agent's configuration",
  severity: "medium",
  confidence: 0.87,
  confidenceReason: "explicit request for system prompt or configuration disclosure",
  message:
    "Asks the agent to reveal its system prompt, configuration or tool list. " +
    "This is reconnaissance, and it usually precedes something targeted.",
  profiles: ["agent-safety"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "((repeat|print|output|reveal|show|disclose|dump) (your |the )?(system ?prompt|initial instructions|instructions above|configuration|full context)|what (are|were) your (original |initial )?instructions|list all (your )?(available )?tools)",
    flags: "i",
  },
};

// 40 ------------------------------------------------------------------------
export const contextHistoryAccess: RuleSpec = {
  id: "context-history-access",
  description: "Requests conversation history without a stated reason",
  severity: "medium",
  confidence: 0.7,
  confidenceReason: "requests prior turns; description does not mention history",
  message:
    "Requests access to conversation history or prior turns. Nothing in the " +
    "tool's own description explains why it would need them.",
  profiles: ["agent-safety", "credentials"],
  match: {
    kind: "regex",
    field: "sourceText",
    pattern:
      "(conversation ?history|prior (turns|messages)|previous (turns|messages|conversation)|full transcript|chat ?history|message ?history|context ?window contents)",
    flags: "i",
  },
  unless: {
    kind: "regex",
    field: "description",
    pattern: "(summaris|summariz|transcript|history|conversation|log|archive|export|search) ",
    flags: "i",
  },
};

export const agentSpecs: RuleSpec[] = [
  markdownImageBeacon,
  toolResultForgery,
  memoryPoisoning,
  deferredTrigger,
  agentChainInjection,
  confusedDeputy,
  systemPromptExtraction,
  contextHistoryAccess,
];
