/**
 * Rules 19-24 — Tier 1. Highest signal, lowest noise.
 * Every one of these is a finding you could send a stranger.
 */

import { RuleSpec } from "./rule-spec";

// 19 ------------------------------------------------------------------------
export const webhookSink: RuleSpec = {
  id: "webhook-sink",
  description: "Hardcoded request-collection endpoint",
  severity: "critical",
  confidence: 0.96,
  confidenceReason: "literal collection endpoint in source; no legitimate use",
  message:
    "Contains a hardcoded request-collection endpoint. These services exist to " +
    "capture arbitrary inbound requests and are not used by production software.",
  profiles: ["exfiltration", "pre-commit", "ci-gate"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net",
      "ngrok.io", "ngrok-free.app", "burpcollaborator.net", "interact.sh",
      "oastify.com", "trycloudflare.com", "localtunnel.me", "serveo.net",
      "beeceptor.com", "hookb.in", "postb.in", "webhook.cool",
    ],
  },
};

// 20 ------------------------------------------------------------------------
export const credentialPathAccess: RuleSpec = {
  id: "credential-path-access",
  description: "Reads a known credential store",
  severity: "critical",
  confidence: 0.9,
  confidenceReason: "literal credential path with no matching purpose in description",
  message:
    "Accesses a file that stores credentials. Unless the tool's stated purpose " +
    "is managing that credential, this is a collection step.",
  profiles: ["credentials", "exfiltration", "ci-gate"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      ".aws/credentials", ".aws/config", ".ssh/id_rsa", ".ssh/id_ed25519",
      ".ssh/id_ecdsa", ".git-credentials", ".docker/config.json",
      ".kube/config", ".npmrc", ".pypirc", ".netrc", ".pgpass",
      "Library/Keychains", "security find-generic-password",
      "Login Data", "cookies.sqlite", "key4.db", "logins.json",
      "AppData\\Roaming\\Microsoft\\Credentials",
    ],
  },
  // A genuine credential manager should say so.
  downgradeWhen: {
    match: {
      kind: "any",
      of: [
        {
          kind: "regex",
          field: "description",
          pattern: "(credential|secret|keychain|ssh key|aws profile|auth)[\\w\\s]{0,30}(manage|rotat|read|inspect|audit)",
          flags: "i",
        },
        {
          kind: "regex",
          field: "description",
          pattern: "(manage|rotat|inspect|audit)[\\w\\s]{0,30}(credential|secret|keychain|ssh key|aws profile)",
          flags: "i",
        },
      ],
    },
    severity: "medium",
    confidence: 0.5,
    confidenceReason:
      "tool describes itself as credential tooling, so this access may be intended",
  },
};

// 21 ------------------------------------------------------------------------
export const cloudMetadataAccess: RuleSpec = {
  id: "cloud-metadata-access",
  description: "Requests a cloud instance metadata endpoint",
  severity: "critical",
  confidence: 0.97,
  confidenceReason: "literal metadata service address",
  message:
    "Requests the cloud instance metadata service. On a CI runner or cloud host " +
    "this returns short-lived credentials for the whole instance role.",
  profiles: ["credentials", "exfiltration", "pre-commit", "ci-gate"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      "169.254.169.254", "metadata.google.internal", "169.254.170.2",
      "metadata.azure.com", "100.100.100.200", "metadata.platformequinix.com",
      "fd00:ec2::254",
    ],
  },
};

// 22 ------------------------------------------------------------------------
export const installScriptHook: RuleSpec = {
  id: "install-script-hook",
  description: "Package install hook that runs network or shell operations",
  severity: "high",
  confidence: 0.88,
  confidenceReason: "install-time hook combined with network or shell invocation",
  message:
    "Defines an install-time script that performs network or shell operations. " +
    "This runs before you have read anything, on every install.",
  profiles: ["supply-chain", "execution", "ci-gate"],
  match: {
    kind: "all",
    of: [
      { kind: "regex", field: "raw", pattern: "\"(pre|post)install\"|\"prepare\"" },
      {
        kind: "regex",
        field: "raw",
        pattern: "(curl|wget|node\\s+-e|python\\s+-c|sh\\s+-c|bash\\s+-c|powershell|iwr|Invoke-WebRequest)",
        flags: "i",
      },
    ],
  },
};

// 23 ------------------------------------------------------------------------
export const persistenceMechanism: RuleSpec = {
  id: "persistence-mechanism",
  description: "Writes to a startup or scheduling location",
  severity: "critical",
  confidence: 0.93,
  confidenceReason: "write target is a persistence location",
  message:
    "Writes to a location that survives reboot. Agent tooling has no reason to " +
    "install itself into your shell profile, scheduler or startup items.",
  profiles: ["execution", "ci-gate"],
  match: {
    kind: "anyOf",
    field: "sourceText",
    values: [
      "crontab -", "/etc/cron.d", "/etc/cron.daily", "~/.bashrc", ".bash_profile",
      "~/.zshrc", "~/.profile", "/etc/profile.d", "LaunchAgents", "LaunchDaemons",
      "systemd/user", "/etc/systemd/system", "CurrentVersion\\Run",
      "Start Menu\\Programs\\Startup", "schtasks /create", "launchctl load",
    ],
  },
};

// 24 ------------------------------------------------------------------------
export const dnsExfiltration: RuleSpec = {
  id: "dns-exfiltration",
  description: "Data encoded into DNS lookups",
  severity: "high",
  confidence: 0.78,
  confidenceReason: "resolver call with an interpolated or high-entropy hostname",
  message:
    "Performs a DNS lookup against a hostname built at runtime. Encoding data " +
    "into subdomain labels moves it out past firewalls that block HTTP.",
  profiles: ["exfiltration", "ci-gate"],
  match: {
    kind: "any",
    of: [
      {
        kind: "regex",
        field: "sourceText",
        pattern: "(dig|nslookup|host|resolve4|resolve6|lookupService|dns\\.resolve)[^\\n]{0,60}(\\$\\{|\\+\\s*\\w+|`)",
        flags: "i",
      },
      {
        kind: "regex",
        field: "sourceText",
        pattern: "\\b[a-z2-7]{24,}\\.[a-z0-9-]+\\.[a-z]{2,}\\b",
        flags: "i",
      },
    ],
  },
};

export const tier1Specs: RuleSpec[] = [
  webhookSink,
  credentialPathAccess,
  cloudMetadataAccess,
  installScriptHook,
  persistenceMechanism,
  dnsExfiltration,
];
