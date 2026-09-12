/**
 * Opt-in telemetry.
 *
 * Design rule, enforced by the shape of the payload rather than by discipline:
 * nothing in here can carry a fragment of the user's code. Every field is an
 * identifier we defined, a count, or a boolean. There is no free-text field
 * anywhere, so there is nothing for a path or a snippet to leak through.
 *
 * `ryzek telemetry --preview` prints the exact JSON that would be sent.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { Finding } from "./types";

export const TELEMETRY_ENDPOINT = "https://ryzek.dev/api/t";
const CONFIG = path.join(os.homedir(), ".ryzek", "telemetry.json");

// ---------------------------------------------------------------------------
// The payload — this is the whole thing
// ---------------------------------------------------------------------------

export interface RuleStat {
  /** Rule id. Ours, not theirs. */
  r: string;
  /** How many findings that rule produced. */
  n: number;
  /** How many of those were already suppressed by the user. */
  sup: number;
  /** Highest severity it reached this run. */
  sev: "info" | "low" | "medium" | "high" | "critical";
}

export interface TelemetryEvent {
  /** Rotating install id. Not an account id, not a machine id. */
  iid: string;
  /** Scanner version. */
  v: string;
  /** "cli" | "ci" | "hook" — how it was invoked. */
  ctx: "cli" | "ci" | "hook";
  /** Focus profile if one was used. */
  focus?: string;
  /** Counts only. */
  tools: number;
  mcpServers: number;
  scanMs: number;
  /** Per-rule outcome. Empty array is a clean scan and is worth knowing. */
  rules: RuleStat[];
  /** Platform bucket, coarse on purpose. */
  os: "darwin" | "linux" | "win32" | "other";
  node: string;
  /** ISO date only. No time — nothing to correlate with. */
  d: string;
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

export interface TelemetryConfig {
  enabled: boolean;
  installId: string;
  /** When they said yes, so we can re-ask after a policy change. */
  consentedAt?: string;
  consentVersion?: number;
}

export const CONSENT_VERSION = 1;

export function loadConfig(): TelemetryConfig {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG, "utf8"));
    if (typeof raw.enabled === "boolean" && typeof raw.installId === "string") {
      return raw;
    }
  } catch {
    /* first run */
  }
  return { enabled: false, installId: newInstallId() };
}

export function saveConfig(c: TelemetryConfig): void {
  fs.mkdirSync(path.dirname(CONFIG), { recursive: true });
  fs.writeFileSync(CONFIG, JSON.stringify(c, null, 2));
}

function newInstallId(): string {
  return crypto.randomBytes(16).toString("hex");
}

/** Rotate the install id. Offered in the CLI; breaks any longitudinal link. */
export function rotateInstallId(): string {
  const c = loadConfig();
  c.installId = newInstallId();
  saveConfig(c);
  return c.installId;
}

/**
 * Default is off. We ask once, plainly, and take silence as no.
 * Never prompted in CI — a build script cannot consent.
 */
export function shouldPrompt(): boolean {
  if (process.env.CI) return false;
  if (!process.stdout.isTTY) return false;
  const c = loadConfig();
  return c.consentVersion !== CONSENT_VERSION && !c.enabled;
}

export const CONSENT_TEXT = `
  Help improve ryzek?

  If you opt in, each scan sends: which rules fired, how many findings
  each produced, how many you had suppressed, scan duration, and your
  OS and version. Counts and rule names only.

  It does not send: your code, file paths, repo names, tool names,
  descriptions, or anything matched by a rule. There is no free-text
  field in the payload — run  ryzek telemetry --preview  to see it.

  You can turn this off at any time with  ryzek telemetry --off
`;

// ---------------------------------------------------------------------------
// Building the event
// ---------------------------------------------------------------------------

export function buildEvent(
  findings: Finding[],
  meta: {
    version: string;
    toolCount: number;
    mcpCount: number;
    scanMs: number;
    focus?: string;
  }
): TelemetryEvent {
  const byRule = new Map<string, RuleStat>();
  const order = ["info", "low", "medium", "high", "critical"];

  for (const f of findings) {
    let s = byRule.get(f.ruleId);
    if (!s) {
      s = { r: f.ruleId, n: 0, sup: 0, sev: "info" };
      byRule.set(f.ruleId, s);
    }
    s.n++;
    if (f.suppressed) s.sup++;
    if (order.indexOf(f.severity) > order.indexOf(s.sev)) s.sev = f.severity;
  }

  const plat = process.platform;
  return {
    iid: loadConfig().installId,
    v: meta.version,
    ctx: process.env.CI ? "ci" : process.env.RYZEK_HOOK ? "hook" : "cli",
    focus: meta.focus,
    tools: meta.toolCount,
    mcpServers: meta.mcpCount,
    scanMs: Math.round(meta.scanMs),
    rules: [...byRule.values()],
    os:
      plat === "darwin" || plat === "linux" || plat === "win32"
        ? plat
        : "other",
    node: process.version.split(".")[0].replace("v", ""),
    d: new Date().toISOString().slice(0, 10),
  };
}

/**
 * Belt and braces. Even though no field can hold code, assert it before send —
 * if someone later adds a field carelessly, this fails loudly in tests.
 */
export function assertNoContent(e: TelemetryEvent): void {
  const allowedRuleIds = /^[a-z0-9-]+$/;
  for (const r of e.rules) {
    if (!allowedRuleIds.test(r.r)) {
      throw new Error(`telemetry: rule id failed shape check: ${r.r}`);
    }
  }
  const json = JSON.stringify(e);
  for (const marker of ["/", "\\", "http", "@", ".js", ".md", ".json"]) {
    if (json.includes(marker)) {
      throw new Error(`telemetry: payload contains "${marker}" — refusing to send`);
    }
  }
}

// ---------------------------------------------------------------------------
// Sending — never blocks, never fails a scan
// ---------------------------------------------------------------------------

export async function send(e: TelemetryEvent): Promise<void> {
  const c = loadConfig();
  if (!c.enabled) return;
  try {
    assertNoContent(e);
  } catch {
    return; // silently drop rather than risk it
  }
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 1500);
    await fetch(TELEMETRY_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(e),
      signal: ctl.signal,
    });
    clearTimeout(t);
  } catch {
    /* offline, blocked, slow — none of it is the user's problem */
  }
}

export function preview(e: TelemetryEvent): string {
  return JSON.stringify(e, null, 2);
}
