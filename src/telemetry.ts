import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";

/**
 * Anonymous adoption telemetry.
 *
 * Purpose: answer one question honestly — "is anyone actually using this?"
 * Without it, a published tool is a black hole: no way to tell 5 users from
 * 500, or to know whether anyone came back after the first run.
 *
 * ============================================================
 * WHAT IS SENT (this is the complete list — nothing else)
 * ============================================================
 *   - A random install ID (generated locally, not derived from anything
 *     about the machine — not hostname, not MAC, not username)
 *   - ryzek version
 *   - OS platform string ("win32" / "darwin" / "linux")
 *   - Node major version
 *   - A count of how many tools were scanned
 *   - A count of how many findings, by severity
 *
 * ============================================================
 * WHAT IS NEVER SENT
 * ============================================================
 *   - No manifest or skill content, ever
 *   - No tool names, file names, or paths
 *   - No findings detail, evidence, or matched text
 *   - No IP-derived identity, email, licence key, or org name
 *   - Nothing that could identify a person, company, or codebase
 *
 * ============================================================
 * WHY OPT-IN, NOT OPT-OUT
 * ============================================================
 * This is a security tool. It runs in CI, over files that may contain
 * credentials, at companies with strict data policies. Silent telemetry in
 * a security tool is a trust catastrophe — several well-known dev tools have
 * been badly damaged by exactly that. So: it is OFF by default, the first
 * run prints a plain-English notice, and enabling it is a deliberate act.
 *
 * A smaller honest number is worth more than a bigger number that costs you
 * the trust of the people you most want as customers.
 */

const CONFIG_DIR = path.join(os.homedir(), ".ryzek");
const TELEMETRY_PATH = path.join(CONFIG_DIR, "telemetry.json");

export const DEFAULT_TELEMETRY_ENDPOINT =
  process.env.RYZEK_TELEMETRY_ENDPOINT || "http://localhost:8787";

export interface TelemetryState {
  /** null = never asked; true/false = user decided. */
  enabled: boolean | null;
  /** Random, locally generated. Not derived from machine identifiers. */
  installId: string;
  /** So the first-run notice only prints once. */
  noticeShown: boolean;
  firstSeen: string;
}

function ensureDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
}

export function loadTelemetryState(): TelemetryState {
  if (fs.existsSync(TELEMETRY_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(TELEMETRY_PATH, "utf-8"));
      if (typeof parsed.installId === "string") return parsed as TelemetryState;
    } catch {
      // fall through and regenerate
    }
  }
  return {
    enabled: null,
    installId: crypto.randomBytes(16).toString("hex"),
    noticeShown: false,
    firstSeen: new Date().toISOString(),
  };
}

export function saveTelemetryState(state: TelemetryState): void {
  ensureDir();
  fs.writeFileSync(TELEMETRY_PATH, JSON.stringify(state, null, 2) + "\n", "utf-8");
}

export function setTelemetryEnabled(enabled: boolean): TelemetryState {
  const state = loadTelemetryState();
  state.enabled = enabled;
  state.noticeShown = true;
  saveTelemetryState(state);
  return state;
}

/**
 * Returns the one-time notice text if it hasn't been shown yet, else null.
 * Deliberately short and specific — a vague notice is worse than none.
 */
export function firstRunNotice(): string | null {
  const state = loadTelemetryState();
  if (state.noticeShown) return null;

  state.noticeShown = true;
  saveTelemetryState(state);

  return [
    "",
    "─────────────────────────────────────────────────────────────",
    " ryzek collects NO data by default.",
    "",
    " If you'd like to help by sharing anonymous usage counts",
    " (tool counts and finding counts only — never file names,",
    " manifest content, or findings detail), you can opt in:",
    "",
    "     ryzek telemetry on",
    "",
    " This notice won't appear again.",
    "─────────────────────────────────────────────────────────────",
  ].join("\n");
}

export interface ScanTelemetry {
  toolsScanned: number;
  findingsTotal: number;
  findingsCritical: number;
  findingsHigh: number;
}

/**
 * Best-effort, fire-and-forget. Never throws, never blocks a scan, and
 * silently does nothing unless the user explicitly opted in.
 */
export async function reportScanTelemetry(
  data: ScanTelemetry,
  version: string,
  endpoint: string = DEFAULT_TELEMETRY_ENDPOINT
): Promise<void> {
  const state = loadTelemetryState();
  if (state.enabled !== true) return;

  try {
    await fetch(`${endpoint}/api/telemetry`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        installId: state.installId,
        version,
        platform: process.platform,
        nodeMajor: process.versions.node.split(".")[0],
        ...data,
      }),
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    // A telemetry failure must never affect a scan. Swallow it entirely.
  }
}

export function telemetryStatusLine(): string {
  const state = loadTelemetryState();
  if (state.enabled === true) {
    return `Telemetry: ON (anonymous counts only) — install ID ${state.installId.slice(0, 8)}…`;
  }
  if (state.enabled === false) {
    return "Telemetry: OFF (explicitly disabled)";
  }
  return "Telemetry: OFF (default — never enabled)";
}
