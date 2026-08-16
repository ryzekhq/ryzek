import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { LicenseState, Tier, TIER_LIMITS, UsageState, UsageEvent, ValidateResponse } from "./license-types";

/**
 * License + usage tracking.
 *
 * Design choices, stated plainly because they matter for how this behaves:
 *
 * - State lives in ~/.ryzek/ (a machine-global config dir, same convention
 *   as ~/.npmrc or ~/.aws/), NOT inside the scanned project. A license belongs
 *   to the person running the tool, not to any one repo.
 * - The FREE tier needs no key and no network call — the local monthly
 *   counter alone enforces the 100-scan limit, so a free user can use this
 *   tool fully offline. Only Pro/Enterprise keys ever talk to the license
 *   server.
 * - A validated Pro/Enterprise key is cached for 24h so every scan doesn't
 *   need a network round-trip. If the license server is unreachable, the
 *   last known-good tier is trusted for a 7-day grace period (so a CI runner
 *   with a flaky network doesn't suddenly get demoted mid-pipeline) — after
 *   7 days of failed revalidation, it quietly falls back to free-tier limits
 *   until a validation succeeds again. It never hard-fails a scan just
 *   because the license server is down.
 * - Usage reporting to the server is best-effort and asynchronous-in-spirit:
 *   if the report fails, events queue locally and get flushed on the next
 *   successful contact. The local counter is always the source of truth for
 *   THIS machine's enforcement; the server's copy is for the dashboard and
 *   cross-machine visibility, not a hard gate.
 */

const CONFIG_DIR = path.join(os.homedir(), ".ryzek");
const LICENSE_PATH = path.join(CONFIG_DIR, "license.json");
const USAGE_PATH = path.join(CONFIG_DIR, "usage.json");

const VALIDATION_CACHE_MS = 24 * 60 * 60 * 1000; // 24h
const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export const DEFAULT_LICENSE_SERVER =
  process.env.RYZEK_LICENSE_SERVER || "http://localhost:8787";

function ensureConfigDir(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export function loadLicenseState(): LicenseState {
  if (!fs.existsSync(LICENSE_PATH)) {
    return { key: null, tier: "free", lastValidatedAt: null, gracePeriodStartedAt: null };
  }
  try {
    return JSON.parse(fs.readFileSync(LICENSE_PATH, "utf-8"));
  } catch {
    return { key: null, tier: "free", lastValidatedAt: null, gracePeriodStartedAt: null };
  }
}

export function saveLicenseState(state: LicenseState): void {
  ensureConfigDir();
  fs.writeFileSync(LICENSE_PATH, JSON.stringify(state, null, 2) + "\n", "utf-8");
}

function currentMonth(): string {
  return new Date().toISOString().slice(0, 7); // "YYYY-MM"
}

export function loadUsageState(): UsageState {
  const month = currentMonth();
  if (!fs.existsSync(USAGE_PATH)) {
    return { month, scanCount: 0, pendingEvents: [] };
  }
  try {
    const parsed: UsageState = JSON.parse(fs.readFileSync(USAGE_PATH, "utf-8"));
    if (parsed.month !== month) {
      // New month — counter resets. Pending events from the old month are
      // dropped rather than mis-attributed to the new month on next report.
      return { month, scanCount: 0, pendingEvents: [] };
    }
    return parsed;
  } catch {
    return { month, scanCount: 0, pendingEvents: [] };
  }
}

export function saveUsageState(state: UsageState): void {
  ensureConfigDir();
  fs.writeFileSync(USAGE_PATH, JSON.stringify(state, null, 2) + "\n", "utf-8");
}

/** Calls the license server to validate a key. Throws on network failure — caller decides fallback behavior. */
export async function validateKeyRemote(
  key: string,
  serverUrl: string = DEFAULT_LICENSE_SERVER
): Promise<ValidateResponse> {
  const res = await fetch(`${serverUrl}/api/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) {
    throw new Error(`License server returned HTTP ${res.status}`);
  }
  return (await res.json()) as ValidateResponse;
}

/** Best-effort — never throws. Reports queued usage events and clears them from local state on success. */
export async function reportUsageRemote(
  key: string,
  usage: UsageState,
  serverUrl: string = DEFAULT_LICENSE_SERVER
): Promise<boolean> {
  try {
    const res = await fetch(`${serverUrl}/api/usage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, month: usage.month, scanCount: usage.scanCount, events: usage.pendingEvents }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves the effective tier for this run: validates a cached/remote key
 * if present, applies the offline grace period, and falls back to "free"
 * for anyone without a key. Never throws — worst case, degrades to free.
 */
export async function resolveEffectiveTier(
  serverUrl: string = DEFAULT_LICENSE_SERVER
): Promise<{ tier: Tier; state: LicenseState; degraded: boolean }> {
  let state = loadLicenseState();

  if (!state.key) {
    return { tier: "free", state, degraded: false };
  }

  const now = Date.now();
  const cacheAge = state.lastValidatedAt ? now - Date.parse(state.lastValidatedAt) : Infinity;

  if (cacheAge < VALIDATION_CACHE_MS) {
    // Cache still fresh, trust it without a network call.
    return { tier: state.tier, state, degraded: false };
  }

  try {
    const result = await validateKeyRemote(state.key, serverUrl);
    if (!result.valid) {
      // Key was actively rejected (revoked/expired/unknown) — this is not a
      // network failure, so no grace period applies. Drop straight to free.
      state = { ...state, tier: "free", lastValidatedAt: new Date().toISOString(), gracePeriodStartedAt: null };
      saveLicenseState(state);
      return { tier: "free", state, degraded: false };
    }
    state = {
      ...state,
      tier: result.tier,
      ownerEmail: result.ownerEmail,
      lastValidatedAt: new Date().toISOString(),
      gracePeriodStartedAt: null,
    };
    saveLicenseState(state);
    return { tier: result.tier, state, degraded: false };
  } catch {
    // Network failure — apply the grace period instead of instantly demoting.
    const graceStart = state.gracePeriodStartedAt ?? new Date().toISOString();
    const inGrace = now - Date.parse(graceStart) < GRACE_PERIOD_MS;

    if (!state.gracePeriodStartedAt) {
      state = { ...state, gracePeriodStartedAt: graceStart };
      saveLicenseState(state);
    }

    if (inGrace) {
      return { tier: state.tier, state, degraded: true };
    }
    return { tier: "free", state, degraded: true };
  }
}

export interface UsageCheckResult {
  allowed: boolean;
  tier: Tier;
  limit: number;
  usedThisMonth: number;
  remaining: number;
}

/** Checks (without incrementing) whether another scan is allowed under the effective tier's limit. */
export function checkUsage(tier: Tier): UsageCheckResult {
  const usage = loadUsageState();
  const limit = TIER_LIMITS[tier];
  const remaining = limit === Infinity ? Infinity : Math.max(0, limit - usage.scanCount);
  return {
    allowed: usage.scanCount < limit,
    tier,
    limit,
    usedThisMonth: usage.scanCount,
    remaining,
  };
}

/** Records one completed scan against the local monthly counter and queues a usage event for reporting. */
export function recordScan(event: UsageEvent): UsageState {
  const usage = loadUsageState();
  usage.scanCount += 1;
  usage.pendingEvents.push(event);
  saveUsageState(usage);
  return usage;
}

export function clearPendingEvents(): void {
  const usage = loadUsageState();
  usage.pendingEvents = [];
  saveUsageState(usage);
}

export function maskKey(key: string): string {
  if (key.length <= 8) return "****";
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}
