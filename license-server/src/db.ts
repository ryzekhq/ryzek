import * as fs from "fs";
import * as path from "path";

export type Tier = "free" | "pro" | "enterprise";

export interface License {
  tier: Tier;
  ownerEmail: string;
  createdAt: string;
  status: "active" | "revoked";
  expiresAt?: string; // optional — omit for a non-expiring key
}

export interface UsageEvent {
  timestamp: string;
  toolsScanned: number;
  findingsCount: number;
  criticalCount: number;
}

export interface MonthlyUsage {
  scanCount: number;
  events: UsageEvent[];
}

export interface TelemetryRow {
  firstSeen: string;
  lastSeen: string;
  scanCount: number;
  toolsScanned: number;
  findingsTotal: number;
  findingsCritical: number;
  version: string;
  platform: string;
}

export interface Db {
  licenses: Record<string, License>;
  usage: Record<string, Record<string, MonthlyUsage>>; // usage[key][month]
  /** Anonymous adoption counts, keyed by a client-generated random install ID. */
  telemetry?: Record<string, TelemetryRow>;
}

/**
 * Walks up from this file's location until it finds package.json, so the
 * data file lands in the same place whether this module is run via ts-node
 * (from src/) or the compiled build (from dist/src/) — those two have a
 * different __dirname depth, and guessing a fixed number of ".." segments
 * silently breaks one of them.
 */
function findPackageRoot(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // Fallback: shouldn't happen in practice, but don't crash — just use startDir.
  return startDir;
}

const DB_PATH = path.join(findPackageRoot(__dirname), "data", "db.json");
const MAX_EVENTS_PER_MONTH = 1000; // keep the file bounded; the count itself is never truncated, only the raw event log

function emptyDb(): Db {
  return { licenses: {}, usage: {}, telemetry: {} };
}

export function loadDb(): Db {
  if (!fs.existsSync(DB_PATH)) {
    return emptyDb();
  }
  try {
    const raw = fs.readFileSync(DB_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    return {
      licenses: parsed.licenses ?? {},
      usage: parsed.usage ?? {},
      telemetry: parsed.telemetry ?? {},
    };
  } catch {
    return emptyDb();
  }
}

export function saveDb(db: Db): void {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2) + "\n", "utf-8");
}

export function getLicense(key: string): License | null {
  const db = loadDb();
  return db.licenses[key] ?? null;
}

export function createLicense(key: string, license: License): void {
  const db = loadDb();
  db.licenses[key] = license;
  saveDb(db);
}

export function revokeLicense(key: string): boolean {
  const db = loadDb();
  if (!db.licenses[key]) return false;
  db.licenses[key].status = "revoked";
  saveDb(db);
  return true;
}

/**
 * Records new usage events for a key/month. The increment is the number of
 * NEW events submitted (not the client's absolute counter) so that usage
 * aggregates correctly if the same key is ever used from more than one
 * machine — each machine only ever reports events it hasn't successfully
 * reported before.
 */
export function recordUsage(key: string, month: string, events: UsageEvent[]): MonthlyUsage {
  const db = loadDb();
  if (!db.usage[key]) db.usage[key] = {};
  if (!db.usage[key][month]) db.usage[key][month] = { scanCount: 0, events: [] };

  const monthly = db.usage[key][month];
  monthly.scanCount += events.length;
  monthly.events.push(...events);
  if (monthly.events.length > MAX_EVENTS_PER_MONTH) {
    monthly.events = monthly.events.slice(-MAX_EVENTS_PER_MONTH);
  }

  saveDb(db);
  return monthly;
}

export function getUsageForKey(key: string): Record<string, MonthlyUsage> {
  const db = loadDb();
  return db.usage[key] ?? {};
}
