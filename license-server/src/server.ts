import express from "express";
import * as fs from "fs";
import * as path from "path";
import { getLicense, recordUsage, getUsageForKey, loadDb, saveDb, Tier } from "./db";

function findPackageRoot(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return startDir;
}

const PACKAGE_ROOT = findPackageRoot(__dirname);

const app = express();
app.use(express.json());

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8787;

const TIER_LIMITS: Record<Tier, number> = {
  free: 100,
  pro: 1000,
  enterprise: Infinity,
};

function currentMonth(): string {
  return new Date().toISOString().slice(0, 7);
}

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/**
 * POST /api/validate { key }
 * Returns whether a key is currently valid, and if so, its tier.
 * A key that doesn't exist, is revoked, or is past its expiry all come back
 * as { valid: false, reason: ... } rather than an HTTP error — this is a
 * normal, expected response shape, not a server failure.
 */
app.post("/api/validate", (req, res) => {
  const { key } = req.body ?? {};
  if (!key || typeof key !== "string") {
    return res.status(400).json({ valid: false, reason: "missing key" });
  }

  const license = getLicense(key);
  if (!license) {
    return res.json({ valid: false, reason: "unknown key" });
  }
  if (license.status === "revoked") {
    return res.json({ valid: false, reason: "revoked" });
  }
  if (license.expiresAt && Date.parse(license.expiresAt) < Date.now()) {
    return res.json({ valid: false, reason: "expired" });
  }

  return res.json({ valid: true, tier: license.tier, ownerEmail: license.ownerEmail });
});

/**
 * POST /api/usage { key, month, scanCount, events }
 * Records new usage events. `scanCount` from the client is accepted for
 * logging/debugging only — the server's own count is always derived from
 * events.length, so a client can't (accidentally or otherwise) report an
 * inflated total.
 */
app.post("/api/usage", (req, res) => {
  const { key, month, events } = req.body ?? {};
  if (!key || typeof key !== "string") {
    return res.status(400).json({ ok: false, error: "missing key" });
  }
  const license = getLicense(key);
  if (!license || license.status === "revoked") {
    return res.status(403).json({ ok: false, error: "invalid or revoked key" });
  }

  const targetMonth = typeof month === "string" ? month : currentMonth();
  const safeEvents = Array.isArray(events) ? events : [];

  const monthly = recordUsage(key, targetMonth, safeEvents);
  return res.json({ ok: true, totalThisMonth: monthly.scanCount });
});

/**
 * GET /api/dashboard-data?key=...
 * Backs the admin dashboard. Free-tier keys (or no key) get a 403 with an
 * upgrade message rather than data — the dashboard is a Pro/Enterprise
 * feature per the spec.
 */
app.get("/api/dashboard-data", (req, res) => {
  const key = req.query.key as string | undefined;
  if (!key) {
    return res.status(400).json({ error: "missing key" });
  }
  const license = getLicense(key);
  if (!license || license.status === "revoked") {
    return res.status(403).json({ error: "invalid or revoked key" });
  }
  if (license.tier === "free") {
    return res.status(403).json({ error: "dashboard is a Pro/Enterprise feature — this key is on the Free tier" });
  }

  const usage = getUsageForKey(key);
  const month = currentMonth();
  const thisMonth = usage[month] ?? { scanCount: 0, events: [] };
  const limit = TIER_LIMITS[license.tier];

  // Last 6 months of totals, oldest first, for a simple trend view.
  const monthTrend: { month: string; scanCount: number }[] = [];
  const now = new Date();
  for (let i = 5; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const m = d.toISOString().slice(0, 7);
    monthTrend.push({ month: m, scanCount: usage[m]?.scanCount ?? 0 });
  }

  const recentEvents = [...thisMonth.events].slice(-25).reverse();

  res.json({
    tier: license.tier,
    ownerEmail: license.ownerEmail,
    limit: limit === Infinity ? null : limit,
    thisMonth: { month, scanCount: thisMonth.scanCount },
    monthTrend,
    recentEvents,
  });
});

// Admin dashboard page (static HTML, fetches /api/dashboard-data client-side).
/**
 * POST /api/telemetry
 *
 * Receives anonymous adoption counts. Deliberately stores NO raw event log —
 * only per-install aggregates keyed by a random install ID the client
 * generated locally. There is nothing here that identifies a person, a
 * company, or a codebase, and there is no way to reconstruct one later.
 */
app.post("/api/telemetry", (req, res) => {
  const { installId, version, platform, toolsScanned, findingsTotal, findingsCritical } = req.body ?? {};
  if (!installId || typeof installId !== "string" || installId.length < 8) {
    return res.status(400).json({ ok: false });
  }

  const db = loadDb();
  if (!db.telemetry) db.telemetry = {};

  const today = new Date().toISOString().slice(0, 10);
  const existing = db.telemetry[installId];

  db.telemetry[installId] = {
    firstSeen: existing?.firstSeen ?? today,
    lastSeen: today,
    scanCount: (existing?.scanCount ?? 0) + 1,
    toolsScanned: (existing?.toolsScanned ?? 0) + (Number(toolsScanned) || 0),
    findingsTotal: (existing?.findingsTotal ?? 0) + (Number(findingsTotal) || 0),
    findingsCritical: (existing?.findingsCritical ?? 0) + (Number(findingsCritical) || 0),
    version: typeof version === "string" ? version : existing?.version ?? "unknown",
    platform: typeof platform === "string" ? platform : existing?.platform ?? "unknown",
  };

  saveDb(db);
  return res.json({ ok: true });
});

/**
 * GET /api/stats
 *
 * Public aggregate stats, safe to call from the landing page. Returns only
 * totals — never per-install rows.
 *
 * Note: these numbers reflect installs that OPTED IN to telemetry, which is
 * off by default. Real adoption is higher than this shows. If you publish
 * these figures, say that, or you are misrepresenting your own data.
 */
app.get("/api/stats", (_req, res) => {
  const db = loadDb();
  const rows = Object.values(db.telemetry ?? {});

  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const active30d = rows.filter((r) => r.lastSeen >= cutoff).length;
  const returning = rows.filter((r) => r.scanCount > 1).length;

  res.json({
    installs: rows.length,
    active30d,
    returning,
    totalScans: rows.reduce((n, r) => n + r.scanCount, 0),
    totalToolsScanned: rows.reduce((n, r) => n + r.toolsScanned, 0),
    totalCriticalFindings: rows.reduce((n, r) => n + r.findingsCritical, 0),
    _note: "Counts reflect opt-in telemetry only (off by default). Actual usage is higher.",
  });
});

app.get("/dashboard", (_req, res) => {
  res.sendFile(path.join(PACKAGE_ROOT, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log(`ryzek license server listening on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/dashboard?key=<your-key>`);
});
