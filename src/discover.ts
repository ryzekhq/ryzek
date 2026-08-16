import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * Skill discovery.
 *
 * The gap this closes: `ryzek ./skills` only scans a folder you already know
 * about. But skills install quietly — from a marketplace, a README's curl
 * command, a teammate's PR — and there is no central registry listing what an
 * agent is actually allowed to run on a given machine. The realistic failure
 * isn't "I scanned my skills and missed something", it's "I didn't know that
 * skill was installed at all."
 *
 * So this walks the known install locations across the common agent tools and
 * reports everything it finds, whether or not the user remembered it.
 *
 * Deliberately read-only: it lists paths, it does not open, execute, or
 * transmit anything. Scanning what it finds is a separate, explicit step.
 */

export interface DiscoveredLocation {
  /** Which tool this location belongs to, e.g. "Claude Code (user)". */
  label: string;
  dir: string;
  exists: boolean;
  skillCount: number;
  skillNames: string[];
}

/**
 * Known skill directories.
 *
 * These are the conventional locations for the current generation of agent
 * tools. They change as tools evolve — if a location is missing, that is a
 * gap in this list, not proof the machine is clean. `--path` lets a user add
 * one, and reporting a missing location is a genuinely useful bug report.
 */
function candidateLocations(cwd: string): { label: string; dir: string }[] {
  const home = os.homedir();
  return [
    { label: "Claude Code (user)", dir: path.join(home, ".claude", "skills") },
    { label: "Claude Code (project)", dir: path.join(cwd, ".claude", "skills") },
    { label: "Agents (user)", dir: path.join(home, ".agents", "skills") },
    { label: "Agents (project)", dir: path.join(cwd, ".agents", "skills") },
    { label: "Gemini (user)", dir: path.join(home, ".gemini", "skills") },
    { label: "Gemini (project)", dir: path.join(cwd, ".gemini", "skills") },
    { label: "Cursor (user)", dir: path.join(home, ".cursor", "skills") },
    { label: "Cursor (project)", dir: path.join(cwd, ".cursor", "skills") },
    { label: "Codex (user)", dir: path.join(home, ".codex", "skills") },
    { label: "MCP config (user)", dir: path.join(home, ".mcp") },
    { label: "Project skills folder", dir: path.join(cwd, "skills") },
  ];
}

/** Lists immediate subdirectories that contain a SKILL.md, plus loose .json manifests. */
function inspectDir(dir: string): { skillNames: string[] } {
  const names: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return { skillNames: [] };
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      try {
        const inner = fs.readdirSync(full);
        if (inner.some((f) => f.toUpperCase() === "SKILL.MD")) {
          names.push(entry.name);
        }
      } catch {
        // unreadable subdirectory — skip
      }
    } else if (entry.name.toLowerCase().endsWith(".json") && !entry.name.startsWith(".ryzek")) {
      names.push(entry.name);
    } else if (entry.name.toUpperCase() === "SKILL.MD") {
      names.push(path.basename(dir));
    }
  }
  return { skillNames: names };
}

export function discoverSkillLocations(cwd: string, extraPaths: string[] = []): DiscoveredLocation[] {
  const candidates = [
    ...candidateLocations(cwd),
    ...extraPaths.map((p) => ({ label: "User-specified", dir: path.resolve(p) })),
  ];

  const seen = new Set<string>();
  const results: DiscoveredLocation[] = [];

  for (const c of candidates) {
    const resolved = path.resolve(c.dir);
    if (seen.has(resolved)) continue;
    seen.add(resolved);

    const exists = fs.existsSync(resolved) && fs.statSync(resolved).isDirectory();
    const { skillNames } = exists ? inspectDir(resolved) : { skillNames: [] };

    results.push({
      label: c.label,
      dir: resolved,
      exists,
      skillCount: skillNames.length,
      skillNames,
    });
  }

  return results;
}

export function formatDiscovery(locations: DiscoveredLocation[]): string {
  const found = locations.filter((l) => l.exists && l.skillCount > 0);
  const emptyButPresent = locations.filter((l) => l.exists && l.skillCount === 0);
  const lines: string[] = [];

  const total = found.reduce((n, l) => n + l.skillCount, 0);

  if (found.length === 0) {
    lines.push("No installed skills found in the known locations.");
    lines.push("");
    lines.push("That means none were found where agent tools normally put them — it does");
    lines.push("not prove the machine has none. If you keep skills somewhere unusual:");
    lines.push("");
    lines.push("    ryzek discover --path /your/folder");
    lines.push("");
    if (emptyButPresent.length) {
      lines.push(`(${emptyButPresent.length} known location(s) exist but are empty.)`);
    }
    return lines.join("\n");
  }

  lines.push(`Found ${total} skill(s) across ${found.length} location(s):`);
  lines.push("");

  for (const loc of found) {
    lines.push(`  ${loc.label}`);
    lines.push(`  ${loc.dir}`);
    for (const name of loc.skillNames) {
      lines.push(`      - ${name}`);
    }
    lines.push("");
  }

  lines.push("Scan any of these with:");
  lines.push("");
  for (const loc of found.slice(0, 3)) {
    lines.push(`    ryzek "${loc.dir}"`);
  }
  lines.push("");
  lines.push("Note: this lists what's installed. It does not judge any of it — run a scan");
  lines.push("on a location to actually check its contents.");

  return lines.join("\n");
}
