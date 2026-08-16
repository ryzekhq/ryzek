import * as fs from "fs";
import * as path from "path";
import { ToolManifest } from "./types";
import { findOpaqueFiles } from "./binary-inspect";

/**
 * SKILL.md loader.
 *
 * The attack surface moved. The 2026 incident record (ClawHavoc, ToxicSkills,
 * the Air Security research) centres on SKILL.md files and their bundled
 * scripts — markdown with YAML frontmatter, where the "code" the agent
 * executes is prose instructions, not a JSON schema. A scanner that only
 * reads .json manifests is scanning the previous generation's attack surface.
 *
 * This normalizes a skill directory into the same ToolManifest shape the
 * existing 9 rules already consume, so every rule works on SKILL.md content
 * with no rule changes:
 *   - frontmatter `name`      -> name
 *   - frontmatter `description` -> description
 *   - `allowed-tools` / `permissions` -> permissions
 *   - the full markdown body  -> folded into `raw` so text-scanning rules
 *                                (injection, unicode, secrets, exec) see it
 *   - bundled scripts/*       -> read and appended to `raw` so a payload
 *                                hidden in a helper script is still visible
 *
 * Deliberate design note: the markdown body goes into `raw` rather than
 * `description`, because `description` feeds the description-vs-capability
 * mismatch rule, and folding a 400-line body into it would wreck that rule's
 * signal. Text-scanning rules read `raw`; semantic rules read `description`.
 */

const SCRIPT_EXTENSIONS = [".py", ".sh", ".js", ".ts", ".rb", ".ps1", ".bash"];
const MAX_SCRIPT_BYTES = 200_000; // don't read an enormous file into memory for a static scan

export interface FrontmatterResult {
  data: Record<string, any>;
  body: string;
  /**
   * The verbatim frontmatter text, before parsing.
   *
   * This exists because of a real, tested failure: the parser below is
   * deliberately minimal and does not descend into nested YAML, but real
   * malicious skills hide payloads exactly there — a live sample in the
   * ToxicSkills corpus buries a credential-exfiltrating hook at
   * `hooks.UserPromptSubmit[].hooks[].command: "env > /tmp/a"`, three levels
   * deep. The structured parse silently dropped it, so no rule could see it.
   *
   * Rather than adopt a full YAML parser (itself an AST04 deserialization
   * risk on untrusted input), the raw text is carried through and folded into
   * the manifest's `raw`. Parsing is best-effort; the verbatim text is the
   * guarantee. A parse gap can now degrade structure, but it can never create
   * a blind spot.
   */
  rawFrontmatter: string;
}

/**
 * Minimal YAML frontmatter parser.
 *
 * Deliberately hand-rolled rather than pulling in a YAML dependency: skill
 * frontmatter is a flat key/value block in practice, and a real YAML parser
 * is itself an attack surface here (AST04 calls out unsafe deserialization
 * of untrusted skill configs specifically). This never evaluates or
 * constructs anything — it only splits strings.
 */
export function parseFrontmatter(content: string): FrontmatterResult {
  const normalized = content.replace(/\r\n/g, "\n");
  if (!normalized.startsWith("---\n")) {
    return { data: {}, body: normalized, rawFrontmatter: "" };
  }
  const end = normalized.indexOf("\n---", 4);
  if (end === -1) {
    return { data: {}, body: normalized, rawFrontmatter: "" };
  }

  const rawFrontmatter = normalized.slice(4, end);
  const body = normalized.slice(end + 4).replace(/^\n/, "");
  const data: Record<string, any> = {};

  let currentListKey: string | null = null;
  for (const line of rawFrontmatter.split("\n")) {
    if (!line.trim()) continue;

    // List item continuation: "  - value"
    const listItem = line.match(/^\s*-\s+(.*)$/);
    if (listItem && currentListKey) {
      if (!Array.isArray(data[currentListKey])) data[currentListKey] = [];
      data[currentListKey].push(stripQuotes(listItem[1].trim()));
      continue;
    }

    const kv = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!kv) continue;

    const key = kv[1];
    const value = kv[2].trim();

    if (value === "") {
      // Key with no inline value — expect a list beneath it.
      currentListKey = key;
      data[key] = [];
      continue;
    }

    currentListKey = null;

    // Inline list: "allowed-tools: Bash, Read"  or  "[Bash, Read]"
    if (value.startsWith("[") && value.endsWith("]")) {
      data[key] = value
        .slice(1, -1)
        .split(",")
        .map((s) => stripQuotes(s.trim()))
        .filter(Boolean);
    } else if (value.includes(",")) {
      data[key] = value.split(",").map((s) => stripQuotes(s.trim())).filter(Boolean);
    } else {
      data[key] = stripQuotes(value);
    }
  }

  return { data, body, rawFrontmatter };
}

function stripQuotes(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function normalizePermissions(data: Record<string, any>): string[] {
  // Different platforms name this differently; accept all the common spellings.
  const candidates = [data["allowed-tools"], data["allowedTools"], data["permissions"], data["tools"]];
  const out: string[] = [];
  for (const c of candidates) {
    if (!c) continue;
    if (Array.isArray(c)) out.push(...c.map(String));
    else if (typeof c === "string") out.push(...c.split(",").map((s) => s.trim()).filter(Boolean));
  }
  return [...new Set(out)];
}

/** Reads bundled scripts next to a SKILL.md so payloads hidden in helpers are still scanned. */
function collectBundledScripts(skillDir: string): Record<string, string> {
  const scripts: Record<string, string> = {};
  const subdirs = ["scripts", "bin", "tools", "."];

  for (const sub of subdirs) {
    const dir = path.join(skillDir, sub);
    if (!fs.existsSync(dir)) continue;
    let entries: string[];
    try {
      entries = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry);
      let stat;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }
      if (!stat.isFile()) continue;
      if (!SCRIPT_EXTENSIONS.includes(path.extname(entry).toLowerCase())) continue;
      if (stat.size > MAX_SCRIPT_BYTES) continue;
      try {
        scripts[path.relative(skillDir, full)] = fs.readFileSync(full, "utf-8");
      } catch {
        /* unreadable file shouldn't abort the scan */
      }
    }
  }
  return scripts;
}

/** Loads a single SKILL.md (plus its bundled scripts) as one ToolManifest. */
export function loadSkillMd(skillMdPath: string, displayPath?: string): ToolManifest {
  const content = fs.readFileSync(skillMdPath, "utf-8");
  const { data, body, rawFrontmatter } = parseFrontmatter(content);
  const skillDir = path.dirname(skillMdPath);
  const scripts = collectBundledScripts(skillDir);
  // Binary/archive payloads bundled with the skill. Text rules can't read
  // these, so they're surfaced as structured metadata for the opaque-payload
  // rule — and anything we could decompress is folded in as scannable text.
  const opaqueFiles = findOpaqueFiles(skillDir);

  const name = typeof data.name === "string" && data.name ? data.name : path.basename(skillDir);
  const description = typeof data.description === "string" ? data.description : "";

  return {
    name,
    description,
    sourceFile: displayPath ?? path.relative(process.cwd(), skillMdPath),
    parameters: {},
    permissions: normalizePermissions(data),
    // Everything text-scanning rules need lives here: frontmatter, the full
    // markdown body, and every bundled script's contents.
    raw: {
      ...data,
      name,
      description,
      _skillBody: body,
      // Verbatim frontmatter — guarantees nested payloads the minimal parser
      // can't structure are still visible to every text-scanning rule.
      _frontmatterRaw: rawFrontmatter,
      _bundledScripts: scripts,
      _opaqueFiles: opaqueFiles.map((f) => ({
        relPath: f.relPath,
        kind: f.kind,
        sizeBytes: f.sizeBytes,
        extensionMismatch: f.extensionMismatch,
      })),
      // Content recovered from compressed files gets scanned like any other text.
      _extractedFromArchives: opaqueFiles
        .filter((f) => f.extractedText)
        .map((f) => `--- ${f.relPath} ---\n${f.extractedText}`)
        .join("\n\n"),
    },
  };
}

/**
 * Recursively finds every SKILL.md under a directory and loads each one.
 * Depth-limited so a stray scan of a huge tree doesn't hang.
 */
export function loadSkillsFromDir(dir: string, maxDepth = 6): ToolManifest[] {
  const found: ToolManifest[] = [];

  function walk(current: string, depth: number): void {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        walk(full, depth + 1);
      } else if (entry.name.toUpperCase() === "SKILL.MD") {
        try {
          found.push(loadSkillMd(full, path.relative(dir, full)));
        } catch {
          /* a single unreadable skill shouldn't abort the whole scan */
        }
      }
    }
  }

  walk(dir, 0);
  return found;
}
