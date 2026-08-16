import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { ToolManifest } from "./types";

/**
 * Baseline / drift tracking.
 *
 * Real MCP tool-poisoning attacks ("rug pulls") don't usually look malicious
 * at install time — a tool passes review, gets approved, and only *later*
 * does its description, permissions, or parameters quietly change to
 * something dangerous, while the agent keeps trusting it because nothing
 * about the install process re-checks that.
 *
 * This module gives ryzek a memory: it hashes each tool's
 * security-relevant fields the first time it's seen, and on every later
 * scan, flags a tool whose hash no longer matches — even if the new version
 * wouldn't trip any other rule on its own. A "clean" tool that silently
 * changed is exactly the case the other 7 rules can't catch, because they
 * only look at a single snapshot in isolation.
 */

export interface BaselineEntry {
  hash: string;
  recordedAt: string;
  permissions: string[];
  /** First 80 chars only — enough to show a human what changed without duplicating the whole manifest. */
  descriptionPreview: string;
}

export interface BaselineStore {
  tools: Record<string, BaselineEntry>;
}

const DEFAULT_FILENAME = ".ryzek-baseline.json";

export function baselinePath(dir: string): string {
  return path.join(dir, DEFAULT_FILENAME);
}

/** Tools are keyed by file + name, since two files could coincidentally reuse a tool name. */
export function toolKey(tool: ToolManifest): string {
  return `${tool.sourceFile}::${tool.name}`;
}

export function computeHash(tool: ToolManifest): string {
  const canonical = JSON.stringify({
    description: tool.description,
    permissions: [...(tool.permissions ?? [])].sort(),
    parameters: tool.parameters ?? {},
  });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

export function loadBaseline(dir: string): BaselineStore {
  const file = baselinePath(dir);
  if (!fs.existsSync(file)) {
    return { tools: {} };
  }
  try {
    const raw = fs.readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed.tools || typeof parsed.tools !== "object") return { tools: {} };
    return parsed as BaselineStore;
  } catch {
    // Corrupt baseline shouldn't crash a scan — treat as if nothing was ever recorded.
    return { tools: {} };
  }
}

export function saveBaseline(dir: string, store: BaselineStore): void {
  fs.writeFileSync(baselinePath(dir), JSON.stringify(store, null, 2) + "\n", "utf-8");
}

export function recordBaseline(store: BaselineStore, tool: ToolManifest): void {
  store.tools[toolKey(tool)] = {
    hash: computeHash(tool),
    recordedAt: new Date().toISOString(),
    permissions: [...(tool.permissions ?? [])],
    descriptionPreview: tool.description.slice(0, 80),
  };
}
