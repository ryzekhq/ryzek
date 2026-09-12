import * as fs from "fs";
import * as path from "path";
import { ToolManifest } from "./types";
import { loadSkillsFromDir } from "./skill-loader";

/**
 * Package-manager and tooling files are JSON with a `name`, so the permissive
 * loader below would otherwise treat them as agent tools. They aren't, and
 * scanning them produces findings on every ordinary repo — `package.json` and
 * `package-lock.json` declaring the same `name` looks exactly like two tools
 * fighting over one name. Skipped by filename rather than by heuristic, because
 * guessing wrong in either direction is worse than a short explicit list.
 */
const NOT_TOOL_MANIFESTS = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "tsconfig.json",
  "jsconfig.json",
  "composer.json",
  "composer.lock",
  "bower.json",
  "deno.json",
  "deno.lock",
  "lerna.json",
  "nx.json",
  "angular.json",
  "renovate.json",
  "jest.config.json",
]);

/**
 * Very deliberately permissive loader: MCP servers and agent "skills" show up as JSON
 * (most common), and this reads them without assuming a rigid schema, since real-world
 * manifests vary a lot between frameworks. Anything with a name+description is treated
 * as a tool.
 */
export function loadManifestsFromDir(dir: string): ToolManifest[] {
  const files = fs
    .readdirSync(dir)
    .filter(
      (f) =>
        f.endsWith(".json") &&
        !f.startsWith(".ryzek") &&
        !NOT_TOOL_MANIFESTS.has(f.toLowerCase())
    );
  const tools: ToolManifest[] = [];

  for (const file of files) {
    const fullPath = path.join(dir, file);
    const raw = JSON.parse(fs.readFileSync(fullPath, "utf-8"));

    // Support both a single tool object and a { tools: [...] } list in one file.
    const entries = Array.isArray(raw.tools) ? raw.tools : [raw];

    for (const entry of entries) {
      tools.push({
        name: entry.name ?? "(unnamed)",
        description: entry.description ?? "",
        sourceFile: file,
        parameters: entry.parameters ?? entry.inputSchema ?? {},
        permissions: entry.permissions ?? [],
        raw: entry,
      });
    }
  }

  // SKILL.md skills are loaded too, and normalized into the same shape, so
  // every rule applies to both formats without knowing which it's looking at.
  tools.push(...loadSkillsFromDir(dir));

  return tools;
}
