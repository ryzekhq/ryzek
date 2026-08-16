import * as fs from "fs";
import * as path from "path";
import { ToolManifest } from "./types";
import { loadSkillsFromDir } from "./skill-loader";

/**
 * Very deliberately permissive loader: MCP servers and agent "skills" show up as JSON
 * (most common), and this reads them without assuming a rigid schema, since real-world
 * manifests vary a lot between frameworks. Anything with a name+description is treated
 * as a tool.
 */
export function loadManifestsFromDir(dir: string): ToolManifest[] {
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json") && !f.startsWith(".ryzek"));
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
