/**
 * MCP config discovery and normalisation.
 *
 * Reads MCP configuration files from the locations agent hosts actually use,
 * and turns each declared server into a ToolManifest so the existing rule
 * pipeline can scan them without knowing anything about MCP file formats.
 *
 * The `__mcp: true` marker on `raw` is what lets MCP-specific rules skip
 * ordinary skills, and ordinary rules skip MCP servers where that matters.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { ToolManifest } from "./types";

/** Config locations, relative to home unless they start with "./". */
const MCP_CONFIG_PATHS: string[] = [
  // Claude Desktop
  "AppData/Roaming/Claude/claude_desktop_config.json",
  "Library/Application Support/Claude/claude_desktop_config.json",
  ".config/Claude/claude_desktop_config.json",
  // Claude Code
  ".claude/mcp.json",
  // Cursor
  ".cursor/mcp.json",
  // Windsurf
  ".codeium/windsurf/mcp_config.json",
];

/** Project-local config locations, relative to the scan target. */
const PROJECT_MCP_PATHS: string[] = [
  ".mcp.json",
  ".cursor/mcp.json",
  ".vscode/mcp.json",
  "mcp.json",
  "mcp-config.json",
];

interface McpServerDef {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: string;
  type?: string;
  disabled?: boolean;
  autoApprove?: string[];
  alwaysAllow?: string[];
}

/** Map an MCP server definition onto the permissions vocabulary rules expect. */
function inferPermissions(def: McpServerDef): string[] {
  const perms: string[] = [];
  const cmd = [def.command ?? "", ...(def.args ?? [])].join(" ");

  if (def.url || /https?:\/\//.test(cmd)) perms.push("network:*");
  if (/\b(sh|bash|zsh|cmd|powershell)\b|-c\b/.test(cmd)) perms.push("shell:exec");
  if (def.env && Object.keys(def.env).length > 0) perms.push("env:read");
  // A stdio server spawns a local process with the user's own permissions.
  if (def.command && !def.url) {
    perms.push("filesystem:read", "filesystem:write");
  }
  return perms;
}

/** Turn one MCP server entry into a ToolManifest. */
export function mcpServerToManifest(
  name: string,
  def: McpServerDef,
  sourceFile: string
): ToolManifest {
  return {
    name,
    description:
      def.url
        ? `MCP server (remote): ${def.url}`
        : `MCP server (stdio): ${[def.command, ...(def.args ?? [])].join(" ")}`,
    sourceFile,
    permissions: inferPermissions(def),
    raw: { ...def, __mcp: true },
  };
}

function parseConfigFile(file: string): ToolManifest[] {
  let parsed: any;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];   // unreadable or malformed config is not a scan failure
  }

  const servers: Record<string, McpServerDef> = {
    ...(parsed.mcpServers ?? {}),
    ...(parsed.servers ?? {}),
  };

  return Object.entries(servers)
    .filter(([, def]) => def && def.disabled !== true)
    .map(([name, def]) => mcpServerToManifest(name, def, file));
}

/**
 * Find every MCP server configured on this machine, plus any in the scanned
 * project. Returns ToolManifests ready to run through the rule pipeline.
 */
export function discoverMcpServers(projectDir?: string): ToolManifest[] {
  const out: ToolManifest[] = [];
  const home = os.homedir();

  for (const rel of MCP_CONFIG_PATHS) {
    const file = path.join(home, rel);
    if (fs.existsSync(file)) out.push(...parseConfigFile(file));
  }

  if (projectDir) {
    for (const rel of PROJECT_MCP_PATHS) {
      const file = path.join(projectDir, rel);
      if (fs.existsSync(file)) out.push(...parseConfigFile(file));
    }
  }

  return out;
}

/** Scan a single named config file, e.g. when the user passes one explicitly. */
export function loadMcpConfigFile(file: string): ToolManifest[] {
  return fs.existsSync(file) ? parseConfigFile(file) : [];
}

export { MCP_CONFIG_PATHS, PROJECT_MCP_PATHS };
