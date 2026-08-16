import * as fs from "fs";
import * as path from "path";

/**
 * Git pre-commit hook installation.
 *
 * Rationale: a scanner that must be remembered gets run once, at setup, and
 * then never again — which is precisely when a rug-pull change would slip
 * through, since drift detection only helps if something re-scans. Wiring it
 * into the commit path makes the check automatic and puts drift detection
 * where it can actually do its job.
 *
 * Deliberate choices:
 *  - Never silently overwrite an existing hook. Clobbering someone's git
 *    config is unacceptable; if a hook exists, we explain and stop.
 *  - The hook fails the commit ONLY on critical findings (exit 2). Warnings
 *    print but don't block, because a hook that blocks on everything gets
 *    disabled within a day and then protects nothing.
 *  - `--no-verify` still bypasses it. That's git's design and trying to
 *    defeat it would be hostile.
 */

const HOOK_MARKER = "# >>> ryzek pre-commit hook >>>";

export function hookScript(scanPath: string): string {
  return `#!/bin/sh
${HOOK_MARKER}
# Installed by: ryzek hook install
# Remove with:  ryzek hook uninstall
#
# Scans agent skill manifests before each commit. Blocks the commit only on
# CRITICAL findings; lower severities print but let the commit through.
# Bypass once with: git commit --no-verify

RYZEK_TARGET="${scanPath}"

if [ ! -d "$RYZEK_TARGET" ]; then
  # Nothing to scan — don't block the commit over a missing folder.
  exit 0
fi

if command -v ryzek >/dev/null 2>&1; then
  RYZEK_CMD="ryzek"
elif [ -f "node_modules/.bin/ryzek" ]; then
  RYZEK_CMD="node_modules/.bin/ryzek"
elif [ -f "dist/cli.js" ]; then
  RYZEK_CMD="node dist/cli.js"
else
  echo "ryzek: not found on PATH — skipping pre-commit scan."
  echo "       install with: npm install -g ryzek"
  exit 0
fi

echo "ryzek: scanning $RYZEK_TARGET ..."
$RYZEK_CMD "$RYZEK_TARGET"
STATUS=$?

if [ $STATUS -eq 2 ]; then
  echo ""
  echo "ryzek: COMMIT BLOCKED — critical findings above."
  echo "  - fix them, or"
  echo "  - if a finding is wrong: $RYZEK_CMD \\"$RYZEK_TARGET\\" --mark-false-positive <ruleId> \\"<toolName>\\""
  echo "  - if a change was intentional: $RYZEK_CMD \\"$RYZEK_TARGET\\" --update-baseline \\"<toolName>\\""
  echo "  - to bypass this once: git commit --no-verify"
  exit 1
fi

exit 0
${HOOK_MARKER.replace(">>>", "<<<")}
`;
}

function hooksDir(repoRoot: string): string {
  return path.join(repoRoot, ".git", "hooks");
}

export function findGitRoot(start: string): string | null {
  let dir = path.resolve(start);
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, ".git"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export interface HookResult {
  ok: boolean;
  message: string;
}

export function installHook(cwd: string, scanPath: string): HookResult {
  const root = findGitRoot(cwd);
  if (!root) {
    return { ok: false, message: "Not inside a git repository — nothing to install into." };
  }

  const dir = hooksDir(root);
  const hookPath = path.join(dir, "pre-commit");

  if (!fs.existsSync(dir)) {
    return { ok: false, message: `No .git/hooks directory at ${dir}.` };
  }

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf-8");
    if (existing.includes(HOOK_MARKER)) {
      fs.writeFileSync(hookPath, hookScript(scanPath), "utf-8");
      try {
        fs.chmodSync(hookPath, 0o755);
      } catch {
        /* chmod is a no-op on some Windows setups */
      }
      return { ok: true, message: `Updated existing ryzek hook at ${hookPath}` };
    }
    return {
      ok: false,
      message:
        `A pre-commit hook already exists at ${hookPath} and was NOT written by ryzek.\n` +
        `Refusing to overwrite it. To combine them, add this line to your existing hook:\n\n` +
        `    ryzek "${scanPath}" || exit 1\n`,
    };
  }

  fs.writeFileSync(hookPath, hookScript(scanPath), "utf-8");
  try {
    fs.chmodSync(hookPath, 0o755);
  } catch {
    /* ignore on Windows */
  }
  return { ok: true, message: `Installed pre-commit hook at ${hookPath}` };
}

export function uninstallHook(cwd: string): HookResult {
  const root = findGitRoot(cwd);
  if (!root) return { ok: false, message: "Not inside a git repository." };

  const hookPath = path.join(hooksDir(root), "pre-commit");
  if (!fs.existsSync(hookPath)) {
    return { ok: false, message: "No pre-commit hook installed." };
  }

  const existing = fs.readFileSync(hookPath, "utf-8");
  if (!existing.includes(HOOK_MARKER)) {
    return {
      ok: false,
      message: "The existing pre-commit hook was not installed by ryzek — leaving it alone.",
    };
  }

  fs.unlinkSync(hookPath);
  return { ok: true, message: `Removed ${hookPath}` };
}
