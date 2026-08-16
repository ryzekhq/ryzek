#!/usr/bin/env node
import * as path from "path";
import * as fs from "fs";
import { loadManifestsFromDir } from "./loader";
import { allRules } from "./rules";
import { scanTools } from "./scanner";
import { formatReport } from "./report";
import { formatSarif } from "./sarif";
import { loadFeedback, markFalsePositive } from "./feedback";
import { loadBaseline, saveBaseline, recordBaseline, toolKey, computeHash } from "./baseline";
import {
  DEFAULT_LICENSE_SERVER,
  saveLicenseState,
  checkUsage,
  recordScan,
  clearPendingEvents,
  loadUsageState,
  reportUsageRemote,
  resolveEffectiveTier,
  validateKeyRemote,
  maskKey,
} from "./license";
import { TIER_LIMITS, Tier } from "./license-types";
import { VERSION } from "./version";
import { writeReport, ReportKind } from "./report-issue";
import { discoverSkillLocations, formatDiscovery } from "./discover";
import { installHook, uninstallHook } from "./hook";
import {
  firstRunNotice,
  setTelemetryEnabled,
  telemetryStatusLine,
  reportScanTelemetry,
} from "./telemetry";



const USAGE =
  "Usage: ryzek <directory-of-tool-manifests> [--sarif [outfile.sarif]]\n" +
  "       ryzek <dir> --verify            (strict CI gate against committed baseline)\n" +
  "       ryzek <dir> --mark-false-positive <ruleId> <toolName>\n" +
  "       ryzek <dir> --update-baseline [toolName]\n" +
  "       ryzek license set <key>\n" +
  "       ryzek license status\n" +
  "       ryzek telemetry on|off\n" +
  "       ryzek report <false-positive|false-negative|bug> [--rule ID] [--sample PATH]\n" +
  "       ryzek discover [--path DIR]\n" +
  "       ryzek hook install|uninstall";

function describeLimit(tier: Tier): string {
  const limit = TIER_LIMITS[tier];
  return limit === Infinity ? "unlimited scans/month" : `${limit} scans/month`;
}

async function handleLicenseCommand(args: string[]): Promise<void> {
  const sub = args[1];

  if (sub === "set") {
    const key = args[2];
    if (!key) {
      console.error("Usage: ryzek license set <key>");
      process.exit(1);
      return;
    }
    console.log("Validating key against the license server...");
    try {
      const result = await validateKeyRemote(key, DEFAULT_LICENSE_SERVER);
      if (!result.valid) {
        console.error(`Key rejected: ${result.reason ?? "invalid key"}`);
        process.exit(1);
        return;
      }
      saveLicenseState({
        key,
        tier: result.tier,
        ownerEmail: result.ownerEmail,
        lastValidatedAt: new Date().toISOString(),
        gracePeriodStartedAt: null,
      });
      console.log(`License saved. Tier: ${result.tier.toUpperCase()} (limit: ${describeLimit(result.tier)}).`);
    } catch (e) {
      console.error(
        `Could not reach the license server at ${DEFAULT_LICENSE_SERVER}: ${
          e instanceof Error ? e.message : e
        }`
      );
      console.error("Key was NOT saved. Check the server is running, or set RYZEK_LICENSE_SERVER.");
      process.exit(1);
    }
    return;
  }

  if (sub === "status") {
    const { tier, state, degraded } = await resolveEffectiveTier();
    const usage = checkUsage(tier);
    console.log(`Tier:        ${tier.toUpperCase()}`);
    console.log(`Key:         ${state.key ? maskKey(state.key) : "(none — free tier)"}`);
    if (state.ownerEmail) console.log(`Owner:       ${state.ownerEmail}`);
    console.log(
      `This month:  ${usage.usedThisMonth} / ${usage.limit === Infinity ? "unlimited" : usage.limit} scans used`
    );
    if (degraded) {
      console.log("Note: license server unreachable — running on cached tier during the offline grace period.");
    }
    return;
  }

  console.error(USAGE);
  process.exit(1);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // These must be checked BEFORE anything treats args[0] as a directory path.
  // Previously "--help" and "--version" fell through to loadManifestsFromDir,
  // which tried to scandir a folder literally named "--help" and crashed with
  // a raw Node stack trace — the first and second commands most people try on
  // an unfamiliar CLI, both broken. Found by an actual first-time user.
  if (args[0] === "--help" || args[0] === "-h" || args[0] === "help") {
    console.log(USAGE);
    console.log("");
    console.log("Examples:");
    console.log("  ryzek ./skills                                    scan a folder");
    console.log("  ryzek ./skills --sarif out.sarif                  scan + write SARIF for GitHub Code Scanning");
    console.log("  ryzek ./skills --verify                           strict CI gate against the committed baseline");
    console.log("  ryzek discover                                    find installed skills on this machine");
    console.log("  ryzek hook install ./skills                       scan automatically before every git commit");
    console.log("  ryzek license status                              check current tier and usage");
    console.log("");
    console.log("Docs: https://github.com/ryzekhq/ryzek");
    return;
  }

  if (args[0] === "--version" || args[0] === "-v" || args[0] === "version") {
    console.log(VERSION);
    return;
  }

  if (args[0] === "license") {
    await handleLicenseCommand(args);
    return;
  }

  if (args[0] === "discover") {
    const extra: string[] = [];
    let i = args.indexOf("--path");
    while (i !== -1) {
      const v = args[i + 1];
      if (v && !v.startsWith("--")) extra.push(v);
      i = args.indexOf("--path", i + 1);
    }
    const locations = discoverSkillLocations(process.cwd(), extra);
    console.log(formatDiscovery(locations));
    return;
  }

  if (args[0] === "hook") {
    const sub = args[1];
    if (sub === "install") {
      const target = args[2] && !args[2].startsWith("--") ? args[2] : "./skills";
      const result = installHook(process.cwd(), target);
      console.log(result.message);
      if (result.ok) {
        console.log("");
        console.log(`It will scan "${target}" before each commit and block only on CRITICAL findings.`);
        console.log("Bypass a single commit with: git commit --no-verify");
      }
      process.exit(result.ok ? 0 : 1);
      return;
    }
    if (sub === "uninstall") {
      const result = uninstallHook(process.cwd());
      console.log(result.message);
      process.exit(result.ok ? 0 : 1);
      return;
    }
    console.error("Usage: ryzek hook install [scanPath]   (default: ./skills)");
    console.error("       ryzek hook uninstall");
    process.exit(1);
    return;
  }

  if (args[0] === "report") {
    const kindArg = (args[1] || "").toLowerCase();
    const valid: ReportKind[] = ["false-positive", "false-negative", "bug"];
    if (!valid.includes(kindArg as ReportKind)) {
      console.error("Usage: ryzek report <false-positive|false-negative|bug> [--rule <ruleId>] [--sample <path>] [--message \"...\"]");
      console.error("");
      console.error("  false-positive   flagged something that's actually fine");
      console.error("  false-negative   missed something malicious (most valuable)");
      console.error("  bug              crash or wrong behaviour");
      process.exit(1);
      return;
    }

    const flagValue = (flag: string): string | undefined => {
      const i = args.indexOf(flag);
      if (i === -1) return undefined;
      const v = args[i + 1];
      return v && !v.startsWith("--") ? v : undefined;
    };

    const file = writeReport({
      kind: kindArg as ReportKind,
      version: VERSION,
      ruleId: flagValue("--rule"),
      description: flagValue("--message"),
      samplePath: flagValue("--sample"),
    });

    console.log(`Report written to:\n  ${file}\n`);
    console.log("Nothing has been sent. Open that file, review it (remove anything sensitive),");
    console.log("then paste it into an issue or email it to the address in SECURITY.md.");
    console.log("");
    console.log("Accepted bypass reports are credited in the release notes.");
    return;
  }

  if (args[0] === "telemetry") {
    const sub = args[1];
    if (sub === "on") {
      setTelemetryEnabled(true);
      console.log("Telemetry ON. Anonymous counts only — never file names, manifest content, or findings detail.");
      console.log("Turn it off any time with: ryzek telemetry off");
    } else if (sub === "off") {
      setTelemetryEnabled(false);
      console.log("Telemetry OFF. Nothing will be sent.");
    } else {
      console.log(telemetryStatusLine());
      console.log("\nUsage: ryzek telemetry on|off");
    }
    return;
  }

  const targetDir = args[0];
  if (!targetDir) {
    console.error(USAGE);
    process.exit(1);
    return;
  }

  const dir = path.resolve(targetDir);

  // Root-cause fix, not a one-off: ANY unrecognized argument reaching this
  // point — a typo'd flag, a bad path, anything starting with "-" that isn't
  // a real folder — previously fell straight into fs.readdirSync and crashed
  // with a raw Node stack trace instead of a usable error. This one check
  // catches that whole class rather than special-casing individual flags.
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    if (targetDir.startsWith("-")) {
      console.error(`Unrecognized option "${targetDir}".`);
      console.error("");
    } else {
      console.error(`"${targetDir}" is not a directory (resolved to ${dir}).`);
      console.error("");
    }
    console.error(USAGE);
    process.exit(1);
    return;
  }

  const markIdx = args.indexOf("--mark-false-positive");
  if (markIdx !== -1) {
    const ruleId = args[markIdx + 1];
    const toolName = args[markIdx + 2];
    if (!ruleId || !toolName) {
      console.error('Usage: --mark-false-positive <ruleId> "<toolName>"');
      process.exit(1);
      return;
    }
    const tools = loadManifestsFromDir(dir);
    const match = tools.find((t) => t.name === toolName);
    if (!match) {
      console.error(`No tool named "${toolName}" found in ${dir}`);
      process.exit(1);
      return;
    }
    markFalsePositive(dir, ruleId, toolName, match.sourceFile);
    console.log(`Marked ${ruleId} on "${toolName}" as a false positive. It will show as suppressed on future scans.`);
    return;
  }

  const updateBaselineIdx = args.indexOf("--update-baseline");
  if (updateBaselineIdx !== -1) {
    const toolName = args[updateBaselineIdx + 1];
    const tools = loadManifestsFromDir(dir);
    const baseline = loadBaseline(dir);

    if (!toolName) {
      for (const t of tools) recordBaseline(baseline, t);
      saveBaseline(dir, baseline);
      console.log(`Baseline updated for all ${tools.length} tool(s) in ${dir}.`);
      return;
    }

    const match = tools.find((t) => t.name === toolName);
    if (!match) {
      console.error(`No tool named "${toolName}" found in ${dir}`);
      process.exit(1);
      return;
    }
    recordBaseline(baseline, match);
    saveBaseline(dir, baseline);
    console.log(`Baseline updated for "${toolName}". Future scans compare against this version.`);
    return;
  }

  // --verify: strict CI gate. Fails if ANY tool has changed since the
  // committed baseline, or if a tool appears that isn't in it at all. Unlike a
  // normal scan (which records first sightings automatically and reports drift
  // as a finding), this treats the baseline as a lockfile: nothing new,
  // nothing changed, or the build fails. Meant to run pre-deploy.
  if (args.includes("--verify")) {
    const tools = loadManifestsFromDir(dir);
    const baseline = loadBaseline(dir);
    const knownKeys = Object.keys(baseline.tools);

    if (knownKeys.length === 0) {
      console.error(
        `No baseline found in ${dir}. Run a normal scan first, then commit ` +
          `.ryzek-baseline.json so --verify has something to check against.`
      );
      process.exit(1);
      return;
    }

    const changed: string[] = [];
    const added: string[] = [];
    const seen = new Set<string>();

    for (const t of tools) {
      const key = toolKey(t);
      seen.add(key);
      const prev = baseline.tools[key];
      if (!prev) {
        added.push(`${t.name} [${t.sourceFile}]`);
      } else if (computeHash(t) !== prev.hash) {
        changed.push(`${t.name} [${t.sourceFile}]`);
      }
    }
    const removed = knownKeys.filter((k) => !seen.has(k));

    if (changed.length === 0 && added.length === 0 && removed.length === 0) {
      console.log(`✓ Verified: all ${tools.length} tool(s) match the committed baseline exactly.`);
      process.exit(0);
      return;
    }

    console.error("✗ Verification FAILED — the scanned tools do not match the committed baseline.\n");
    if (changed.length) {
      console.error(`Changed since baseline (${changed.length}):`);
      changed.forEach((c) => console.error(`    - ${c}`));
    }
    if (added.length) {
      console.error(`Not in baseline at all (${added.length}):`);
      added.forEach((a) => console.error(`    + ${a}`));
    }
    if (removed.length) {
      console.error(`In baseline but missing now (${removed.length}):`);
      removed.forEach((r) => console.error(`    ? ${r}`));
    }
    console.error(
      `\nIf these changes are intentional, re-run with --update-baseline and commit the updated ` +
        `.ryzek-baseline.json.`
    );
    process.exit(4); // distinct from findings (2) and quota (3)
    return;
  }

  // --- License / usage gate, before any scanning happens ---
  const { tier, state, degraded } = await resolveEffectiveTier();
  const usageCheck = checkUsage(tier);

  if (!usageCheck.allowed) {
    console.error(
      `\nMonthly scan limit reached: ${usageCheck.usedThisMonth}/${usageCheck.limit} scans used on the ${tier.toUpperCase()} tier this month.`
    );
    if (tier === "free") {
      console.error("Upgrade to Pro (1,000 scans/month) or Enterprise (unlimited) to keep scanning this month.");
    } else {
      console.error("Contact your license administrator, or wait until next month's counter resets.");
    }
    console.error(`Run "ryzek license status" to see current usage.`);
    process.exit(3); // distinct from "critical findings" (2), so CI can tell the difference
    return;
  }

  if (degraded) {
    console.error(
      `(license server unreachable — running on cached ${tier.toUpperCase()} tier during offline grace period)`
    );
  }

  const tools = loadManifestsFromDir(dir);

  if (tools.length === 0) {
    console.log(`No .json tool manifests found in ${dir}`);
    return;
  }

  const feedback = loadFeedback(dir);
  const baseline = loadBaseline(dir);
  const results = scanTools(tools, allRules, feedback, baseline);

  // --sarif [outfile] emits SARIF 2.1.0 for GitHub Code Scanning. With no
  // filename it goes to stdout (so it can be piped); with one, it's written
  // to that file and the normal human report still prints, which is what you
  // want in CI — a readable log AND an uploadable artifact from one run.
  const sarifIdx = args.indexOf("--sarif");
  if (sarifIdx !== -1) {
    const outFile = args[sarifIdx + 1];
    const sarif = formatSarif(results);
    if (outFile && !outFile.startsWith("--")) {
      fs.writeFileSync(path.resolve(outFile), sarif + "\n", "utf-8");
      console.log(formatReport(results));
      console.log(`\nSARIF written to ${outFile}`);
    } else {
      console.log(sarif);
    }
  } else {
    console.log(formatReport(results));
  }

  let newlyBaselined = 0;
  for (const t of tools) {
    if (!baseline.tools[toolKey(t)]) {
      recordBaseline(baseline, t);
      newlyBaselined++;
    }
  }
  if (newlyBaselined > 0) {
    saveBaseline(dir, baseline);
    console.log(
      `(${newlyBaselined} tool(s) seen for the first time — recorded as this run's baseline for future drift detection)`
    );
  }

  const totalFindings = results.reduce((n, r) => n + r.findings.filter((f) => !f.suppressed).length, 0);
  const criticalCount = results.reduce(
    (n, r) => n + r.findings.filter((f) => !f.suppressed && f.severity === "critical").length,
    0
  );

  recordScan({
    timestamp: new Date().toISOString(),
    toolsScanned: tools.length,
    findingsCount: totalFindings,
    criticalCount,
  });

  await reportScanTelemetry(
    {
      toolsScanned: tools.length,
      findingsTotal: totalFindings,
      findingsCritical: criticalCount,
      findingsHigh: results.reduce(
        (n, r) => n + r.findings.filter((f) => !f.suppressed && f.severity === "high").length,
        0
      ),
    },
    VERSION
  );

  const notice = firstRunNotice();
  if (notice) console.log(notice);

  const updatedUsage = checkUsage(tier);
  console.log(
    `\n(${tier.toUpperCase()} tier: ${updatedUsage.usedThisMonth}/${
      updatedUsage.limit === Infinity ? "unlimited" : updatedUsage.limit
    } scans used this month)`
  );

  if (state.key) {
    const usage = loadUsageState();
    const reported = await reportUsageRemote(state.key, usage, DEFAULT_LICENSE_SERVER);
    if (reported) clearPendingEvents();
  }

  const hasCritical = results.some((r) => r.overallSeverity === "critical");
  process.exit(hasCritical ? 2 : 0);
}

main();
