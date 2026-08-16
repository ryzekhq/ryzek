import * as fs from "fs";
import * as os from "os";
import * as path from "path";

/**
 * Bug / bypass report generator.
 *
 * Design decision that matters: this does NOT transmit anything. It writes a
 * report to a local file that the user reads, edits, and sends themselves.
 *
 * The alternative — a command that silently POSTs a report containing their
 * manifest — would mean a security tool exfiltrating the exact files it was
 * pointed at. That's the behaviour ryzek itself flags as critical. So
 * the report is generated locally, the user sees every line before it leaves
 * their machine, and attaching a sample is an explicit choice they make.
 */

export type ReportKind = "false-positive" | "false-negative" | "bug";

export interface ReportOptions {
  kind: ReportKind;
  version: string;
  ruleId?: string;
  description?: string;
  /** Path to a sample the user explicitly chose to include. */
  samplePath?: string;
}

const KIND_LABEL: Record<ReportKind, string> = {
  "false-positive": "False positive — flagged something that is actually fine",
  "false-negative": "Missed detection / bypass — did NOT flag something malicious",
  bug: "Bug — crash, wrong output, or unexpected behaviour",
};

const KIND_GUIDANCE: Record<ReportKind, string> = {
  "false-positive":
    "Please describe what the tool flagged and why it's actually safe. If you can share the\n" +
    "manifest (or a redacted version), that's the single most useful thing you can attach —\n" +
    "it goes into the test suite so this specific false positive can never come back.",
  "false-negative":
    "This is the most valuable report type. Please describe what the skill actually does and\n" +
    "why it should have been flagged. If you can share the sample, it goes straight into the\n" +
    "benchmark corpus, and the fix ships with your finding credited in the release notes.",
  bug:
    "Please describe what you ran, what you expected, and what happened instead. If there was\n" +
    "an error message, paste the full text — the first line is rarely the useful one.",
};

export function buildReport(opts: ReportOptions): string {
  const lines: string[] = [];

  lines.push("# ryzek report");
  lines.push("");
  lines.push(`**Type:** ${KIND_LABEL[opts.kind]}`);
  lines.push(`**Generated:** ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Environment");
  lines.push("");
  lines.push(`- ryzek version: ${opts.version}`);
  lines.push(`- Node: ${process.version}`);
  lines.push(`- Platform: ${process.platform} (${os.release()})`);
  lines.push("");

  if (opts.ruleId) {
    lines.push("## Rule involved");
    lines.push("");
    lines.push(`\`${opts.ruleId}\``);
    lines.push("");
  }

  lines.push("## What happened");
  lines.push("");
  lines.push(opts.description ? opts.description : "<!-- Describe it here. -->");
  lines.push("");
  lines.push("<!--");
  lines.push(KIND_GUIDANCE[opts.kind]);
  lines.push("-->");
  lines.push("");

  if (opts.samplePath) {
    lines.push("## Sample");
    lines.push("");
    try {
      const content = fs.readFileSync(opts.samplePath, "utf-8");
      lines.push(`Included from \`${path.basename(opts.samplePath)}\` at your request:`);
      lines.push("");
      lines.push("```");
      lines.push(content.slice(0, 8000));
      if (content.length > 8000) lines.push("... (truncated at 8000 characters)");
      lines.push("```");
    } catch (e) {
      lines.push(`Could not read ${opts.samplePath}: ${e instanceof Error ? e.message : e}`);
    }
    lines.push("");
    lines.push(
      "> Review the above before sending. Remove anything sensitive — this file has not left your machine."
    );
    lines.push("");
  } else {
    lines.push("## Sample");
    lines.push("");
    lines.push("<!--");
    lines.push("No sample was attached. If you can include the manifest or SKILL.md (redacted is fine),");
    lines.push("re-run with --sample <path>, or paste it below. Samples are what actually fix things.");
    lines.push("-->");
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push("**Nothing here has been sent anywhere.** Review this file, then either:");
  lines.push("");
  lines.push("- Open an issue and paste it in, or");
  lines.push("- Email it to the address in SECURITY.md");
  lines.push("");
  lines.push("Accepted bypass reports are credited in the release notes.");

  return lines.join("\n");
}

export function writeReport(opts: ReportOptions, outPath?: string): string {
  const file = outPath || path.resolve(`ryzek-report-${Date.now()}.md`);
  fs.writeFileSync(file, buildReport(opts) + "\n", "utf-8");
  return file;
}
