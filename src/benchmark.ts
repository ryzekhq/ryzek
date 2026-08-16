/**
 * Benchmark harness.
 *
 * Runs ryzek against a corpus of samples with known ground-truth labels
 * and reports true positives, false negatives, and false positives — so the
 * project can state a *measured* detection rate instead of asserting quality.
 *
 * Why this matters more than another rule: published research has bypassed
 * every public skill scanner tested, and the standard industry response is to
 * keep asserting quality without publishing a number. A measured number,
 * including the misses, is both more useful internally and more credible
 * externally than any claim.
 *
 * Usage:
 *   node dist/benchmark.js <corpus-dir> <labels.json>
 *
 * labels.json format:
 *   { "samples": [ { "path": "relative/path/SKILL.md", "malicious": true, "note": "..." } ] }
 *
 * Paths are matched against a finding's sourceFile by suffix, so labels stay
 * stable regardless of where the corpus is checked out.
 */
import * as fs from "fs";
import * as path from "path";
import { loadManifestsFromDir } from "./loader";
import { allRules } from "./rules";
import { scanTools } from "./scanner";
import { ScanResult } from "./types";

interface LabelEntry {
  path: string;
  malicious: boolean;
  note?: string;
}

interface Labels {
  corpusName?: string;
  source?: string;
  samples: LabelEntry[];
}

function matchesLabel(result: ScanResult, label: LabelEntry): boolean {
  const norm = (s: string) => s.replace(/\\/g, "/").toLowerCase();
  return norm(result.sourceFile).endsWith(norm(label.path));
}

function main(): void {
  const [, , corpusDir, labelsPath, thresholdArg] = process.argv;
  if (!corpusDir || !labelsPath) {
    console.error("Usage: node dist/benchmark.js <corpus-dir> <labels.json> [confidence-threshold]");
    process.exit(1);
  }

  // A finding only counts as "flagged" at or above this confidence. This
  // mirrors how anyone actually triages: a 20%-confidence note and a
  // 95%-confidence critical are not the same event, and scoring them
  // identically would let the benchmark be gamed by emitting low-confidence
  // findings on everything.
  const threshold = thresholdArg ? parseFloat(thresholdArg) : 0.5;

  const labels: Labels = JSON.parse(fs.readFileSync(path.resolve(labelsPath), "utf-8"));
  const tools = loadManifestsFromDir(path.resolve(corpusDir));
  const results = scanTools(tools, allRules, undefined, undefined);

  const truePositives: { label: LabelEntry; rules: string[] }[] = [];
  const falseNegatives: LabelEntry[] = [];
  const falsePositives: { label: LabelEntry; rules: string[] }[] = [];
  const trueNegatives: LabelEntry[] = [];
  const unmatched: LabelEntry[] = [];

  for (const label of labels.samples) {
    const matching = results.filter((r) => matchesLabel(r, label));
    if (matching.length === 0) {
      unmatched.push(label);
      continue;
    }
    const firedRules = [
      ...new Set(
        matching.flatMap((r) =>
          r.findings.filter((f) => !f.suppressed && f.confidence >= threshold).map((f) => f.ruleId)
        )
      ),
    ];
    const flagged = firedRules.length > 0;

    if (label.malicious && flagged) truePositives.push({ label, rules: firedRules });
    else if (label.malicious && !flagged) falseNegatives.push(label);
    else if (!label.malicious && flagged) falsePositives.push({ label, rules: firedRules });
    else trueNegatives.push(label);
  }

  const maliciousTotal = truePositives.length + falseNegatives.length;
  const benignTotal = falsePositives.length + trueNegatives.length;
  const detectionRate = maliciousTotal ? (truePositives.length / maliciousTotal) * 100 : 0;
  const falsePositiveRate = benignTotal ? (falsePositives.length / benignTotal) * 100 : 0;

  const line = "=".repeat(64);
  console.log(line);
  console.log(`ryzek benchmark — ${labels.corpusName ?? path.basename(corpusDir)}`);
  if (labels.source) console.log(`Corpus source: ${labels.source}`);
  console.log(line);
  console.log(`Confidence threshold:  ${(threshold * 100).toFixed(0)}% (findings below this don't count as a flag)`);
  console.log(`Samples labelled:      ${labels.samples.length}`);
  console.log(`  malicious:           ${maliciousTotal}`);
  console.log(`  benign:              ${benignTotal}`);
  if (unmatched.length) console.log(`  unmatched (skipped): ${unmatched.length}`);
  console.log("");
  console.log(`DETECTION RATE:        ${detectionRate.toFixed(1)}%  (${truePositives.length}/${maliciousTotal} malicious samples flagged)`);
  console.log(`FALSE POSITIVE RATE:   ${falsePositiveRate.toFixed(1)}%  (${falsePositives.length}/${benignTotal} benign samples flagged)`);
  console.log("");

  if (truePositives.length) {
    console.log("CAUGHT:");
    for (const tp of truePositives) {
      console.log(`  ✓ ${tp.label.path}`);
      console.log(`      via: ${tp.rules.join(", ")}`);
    }
    console.log("");
  }

  if (falseNegatives.length) {
    console.log("MISSED (these are the honest gaps — this is the useful part):");
    for (const fn of falseNegatives) {
      console.log(`  ✗ ${fn.path}`);
      if (fn.note) console.log(`      ${fn.note}`);
    }
    console.log("");
  }

  if (falsePositives.length) {
    console.log("FALSE POSITIVES (benign samples wrongly flagged):");
    for (const fp of falsePositives) {
      console.log(`  ! ${fp.label.path}`);
      console.log(`      via: ${fp.rules.join(", ")}`);
    }
    console.log("");
  }

  if (unmatched.length) {
    console.log("UNMATCHED LABELS (path in labels.json didn't match any scanned file):");
    for (const u of unmatched) console.log(`  ? ${u.path}`);
    console.log("");
  }

  console.log(line);
  console.log("Reminder: a detection rate on a small corpus is a floor, not a guarantee.");
  console.log("It says what this scanner catches on THESE samples — nothing about novel attacks.");
  console.log(line);
}

main();
