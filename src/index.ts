/**
 * Programmatic API.
 *
 * The CLI is the primary interface, but exposing the scanner as a library
 * means it can be embedded in a custom pipeline, a pre-commit hook, or
 * another tool without shelling out and parsing stdout.
 *
 * Example:
 *
 *   import { loadManifestsFromDir, scanTools, allRules } from "ryzek";
 *
 *   const tools = loadManifestsFromDir("./skills");
 *   const results = scanTools(tools, allRules);
 *   const critical = results.filter(r => r.overallSeverity === "critical");
 */

export { loadManifestsFromDir } from "./loader";
export { loadSkillMd, loadSkillsFromDir, parseFrontmatter } from "./skill-loader";
export { allRules } from "./rules";
export { scanTool, scanTools, checkDrift } from "./scanner";
export { formatReport } from "./report";
export { formatSarif } from "./sarif";
export {
  loadBaseline,
  saveBaseline,
  recordBaseline,
  computeHash,
  toolKey,
} from "./baseline";
export {
  loadFeedback,
  saveFeedback,
  markFalsePositive,
  isKnownFalsePositive,
} from "./feedback";
export {
  AST_CATEGORIES,
  RULE_TO_AST,
  AST10_COVERAGE,
  astLabelsForRule,
} from "./ast10";

export type {
  ToolManifest,
  Finding,
  ScanResult,
  Rule,
  Severity,
} from "./types";
