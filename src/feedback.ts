import * as fs from "fs";
import * as path from "path";

/**
 * Local false-positive feedback store.
 *
 * Key design goal: ryzek's biggest competitive risk is the same one every
 * security scanner has — noisy output erodes trust until people stop reading it.
 * This gives users a one-line way to say "this specific finding, on this specific
 * tool, is not a real problem for us" and have the scanner remember it.
 *
 * Storage is a flat JSON file, `.ryzek-feedback.json`, meant to live next to
 * the scanned manifests (or be committed to the repo) so the suppression list is
 * shared across a team, not just one person's machine.
 */

export interface FeedbackEntry {
  ruleId: string;
  toolName: string;
  sourceFile: string;
  /** Free-text reason the user gave, if any — kept for audit purposes. */
  note?: string;
  markedAt: string; // ISO timestamp
}

export interface FeedbackStore {
  falsePositives: FeedbackEntry[];
}

const DEFAULT_FILENAME = ".ryzek-feedback.json";

export function feedbackPath(dir: string): string {
  return path.join(dir, DEFAULT_FILENAME);
}

export function loadFeedback(dir: string): FeedbackStore {
  const file = feedbackPath(dir);
  if (!fs.existsSync(file)) {
    return { falsePositives: [] };
  }
  try {
    const raw = fs.readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed.falsePositives)) return { falsePositives: [] };
    return parsed as FeedbackStore;
  } catch {
    // Corrupt or unreadable feedback file shouldn't crash a scan — just proceed with none.
    return { falsePositives: [] };
  }
}

export function saveFeedback(dir: string, store: FeedbackStore): void {
  fs.writeFileSync(feedbackPath(dir), JSON.stringify(store, null, 2) + "\n", "utf-8");
}

function isSameFinding(a: FeedbackEntry, ruleId: string, toolName: string, sourceFile: string): boolean {
  return a.ruleId === ruleId && a.toolName === toolName && a.sourceFile === sourceFile;
}

export function markFalsePositive(
  dir: string,
  ruleId: string,
  toolName: string,
  sourceFile: string,
  note?: string
): FeedbackStore {
  const store = loadFeedback(dir);
  const alreadyMarked = store.falsePositives.some((e) => isSameFinding(e, ruleId, toolName, sourceFile));
  if (!alreadyMarked) {
    store.falsePositives.push({
      ruleId,
      toolName,
      sourceFile,
      note,
      markedAt: new Date().toISOString(),
    });
    saveFeedback(dir, store);
  }
  return store;
}

export function isKnownFalsePositive(
  store: FeedbackStore,
  ruleId: string,
  toolName: string,
  sourceFile: string
): boolean {
  return store.falsePositives.some((e) => isSameFinding(e, ruleId, toolName, sourceFile));
}
