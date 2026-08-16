/**
 * Single source of truth for the version string.
 *
 * This exists because the version was previously duplicated in cli.ts and
 * sarif.ts, and they drifted — SARIF output reported 1.0.0 while the package
 * was 1.2.0. A published detection rate is only meaningful if you can tell
 * which build produced it, so a wrong version in machine-readable output is
 * a real problem, not a cosmetic one.
 *
 * Keep this in step with package.json on every release.
 */
export const VERSION = "1.2.1";
