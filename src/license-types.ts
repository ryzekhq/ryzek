export type Tier = "free" | "pro" | "enterprise";

export const TIER_LIMITS: Record<Tier, number> = {
  free: 100,
  pro: 1000,
  enterprise: Infinity,
};

/** Stored at ~/.ryzek/license.json — the license key and last-known-good validation result. */
export interface LicenseState {
  key: string | null;
  tier: Tier;
  /** ISO timestamp of the last successful remote validation. Null if never validated (e.g. free tier, or offline since install). */
  lastValidatedAt: string | null;
  /** ISO timestamp — if validation has been failing since before this, we stop trusting the cached tier and fall back to free. */
  gracePeriodStartedAt: string | null;
  ownerEmail?: string;
}

/** Stored at ~/.ryzek/usage.json — local monthly scan counter, keyed by month so it self-resets. */
export interface UsageState {
  month: string; // "YYYY-MM"
  scanCount: number;
  /** Scan-level metadata queued for the next successful usage report to the license server. Cleared on report. */
  pendingEvents: UsageEvent[];
}

export interface UsageEvent {
  timestamp: string;
  toolsScanned: number;
  findingsCount: number;
  criticalCount: number;
}

export interface ValidateResponse {
  valid: boolean;
  tier: Tier;
  ownerEmail?: string;
  reason?: string; // present when valid: false — e.g. "revoked", "expired", "unknown key"
}
