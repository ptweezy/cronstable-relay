/**
 * The monthly delivery quota (relay-protocol.md, "Delivery quota") as
 * pure functions over explicit state, in the same spirit as policy.ts:
 * everything is deterministic in (state, now, config) so the period
 * edges are cheap to pin in tests.
 *
 * A device on the free plan gets `freeMonthlyForwards` forwards per UTC
 * calendar month.  Only forwards that reach APNs count; the Durable
 * Object counts optimistically alongside its forward record and
 * uncounts on rollback, so coalesced, suppressed, rate-limited, and
 * failed envelopes never consume quota.  Past the bound the relay
 * answers "digested" and, at most once per `digestIntervalMs`, sends a
 * fixed digest push instead of the alert.  A valid entitlement (see
 * appstore.ts) lifts the bound entirely.
 */

export interface QuotaState {
  /** The period the count belongs to; a mismatch with the current
   * period means the state rolled over and reads as zero. */
  period: string;
  /** Successful forwards so far this period. */
  forwards: number;
  /** Instant of the last digest push; 0 = none this period. */
  digestAt: number;
}

export interface QuotaConfig {
  freeMonthlyForwards: number;
  digestIntervalMs: number;
  /**
   * Test hook: with a value, periods are fixed-length buckets of this
   * many milliseconds instead of UTC calendar months, so a rollover
   * can be crossed with a sleep.  Null in production.
   */
  periodMs: number | null;
}

export const DEFAULT_QUOTA: QuotaConfig = {
  freeMonthlyForwards: 500,
  digestIntervalMs: 3_600_000,
  periodMs: null,
};

/** The stored entitlement record (written by DeviceState.setEntitlement). */
export interface EntitlementRecord {
  originalTransactionId: string;
  productId: string;
  /** Epoch ms, or null for an entitlement without an expiry. */
  expiresAt: number | null;
  environment: "Production" | "Sandbox";
  /** Epoch ms of the verification that wrote this record. */
  verifiedAt: number;
}

/** "YYYY-MM" of `now` in UTC, or the bucket index under a test period. */
export function periodKey(now: number, cfg: QuotaConfig): string {
  if (cfg.periodMs !== null) return String(Math.floor(now / cfg.periodMs));
  const d = new Date(now);
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${d.getUTCFullYear()}-${month}`;
}

/** Epoch ms of the next rollover after `now`. */
export function periodEndsAt(now: number, cfg: QuotaConfig): number {
  if (cfg.periodMs !== null) {
    return (Math.floor(now / cfg.periodMs) + 1) * cfg.periodMs;
  }
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
}

/** The state as of `now`: the stored one if its period is current,
 * otherwise a fresh zero for the new period. */
export function currentQuota(
  stored: QuotaState | undefined,
  now: number,
  cfg: QuotaConfig,
): QuotaState {
  const period = periodKey(now, cfg);
  if (stored && stored.period === period) return stored;
  return { period, forwards: 0, digestAt: 0 };
}

export function quotaExhausted(state: QuotaState, cfg: QuotaConfig): boolean {
  return state.forwards >= cfg.freeMonthlyForwards;
}

/** Count one forward (call alongside the optimistic forward record). */
export function countForward(state: QuotaState): QuotaState {
  return { ...state, forwards: state.forwards + 1 };
}

/** Undo one counted forward after APNs refused it. */
export function uncountForward(state: QuotaState): QuotaState {
  return { ...state, forwards: Math.max(0, state.forwards - 1) };
}

/** Whether a digest push may go out now (none yet, or the interval passed). */
export function digestDue(
  state: QuotaState,
  now: number,
  cfg: QuotaConfig,
): boolean {
  return state.digestAt === 0 || now - state.digestAt >= cfg.digestIntervalMs;
}

export function markDigest(state: QuotaState, now: number): QuotaState {
  return { ...state, digestAt: now };
}

/** An entitlement lifts the quota while unexpired (null = never expires). */
export function entitlementValid(
  record: EntitlementRecord | undefined,
  now: number,
): record is EntitlementRecord {
  if (!record) return false;
  return record.expiresAt === null || record.expiresAt > now;
}

function num(raw: string | undefined, fallback: number): number {
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Quota config from env vars (seconds in the vars, ms internally). */
export function quotaFromEnv(env: {
  RELAY_FREE_MONTHLY_FORWARDS?: string;
  RELAY_DIGEST_INTERVAL_S?: string;
  RELAY_QUOTA_PERIOD_S?: string;
}): QuotaConfig {
  const d = DEFAULT_QUOTA;
  const period = num(env.RELAY_QUOTA_PERIOD_S, 0);
  return {
    freeMonthlyForwards: num(
      env.RELAY_FREE_MONTHLY_FORWARDS,
      d.freeMonthlyForwards,
    ),
    digestIntervalMs:
      num(env.RELAY_DIGEST_INTERVAL_S, d.digestIntervalMs / 1000) * 1000,
    periodMs: period > 0 ? period * 1000 : null,
  };
}
