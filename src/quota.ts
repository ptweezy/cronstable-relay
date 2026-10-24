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
 * fixed digest push instead of the alert: at once when the interval
 * allows, and otherwise once when it ends (the pending marker, which
 * the Durable Object's alarm acts on).  A valid entitlement (see
 * appstore.ts) lifts the bound entirely, and forwards made while it
 * does never count toward the bound, so a device whose entitlement
 * lapses mid-month starts from the free forwards it has used.
 */

export interface QuotaState {
  /** The period the count belongs to; a mismatch with the current
   * period means the state rolled over and reads as zero. */
  period: string;
  /** Successful forwards so far this period, lifted or not. */
  forwards: number;
  /** The forwards that count toward the free bound: those made while
   * no entitlement lifted the quota.  A row without it reads as
   * `forwards` (see `freeForwards()`). */
  freeForwards?: number;
  /** Instant of the last digest push; 0 = none this period. */
  digestAt: number;
  /** Set when an envelope was digested while the interval since
   * `digestAt` was still running: one digest is owed when it ends.  It
   * survives a period rollover (`currentQuota`). */
  digestPending?: boolean;
}

/**
 * The burst digest (device.ts folds an envelope into it when its lane's
 * rate bucket is empty): the same push as the quota digest, on its own
 * interval and with its own last-sent instant.  It goes out
 * time-sensitive when any envelope folded since the last one was.
 */
export interface BurstState {
  /** Instant of the last burst digest; 0 = none yet. */
  digestAt: number;
  /** Instant of the first envelope folded since then; 0 = none owed. */
  pendingSince: number;
  /** Whether any envelope folded since the last burst digest was
   * time-sensitive. */
  timeSensitive: boolean;
}

export type DigestLevel = "time-sensitive" | "passive";

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

export const DEFAULT_PRO_GRACE_MS = 1_382_400_000;

export const DEFAULT_BURST_DIGEST_INTERVAL_MS = 300_000;

/** The stored entitlement record (written by DeviceState.setEntitlement). */
export interface EntitlementRecord {
  originalTransactionId: string;
  productId: string;
  /** Epoch ms, or null for an entitlement without an expiry. */
  expiresAt: number | null;
  environment: "Production" | "Sandbox";
  /** Epoch ms of the verification that wrote this record. */
  verifiedAt: number;
  /** Epoch ms of the purchase the transaction records.  Null or absent
   * when unknown, which a revocation of the same transaction treats as
   * covered (DeviceState.revoke). */
  purchaseDate?: number | null;
  /** Epoch ms at which the device's slot on the transaction lapses
   * unless the device re-posts its proof (EntitlementState.claim).
   * `liftEndsAt()` covers a record without it. */
  slotExpiresAt?: number;
}

/** What bounds how long a stored entitlement lifts the quota. */
export interface LiftConfig {
  /** How long past `expiresAt` a subscription still lifts the quota
   * (`RELAY_PRO_GRACE_S`): it covers the gap between a renewal and the
   * device's next re-post, and Apple's billing grace period. */
  graceMs: number;
  /** The slot TTL (`RELAY_PRO_DEVICE_SLOT_TTL_S`), for records that
   * carry no `slotExpiresAt`. */
  slotTtlMs: number;
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
 * otherwise a fresh zero for the new period.  A digest still owed from
 * the old period carries over with the instant it is measured from. */
export function currentQuota(
  stored: QuotaState | undefined,
  now: number,
  cfg: QuotaConfig,
): QuotaState {
  const period = periodKey(now, cfg);
  if (stored && stored.period === period) return stored;
  if (stored?.digestPending) {
    return {
      period,
      forwards: 0,
      freeForwards: 0,
      digestAt: stored.digestAt,
      digestPending: true,
    };
  }
  return { period, forwards: 0, freeForwards: 0, digestAt: 0 };
}

/** This period's forwards that count toward the free bound. */
export function freeForwards(state: QuotaState): number {
  return state.freeForwards ?? state.forwards;
}

export function quotaExhausted(state: QuotaState, cfg: QuotaConfig): boolean {
  return freeForwards(state) >= cfg.freeMonthlyForwards;
}

/** Count one forward (call alongside the optimistic forward record).
 * `free` is whether it counts toward the free bound: true unless an
 * entitlement lifts the quota. */
export function countForward(state: QuotaState, free: boolean): QuotaState {
  return {
    ...state,
    forwards: state.forwards + 1,
    freeForwards: freeForwards(state) + (free ? 1 : 0),
  };
}

/** Undo one counted forward after APNs refused it; `free` must match
 * what `countForward` was given. */
export function uncountForward(state: QuotaState, free: boolean): QuotaState {
  const counted = freeForwards(state);
  return {
    ...state,
    forwards: Math.max(0, state.forwards - 1),
    freeForwards: free ? Math.max(0, counted - 1) : counted,
  };
}

/** Whether a digest push may go out now (none yet, or the interval passed). */
export function digestDue(
  state: QuotaState,
  now: number,
  cfg: QuotaConfig,
): boolean {
  return state.digestAt === 0 || now - state.digestAt >= cfg.digestIntervalMs;
}

/** Record a digest sent at `now`; it covers any digest owed. */
export function markDigest(state: QuotaState, now: number): QuotaState {
  const { digestPending: _, ...rest } = state;
  return { ...rest, digestAt: now };
}

/** Record that one digest is owed when the running interval ends. */
export function markDigestPending(state: QuotaState): QuotaState {
  return { ...state, digestPending: true };
}

/** When the owed quota digest is due, or null when none is owed.  Reads
 * the raw stored row: a rollover never cancels what it owes. */
export function quotaDigestDueAt(
  state: QuotaState | undefined,
  cfg: QuotaConfig,
): number | null {
  if (!state?.digestPending) return null;
  return state.digestAt + cfg.digestIntervalMs;
}

/**
 * Whether a stored row still tells the relay something at `now`: a digest
 * it owes (from any period), or this period's forwards or digest instant.
 * Any other row reads exactly like no row at all (`currentQuota`).
 */
export function quotaWorthKeeping(
  state: QuotaState | undefined,
  now: number,
  cfg: QuotaConfig,
): boolean {
  if (!state) return false;
  if (state.digestPending) return true;
  return (
    state.period === periodKey(now, cfg) &&
    (state.forwards > 0 || state.digestAt > 0)
  );
}

/**
 * Fold one envelope into the burst digest.  `send` is the level of a
 * digest to send now (the leading edge), or null when the interval since
 * the last one is still running; the envelope then marks one digest as
 * owed for when it ends.  `write` says whether the state changed.
 */
export function foldBurst(
  stored: BurstState | undefined,
  now: number,
  intervalMs: number,
  timeSensitive: boolean,
): { state: BurstState; send: DigestLevel | null; write: boolean } {
  const burst: BurstState = stored ?? {
    digestAt: 0,
    pendingSince: 0,
    timeSensitive: false,
  };
  const urgent = burst.timeSensitive || timeSensitive;
  if (burst.digestAt === 0 || now - burst.digestAt >= intervalMs) {
    return {
      state: { digestAt: now, pendingSince: 0, timeSensitive: false },
      send: urgent ? "time-sensitive" : "passive",
      write: true,
    };
  }
  if (burst.pendingSince !== 0 && burst.timeSensitive === urgent) {
    return { state: burst, send: null, write: false };
  }
  return {
    state: {
      digestAt: burst.digestAt,
      pendingSince: burst.pendingSince === 0 ? now : burst.pendingSince,
      timeSensitive: urgent,
    },
    send: null,
    write: true,
  };
}

/** When the owed burst digest is due, or null when none is owed. */
export function burstDigestDueAt(
  state: BurstState | undefined,
  intervalMs: number,
): number | null {
  if (!state || state.pendingSince === 0) return null;
  return state.digestAt + intervalMs;
}

/** The burst state after a digest sent at `now`. */
export function burstSent(now: number): BurstState {
  return { digestAt: now, pendingSince: 0, timeSensitive: false };
}

/**
 * The instant a stored entitlement stops lifting the quota: the
 * purchase's expiry plus the grace, or the device's slot lapse, whichever
 * comes first.  A record without an expiry is bound by its slot alone,
 * and one without `slotExpiresAt` lapses one slot TTL after it was
 * verified.
 */
export function liftEndsAt(record: EntitlementRecord, cfg: LiftConfig): number {
  const slotEnd = record.slotExpiresAt ?? record.verifiedAt + cfg.slotTtlMs;
  if (record.expiresAt === null) return slotEnd;
  return Math.min(record.expiresAt + cfg.graceMs, slotEnd);
}

/** Whether a stored entitlement lifts the quota at `now`.  Delivery,
 * the status report, and the sweep alarm all decide with this. */
export function entitlementValid(
  record: EntitlementRecord | undefined,
  now: number,
  cfg: LiftConfig,
): record is EntitlementRecord {
  if (!record) return false;
  return now < liftEndsAt(record, cfg);
}

function num(raw: string | undefined, fallback: number): number {
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** `RELAY_PRO_GRACE_S` in ms.  Zero is allowed: no grace past expiry. */
export function proGraceFromEnv(env: { RELAY_PRO_GRACE_S?: string }): number {
  const raw = env.RELAY_PRO_GRACE_S;
  const parsed = raw === undefined || raw.trim() === "" ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed >= 0
    ? parsed * 1000
    : DEFAULT_PRO_GRACE_MS;
}

/** `RELAY_BURST_DIGEST_INTERVAL_S` in ms. */
export function burstDigestIntervalFromEnv(env: {
  RELAY_BURST_DIGEST_INTERVAL_S?: string;
}): number {
  return (
    num(
      env.RELAY_BURST_DIGEST_INTERVAL_S,
      DEFAULT_BURST_DIGEST_INTERVAL_MS / 1000,
    ) * 1000
  );
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
