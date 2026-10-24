/**
 * The relay's delivery policy: deduplication, flap suppression and
 * per-device rate limiting, as pure functions over explicit state.
 *
 * relay-protocol.md deliberately leaves the policy numbers to the relay;
 * this module is where they live.  Everything is deterministic in
 * (state, now, config) so the tests can exercise window edges without
 * clocks or sleeps; the Durable Object is only the I/O shell around it.
 *
 * Decision order for one inbound envelope:
 *
 *   1. Coalesce: the same (device, collapseId) forwarded less than
 *      dedupWindow ago is the same alert reported again (typically by
 *      another node of a cluster), so it is accepted without forwarding.
 *   2. Flap suppression: once flapMaxForwards notifications for one
 *      flap key have been forwarded within flapWindow, the key is
 *      "cooled": at most one heartbeat forward per cooldownInterval
 *      until it has been quiet for flapReset.  The flap key is the
 *      envelope's flapId, which stays the same across runs of one
 *      alert, or its collapseId when it carries none.  A job failing
 *      in a tight loop pages flapMaxForwards times, then reminds once
 *      per cooldownInterval instead of streaming.  A per-run collapseId
 *      without a flapId starts every run from a fresh history, so only
 *      the flapId lets suppression engage across runs.
 *   3. Rate limit: a token bucket per device and lane (daemon events
 *      and alerts each get their own) bounds what one device can be
 *      sent regardless of how many ids are involved (the admission
 *      control an unauthenticated relay relies on).
 *
 * Every decision is accepted (2xx): the relay has taken responsibility.
 * Delivering nothing is the policy for coalesced and suppressed posts.
 * The daemon never retries a relay POST, so an envelope that finds its
 * lane's bucket empty ("rate_limit") is folded into a digest push
 * rather than refused (device.ts).
 */

export interface PolicyConfig {
  dedupWindowMs: number;
  rateCapacity: number;
  rateRefillPerSec: number;
  flapMaxForwards: number;
  flapWindowMs: number;
  cooldownIntervalMs: number;
  flapResetMs: number;
}

/**
 * Defaults, tuned for "a homelab's alerting", not a firehose:
 * - dedup 75 s: covers a cluster's near-simultaneous re-reports of one
 *   alert, plus a straggler node one minute-boundary behind.
 * - flap: more than 6 pages for one flap key inside 30 min is a flap;
 *   after that one reminder per 30 min until 2 h of quiet.
 * - rate: bursts of 60 distinct alerts per lane, refilling one every
 *   2 s (a mass outage still pages, and what the bucket holds back
 *   folds into a digest; an abusive caller cannot stream).
 */
export const DEFAULT_POLICY: PolicyConfig = {
  dedupWindowMs: 75_000,
  rateCapacity: 60,
  rateRefillPerSec: 0.5,
  flapMaxForwards: 6,
  flapWindowMs: 1_800_000,
  cooldownIntervalMs: 1_800_000,
  flapResetMs: 7_200_000,
};

/**
 * Per-(device, collapseId) history, and the shape of a per-(device,
 * flapId) flap row too.  A collapse row whose envelope carries a flapId
 * keeps only what dedup reads (`lastForwardAt`, `lastSeenAt`); the flap
 * row holds the forward history and the cooling.
 */
export interface CollapseState {
  /** Instant of the most recent successful forward; 0 = never. */
  lastForwardAt: number;
  /** Successful forward instants, pruned to the flap window. */
  forwards: number[];
  /** While now < cooledUntil the id is in flap suppression; 0 = not. */
  cooledUntil: number;
  /** Last time any post for this id arrived (drives state expiry). */
  lastSeenAt: number;
}

/** Per-device token bucket. */
export interface BucketState {
  tokens: number;
  ts: number;
}

export type Admission = "forward" | "coalesce" | "suppress" | "rate_limit";

export interface AdmitResult {
  /** "rate_limit" means the lane's bucket is empty: the caller folds
   * the envelope into a digest. */
  decision: Admission;
  /** The collapse row's successor. */
  collapse: CollapseState;
  /** The flap row's successor, present when admit() was given one. */
  flap?: CollapseState;
  /** The lane's bucket, refilled to `now`; a token is gone only on
   * "forward". */
  bucket: BucketState;
}

/** The flap row of an envelope that carries a flapId: `row` is
 * undefined when none is stored yet. */
export interface FlapInput {
  row: CollapseState | undefined;
}

function freshCollapse(): CollapseState {
  return { lastForwardAt: 0, forwards: [], cooledUntil: 0, lastSeenAt: 0 };
}

/** A working copy of a stored row, pruned to the flap window and seen at
 * `now`. */
function touched(
  stored: CollapseState | undefined,
  now: number,
  cfg: PolicyConfig,
): CollapseState {
  const row: CollapseState = stored
    ? { ...stored, forwards: [...stored.forwards] }
    : freshCollapse();
  row.forwards = row.forwards.filter((t) => now - t < cfg.flapWindowMs);
  row.lastSeenAt = now;
  return row;
}

function refill(
  bucket: BucketState | undefined,
  now: number,
  cfg: PolicyConfig,
): BucketState {
  if (!bucket) return { tokens: cfg.rateCapacity, ts: now };
  const elapsedS = Math.max(0, now - bucket.ts) / 1000;
  return {
    tokens: Math.min(
      cfg.rateCapacity,
      bucket.tokens + elapsedS * cfg.rateRefillPerSec,
    ),
    ts: now,
  };
}

/**
 * Admit one envelope.  `bucketIn` is the bucket of the envelope's lane.
 * Pass `flapIn` for an envelope that carries a flapId: flap suppression
 * then reads and moves that row, and the collapse row serves dedup
 * alone.  Without it the collapse row carries both.
 *
 * Returns the decision plus the successor states; a token is consumed
 * only by "forward", so the caller persists the bucket only then (the
 * refill is re-derivable from the stored one).  A forward is recorded
 * with `forwardRows`; admission alone never marks one.
 */
export function admit(
  collapseIn: CollapseState | undefined,
  bucketIn: BucketState | undefined,
  now: number,
  cfg: PolicyConfig,
  flapIn?: FlapInput,
): AdmitResult {
  const collapse = touched(collapseIn, now, cfg);
  const flap = flapIn === undefined ? collapse : touched(flapIn.row, now, cfg);
  const bucket = refill(bucketIn, now, cfg);
  const result = (decision: Admission): AdmitResult =>
    flapIn === undefined
      ? { decision, collapse, bucket }
      : { decision, collapse, flap, bucket };

  // 1. The same alert again, within the dedup window of the last copy
  //    actually forwarded (never of one merely seen: a stateless
  //    install re-reporting a failure every minute must not slide the
  //    window forever and alert exactly once).
  if (
    collapse.lastForwardAt !== 0 &&
    now - collapse.lastForwardAt < cfg.dedupWindowMs
  ) {
    return result("coalesce");
  }

  // 2. Flap suppression, on the flap row.
  if (flap.cooledUntil > now) {
    // Every post while flapping keeps the key cooled; the state only
    // thaws after flapReset of silence.
    flap.cooledUntil = now + cfg.flapResetMs;
    if (
      flap.lastForwardAt !== 0 &&
      now - flap.lastForwardAt < cfg.cooldownIntervalMs
    ) {
      return result("suppress");
    }
    // Heartbeat: one forward per cooldownInterval while the flap lasts.
  } else if (flap.forwards.length >= cfg.flapMaxForwards) {
    flap.cooledUntil = now + cfg.flapResetMs;
    return result("suppress");
  }

  // 3. The lane's rate limit.
  if (bucket.tokens < 1) return result("rate_limit");
  bucket.tokens -= 1;
  return result("forward");
}

/** Mark a successful forward on one row (call only after APNs accepted
 * it). */
export function recordForward(
  collapse: CollapseState,
  now: number,
): CollapseState {
  return {
    ...collapse,
    forwards: [...collapse.forwards, now],
    lastForwardAt: now,
  };
}

/**
 * The rows a forward admitted at `now` stores.  With a flap row, that
 * row takes the forward history and the collapse row records only the
 * instant dedup measures from.
 */
export function forwardRows(
  result: AdmitResult,
  now: number,
): { collapse: CollapseState; flap?: CollapseState } {
  if (result.flap === undefined) {
    return { collapse: recordForward(result.collapse, now) };
  }
  return {
    collapse: { ...result.collapse, lastForwardAt: now },
    flap: recordForward(result.flap, now),
  };
}

function num(raw: string | undefined, fallback: number): number {
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Policy from env vars (seconds in the vars, ms internally). */
export function policyFromEnv(env: {
  RELAY_DEDUP_WINDOW_S?: string;
  RELAY_RATE_CAPACITY?: string;
  RELAY_RATE_REFILL_PER_S?: string;
  RELAY_FLAP_MAX_FORWARDS?: string;
  RELAY_FLAP_WINDOW_S?: string;
  RELAY_COOLDOWN_INTERVAL_S?: string;
  RELAY_FLAP_RESET_S?: string;
}): PolicyConfig {
  const d = DEFAULT_POLICY;
  return {
    dedupWindowMs: num(env.RELAY_DEDUP_WINDOW_S, d.dedupWindowMs / 1000) * 1000,
    rateCapacity: num(env.RELAY_RATE_CAPACITY, d.rateCapacity),
    rateRefillPerSec: num(env.RELAY_RATE_REFILL_PER_S, d.rateRefillPerSec),
    flapMaxForwards: num(env.RELAY_FLAP_MAX_FORWARDS, d.flapMaxForwards),
    flapWindowMs: num(env.RELAY_FLAP_WINDOW_S, d.flapWindowMs / 1000) * 1000,
    cooldownIntervalMs:
      num(env.RELAY_COOLDOWN_INTERVAL_S, d.cooldownIntervalMs / 1000) * 1000,
    flapResetMs: num(env.RELAY_FLAP_RESET_S, d.flapResetMs / 1000) * 1000,
  };
}
