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
 *      another node of a cluster) — accept without forwarding.
 *   2. Flap suppression: once flapMaxForwards notifications for one
 *      collapseId have been forwarded within flapWindow, the id is
 *      "cooled": at most one heartbeat forward per cooldownInterval
 *      until it has been quiet for flapReset.  A job failing in a tight
 *      loop pages once, then reminds, instead of streaming.
 *   3. Rate limit: a token bucket per device token bounds what one
 *      device can be sent regardless of how many ids are involved —
 *      the admission control an unauthenticated relay relies on.
 *
 * Suppressed and coalesced posts are accepted (2xx): the relay has
 * taken responsibility, and delivering nothing IS the policy.  Only the
 * rate limiter answers 429.
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
 * - flap: more than 6 pages for the same alert id inside 30 min is a
 *   flap; after that one reminder per 30 min until 2 h of quiet.
 * - rate: bursts of 60 distinct alerts, refilling one every 2 s
 *   (a mass outage still pages; an abusive caller cannot stream).
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

/** Per-(device, collapseId) history. */
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
  decision: Admission;
  collapse: CollapseState;
  bucket: BucketState;
  /** On rate_limit: seconds until one token is available again. */
  retryAfterS?: number;
}

function freshCollapse(): CollapseState {
  return { lastForwardAt: 0, forwards: [], cooledUntil: 0, lastSeenAt: 0 };
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
 * Admit one envelope.  Returns the decision plus the successor states,
 * which the caller persists; a token is consumed only by "forward".
 * A forward that then succeeds against APNs must be recorded with
 * `recordForward` — admission alone never marks one.
 */
export function admit(
  collapseIn: CollapseState | undefined,
  bucketIn: BucketState | undefined,
  now: number,
  cfg: PolicyConfig,
): AdmitResult {
  const collapse: CollapseState = collapseIn
    ? { ...collapseIn, forwards: [...collapseIn.forwards] }
    : freshCollapse();
  collapse.forwards = collapse.forwards.filter(
    (t) => now - t < cfg.flapWindowMs,
  );
  collapse.lastSeenAt = now;
  const bucket = refill(bucketIn, now, cfg);

  // 1. The same alert again, within the dedup window of the last copy
  //    actually forwarded (never of one merely seen: a stateless
  //    install re-reporting a failure every minute must not slide the
  //    window forever and alert exactly once).
  if (
    collapse.lastForwardAt !== 0 &&
    now - collapse.lastForwardAt < cfg.dedupWindowMs
  ) {
    return { decision: "coalesce", collapse, bucket };
  }

  // 2. Flap suppression.
  if (collapse.cooledUntil > now) {
    // Every post while flapping keeps the id cooled; the state only
    // thaws after flapReset of silence.
    collapse.cooledUntil = now + cfg.flapResetMs;
    if (
      collapse.lastForwardAt !== 0 &&
      now - collapse.lastForwardAt < cfg.cooldownIntervalMs
    ) {
      return { decision: "suppress", collapse, bucket };
    }
    // Heartbeat: one forward per cooldownInterval while the flap lasts.
  } else if (collapse.forwards.length >= cfg.flapMaxForwards) {
    collapse.cooledUntil = now + cfg.flapResetMs;
    return { decision: "suppress", collapse, bucket };
  }

  // 3. Per-device rate limit.
  if (bucket.tokens < 1) {
    const deficit = 1 - bucket.tokens;
    return {
      decision: "rate_limit",
      collapse,
      bucket,
      retryAfterS: Math.ceil(deficit / cfg.rateRefillPerSec),
    };
  }
  bucket.tokens -= 1;
  return { decision: "forward", collapse, bucket };
}

/** Mark a successful forward (call only after APNs accepted it). */
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
