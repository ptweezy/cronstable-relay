/**
 * One Durable Object per device token: the serialization point where
 * dedup, flap suppression, rate limiting and the monthly quota become
 * race-free, and the only place APNs is called from.
 *
 * Storage layout (SQLite-backed KV):
 *   c:<collapseId> -> CollapseState       per-alert dedup history, plus
 *                                         the flap history of an alert
 *                                         sent without a flapId
 *   f:<flapId>     -> CollapseState       per-flapId flap history
 *   bucket         -> BucketState         the alert lane's rate bucket
 *   bucket:event   -> BucketState         the daemon-event lane's bucket
 *   apnsEnv        -> "production" | "sandbox"   auto-mode cache
 *   quota          -> QuotaState          this period's forward count and
 *                                         the quota digest
 *   burst          -> BurstState          the burst digest
 *   entitlement    -> EntitlementRecord   the verified Pro entitlement
 *
 * Past a free device's monthly bound, and past a lane's rate bucket, the
 * relay answers "digested" rather than refusing the envelope, and a
 * digest push stands in for it: at once when its trigger's interval
 * allows, and otherwise once when that interval ends.  A digest whose
 * send fails transiently stays owed, and the alarm sends it after a
 * short backoff.
 *
 * The object keeps one alarm, set for the earliest instant anything it
 * holds needs attention: the oldest live c: or f: row going silent past
 * the flap-reset horizon (a day at least, and no sooner than
 * ROW_SWEEP_MIN_MS after a sweep), an owed digest falling due,
 * the quota period ending while the quota row carries a count, and the
 * entitlement ceasing to lift the quota (`liftEndsAt`).  The alarm
 * sends owed digests, sweeps silent rows, drops what no longer carries
 * information, and deletes everything once nothing does, so an idle
 * device's object holds no storage at all.  A token APNs rejects for good
 * (410) empties its object at once, unless the object holds an
 * entitlement that still lifts the quota.
 */

import { DurableObject } from "cloudflare:workers";

import {
  APNS_HOSTS,
  apnsTimeoutFromEnv,
  sendToApns,
  type ApnsAuth,
  type ApnsDigest,
  type ApnsEnvironment,
  type ApnsMessage,
  type ApnsResult,
} from "./apns";
import { deviceCapFromEnv } from "./entitlement";
import {
  admit,
  forwardRows,
  policyFromEnv,
  type BucketState,
  type CollapseState,
  type PolicyConfig,
} from "./policy";
import {
  burstDigestDueAt,
  burstDigestIntervalFromEnv,
  burstSent,
  countForward,
  currentQuota,
  digestDue,
  entitlementValid,
  foldBurst,
  freeForwards,
  liftEndsAt,
  markDigest,
  markDigestPending,
  periodEndsAt,
  periodKey,
  proGraceFromEnv,
  quotaDigestDueAt,
  quotaExhausted,
  quotaFromEnv,
  quotaWorthKeeping,
  uncountForward,
  type BurstState,
  type DigestLevel,
  type EntitlementRecord,
  type LiftConfig,
  type QuotaConfig,
  type QuotaState,
} from "./quota";
import type { DeliverOutcome, DeviceStatus, Envelope, Env } from "./types";
import { parseDevice } from "./validate";

const DAY_MS = 24 * 3600 * 1000;

/** Rows one sweep page loads: the sweep never holds every row at once. */
const SWEEP_PAGE = 512;

/**
 * The shortest wait before a sweep that only the c: and f: rows ask for.
 * Rows written a minute apart (a fresh collapseId per alert) expire a
 * minute apart, so waking at each expiry would list every row once per
 * alert.  Rows live past the horizon by at most this much.
 */
const ROW_SWEEP_MIN_MS = 6 * 3600 * 1000;

/** When an alarm that failed runs again. */
const ALARM_RETRY_MS = 15 * 60 * 1000;

/** The pause before a send's one retry of a transient failure. */
const APNS_RETRY_DELAY_MS = 300;

/** How long a digest whose send failed transiently stays owed before
 * the alarm sends it again (`digestRetryMs`). */
const DIGEST_RETRY_MS = 5 * 60 * 1000;

/** The shortest wait before an owed digest's send is tried again. */
const DIGEST_RETRY_MIN_MS = 60 * 1000;

const DIGESTED: DeliverOutcome = {
  status: 202,
  body: { v: 1, outcome: "digested" },
};

const APNS_UNREACHABLE: DeliverOutcome = {
  status: 502,
  body: { v: 1, error: "APNs unreachable" },
};

/** APNs reasons that mean "this token is not deliverable, ever". */
const TOKEN_REJECTED = new Set([
  "BadDeviceToken",
  "DeviceTokenNotForTopic",
  "Unregistered",
  "ExpiredToken",
]);

/** Reasons that mean the token belongs to the *other* APNs environment
 * (or is plain bad); in auto mode these are worth one retry against
 * the other host before giving up. */
const WRONG_ENVIRONMENT = new Set(["BadDeviceToken", "DeviceTokenNotForTopic"]);

/** Reasons that mean the relay's own credentials/config are broken. */
const RELAY_MISCONFIGURED = new Set([
  "InvalidProviderToken",
  "ExpiredProviderToken",
  "MissingProviderToken",
  "TopicDisallowed",
  "BadTopic",
  "Forbidden",
]);

/** A send's outcome.  `transient` says whether the last attempt failed
 * in a way worth trying again later: no answer from APNs, or a 500 or
 * 503 (`transient()`). */
type SendResult =
  | { delivered: true }
  | { delivered: false; failure: DeliverOutcome; transient: boolean };

/**
 * What one digest push stands in for, so a send that fails transiently
 * can owe it again (`oweAgain`).  `sentAt` is the instant the sent
 * marker recorded.  `quota` is set when the push covers the quota
 * trigger; `burst` is set when it covers the burst trigger, with the
 * first folded envelope's instant and whether any was time-sensitive.
 */
interface OwedDigest {
  sentAt: number;
  quota: boolean;
  burst?: { pendingSince: number; timeSensitive: boolean };
}

type Auth = ApnsAuth & { topic: string };

/** How long a stored entitlement lifts the quota (quota.ts, liftEndsAt). */
function liftFromEnv(env: Env): LiftConfig {
  return {
    graceMs: proGraceFromEnv(env),
    slotTtlMs: deviceCapFromEnv(env).slotTtlMs,
  };
}

/** How long a c: or f: row outlives its last sighting. */
function rowHorizonMs(cfg: PolicyConfig): number {
  return Math.max(cfg.flapResetMs, DAY_MS);
}

/** The backoff before a transiently failed digest goes out again: five
 * minutes, or the trigger's interval when that is shorter, and a minute
 * at least. */
function digestRetryMs(intervalMs: number): number {
  return Math.max(DIGEST_RETRY_MIN_MS, Math.min(DIGEST_RETRY_MS, intervalMs));
}

/** Whether two records differ in anything but `verifiedAt`. */
function sameEntitlement(
  a: EntitlementRecord | undefined,
  b: EntitlementRecord,
): boolean {
  return (
    a !== undefined &&
    a.originalTransactionId === b.originalTransactionId &&
    a.productId === b.productId &&
    a.expiresAt === b.expiresAt &&
    a.environment === b.environment &&
    (a.purchaseDate ?? null) === (b.purchaseDate ?? null) &&
    a.slotExpiresAt === b.slotExpiresAt
  );
}

export class DeviceState extends DurableObject<Env> {
  async deliver(envelope: Envelope): Promise<DeliverOutcome> {
    const auth = this.apnsAuth();
    if ("error" in auth) {
      return { status: 502, body: { v: 1, error: auth.error } };
    }
    const cfg = policyFromEnv(this.env);
    const quotaCfg = quotaFromEnv(this.env);
    const now = Date.now();
    const collapseKey = `c:${envelope.collapseId}`;
    const flapKey =
      envelope.flapId === undefined ? null : `f:${envelope.flapId}`;
    const bucketKey = envelope.event ? "bucket:event" : "bucket";
    // From this read to a digest's due check and the write that marks
    // it, nothing awaits: a sibling envelope must never see the digest
    // state from before that write, or both send a digest.
    const stored = await this.ctx.storage.get<unknown>([
      collapseKey,
      ...(flapKey === null ? [] : [flapKey]),
      bucketKey,
      "apnsEnv",
      "quota",
      "burst",
      "entitlement",
    ]);
    const result = admit(
      stored.get(collapseKey) as CollapseState | undefined,
      stored.get(bucketKey) as BucketState | undefined,
      now,
      cfg,
      flapKey === null
        ? undefined
        : { row: stored.get(flapKey) as CollapseState | undefined },
    );

    // An envelope that is not forwarded spends no token, so the bucket
    // stays as stored (its refill is re-derivable), and it writes only
    // rows that already exist: a fresh row carries nothing admit() would
    // read differently from no row at all.
    if (result.decision === "coalesce") {
      await this.ctx.storage.put(collapseKey, result.collapse);
      return { status: 202, body: { v: 1, outcome: "coalesced" } };
    }
    if (result.decision === "suppress") {
      // The cooling moved on the row that holds the flap history.
      if (flapKey !== null && result.flap !== undefined) {
        await this.ctx.storage.put(flapKey, result.flap);
      } else {
        await this.ctx.storage.put(collapseKey, result.collapse);
      }
      return { status: 202, body: { v: 1, outcome: "suppressed" } };
    }
    const seen: Record<string, CollapseState> = {};
    if (stored.has(collapseKey)) seen[collapseKey] = result.collapse;
    if (flapKey !== null && stored.has(flapKey) && result.flap) {
      seen[flapKey] = result.flap;
    }
    const cachedEnv = stored.get("apnsEnv") as ApnsEnvironment | undefined;

    // The lane's bucket is empty.  The daemon never retries a relay
    // POST, so the envelope folds into the burst digest instead of
    // being refused.
    if (result.decision === "rate_limit") {
      return this.fold(
        envelope,
        seen,
        stored.get("burst") as BurstState | undefined,
        now,
        auth,
        cachedEnv,
      );
    }

    // Quota: a free device past its monthly bound gets a digest in place
    // of the alert.  Checked after admission so coalesced, suppressed and
    // folded envelopes neither count nor trigger a quota digest.
    const quota = currentQuota(
      stored.get("quota") as QuotaState | undefined,
      now,
      quotaCfg,
    );
    const entitlement = stored.get("entitlement") as
      EntitlementRecord | undefined;
    const lifted = entitlementValid(entitlement, now, liftFromEnv(this.env));
    if (!lifted && quotaExhausted(quota, quotaCfg)) {
      return this.digest(
        envelope.device,
        seen,
        quota,
        now,
        quotaCfg,
        auth,
        cachedEnv,
      );
    }

    // Forward.  Record it BEFORE the APNs call: while we await Apple
    // the input gate is open, and a cluster sibling posting the same
    // alert must read "already forwarded" and coalesce rather than
    // triple-send (and triple-count toward flap suppression).  The
    // quota count rides along, toward the free bound only while no
    // entitlement lifts it; on failure both are rolled back so the
    // alert stays eligible and the failed send costs no quota.
    const counted = countForward(quota, !lifted);
    const recorded = forwardRows(result, now);
    await this.ctx.storage.put({
      [collapseKey]: recorded.collapse,
      ...(flapKey === null ? {} : { [flapKey]: recorded.flap }),
      [bucketKey]: result.bucket,
      quota: counted,
    });
    await this.wakeBy(now + rowHorizonMs(cfg));
    const msg: ApnsMessage = {
      deviceToken: envelope.device,
      ciphertext: envelope.ciphertext,
      collapseId: envelope.collapseId,
      priority: envelope.priority,
      topic: auth.topic,
      suite: envelope.suite,
    };
    const sent = await this.send(msg, auth, cachedEnv);
    if (sent.delivered) {
      return { status: 202, body: { v: 1, outcome: "forwarded" } };
    }
    if (sent.failure.status === 410 && (await this.forgetDeadToken())) {
      return sent.failure;
    }
    const rows = flapKey === null ? [collapseKey] : [collapseKey, flapKey];
    await this.rollbackForward(rows, now, quotaCfg, {
      before: stored.get("quota") as QuotaState | undefined,
      written: counted,
      free: !lifted,
    });
    return sent.failure;
  }

  /**
   * Store a verified entitlement (POST /entitlement), replacing any
   * earlier one, and report the resulting plan and quota.  A re-post
   * that changes nothing but `verifiedAt` leaves the stored record as
   * it is.
   */
  async setEntitlement(record: EntitlementRecord): Promise<DeviceStatus> {
    const stored = await this.ctx.storage.get<EntitlementRecord>(
      "entitlement",
    );
    if (!sameEntitlement(stored, record)) {
      await this.ctx.storage.put("entitlement", record);
    }
    await this.wakeBy(liftEndsAt(record, liftFromEnv(this.env)));
    return this.status();
  }

  /**
   * An authentic revocation of `originalTransactionId` reached the
   * relay: delete the stored entitlement when it names that transaction
   * and its purchase is no later than the revoked one.  A null
   * `purchaseDate` on either side counts as covered.  Returns whether a
   * record was deleted.
   */
  async revoke(
    originalTransactionId: string,
    purchaseDate: number | null,
  ): Promise<boolean> {
    const stored = await this.ctx.storage.get<EntitlementRecord>(
      "entitlement",
    );
    if (stored?.originalTransactionId !== originalTransactionId) return false;
    const held = stored.purchaseDate ?? null;
    if (held !== null && purchaseDate !== null && held > purchaseDate) {
      return false;
    }
    await this.ctx.storage.delete("entitlement");
    return true;
  }

  /** The device's plan and this period's quota. */
  async status(): Promise<DeviceStatus> {
    const quotaCfg = quotaFromEnv(this.env);
    const now = Date.now();
    const stored = await this.ctx.storage.get<unknown>([
      "quota",
      "entitlement",
    ]);
    const quota = currentQuota(
      stored.get("quota") as QuotaState | undefined,
      now,
      quotaCfg,
    );
    const entitlement = stored.get("entitlement") as
      EntitlementRecord | undefined;
    const resetsAt = periodEndsAt(now, quotaCfg);
    if (entitlementValid(entitlement, now, liftFromEnv(this.env))) {
      return {
        plan: "pro",
        expiresAt: entitlement.expiresAt,
        environment: entitlement.environment,
        used: quota.forwards,
        limit: null,
        resetsAt,
      };
    }
    return {
      plan: "free",
      used: freeForwards(quota),
      limit: quotaCfg.freeMonthlyForwards,
      resetsAt,
    };
  }

  /**
   * The over-rate path: accept the envelope as "digested" and fold it
   * into the burst digest, which goes out now when its interval allows
   * and is otherwise owed for when the interval ends.
   */
  private async fold(
    envelope: Envelope,
    seen: Record<string, CollapseState>,
    burst: BurstState | undefined,
    now: number,
    auth: Auth,
    cachedEnv: ApnsEnvironment | undefined,
  ): Promise<DeliverOutcome> {
    const intervalMs = burstDigestIntervalFromEnv(this.env);
    const folded = foldBurst(
      burst,
      now,
      intervalMs,
      envelope.priority === "time-sensitive",
    );
    const writes: Record<string, unknown> = folded.write
      ? { ...seen, burst: folded.state }
      : seen;
    if (Object.keys(writes).length > 0) await this.ctx.storage.put(writes);
    if (folded.send !== null) {
      // The leading digest covers this envelope and any fold still owed.
      const owedSince = burst?.pendingSince ? burst.pendingSince : now;
      return this.sendDigest(envelope.device, folded.send, auth, cachedEnv, {
        sentAt: now,
        quota: false,
        burst: {
          pendingSince: owedSince,
          timeSensitive: folded.send === "time-sensitive",
        },
      });
    }
    if (folded.write) {
      await this.wakeBy(burstDigestDueAt(folded.state, intervalMs)!);
    }
    return DIGESTED;
  }

  /**
   * The over-quota path: accept the envelope as "digested" and, when
   * the digest interval allows, send the digest push; otherwise one
   * digest is owed for when the interval ends.
   */
  private async digest(
    deviceToken: string,
    seen: Record<string, CollapseState>,
    quota: QuotaState,
    now: number,
    quotaCfg: QuotaConfig,
    auth: Auth,
    cachedEnv: ApnsEnvironment | undefined,
  ): Promise<DeliverOutcome> {
    if (!digestDue(quota, now, quotaCfg)) {
      const owing = !quota.digestPending;
      const writes: Record<string, unknown> = owing
        ? { ...seen, quota: markDigestPending(quota) }
        : seen;
      if (Object.keys(writes).length > 0) await this.ctx.storage.put(writes);
      if (owing) await this.wakeBy(quota.digestAt + quotaCfg.digestIntervalMs);
      return DIGESTED;
    }
    await this.ctx.storage.put({ ...seen, quota: markDigest(quota, now) });
    await this.wakeBy(periodEndsAt(now, quotaCfg));
    return this.sendDigest(deviceToken, "passive", auth, cachedEnv, {
      sentAt: now,
      quota: true,
    });
  }

  /**
   * Send a digest for an envelope already answered "digested".  A digest
   * that fails still leaves the envelope digested.  A failure worth
   * retrying (`transient`) owes the digest again for after a short
   * backoff (`oweAgain`), and any other refusal spends the interval,
   * except when the token itself is dead (410), which the daemon needs
   * to hear and which empties the object (`forgetDeadToken`).
   */
  private async sendDigest(
    deviceToken: string,
    priority: DigestLevel,
    auth: Auth,
    cachedEnv: ApnsEnvironment | undefined,
    owed: OwedDigest,
  ): Promise<DeliverOutcome> {
    const msg: ApnsDigest = { deviceToken, topic: auth.topic, priority };
    const sent = await this.send(msg, auth, cachedEnv);
    if (!sent.delivered) {
      if (sent.failure.status === 410) {
        await this.forgetDeadToken();
        return sent.failure;
      }
      console.error(
        JSON.stringify({ evt: "digest_failed", ...sent.failure.body }),
      );
      if (sent.transient) await this.oweAgain(owed);
    }
    return DIGESTED;
  }

  /**
   * Owe a digest again after its send failed transiently, so it falls
   * due one backoff from now (`digestRetryMs` of the trigger's
   * interval): the trigger's last-sent instant moves to one interval
   * before that due time, and its pending marker comes back, merged
   * with whatever a sibling envelope folded or digested meanwhile.  A
   * trigger settled while the send waited stays as it is: its row is
   * gone (a dead token emptied the object), or a later digest went out.
   * The burst row's last-sent instant then differs from `owed.sentAt`,
   * and the quota row's is later than it.  A quota row whose instant is
   * earlier belongs to a new period: a sibling's forward started it and
   * sent no digest, so it takes the owed digest.  The read and the write
   * have no await between them but storage's, so no sibling lands in
   * between.
   */
  private async oweAgain(owed: OwedDigest): Promise<void> {
    const now = Date.now();
    const quotaCfg = quotaFromEnv(this.env);
    const burstIntervalMs = burstDigestIntervalFromEnv(this.env);
    const stored = await this.ctx.storage.get<unknown>(["quota", "burst"]);
    const updates: Record<string, unknown> = {};
    const wakes: number[] = [];
    const quota = stored.get("quota") as QuotaState | undefined;
    if (owed.quota && quota !== undefined && quota.digestAt <= owed.sentAt) {
      const intervalMs = quotaCfg.digestIntervalMs;
      const dueAt = now + digestRetryMs(intervalMs);
      updates.quota = {
        ...quota,
        digestAt: dueAt - intervalMs,
        digestPending: true,
      } satisfies QuotaState;
      wakes.push(dueAt);
    }
    const burst = stored.get("burst") as BurstState | undefined;
    if (owed.burst && burst?.digestAt === owed.sentAt) {
      const dueAt = now + digestRetryMs(burstIntervalMs);
      updates.burst = {
        digestAt: dueAt - burstIntervalMs,
        pendingSince:
          burst.pendingSince === 0
            ? owed.burst.pendingSince
            : Math.min(burst.pendingSince, owed.burst.pendingSince),
        timeSensitive: burst.timeSensitive || owed.burst.timeSensitive,
      } satisfies BurstState;
      wakes.push(dueAt);
    }
    if (wakes.length === 0) return;
    await this.ctx.storage.put(updates);
    await this.wakeBy(Math.min(...wakes));
  }

  private apnsAuth(): Auth | { error: string } {
    const { APNS_TEAM_ID, APNS_KEY_ID, APNS_AUTH_KEY, APNS_TOPIC } = this.env;
    if (!APNS_TEAM_ID || !APNS_KEY_ID || !APNS_AUTH_KEY || !APNS_TOPIC) {
      console.error(
        "relay is missing APNs configuration " +
          "(APNS_TEAM_ID / APNS_KEY_ID / APNS_AUTH_KEY secrets, APNS_TOPIC var)",
      );
      return { error: "relay is not configured for APNs delivery" };
    }
    return {
      teamId: APNS_TEAM_ID,
      keyId: APNS_KEY_ID,
      privateKeyPem: APNS_AUTH_KEY,
      topic: APNS_TOPIC,
    };
  }

  /**
   * One APNs send, inside one deadline of `RELAY_APNS_TIMEOUT_S`.  In
   * auto mode, an answer saying the token belongs to the other
   * environment moves the send to the other host.  Apart from that hop,
   * the send retries once, against the same host, when an attempt fails
   * in a way worth repeating (`transient`) and the deadline leaves room.
   * A retried push that APNs had in fact accepted reaches the phone
   * twice under one apns-collapse-id, so the second copy replaces the
   * first.
   */
  private async send(
    msg: ApnsMessage | ApnsDigest,
    auth: Auth,
    cachedEnv: ApnsEnvironment | undefined,
  ): Promise<SendResult> {
    const mode = this.env.APNS_ENVIRONMENT ?? "auto";
    let order: ApnsEnvironment[];
    if (mode === "production" || mode === "sandbox") {
      order = [mode];
    } else {
      const first: ApnsEnvironment =
        cachedEnv === "sandbox" ? "sandbox" : "production";
      order = [first, first === "production" ? "sandbox" : "production"];
    }
    const budgetMs = apnsTimeoutFromEnv(this.env);
    const deadline = Date.now() + budgetMs;
    let retried = false;
    let last: ApnsResult | null = null;
    for (const environment of order) {
      last = await attemptApns(environment, auth, msg, deadline, budgetMs);
      if (
        !retried &&
        transient(last) &&
        deadline - Date.now() > APNS_RETRY_DELAY_MS
      ) {
        retried = true;
        console.error(
          JSON.stringify({
            evt: "apns_retry",
            environment,
            apnsStatus: last?.status ?? null,
            reason: last?.reason ?? null,
          }),
        );
        await new Promise((r) => setTimeout(r, APNS_RETRY_DELAY_MS));
        last = await attemptApns(environment, auth, msg, deadline, budgetMs);
      }
      if (last === null) break;
      if (last.status === 200) {
        if (mode === "auto" && cachedEnv !== environment) {
          await this.ctx.storage.put("apnsEnv", environment);
        }
        return { delivered: true };
      }
      if (!(last.reason !== null && WRONG_ENVIRONMENT.has(last.reason))) {
        break;
      }
    }
    return {
      delivered: false,
      failure: last === null ? APNS_UNREACHABLE : mapApnsFailure(last),
      transient: transient(last),
    };
  }

  /**
   * APNs rejected the token for good (410).  Unless the object holds an
   * entitlement that still lifts the quota, nothing in it is worth
   * keeping, so it deletes everything, alarm included, and returns true.
   * An entitlement stays because a 410 can come from the relay's own
   * configuration (a wrong APNS_TOPIC makes APNs reject every token), and
   * only the device's app can post its proof again.
   */
  private async forgetDeadToken(): Promise<boolean> {
    const entitlement = await this.ctx.storage.get<EntitlementRecord>(
      "entitlement",
    );
    if (entitlementValid(entitlement, Date.now(), liftFromEnv(this.env))) {
      return false;
    }
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
    return true;
  }

  /**
   * Undo one optimistic forward after APNs refused it.  Each of
   * `rowKeys` loses the forward's instant.  The quota row goes back to
   * `quota.before`, the row stored ahead of the forward (deleted when
   * there was none), while it still holds what the forward wrote.  If a
   * sibling envelope has written the row since, only the counters the
   * forward bumped come back down (`quota.free` is what it passed to
   * `countForward`), and a row left carrying nothing is deleted.
   */
  private async rollbackForward(
    rowKeys: string[],
    forwardedAt: number,
    quotaCfg: QuotaConfig,
    quota: {
      before: QuotaState | undefined;
      written: QuotaState;
      free: boolean;
    },
  ): Promise<void> {
    const stored = await this.ctx.storage.get<unknown>([...rowKeys, "quota"]);
    const updates: Record<string, unknown> = {};
    for (const key of rowKeys) {
      const current = stored.get(key) as CollapseState | undefined;
      if (!current) continue;
      const forwards = [...current.forwards];
      const index = forwards.lastIndexOf(forwardedAt);
      if (index >= 0) forwards.splice(index, 1);
      updates[key] = {
        ...current,
        forwards,
        lastForwardAt:
          current.lastForwardAt === forwardedAt
            ? (forwards[forwards.length - 1] ?? 0)
            : current.lastForwardAt,
      };
    }
    const held = stored.get("quota") as QuotaState | undefined;
    let restored = held;
    if (sameQuota(held, quota.written)) {
      restored = quota.before;
    } else if (held && held.period === periodKey(forwardedAt, quotaCfg)) {
      const uncounted = uncountForward(held, quota.free);
      restored = quotaWorthKeeping(uncounted, Date.now(), quotaCfg)
        ? uncounted
        : undefined;
    }
    if (restored !== undefined && restored !== held) updates.quota = restored;
    if (Object.keys(updates).length > 0) await this.ctx.storage.put(updates);
    if (restored === undefined && held !== undefined) {
      await this.ctx.storage.delete("quota");
    }
  }

  /**
   * Make sure the alarm fires no later than `at`.  An earlier alarm
   * stays: the alarm handler derives the next instant from what storage
   * holds, so lowering the alarm is always safe and raising it is not.
   */
  private async wakeBy(at: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }

  async alarm(): Promise<void> {
    try {
      const forgotten = await this.sendOwedDigests();
      if (!forgotten) await this.sweep();
    } catch (err) {
      // A thrown alarm is retried a few times and then abandoned, which
      // would leave the object's rows in place for good.  Run again
      // later instead, unless something already asked for an earlier
      // wake while this one ran.
      console.error(JSON.stringify({ evt: "alarm_error", err: String(err) }));
      const now = Date.now();
      const retryAt = now + ALARM_RETRY_MS;
      const current = await this.ctx.storage.getAlarm();
      if (current === null || current <= now || current > retryAt) {
        await this.ctx.storage.setAlarm(retryAt);
      }
    }
  }

  /**
   * Send the digest each trigger owes once its interval has ended; one
   * push covers both when both are due.  Reads the raw stored quota row,
   * so a period rollover never cancels a digest owed from the period
   * before.  A failed send is logged, never thrown, and handled as on
   * the delivery path: a transient failure owes the digest again after
   * a short backoff (`oweAgain`), and any other refusal spends the
   * interval.  A 410 has no daemon to hear it here, so the object
   * forgets the token (`forgetDeadToken`); returns true when it did.
   */
  private async sendOwedDigests(): Promise<boolean> {
    const now = Date.now();
    const quotaCfg = quotaFromEnv(this.env);
    const burstIntervalMs = burstDigestIntervalFromEnv(this.env);
    const stored = await this.ctx.storage.get<unknown>([
      "quota",
      "burst",
      "apnsEnv",
    ]);
    const quota = stored.get("quota") as QuotaState | undefined;
    const burst = stored.get("burst") as BurstState | undefined;
    const quotaDue = quotaDigestDueAt(quota, quotaCfg);
    const burstDue = burstDigestDueAt(burst, burstIntervalMs);
    const quotaOwed =
      quota !== undefined && quotaDue !== null && quotaDue <= now;
    const burstOwed =
      burst !== undefined && burstDue !== null && burstDue <= now;
    if (!quotaOwed && !burstOwed) return false;
    // The sent marker lands before the APNs await, so an alarm retried
    // past this point never sends the same digest twice.
    const updates: Record<string, unknown> = {};
    if (quotaOwed) updates.quota = markDigest(quota, now);
    if (burstOwed) updates.burst = burstSent(now);
    await this.ctx.storage.put(updates);

    const priority: DigestLevel =
      burstOwed && burst.timeSensitive ? "time-sensitive" : "passive";
    // The object's name is its device token (index.ts, idFromName).
    const deviceToken = parseDevice(this.ctx.id.name);
    if (deviceToken === null) {
      console.error(
        JSON.stringify({
          evt: "digest_failed",
          error: "the object does not know its device token",
        }),
      );
      return false;
    }
    const auth = this.apnsAuth();
    if ("error" in auth) {
      console.error(
        JSON.stringify({ evt: "digest_failed", error: auth.error }),
      );
      return false;
    }
    try {
      const msg: ApnsDigest = { deviceToken, topic: auth.topic, priority };
      const sent = await this.send(
        msg,
        auth,
        stored.get("apnsEnv") as ApnsEnvironment | undefined,
      );
      if (!sent.delivered) {
        console.error(
          JSON.stringify({ evt: "digest_failed", ...sent.failure.body }),
        );
        if (sent.failure.status === 410) return await this.forgetDeadToken();
        if (sent.transient) {
          await this.oweAgain({
            sentAt: now,
            quota: quotaOwed,
            ...(burstOwed
              ? {
                  burst: {
                    pendingSince: burst.pendingSince,
                    timeSensitive: burst.timeSensitive,
                  },
                }
              : {}),
          });
        }
      }
    } catch (err) {
      console.error(JSON.stringify({ evt: "digest_failed", err: String(err) }));
    }
    return false;
  }

  /**
   * Sweep c: and f: rows silent past the horizon, one page at a time,
   * drop whatever no longer carries information, and set the alarm for
   * the earliest instant the rest needs attention, which for the rows
   * alone is ROW_SWEEP_MIN_MS out at the soonest.  When nothing is left
   * the object deletes everything, its alarm included.
   */
  private async sweep(): Promise<void> {
    const now = Date.now();
    const cfg = policyFromEnv(this.env);
    const quotaCfg = quotaFromEnv(this.env);
    const burstIntervalMs = burstDigestIntervalFromEnv(this.env);
    const lift = liftFromEnv(this.env);
    const horizonMs = rowHorizonMs(cfg);

    let live = 0;
    let oldestLive = Infinity;
    for (const prefix of ["c:", "f:"]) {
      let startAfter: string | undefined;
      for (;;) {
        const page = await this.ctx.storage.list<CollapseState>({
          prefix,
          limit: SWEEP_PAGE,
          ...(startAfter === undefined ? {} : { startAfter }),
        });
        const stale: string[] = [];
        for (const [key, row] of page) {
          const seenAt = row.lastSeenAt ?? 0;
          if (seenAt <= now - horizonMs) {
            stale.push(key);
          } else {
            live += 1;
            oldestLive = Math.min(oldestLive, seenAt);
          }
          startAfter = key;
        }
        for (let i = 0; i < stale.length; i += 128) {
          await this.ctx.storage.delete(stale.slice(i, i + 128));
        }
        if (page.size < SWEEP_PAGE) break;
      }
    }

    const stored = await this.ctx.storage.get<unknown>([
      "quota",
      "burst",
      "entitlement",
    ]);
    const quota = stored.get("quota") as QuotaState | undefined;
    const burst = stored.get("burst") as BurstState | undefined;
    const entitlement = stored.get("entitlement") as
      EntitlementRecord | undefined;
    const keepQuota = quotaWorthKeeping(quota, now, quotaCfg);
    const keepEntitlement = entitlementValid(entitlement, now, lift);
    const quotaDue = quotaDigestDueAt(quota, quotaCfg);
    const burstDue = burstDigestDueAt(burst, burstIntervalMs);
    // The burst state matters while it owes a digest or its interval runs.
    const keepBurst =
      burstDue !== null ||
      (burst !== undefined && now - burst.digestAt < burstIntervalMs);
    if (live === 0 && !keepQuota && !keepEntitlement && !keepBurst) {
      await this.ctx.storage.deleteAll();
      return;
    }

    const drop: string[] = [];
    if (quota !== undefined && !keepQuota) drop.push("quota");
    if (entitlement !== undefined && !keepEntitlement) {
      drop.push("entitlement");
    }
    if (burst !== undefined && !keepBurst) drop.push("burst");
    if (live === 0) {
      // Nothing recent: the buckets read full again by now.  The env
      // cache stays while a digest is owed, since the alarm sends it.
      drop.push("bucket", "bucket:event");
      if (quotaDue === null && burstDue === null) drop.push("apnsEnv");
    }
    if (drop.length > 0) await this.ctx.storage.delete(drop);

    // Digests, the period's end, and the lift's end keep exact wakes; the
    // rows wait for the coarser cadence.
    const wakes: number[] = [];
    if (live > 0) {
      wakes.push(Math.max(oldestLive + horizonMs, now + ROW_SWEEP_MIN_MS));
    }
    if (quotaDue !== null) wakes.push(quotaDue);
    if (burstDue !== null) wakes.push(burstDue);
    if (keepQuota && quota!.period === periodKey(now, quotaCfg)) {
      wakes.push(periodEndsAt(now, quotaCfg));
    }
    if (keepEntitlement) wakes.push(liftEndsAt(entitlement, lift));
    // A burst state kept for its running interval alone goes when that
    // interval ends.
    if (wakes.length === 0) wakes.push(burst!.digestAt + burstIntervalMs);
    await this.ctx.storage.setAlarm(Math.max(Math.min(...wakes), now + 1000));
  }
}

function mapApnsFailure(result: ApnsResult): DeliverOutcome {
  const reason = result.reason;
  if (reason !== null && TOKEN_REJECTED.has(reason)) {
    return {
      status: 410,
      body: { v: 1, error: "device token rejected by APNs", reason },
    };
  }
  if (result.status === 429) {
    return {
      status: 429,
      body: { v: 1, error: "APNs rate limited this device", reason },
    };
  }
  if (
    result.status === 403 ||
    (reason !== null && RELAY_MISCONFIGURED.has(reason))
  ) {
    console.error(
      `APNs rejected the relay's credentials/config: ${result.status} ${reason ?? ""}`,
    );
    return {
      status: 502,
      body: { v: 1, error: "relay APNs credentials rejected", reason },
    };
  }
  return {
    status: 502,
    body: {
      v: 1,
      error: "APNs error",
      apnsStatus: result.status,
      reason,
    },
  };
}

/**
 * One request to one APNs host, cut off at half the send's budget or at
 * its deadline, whichever comes first, so a stalled first attempt still
 * leaves room for the retry.  Null when no answer came back: the
 * connection failed, the attempt ran out of time, or the deadline had
 * already passed.
 */
async function attemptApns(
  environment: ApnsEnvironment,
  auth: Auth,
  msg: ApnsMessage | ApnsDigest,
  deadline: number,
  budgetMs: number,
): Promise<ApnsResult | null> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    console.error(
      `APNs unreachable (${environment}): the send's deadline passed`,
    );
    return null;
  }
  const limitMs = Math.max(1, Math.floor(Math.min(remaining, budgetMs / 2)));
  try {
    return await sendToApns(
      APNS_HOSTS[environment],
      auth,
      msg,
      AbortSignal.timeout(limitMs),
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`APNs unreachable (${environment}): ${message}`);
    return null;
  }
}

/**
 * Whether a failed attempt is worth one more try against the same host:
 * no answer at all, or APNs reporting trouble on its side (500, 503).
 * An answer about the request, the token, the relay's credentials, or
 * throttling (4xx) would come back the same.
 */
function transient(result: ApnsResult | null): boolean {
  if (result === null) return true;
  if (result.reason !== null && RELAY_MISCONFIGURED.has(result.reason)) {
    return false;
  }
  return result.status === 500 || result.status === 503;
}

/** Whether a stored quota row is still the one a forward wrote. */
function sameQuota(a: QuotaState | undefined, b: QuotaState): boolean {
  return (
    a !== undefined &&
    a.period === b.period &&
    a.forwards === b.forwards &&
    freeForwards(a) === freeForwards(b) &&
    a.digestAt === b.digestAt &&
    (a.digestPending ?? false) === (b.digestPending ?? false)
  );
}
