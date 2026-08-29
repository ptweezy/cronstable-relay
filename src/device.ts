/**
 * One Durable Object per device token: the serialization point where
 * dedup, flap suppression, rate limiting and the monthly quota become
 * race-free, and the only place APNs is called from.
 *
 * Storage layout (SQLite-backed KV):
 *   c:<collapseId> -> CollapseState       per-alert history
 *   bucket         -> BucketState         the device's rate-limit bucket
 *   apnsEnv        -> "production" | "sandbox"   auto-mode cache
 *   quota          -> QuotaState          this period's forward count
 *   entitlement    -> EntitlementRecord   the verified Pro entitlement
 *
 * A daily-ish alarm sweeps collapse rows that have been silent past
 * the flap-reset horizon.  When none are left it drops the bucket and
 * env cache too, keeps `quota` while its period is current and
 * `entitlement` while unexpired, and deletes everything once neither
 * is live, so an idle device's object holds no storage at all.
 */

import { DurableObject } from "cloudflare:workers";

import {
  APNS_HOSTS,
  sendToApns,
  type ApnsAuth,
  type ApnsDigest,
  type ApnsEnvironment,
  type ApnsMessage,
  type ApnsResult,
} from "./apns";
import {
  admit,
  policyFromEnv,
  recordForward,
  type BucketState,
  type CollapseState,
} from "./policy";
import {
  countForward,
  currentQuota,
  digestDue,
  entitlementValid,
  markDigest,
  periodEndsAt,
  periodKey,
  quotaExhausted,
  quotaFromEnv,
  uncountForward,
  type EntitlementRecord,
  type QuotaConfig,
  type QuotaState,
} from "./quota";
import type { DeliverOutcome, DeviceStatus, Envelope, Env } from "./types";

const SWEEP_INTERVAL_MS = 6 * 3600 * 1000;
const DAY_MS = 24 * 3600 * 1000;

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

type SendResult =
  { delivered: true } | { delivered: false; failure: DeliverOutcome };

type Auth = ApnsAuth & { topic: string };

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
    const stored = await this.ctx.storage.get<unknown>([
      collapseKey,
      "bucket",
      "apnsEnv",
      "quota",
      "entitlement",
    ]);
    const result = admit(
      stored.get(collapseKey) as CollapseState | undefined,
      stored.get("bucket") as BucketState | undefined,
      now,
      cfg,
    );

    if (result.decision === "coalesce" || result.decision === "suppress") {
      await this.ctx.storage.put({
        [collapseKey]: result.collapse,
        bucket: result.bucket,
      });
      const outcome =
        result.decision === "coalesce" ? "coalesced" : "suppressed";
      return { status: 202, body: { v: 1, outcome } };
    }
    if (result.decision === "rate_limit") {
      await this.ctx.storage.put({
        [collapseKey]: result.collapse,
        bucket: result.bucket,
      });
      return {
        status: 429,
        body: { v: 1, error: "device is rate limited" },
        retryAfterS: result.retryAfterS,
      };
    }

    // Quota: a free device past its monthly bound gets a digest in place
    // of the alert.  Checked after admission so coalesced, suppressed and
    // rate-limited envelopes neither count nor trigger a digest.
    const cachedEnv = stored.get("apnsEnv") as ApnsEnvironment | undefined;
    const quota = currentQuota(
      stored.get("quota") as QuotaState | undefined,
      now,
      quotaCfg,
    );
    const entitlement = stored.get("entitlement") as
      EntitlementRecord | undefined;
    if (
      !entitlementValid(entitlement, now) &&
      quotaExhausted(quota, quotaCfg)
    ) {
      return this.digest(
        envelope.device,
        { collapseKey, collapse: result.collapse },
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
    // quota count rides along; on failure both are rolled back so the
    // alert stays eligible and the failed send costs no quota.
    const optimistic = recordForward(result.collapse, now);
    await this.ctx.storage.put({
      [collapseKey]: optimistic,
      bucket: result.bucket,
      quota: countForward(quota),
    });
    await this.ensureSweepAlarm(now);
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
    await this.rollbackForward(collapseKey, now, quotaCfg);
    return sent.failure;
  }

  /**
   * Store a verified entitlement (POST /entitlement), replacing any
   * earlier one, and report the resulting plan and quota.
   */
  async setEntitlement(record: EntitlementRecord): Promise<DeviceStatus> {
    await this.ctx.storage.put("entitlement", record);
    await this.ensureSweepAlarm(Date.now());
    return this.status();
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
    const base = {
      used: quota.forwards,
      resetsAt: periodEndsAt(now, quotaCfg),
    };
    if (entitlementValid(entitlement, now)) {
      return {
        plan: "pro",
        expiresAt: entitlement.expiresAt,
        environment: entitlement.environment,
        limit: null,
        ...base,
      };
    }
    return { plan: "free", limit: quotaCfg.freeMonthlyForwards, ...base };
  }

  /**
   * The over-quota path: accept the envelope as "digested" and, when
   * the digest interval allows, send the fixed digest push.  A digest
   * that APNs refuses still leaves the envelope digested, except when
   * the token itself is dead (410), which the daemon needs to hear.
   */
  private async digest(
    deviceToken: string,
    seen: { collapseKey: string; collapse: CollapseState },
    quota: QuotaState,
    now: number,
    quotaCfg: QuotaConfig,
    auth: Auth,
    cachedEnv: ApnsEnvironment | undefined,
  ): Promise<DeliverOutcome> {
    const digested: DeliverOutcome = {
      status: 202,
      body: { v: 1, outcome: "digested" },
    };
    // The collapse row records the sighting.  The bucket is left as it
    // was: admission took a token for a forward that is not happening.
    if (!digestDue(quota, now, quotaCfg)) {
      await this.ctx.storage.put(seen.collapseKey, seen.collapse);
      return digested;
    }
    await this.ctx.storage.put({
      [seen.collapseKey]: seen.collapse,
      quota: markDigest(quota, now),
    });
    await this.ensureSweepAlarm(now);
    const msg: ApnsDigest = { deviceToken, topic: auth.topic };
    const sent = await this.send(msg, auth, cachedEnv);
    if (!sent.delivered) {
      if (sent.failure.status === 410) return sent.failure;
      console.error(
        JSON.stringify({ evt: "digest_failed", ...sent.failure.body }),
      );
    }
    return digested;
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

  /** One APNs send, with the auto-mode environment dance. */
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
    let last: ApnsResult = { status: 0, reason: null };
    for (const environment of order) {
      try {
        last = await sendToApns(APNS_HOSTS[environment], auth, msg);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`APNs unreachable (${environment}): ${message}`);
        return {
          delivered: false,
          failure: {
            status: 502,
            body: { v: 1, error: "APNs unreachable" },
          },
        };
      }
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
    return { delivered: false, failure: mapApnsFailure(last) };
  }

  /** Undo one optimistic forward record (and its quota count) after
   * APNs refused it. */
  private async rollbackForward(
    collapseKey: string,
    forwardedAt: number,
    quotaCfg: QuotaConfig,
  ): Promise<void> {
    const stored = await this.ctx.storage.get<unknown>([collapseKey, "quota"]);
    const updates: Record<string, unknown> = {};
    const current = stored.get(collapseKey) as CollapseState | undefined;
    if (current) {
      const forwards = [...current.forwards];
      const index = forwards.lastIndexOf(forwardedAt);
      if (index >= 0) forwards.splice(index, 1);
      updates[collapseKey] = {
        ...current,
        forwards,
        lastForwardAt:
          current.lastForwardAt === forwardedAt
            ? (forwards[forwards.length - 1] ?? 0)
            : current.lastForwardAt,
      };
    }
    const quota = stored.get("quota") as QuotaState | undefined;
    if (quota && quota.period === periodKey(forwardedAt, quotaCfg)) {
      updates.quota = uncountForward(quota);
    }
    await this.ctx.storage.put(updates);
  }

  private async ensureSweepAlarm(now: number): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(now + SWEEP_INTERVAL_MS);
    }
  }

  async alarm(): Promise<void> {
    const cfg = policyFromEnv(this.env);
    const quotaCfg = quotaFromEnv(this.env);
    const now = Date.now();
    const horizon = now - Math.max(cfg.flapResetMs, DAY_MS);
    const entries = await this.ctx.storage.list<CollapseState>({
      prefix: "c:",
    });
    const stale: string[] = [];
    let live = 0;
    for (const [key, value] of entries) {
      if ((value.lastSeenAt ?? 0) < horizon) stale.push(key);
      else live += 1;
    }
    for (let i = 0; i < stale.length; i += 128) {
      await this.ctx.storage.delete(stale.slice(i, i + 128));
    }
    if (live > 0) {
      await this.ctx.storage.setAlarm(now + SWEEP_INTERVAL_MS);
      return;
    }
    // Nothing recent: drop the bucket and env cache.  The quota count
    // stays for the rest of its period and the entitlement until it
    // expires; once neither is live the object holds no storage at all
    // (and is not billed).
    const stored = await this.ctx.storage.get<unknown>([
      "quota",
      "entitlement",
    ]);
    const quota = stored.get("quota") as QuotaState | undefined;
    const keepQuota =
      quota !== undefined && quota.period === periodKey(now, quotaCfg);
    const keepEntitlement = entitlementValid(
      stored.get("entitlement") as EntitlementRecord | undefined,
      now,
    );
    if (!keepQuota && !keepEntitlement) {
      await this.ctx.storage.deleteAll();
      return;
    }
    const drop = ["bucket", "apnsEnv"];
    if (!keepQuota) drop.push("quota");
    if (!keepEntitlement) drop.push("entitlement");
    await this.ctx.storage.delete(drop);
    await this.ctx.storage.setAlarm(now + SWEEP_INTERVAL_MS);
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
