/**
 * One Durable Object per device token: the serialization point where
 * dedup, flap suppression and rate limiting become race-free, and the
 * only place APNs is called from.
 *
 * Storage layout (SQLite-backed KV):
 *   c:<collapseId> -> CollapseState   per-alert history
 *   bucket         -> BucketState     the device's rate-limit bucket
 *   apnsEnv        -> "production" | "sandbox"   auto-mode cache
 *
 * A daily-ish alarm sweeps collapse rows that have been silent past
 * the flap-reset horizon; when nothing is left the object deletes all
 * its state and evaporates.
 */

import { DurableObject } from "cloudflare:workers";

import {
  APNS_HOSTS,
  sendToApns,
  type ApnsAuth,
  type ApnsEnvironment,
  type ApnsResult,
} from "./apns";
import {
  admit,
  policyFromEnv,
  recordForward,
  type BucketState,
  type CollapseState,
} from "./policy";
import type { DeliverOutcome, Envelope, Env } from "./types";

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

type ForwardResult =
  | { delivered: true }
  | { delivered: false; failure: DeliverOutcome };

export class DeviceState extends DurableObject<Env> {
  async deliver(envelope: Envelope): Promise<DeliverOutcome> {
    const auth = this.apnsAuth();
    if ("error" in auth) {
      return { status: 502, body: { v: 1, error: auth.error } };
    }
    const cfg = policyFromEnv(this.env);
    const now = Date.now();
    const collapseKey = `c:${envelope.collapseId}`;
    const stored = await this.ctx.storage.get<unknown>([
      collapseKey,
      "bucket",
      "apnsEnv",
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

    // Forward.  Record it BEFORE the APNs call: while we await Apple
    // the input gate is open, and a cluster sibling posting the same
    // alert must read "already forwarded" and coalesce rather than
    // triple-send (and triple-count toward flap suppression).  On
    // failure the record is rolled back so the alert stays eligible.
    const optimistic = recordForward(result.collapse, now);
    await this.ctx.storage.put({
      [collapseKey]: optimistic,
      bucket: result.bucket,
    });
    await this.ensureSweepAlarm(now);
    const forwarded = await this.forward(
      envelope,
      auth,
      stored.get("apnsEnv") as ApnsEnvironment | undefined,
    );
    if (forwarded.delivered) {
      return { status: 202, body: { v: 1, outcome: "forwarded" } };
    }
    await this.rollbackForward(collapseKey, now);
    return forwarded.failure;
  }

  private apnsAuth(): (ApnsAuth & { topic: string }) | { error: string } {
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

  private async forward(
    envelope: Envelope,
    auth: ApnsAuth & { topic: string },
    cachedEnv: ApnsEnvironment | undefined,
  ): Promise<ForwardResult> {
    const mode = this.env.APNS_ENVIRONMENT ?? "auto";
    let order: ApnsEnvironment[];
    if (mode === "production" || mode === "sandbox") {
      order = [mode];
    } else {
      const first: ApnsEnvironment =
        cachedEnv === "sandbox" ? "sandbox" : "production";
      order = [first, first === "production" ? "sandbox" : "production"];
    }
    const msg = {
      deviceToken: envelope.device,
      ciphertext: envelope.ciphertext,
      collapseId: envelope.collapseId,
      priority: envelope.priority,
      topic: auth.topic,
      suite: envelope.suite,
    };
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

  /** Undo one optimistic forward record after APNs refused it. */
  private async rollbackForward(
    collapseKey: string,
    forwardedAt: number,
  ): Promise<void> {
    const current = await this.ctx.storage.get<CollapseState>(collapseKey);
    if (!current) return;
    const forwards = [...current.forwards];
    const index = forwards.lastIndexOf(forwardedAt);
    if (index >= 0) forwards.splice(index, 1);
    await this.ctx.storage.put(collapseKey, {
      ...current,
      forwards,
      lastForwardAt:
        current.lastForwardAt === forwardedAt
          ? (forwards[forwards.length - 1] ?? 0)
          : current.lastForwardAt,
    });
  }

  private async ensureSweepAlarm(now: number): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(now + SWEEP_INTERVAL_MS);
    }
  }

  async alarm(): Promise<void> {
    const cfg = policyFromEnv(this.env);
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
    } else {
      // Nothing recent: drop the bucket and env cache too, so an idle
      // device's object holds no storage at all (and is not billed).
      await this.ctx.storage.deleteAll();
    }
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
