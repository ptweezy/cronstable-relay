/**
 * Digests, admission writes, and the alarm, end to end in the "relay"
 * project: rate capacity 5 per lane, the production burst digest
 * interval (300 s), the production quota (500 forwards, hourly digests,
 * calendar months).  Cases that need a lane already empty or a digest
 * already owed seed the device's storage directly, so no case depends on
 * how fast the posts land; alarms run through runDurableObjectAlarm.
 */

import { env, exports } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { APNS_EXPIRATION_S, DIGEST_EXPIRATION_S } from "../src/apns";
import type { DeviceState } from "../src/device";
import { policyFromEnv, type CollapseState } from "../src/policy";
import {
  burstDigestIntervalFromEnv,
  liftEndsAt,
  periodEndsAt,
  periodKey,
  proGraceFromEnv,
  quotaFromEnv,
  type BurstState,
  type EntitlementRecord,
  type QuotaState,
} from "../src/quota";

import {
  apnsRequests,
  expectApns,
  expectApnsError,
  expectNoPendingApns,
  installApnsMock,
  PROD,
  resetApnsMock,
  SANDBOX,
  type ApnsRequest,
} from "./apns-mock";

beforeEach(() => {
  resetApnsMock();
  installApnsMock();
});

afterEach(() => {
  expectNoPendingApns();
});

const DAY_MS = 86_400_000;
const HORIZON_MS = Math.max(policyFromEnv(env).flapResetMs, DAY_MS);
const QUOTA = quotaFromEnv(env);
const BURST_MS = burstDigestIntervalFromEnv(env);

let deviceCounter = 0x3000;

function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

function randHex(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function envelope(
  device: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    v: 1,
    device,
    ciphertext: "A".repeat(96),
    collapseId: randHex(),
    priority: "time-sensitive",
    event: false,
    ...overrides,
  };
}

async function post(body: unknown): Promise<Response> {
  return exports.default.fetch("https://relay.test/", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** "<status> <outcome or error>" for one post. */
async function answer(body: unknown): Promise<string> {
  const res = await post(body);
  const json = (await res.json()) as { outcome?: string; error?: string };
  return `${res.status} ${json.outcome ?? json.error}`;
}

function tally(answers: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const a of answers) counts[a] = (counts[a] ?? 0) + 1;
  return counts;
}

function stub(device: string) {
  return env.DEVICE.get(env.DEVICE.idFromName(device));
}

function inObject<T>(
  device: string,
  fn: (object: DeviceState, state: DurableObjectState) => Promise<T>,
): Promise<T> {
  return runInDurableObject(stub(device), (instance, state) =>
    fn(instance as unknown as DeviceState, state),
  );
}

function stored<T>(device: string, key: string): Promise<T | undefined> {
  return inObject(device, (_o, state) => state.storage.get<T>(key));
}

/** Empty one lane's bucket for the next minute: a bucket stamped in the
 * future refills nothing until then. */
function drainLane(device: string, key = "bucket"): Promise<void> {
  return inObject(device, (_o, state) =>
    state.storage.put(key, { tokens: 0, ts: Date.now() + 60_000 }),
  );
}

async function rowCount(device: string, prefix: string): Promise<number> {
  return inObject(
    device,
    async (_o, state) => (await state.storage.list({ prefix })).size,
  );
}

function digests(): ApnsRequest[] {
  return apnsRequests().filter((r) => r.headers["apns-collapse-id"] === "digest");
}

function level(request: ApnsRequest): {
  interruption: unknown;
  sound: unknown;
  priority: string | undefined;
} {
  const aps = (JSON.parse(request.body) as { aps: Record<string, unknown> })
    .aps;
  return {
    interruption: aps["interruption-level"],
    sound: aps.sound,
    priority: request.headers["apns-priority"],
  };
}

const PASSIVE = { interruption: "passive", sound: undefined, priority: "5" };
const URGENT = {
  interruption: "time-sensitive",
  sound: "default",
  priority: "10",
};

/** Move the burst digest's last-sent instant back past its interval. */
function burstIntervalEnded(device: string): Promise<void> {
  return inObject(device, async (_o, state) => {
    const burst = (await state.storage.get<BurstState>("burst"))!;
    await state.storage.put("burst", {
      ...burst,
      digestAt: burst.digestAt - BURST_MS,
    });
  });
}

describe("over-rate envelopes fold into the burst digest", () => {
  it("answers a burst past capacity with digested and exactly one digest", async () => {
    const device = freshDevice();
    await drainLane(device);
    expectApns(PROD, 200);
    // Concurrent: the posts interleave while the digest awaits APNs, and
    // every one after the first must read the digest as sent.
    const answers = await Promise.all(
      Array.from({ length: 100 }, () => answer(envelope(device))),
    );
    expect(tally(answers)).toEqual({ "202 digested": 100 });
    expect(apnsRequests()).toHaveLength(1);
    expect(digests()).toHaveLength(1);
    // The rest of the burst is owed one digest when the interval ends.
    const burst = (await stored<BurstState>(device, "burst"))!;
    expect(burst.pendingSince).toBeGreaterThan(0);
    const alarm = await inObject(device, (_o, state) => state.storage.getAlarm());
    expect(alarm).toBe(burst.digestAt + BURST_MS);
  });

  it("forwards up to capacity, then digests, and never answers 429", async () => {
    const device = freshDevice();
    for (let i = 0; i < 6; i += 1) expectApns(PROD, 200);
    const answers: string[] = [];
    for (let i = 0; i < 5; i += 1) answers.push(await answer(envelope(device)));
    await drainLane(device);
    for (let i = 0; i < 5; i += 1) answers.push(await answer(envelope(device)));
    expect(tally(answers)).toEqual({ "202 forwarded": 5, "202 digested": 5 });
    expect(digests()).toHaveLength(1);
  });

  it("forwards a daemon event while the alert lane is empty", async () => {
    const device = freshDevice();
    await drainLane(device);
    expectApns(PROD, 200);
    const gate = envelope(device, { event: true });
    expect(await answer(gate)).toBe("202 forwarded");
    expect(apnsRequests()[0]!.headers["apns-collapse-id"]).toBe(
      gate.collapseId,
    );
    // The event spent its own lane's token, not the alert lane's.
    expect(await stored(device, "bucket:event")).toMatchObject({ tokens: 4 });
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 digested");
    expect(digests()).toHaveLength(1);
  });

  it("folds an event too once the event lane is empty", async () => {
    const device = freshDevice();
    await drainLane(device, "bucket:event");
    expectApns(PROD, 200);
    expect(await answer(envelope(device, { event: true }))).toBe(
      "202 digested",
    );
    expect(digests()).toHaveLength(1);
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
  });

  it("sends the burst digest time-sensitive only when a folded envelope was", async () => {
    const quiet = freshDevice();
    await drainLane(quiet);
    expectApns(PROD, 200);
    expect(await answer(envelope(quiet, { priority: "passive" }))).toBe(
      "202 digested",
    );
    expect(level(digests()[0]!)).toEqual(PASSIVE);

    const loud = freshDevice();
    await drainLane(loud);
    expectApns(PROD, 200);
    expect(await answer(envelope(loud))).toBe("202 digested");
    expect(level(digests()[1]!)).toEqual(URGENT);
  });

  it("escalates the owed burst digest when a time-sensitive envelope folds", async () => {
    const device = freshDevice();
    await drainLane(device);
    expectApns(PROD, 200);
    await answer(envelope(device, { priority: "passive" }));
    await answer(envelope(device, { priority: "passive" }));
    expect(await stored(device, "burst")).toMatchObject({
      timeSensitive: false,
    });
    await answer(envelope(device));
    expect(await stored(device, "burst")).toMatchObject({
      timeSensitive: true,
    });
    await burstIntervalEnded(device);
    expectApns(PROD, 200);
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    expect(digests()).toHaveLength(2);
    expect(level(digests()[1]!)).toEqual(URGENT);
  });

  it("sends the owed burst digest passive when every folded envelope was", async () => {
    const device = freshDevice();
    await drainLane(device);
    expectApns(PROD, 200);
    await answer(envelope(device));
    await answer(envelope(device, { priority: "passive" }));
    await burstIntervalEnded(device);
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(2);
    expect(level(digests()[0]!)).toEqual(URGENT);
    expect(level(digests()[1]!)).toEqual(PASSIVE);
    expect(await stored(device, "burst")).toMatchObject({
      pendingSince: 0,
      timeSensitive: false,
    });
  });
});

describe("trailing digests", () => {
  /** A free device past its bound whose last digest went out at
   * `digestAt`. */
  function pastBound(device: string, digestAt: number): Promise<void> {
    return inObject(device, (_o, state) =>
      state.storage.put("quota", {
        period: periodKey(Date.now(), QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt,
      } satisfies QuotaState),
    );
  }

  it("owes one digest for alerts digested inside the interval, and the alarm sends it", async () => {
    const device = freshDevice();
    const digestAt = Date.now();
    await pastBound(device, digestAt);
    for (let i = 0; i < 3; i += 1) {
      expect(await answer(envelope(device))).toBe("202 digested");
    }
    expect(apnsRequests()).toHaveLength(0);
    const owed = await inObject(device, async (_o, state) => ({
      quota: await state.storage.get<QuotaState>("quota"),
      alarm: await state.storage.getAlarm(),
    }));
    expect(owed.quota!.digestPending).toBe(true);
    expect(owed.alarm).toBe(digestAt + QUOTA.digestIntervalMs);

    // The alarm runs once the interval has ended.
    await inObject(device, (_o, state) =>
      state.storage.put("quota", {
        ...owed.quota!,
        digestAt: digestAt - QUOTA.digestIntervalMs,
      }),
    );
    expectApns(PROD, 200);
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    expect(digests()).toHaveLength(1);
    expect(level(digests()[0]!)).toEqual(PASSIVE);

    // Nothing owed any more: a later alarm sends nothing.
    await inObject(device, (_o, state) => state.storage.setAlarm(Date.now() + 60_000));
    await runDurableObjectAlarm(stub(device));
    expect(apnsRequests()).toHaveLength(1);
  });

  it("sends nothing from an alarm when no digest is owed", async () => {
    const device = freshDevice();
    await pastBound(device, Date.now() - 2 * QUOTA.digestIntervalMs);
    await inObject(device, (_o, state) => state.storage.setAlarm(Date.now() + 60_000));
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    expect(apnsRequests()).toHaveLength(0);
  });

  it("does not run an owed digest early", async () => {
    const device = freshDevice();
    await pastBound(device, Date.now());
    expect(await answer(envelope(device))).toBe("202 digested");
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    expect(apnsRequests()).toHaveLength(0);
    // Still owed, and the alarm is back at the due time.
    const quota = (await stored<QuotaState>(device, "quota"))!;
    expect(quota.digestPending).toBe(true);
    expect(await inObject(device, (_o, state) => state.storage.getAlarm())).toBe(
      Math.min(
        quota.digestAt + QUOTA.digestIntervalMs,
        periodEndsAt(Date.now(), QUOTA),
      ),
    );
  });

  it("keeps an owed digest across a period rollover", async () => {
    const device = freshDevice();
    const now = Date.now();
    // Owed in the period before this one, and due already.
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        period: periodKey(now - 40 * DAY_MS, QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now - QUOTA.digestIntervalMs - 1_000,
        digestPending: true,
      } satisfies QuotaState);
    });
    // The new period forwards again, and the debt rides along.
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    const carried = (await stored<QuotaState>(device, "quota"))!;
    expect(carried).toMatchObject({
      period: periodKey(Date.now(), QUOTA),
      forwards: 1,
      digestPending: true,
      digestAt: now - QUOTA.digestIntervalMs - 1_000,
    });
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(1);
    expect((await stored<QuotaState>(device, "quota"))!.digestPending).toBe(
      undefined,
    );
  });

  it("sends an owed digest from a past period's row in the alarm", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        period: periodKey(now - 40 * DAY_MS, QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now - QUOTA.digestIntervalMs,
        digestPending: true,
      } satisfies QuotaState);
      await state.storage.setAlarm(now + 60_000);
    });
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(1);
    // Sent, the past period's row carries nothing, and the object empties.
    expect(await rowCount(device, "")).toBe(0);
  });

  it("marks the digest sent before APNs answers, so a refused one is not retried", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        period: periodKey(now, QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now - QUOTA.digestIntervalMs,
        digestPending: true,
      } satisfies QuotaState);
      await state.storage.setAlarm(now + 60_000);
    });
    expectApns(PROD, 400, JSON.stringify({ reason: "PayloadTooLarge" }));
    // A refused send is logged, not thrown, so the alarm completes.
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    const quota = (await stored<QuotaState>(device, "quota"))!;
    expect(quota.digestPending).toBeUndefined();
    expect(quota.digestAt).toBeGreaterThanOrEqual(now);
    await runDurableObjectAlarm(stub(device));
    expect(apnsRequests()).toHaveLength(1);
  });

  it("owes the alarm's quota digest again after a transient failure", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        period: periodKey(now, QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now - QUOTA.digestIntervalMs,
        digestPending: true,
      } satisfies QuotaState);
      await state.storage.setAlarm(now + 60_000);
    });
    // APNs answers 503 to the send and to its one retry.
    expectApns(PROD, 503, JSON.stringify({ reason: "ServiceUnavailable" }));
    expectApns(PROD, 503, JSON.stringify({ reason: "ServiceUnavailable" }));
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    const failedAt = Date.now();
    const owed = await inObject(device, async (_o, state) => ({
      quota: (await state.storage.get<QuotaState>("quota"))!,
      alarm: await state.storage.getAlarm(),
    }));
    expect(owed.quota).toMatchObject({
      forwards: QUOTA.freeMonthlyForwards,
      digestPending: true,
    });
    // Due again after a backoff of a minute at least and one interval at
    // most, and the alarm wakes for it.
    const dueAt = owed.quota.digestAt + QUOTA.digestIntervalMs;
    expect(dueAt).toBeGreaterThanOrEqual(now + 60_000);
    expect(dueAt).toBeLessThanOrEqual(failedAt + QUOTA.digestIntervalMs);
    expect(owed.alarm).toBe(dueAt);

    // An alarm inside the backoff sends nothing; one past it sends.
    await runDurableObjectAlarm(stub(device));
    expect(apnsRequests()).toHaveLength(2);
    await inObject(device, (_o, state) =>
      state.storage.put("quota", {
        ...owed.quota,
        digestAt: Date.now() - QUOTA.digestIntervalMs,
      }),
    );
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(3);
    expect(level(digests()[2]!)).toEqual(PASSIVE);
    expect((await stored<QuotaState>(device, "quota"))!.digestPending).toBe(
      undefined,
    );
  });

  it("owes the alarm's burst digest again, at its level, after a dropped connection", async () => {
    const device = freshDevice();
    const now = Date.now();
    const pendingSince = now - 1_000;
    await inObject(device, async (_o, state) => {
      await state.storage.put("burst", {
        digestAt: now - BURST_MS,
        pendingSince,
        timeSensitive: true,
      } satisfies BurstState);
      await state.storage.setAlarm(now + 60_000);
    });
    expectApnsError(PROD);
    expectApnsError(PROD);
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    const failedAt = Date.now();
    const owed = await inObject(device, async (_o, state) => ({
      burst: (await state.storage.get<BurstState>("burst"))!,
      alarm: await state.storage.getAlarm(),
    }));
    expect(owed.burst).toMatchObject({ pendingSince, timeSensitive: true });
    const dueAt = owed.burst.digestAt + BURST_MS;
    expect(dueAt).toBeGreaterThanOrEqual(now + 60_000);
    expect(dueAt).toBeLessThanOrEqual(failedAt + BURST_MS);
    expect(owed.alarm).toBe(dueAt);

    await burstIntervalEnded(device);
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(3);
    expect(level(digests()[2]!)).toEqual(URGENT);
    expect(await stored(device, "burst")).toMatchObject({ pendingSince: 0 });
  });

  it("owes a leading burst digest again after a transient failure", async () => {
    const device = freshDevice();
    await drainLane(device);
    expectApns(PROD, 503, JSON.stringify({ reason: "ServiceUnavailable" }));
    expectApns(PROD, 503, JSON.stringify({ reason: "ServiceUnavailable" }));
    const before = Date.now();
    expect(await answer(envelope(device))).toBe("202 digested");
    const failedAt = Date.now();
    const owed = await inObject(device, async (_o, state) => ({
      burst: (await state.storage.get<BurstState>("burst"))!,
      alarm: await state.storage.getAlarm(),
    }));
    expect(owed.burst.pendingSince).toBeGreaterThanOrEqual(before);
    expect(owed.burst.pendingSince).toBeLessThanOrEqual(failedAt);
    expect(owed.burst.timeSensitive).toBe(true);
    const dueAt = owed.burst.digestAt + BURST_MS;
    expect(dueAt).toBeGreaterThanOrEqual(before + 60_000);
    expect(dueAt).toBeLessThanOrEqual(failedAt + BURST_MS);
    expect(owed.alarm).toBe(dueAt);

    // A fold inside the backoff sends nothing; the alarm sends it after.
    expect(await answer(envelope(device, { priority: "passive" }))).toBe(
      "202 digested",
    );
    expect(apnsRequests()).toHaveLength(2);
    await burstIntervalEnded(device);
    expectApns(PROD, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(3);
    expect(level(digests()[2]!)).toEqual(URGENT);
  });

  it("owes a leading quota digest again after a dropped connection", async () => {
    const device = freshDevice();
    await pastBound(device, Date.now() - 2 * QUOTA.digestIntervalMs);
    expectApnsError(PROD);
    expectApnsError(PROD);
    const before = Date.now();
    expect(await answer(envelope(device))).toBe("202 digested");
    const failedAt = Date.now();
    const owed = await inObject(device, async (_o, state) => ({
      quota: (await state.storage.get<QuotaState>("quota"))!,
      alarm: await state.storage.getAlarm(),
    }));
    expect(owed.quota.digestPending).toBe(true);
    const dueAt = owed.quota.digestAt + QUOTA.digestIntervalMs;
    expect(dueAt).toBeGreaterThanOrEqual(before + 60_000);
    expect(dueAt).toBeLessThanOrEqual(failedAt + QUOTA.digestIntervalMs);
    expect(owed.alarm).toBe(dueAt);
  });

  it("covers both triggers with one push when both are owed", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put({
        quota: {
          period: periodKey(now, QUOTA),
          forwards: QUOTA.freeMonthlyForwards,
          digestAt: now - QUOTA.digestIntervalMs,
          digestPending: true,
        } satisfies QuotaState,
        burst: {
          digestAt: now - BURST_MS,
          pendingSince: now - 1_000,
          timeSensitive: true,
        } satisfies BurstState,
        apnsEnv: "sandbox",
      });
      await state.storage.setAlarm(now + 60_000);
    });
    expectApns(SANDBOX, 200);
    await runDurableObjectAlarm(stub(device));
    expect(digests()).toHaveLength(1);
    expect(level(digests()[0]!)).toEqual(URGENT);
    expect(apnsRequests()[0]!.path).toBe(`/3/device/${device}`);
  });
});

describe("APNs expiration", () => {
  it("holds an alert for 10 minutes and a digest for a day", async () => {
    const device = freshDevice();
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    await drainLane(device);
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 digested");
    const nowS = Date.now() / 1000;
    const [alert, digest] = apnsRequests();
    expect(Number(alert!.headers["apns-expiration"])).toBeCloseTo(
      nowS + APNS_EXPIRATION_S,
      -1,
    );
    expect(Number(digest!.headers["apns-expiration"])).toBeCloseTo(
      nowS + DIGEST_EXPIRATION_S,
      -1,
    );
    expect(APNS_EXPIRATION_S).toBe(600);
    expect(DIGEST_EXPIRATION_S).toBe(86_400);
  });
});

describe("admission writes", () => {
  it("writes no row for a fold on a new collapse id", async () => {
    const device = freshDevice();
    await drainLane(device);
    const drained = await stored(device, "bucket");
    expectApns(PROD, 200);
    const flapId = randHex();
    for (let i = 0; i < 10; i += 1) {
      expect(await answer(envelope(device, i % 2 ? { flapId } : {}))).toBe(
        "202 digested",
      );
    }
    expect(await rowCount(device, "c:")).toBe(0);
    expect(await rowCount(device, "f:")).toBe(0);
    // A fold spends no token, so the bucket stays as stored: a refill
    // written back would restamp its future `ts`.
    expect(await stored(device, "bucket")).toEqual(drained);
  });

  it("writes no row for a digested alert on a new collapse id", async () => {
    const device = freshDevice();
    await inObject(device, (_o, state) =>
      state.storage.put("quota", {
        period: periodKey(Date.now(), QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: Date.now(),
      } satisfies QuotaState),
    );
    const answers: string[] = [];
    for (let i = 0; i < 20; i += 1) answers.push(await answer(envelope(device)));
    expect(tally(answers)).toEqual({ "202 digested": 20 });
    expect(apnsRequests()).toHaveLength(0);
    expect(await rowCount(device, "c:")).toBe(0);
    // Only the first digested alert wrote anything: the owed marker.
    expect(await stored(device, "bucket")).toBeUndefined();
  });

  it("keeps an existing row up to date on a fold", async () => {
    const device = freshDevice();
    expectApns(PROD, 200);
    const first = envelope(device);
    expect(await answer(first)).toBe("202 forwarded");
    const before = (await stored<CollapseState>(
      device,
      `c:${String(first.collapseId)}`,
    ))!;
    await drainLane(device);
    expectApns(PROD, 200);
    // Past the dedup window the same alert is admitted again, and folds.
    await new Promise((r) => setTimeout(r, 2_100));
    expect(await answer(first)).toBe("202 digested");
    const after = (await stored<CollapseState>(
      device,
      `c:${String(first.collapseId)}`,
    ))!;
    expect(after.lastSeenAt).toBeGreaterThan(before.lastSeenAt);
    expect(after.lastForwardAt).toBe(before.lastForwardAt);
  }, 10_000);

  it("leaves the bucket as stored on a coalesced or suppressed post", async () => {
    const device = freshDevice();
    const flapId = randHex();
    const body = envelope(device, { flapId });
    for (let i = 0; i < 3; i += 1) expectApns(PROD, 200);
    expect(await answer(body)).toBe("202 forwarded");
    const afterForward = await stored(device, "bucket");
    expect(await answer(body)).toBe("202 coalesced");
    expect(await stored(device, "bucket")).toEqual(afterForward);
    expect(await answer(envelope(device, { flapId }))).toBe("202 forwarded");
    expect(await answer(envelope(device, { flapId }))).toBe("202 forwarded");
    const beforeSuppress = await stored(device, "bucket");
    expect(await answer(envelope(device, { flapId }))).toBe("202 suppressed");
    expect(await stored(device, "bucket")).toEqual(beforeSuppress);
    // The cooling landed on the flap row; the suppressed run's own
    // collapse id left no row.
    expect(await rowCount(device, "c:")).toBe(3);
    const flap = (await stored<CollapseState>(device, `f:${flapId}`))!;
    expect(flap.forwards).toHaveLength(3);
    expect(flap.cooledUntil).toBeGreaterThan(Date.now());
  });

  it("rolls a refused forward back on the flap row too", async () => {
    const device = freshDevice();
    const flapId = randHex();
    expectApns(PROD, 400, JSON.stringify({ reason: "PayloadTooLarge" }));
    expect(await answer(envelope(device, { flapId }))).toBe("502 APNs error");
    const flap = (await stored<CollapseState>(device, `f:${flapId}`))!;
    expect(flap.forwards).toEqual([]);
    expect(flap.lastForwardAt).toBe(0);
  });
});

describe("the alarm", () => {
  /** Age every c: and f: row past the sweep horizon. */
  async function ageRows(state: DurableObjectState): Promise<void> {
    for (const prefix of ["c:", "f:"]) {
      const rows = await state.storage.list<CollapseState>({ prefix });
      for (const [key, row] of rows) {
        await state.storage.put(key, { ...row, lastSeenAt: 0 });
      }
    }
  }

  it("arms at the rows' horizon after a forward, not a fixed cadence", async () => {
    const device = freshDevice();
    expectApns(PROD, 200);
    const before = Date.now();
    expect(await answer(envelope(device))).toBe("202 forwarded");
    const row = await inObject(device, async (_o, state) => {
      const rows = await state.storage.list<CollapseState>({ prefix: "c:" });
      return [...rows.values()][0]!;
    });
    const alarm = await inObject(device, (_o, state) => state.storage.getAlarm());
    expect(alarm).toBe(row.lastSeenAt + HORIZON_MS);
    expect(alarm!).toBeGreaterThanOrEqual(before + HORIZON_MS);
  });

  /** Rows seen a minute apart, the oldest a minute short of the horizon:
   * what a fresh collapseId per alert leaves behind. */
  function staggeredRows(now: number, count: number): Record<string, CollapseState> {
    const rows: Record<string, CollapseState> = {};
    for (let i = 1; i <= count; i += 1) {
      const seenAt = now - HORIZON_MS + i * 60_000;
      rows[`c:${randHex()}`] = {
        lastForwardAt: seenAt,
        forwards: [seenAt],
        cooledUntil: 0,
        lastSeenAt: seenAt,
      };
    }
    return rows;
  }

  it("waits six hours to sweep rows that expire one by one", async () => {
    const device = freshDevice();
    const now = Date.now();
    const after = await inObject(device, async (object, state) => {
      await state.storage.put(staggeredRows(now, 30));
      await object.alarm();
      return {
        rows: (await state.storage.list({ prefix: "c:" })).size,
        alarm: await state.storage.getAlarm(),
      };
    });
    expect(after.rows).toBe(30);
    expect(after.alarm!).toBeGreaterThanOrEqual(now + 6 * 3_600_000);
    expect(after.alarm!).toBeLessThanOrEqual(Date.now() + 6 * 3_600_000);
  });

  it("keeps an owed burst digest's wake ahead of the rows' sweep", async () => {
    const device = freshDevice();
    const now = Date.now();
    const burst: BurstState = {
      digestAt: now,
      pendingSince: now,
      timeSensitive: false,
    };
    const alarm = await inObject(device, async (object, state) => {
      await state.storage.put({ ...staggeredRows(now, 3), burst });
      await object.alarm();
      return state.storage.getAlarm();
    });
    expect(alarm).toBe(now + BURST_MS);
  });

  it("leaves a dead token's object empty through the alarm", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, JSON.stringify({ reason: "BadDeviceToken" }));
    expectApns(SANDBOX, 400, JSON.stringify({ reason: "BadDeviceToken" }));
    expect((await post(envelope(device))).status).toBe(410);
    const left = await inObject(device, async (object, state) => {
      await ageRows(state);
      await object.alarm();
      return {
        keys: [...(await state.storage.list()).keys()],
        alarm: await state.storage.getAlarm(),
      };
    });
    expect(left).toEqual({ keys: [], alarm: null });
  });

  it("empties an object holding a zero-count quota row, a silent row, and a bucket", async () => {
    // The state a junk token's one refused post leaves in an object
    // written by earlier relay versions, with a 6-hour alarm: none of it
    // reads differently from no state at all.
    const device = freshDevice();
    const now = Date.now();
    const silentSince = now - HORIZON_MS - 60_000;
    await inObject(device, async (_o, state) => {
      await state.storage.put({
        [`c:${randHex()}`]: {
          lastForwardAt: 0,
          forwards: [],
          cooledUntil: 0,
          lastSeenAt: silentSince,
        } satisfies CollapseState,
        quota: {
          period: periodKey(now, QUOTA),
          forwards: 0,
          digestAt: 0,
        } satisfies QuotaState,
        bucket: { tokens: 4, ts: silentSince },
      });
      await state.storage.setAlarm(now + 6 * 3_600_000);
    });
    expect(await runDurableObjectAlarm(stub(device))).toBe(true);
    const left = await inObject(device, async (_o, state) => ({
      keys: [...(await state.storage.list()).keys()],
      alarm: await state.storage.getAlarm(),
    }));
    expect(left).toEqual({ keys: [], alarm: null });
  });

  it("drops a quota row that carries nothing while rows stay live", async () => {
    const device = freshDevice();
    const now = Date.now();
    const keys = await inObject(device, async (object, state) => {
      await state.storage.put({
        [`c:${randHex()}`]: {
          lastForwardAt: now,
          forwards: [now],
          cooledUntil: 0,
          lastSeenAt: now,
        } satisfies CollapseState,
        quota: { period: periodKey(now, QUOTA), forwards: 0, digestAt: 0 },
      });
      await object.alarm();
      return [...(await state.storage.list()).keys()];
    });
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^c:/);
  });

  it("sleeps an idle free device until its period ends", async () => {
    const device = freshDevice();
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    const after = await inObject(device, async (object, state) => {
      await ageRows(state);
      await object.alarm();
      return {
        keys: [...(await state.storage.list()).keys()],
        alarm: await state.storage.getAlarm(),
      };
    });
    expect(after.keys).toEqual(["quota"]);
    expect(after.alarm).toBe(periodEndsAt(Date.now(), QUOTA));
  });

  it("sleeps an idle Pro device until its lift ends", async () => {
    const device = freshDevice();
    const now = Date.now();
    const record: EntitlementRecord = {
      originalTransactionId: "2000000955500001",
      productId: "com.cronstable.app.pro.monthly",
      expiresAt: now + 30 * DAY_MS,
      environment: "Production",
      verifiedAt: now,
      purchaseDate: now - DAY_MS,
      slotExpiresAt: now + 60 * DAY_MS,
    };
    const liftEnd = liftEndsAt(record, {
      graceMs: proGraceFromEnv(env),
      slotTtlMs: 2_000,
    });
    const after = await inObject(device, async (object, state) => {
      await object.setEntitlement(record);
      const armed = await state.storage.getAlarm();
      await object.alarm();
      return {
        armed,
        keys: [...(await state.storage.list()).keys()],
        alarm: await state.storage.getAlarm(),
      };
    });
    expect(after).toEqual({
      armed: liftEnd,
      keys: ["entitlement"],
      alarm: liftEnd,
    });
  });

  it("lowers a later alarm for an owed digest and never raises one", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        period: periodKey(now, QUOTA),
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now,
      } satisfies QuotaState);
      await state.storage.setAlarm(now + 7 * DAY_MS);
    });
    expect(await answer(envelope(device))).toBe("202 digested");
    expect(await inObject(device, (_o, state) => state.storage.getAlarm())).toBe(
      now + QUOTA.digestIntervalMs,
    );
    // A forward wants its rows swept a day out, and leaves an earlier
    // alarm where it is.
    const other = freshDevice();
    await inObject(other, (_o, state) => state.storage.setAlarm(now + 60_000));
    expectApns(PROD, 200);
    expect(await answer(envelope(other))).toBe("202 forwarded");
    expect(await inObject(other, (_o, state) => state.storage.getAlarm())).toBe(
      now + 60_000,
    );
  });

  it("sweeps in bounded pages", async () => {
    const device = freshDevice();
    const now = Date.now();
    const stale = 1_200;
    const result = await inObject(device, async (object, state) => {
      for (let i = 0; i < stale; i += 100) {
        const batch: Record<string, CollapseState> = {};
        for (let j = i; j < Math.min(stale, i + 100); j += 1) {
          batch[`c:${j.toString(16).padStart(32, "0")}`] = {
            lastForwardAt: 0,
            forwards: [],
            cooledUntil: 0,
            lastSeenAt: 0,
          };
        }
        await state.storage.put(batch);
      }
      await state.storage.put(`c:${"f".repeat(32)}`, {
        lastForwardAt: now - 1_000,
        forwards: [now - 1_000],
        cooledUntil: 0,
        lastSeenAt: now - 1_000,
      } satisfies CollapseState);
      const storage = state.storage;
      const original = storage.list.bind(storage);
      const calls: (DurableObjectListOptions | undefined)[] = [];
      (storage as unknown as { list: unknown }).list = (
        options?: DurableObjectListOptions,
      ) => {
        calls.push(options);
        return original(options);
      };
      try {
        await object.alarm();
      } finally {
        (storage as unknown as { list: unknown }).list = original;
      }
      return {
        calls,
        keys: [...(await state.storage.list()).keys()],
        alarm: await state.storage.getAlarm(),
      };
    });
    // Three pages of c: rows, one of f: rows.
    expect(result.calls.length).toBeGreaterThanOrEqual(4);
    for (const options of result.calls) {
      expect(typeof options?.limit).toBe("number");
      expect(options!.limit!).toBeLessThanOrEqual(512);
    }
    expect(result.keys).toEqual([`c:${"f".repeat(32)}`]);
    expect(result.alarm).toBe(now - 1_000 + HORIZON_MS);
  });

  it("re-arms instead of throwing when the sweep fails", async () => {
    const device = freshDevice();
    const now = Date.now();
    const result = await inObject(device, async (object, state) => {
      await state.storage.put("quota", {
        period: periodKey(now, QUOTA),
        forwards: 3,
        digestAt: 0,
      } satisfies QuotaState);
      const storage = state.storage;
      const original = storage.list.bind(storage);
      (storage as unknown as { list: unknown }).list = () =>
        Promise.reject(new Error("storage unavailable"));
      let threw = false;
      try {
        await object.alarm();
      } catch {
        threw = true;
      } finally {
        (storage as unknown as { list: unknown }).list = original;
      }
      return { threw, alarm: await state.storage.getAlarm() };
    });
    expect(result.threw).toBe(false);
    expect(result.alarm).not.toBeNull();
    expect(result.alarm!).toBeGreaterThan(now);
    expect(result.alarm!).toBeLessThanOrEqual(Date.now() + 15 * 60_000);
  });
});
