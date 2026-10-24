/**
 * APNs failures end to end, in the "relay" project: the deadline on one
 * send (RELAY_APNS_TIMEOUT_S, two seconds here), its one retry of a
 * transient failure, the rollback of a refused forward, the digest a
 * failed send still owes, and what a dead token (410) leaves behind.
 * The APNs stub (tests/apns-mock.ts) honors each request's signal, so
 * the deadline runs on real timers.
 */

import { env, exports } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { DeviceState } from "../src/device";
import type { CollapseState } from "../src/policy";
import {
  periodKey,
  quotaFromEnv,
  type BurstState,
  type EntitlementRecord,
  type QuotaState,
} from "../src/quota";

import {
  apnsRequests,
  expectApns,
  expectApnsError,
  expectApnsHang,
  expectNoPendingApns,
  installApnsMock,
  PROD,
  resetApnsMock,
  SANDBOX,
} from "./apns-mock";

beforeEach(() => {
  resetApnsMock();
  installApnsMock();
});

afterEach(() => {
  expectNoPendingApns();
});

const BUDGET_MS = Number(env.RELAY_APNS_TIMEOUT_S) * 1000;
const QUOTA = quotaFromEnv(env);
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

let deviceCounter = 0x5000;

function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

function randHex(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function envelope(device: string): Record<string, unknown> {
  return {
    v: 1,
    device,
    ciphertext: "A".repeat(96),
    collapseId: randHex(),
    priority: "time-sensitive",
    event: false,
  };
}

async function post(path: string, body: unknown): Promise<Response> {
  return exports.default.fetch(`https://relay.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** "<status> <outcome or error>" for one envelope. */
async function answer(body: unknown): Promise<string> {
  const res = await post("/", body);
  const json = (await res.json()) as { outcome?: string; error?: string };
  return `${res.status} ${json.outcome ?? json.error}`;
}

/** The device's used/limit as POST /entitlement reports them. */
async function quota(
  device: string,
): Promise<{ used: number; limit: number | null }> {
  const res = await post("/entitlement", { v: 1, device });
  const body = (await res.json()) as {
    quota: { used: number; limit: number | null };
  };
  return { used: body.quota.used, limit: body.quota.limit };
}

function inObject<T>(
  device: string,
  fn: (object: DeviceState, state: DurableObjectState) => Promise<T>,
): Promise<T> {
  const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
  return runInDurableObject(stub, (instance, state) =>
    fn(instance as unknown as DeviceState, state),
  );
}

function stored<T>(device: string, key: string): Promise<T | undefined> {
  return inObject(device, (_o, state) => state.storage.get<T>(key));
}

/** Everything the device's object holds, and its alarm. */
function contents(
  device: string,
): Promise<{ keys: string[]; alarm: number | null }> {
  return inObject(device, async (_o, state) => ({
    keys: [...(await state.storage.list()).keys()].sort(),
    alarm: await state.storage.getAlarm(),
  }));
}

const reason = (name: string) => JSON.stringify({ reason: name });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** An entitlement that lifts the quota for the next hour. */
function liveEntitlement(now: number): EntitlementRecord {
  return {
    originalTransactionId: "2000000955500001",
    productId: "com.cronstable.app.pro.monthly",
    expiresAt: now + HOUR_MS,
    environment: "Production",
    verifiedAt: now,
    slotExpiresAt: now + HOUR_MS,
  };
}

/** A free device at its monthly bound, so its next envelope is digested. */
function atTheBound(now: number): QuotaState {
  return {
    period: periodKey(now, QUOTA),
    forwards: QUOTA.freeMonthlyForwards,
    freeForwards: QUOTA.freeMonthlyForwards,
    digestAt: 0,
  };
}

/** Last period's row, at its bound and owing a digest that is due, so
 * the alarm sends it and this period's next envelope forwards. */
function owedFromLastPeriod(now: number): QuotaState {
  return {
    period: periodKey(now - 40 * DAY_MS, QUOTA),
    forwards: QUOTA.freeMonthlyForwards,
    digestAt: now - QUOTA.digestIntervalMs - 1_000,
    digestPending: true,
  };
}

describe("the APNs deadline", () => {
  it("answers a bounded 502 when APNs never answers, and rolls the forward back", async () => {
    const device = freshDevice();
    const body = envelope(device);
    expectApnsHang(PROD);
    expectApnsHang(PROD);
    const started = Date.now();
    const res = await post("/", body);
    const elapsed = Date.now() - started;
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ v: 1, error: "APNs unreachable" });
    // Each attempt was cut off by its signal, and both fit the budget.
    expect(elapsed).toBeGreaterThanOrEqual(BUDGET_MS / 2);
    expect(elapsed).toBeLessThan(BUDGET_MS + 1_000);
    expect(apnsRequests().map((r) => r.origin)).toEqual([PROD, PROD]);
    expect(apnsRequests().map((r) => r.aborted)).toEqual([true, true]);

    // Rolled back: no quota spent, no quota row on the fresh object, and
    // no forward on the collapse row.
    expect(await quota(device)).toEqual({ used: 0, limit: 500 });
    expect(await stored(device, "quota")).toBeUndefined();
    const row = (await stored<CollapseState>(
      device,
      `c:${body.collapseId as string}`,
    ))!;
    expect(row.forwards).toEqual([]);
    expect(row.lastForwardAt).toBe(0);

    // A later copy of the same alert gets a fresh attempt.
    expectApns(PROD, 200);
    expect(await answer(body)).toBe("202 forwarded");
  }, 15_000);

  it("cuts a stalled attempt at half the budget, leaving room for the retry", async () => {
    const device = freshDevice();
    expectApnsHang(PROD);
    expectApns(PROD, 200);
    const started = Date.now();
    expect(await answer(envelope(device))).toBe("202 forwarded");
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(BUDGET_MS / 2);
    expect(elapsed).toBeLessThan(BUDGET_MS);
    expect(apnsRequests().map((r) => r.aborted)).toEqual([true, false]);
    expect(await quota(device)).toEqual({ used: 1, limit: 500 });
  }, 15_000);

  it("keeps both auto-mode legs inside one budget", async () => {
    const device = freshDevice();
    // Production answers late that the token is not its own; the sandbox
    // leg gets what is left of the budget and no retry after it.
    expectApns(PROD, 400, reason("BadDeviceToken"), {
      delayMs: BUDGET_MS * 0.45,
    });
    expectApnsHang(SANDBOX);
    const started = Date.now();
    expect(await answer(envelope(device))).toBe("502 APNs unreachable");
    expect(Date.now() - started).toBeLessThan(BUDGET_MS + 1_000);
    expect(apnsRequests().map((r) => r.origin)).toEqual([PROD, SANDBOX]);
  }, 15_000);
});

describe("the transient retry", () => {
  for (const [status, name] of [
    [500, "InternalServerError"],
    [503, "ServiceUnavailable"],
  ] as const) {
    it(`retries a ${status} once and delivers`, async () => {
      const device = freshDevice();
      const body = envelope(device);
      expectApns(PROD, status, reason(name));
      expectApns(PROD, 200);
      expect(await answer(body)).toBe("202 forwarded");
      const requests = apnsRequests();
      expect(requests.map((r) => r.origin)).toEqual([PROD, PROD]);
      expect(requests.map((r) => r.signalled)).toEqual([true, true]);
      // The retry is the same push under the same collapse id, so a copy
      // APNs had already accepted is replaced on the phone.
      expect(requests[1]!.headers["apns-collapse-id"]).toBe(body.collapseId);
      expect(requests[1]!.body).toBe(requests[0]!.body);
      expect(await quota(device)).toEqual({ used: 1, limit: 500 });
    });
  }

  it("retries a dropped connection once and delivers", async () => {
    const device = freshDevice();
    expectApnsError(PROD);
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect(apnsRequests()).toHaveLength(2);
    expect(await quota(device)).toEqual({ used: 1, limit: 500 });
  });

  it("gives up after one retry", async () => {
    expectApnsError(PROD);
    expectApnsError(PROD);
    expect(await answer(envelope(freshDevice()))).toBe(
      "502 APNs unreachable",
    );
    expect(apnsRequests()).toHaveLength(2);
  });

  it("never retries a 400, 403, 410, or 429", async () => {
    const cases = [
      { status: 400, name: "PayloadTooLarge", answer: 502 },
      { status: 403, name: "InvalidProviderToken", answer: 502 },
      { status: 410, name: "Unregistered", answer: 410 },
      { status: 429, name: "TooManyRequests", answer: 429 },
    ];
    for (const c of cases) {
      const seen = apnsRequests().length;
      expectApns(PROD, c.status, reason(c.name));
      const res = await post("/", envelope(freshDevice()));
      expect(res.status, c.name).toBe(c.answer);
      expect(apnsRequests().length - seen, c.name).toBe(1);
    }
  });

  it("retries once per send, not once per environment", async () => {
    // Production fails, its retry hops to sandbox, and sandbox's own
    // failure gets no second retry, so the send makes three attempts,
    // not four.
    expectApns(PROD, 500, reason("InternalServerError"));
    expectApns(PROD, 400, reason("BadDeviceToken"));
    expectApns(SANDBOX, 500, reason("InternalServerError"));
    const res = await post("/", envelope(freshDevice()));
    expect(res.status).toBe(502);
    expect(await res.json()).toMatchObject({ apnsStatus: 500 });
    expect(apnsRequests().map((r) => r.origin)).toEqual([
      PROD,
      PROD,
      SANDBOX,
    ]);
  });

  it("retries on the environment the token turned out to belong to", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, reason("BadDeviceToken"));
    expectApns(SANDBOX, 503, reason("ServiceUnavailable"));
    expectApns(SANDBOX, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect(apnsRequests().map((r) => r.origin)).toEqual([
      PROD,
      SANDBOX,
      SANDBOX,
    ]);
    expect(await stored(device, "apnsEnv")).toBe("sandbox");
  });

  it("retries a digest too", async () => {
    const device = freshDevice();
    await inObject(device, (_o, state) =>
      state.storage.put("quota", atTheBound(Date.now())),
    );
    expectApns(PROD, 500, reason("InternalServerError"));
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 digested");
    expect(apnsRequests().map((r) => r.headers["apns-collapse-id"])).toEqual([
      "digest",
      "digest",
    ]);
  });
});

describe("a refused forward's rollback", () => {
  it("leaves no quota row on a fresh object", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, reason("PayloadTooLarge"));
    expect(await answer(envelope(device))).toBe("502 APNs error");
    expect(await stored(device, "quota")).toBeUndefined();
  });

  it("puts back the stored quota row exactly", async () => {
    const now = Date.now();
    const rows: QuotaState[] = [
      // A row written before freeForwards existed.
      { period: periodKey(now, QUOTA), forwards: 3, digestAt: 0 },
      // A past period's row that still owes its digest.
      {
        period: "2000-01",
        forwards: QUOTA.freeMonthlyForwards,
        digestAt: now - 60_000,
        digestPending: true,
      },
    ];
    for (const row of rows) {
      const device = freshDevice();
      await inObject(device, (_o, state) => state.storage.put("quota", row));
      expectApns(PROD, 400, reason("PayloadTooLarge"));
      expect(await answer(envelope(device))).toBe("502 APNs error");
      expect(await stored(device, "quota")).toStrictEqual(row);
    }
  });

  it("keeps a sibling's forward that lands while the failed send waits", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, reason("PayloadTooLarge"), {
      delayMs: BUDGET_MS * 0.4,
    });
    expectApns(PROD, 200);
    const first = post("/", envelope(device));
    await sleep(BUDGET_MS * 0.1);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect((await first).status).toBe(502);
    expect(await stored(device, "quota")).toMatchObject({
      forwards: 1,
      freeForwards: 1,
    });
  });

  it("keeps a lifted device's free count when a sibling lands while the failed send waits", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, (_o, state) =>
      state.storage.put({
        entitlement: liveEntitlement(now),
        quota: {
          period: periodKey(now, QUOTA),
          forwards: 4,
          freeForwards: 1,
          digestAt: 0,
        } satisfies QuotaState,
      }),
    );
    expectApns(PROD, 400, reason("PayloadTooLarge"), {
      delayMs: BUDGET_MS * 0.4,
    });
    expectApns(PROD, 200);
    const first = post("/", envelope(device));
    await sleep(BUDGET_MS * 0.1);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect((await first).status).toBe(502);
    // The sibling's count sits on top, so the rollback uncounts the
    // failed forward from the total alone: neither one counted toward
    // the free bound.
    expect(await stored(device, "quota")).toMatchObject({
      forwards: 5,
      freeForwards: 1,
    });
  });

  it("leaves no quota row when two overlapping forwards both fail", async () => {
    const device = freshDevice();
    // The first send fails while the second's count sits on top of its
    // own, and the second fails after it.
    expectApns(PROD, 400, reason("PayloadTooLarge"), {
      delayMs: BUDGET_MS * 0.2,
    });
    expectApns(PROD, 400, reason("PayloadTooLarge"), {
      delayMs: BUDGET_MS * 0.4,
    });
    const first = post("/", envelope(device));
    await sleep(BUDGET_MS * 0.05);
    const second = post("/", envelope(device));
    expect((await first).status).toBe(502);
    expect((await second).status).toBe(502);
    expect(await stored(device, "quota")).toBeUndefined();
  });
});

describe("an owed digest whose send fails", () => {
  it("stays owed when a new period's first forward lands while the alarm's send fails", async () => {
    const device = freshDevice();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", owedFromLastPeriod(Date.now()));
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    // The alarm's digest meets a slow 503, a forward starts the new
    // period's row meanwhile, and the digest's retry fails too.  The new
    // row sent no digest, so the old period's digest is still owed.
    expectApns(PROD, 503, reason("ServiceUnavailable"), {
      delayMs: BUDGET_MS * 0.3,
    });
    expectApns(PROD, 200);
    expectApns(PROD, 503, reason("ServiceUnavailable"));
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    const alarm = runDurableObjectAlarm(stub);
    await sleep(BUDGET_MS * 0.1);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect(await alarm).toBe(true);
    const owed = (await stored<QuotaState>(device, "quota"))!;
    expect(owed).toMatchObject({
      period: periodKey(Date.now(), QUOTA),
      forwards: 1,
      freeForwards: 1,
      digestPending: true,
    });
    const dueAt = owed.digestAt + QUOTA.digestIntervalMs;
    expect((await contents(device)).alarm).toBe(dueAt);

    // Once the backoff ends, the alarm sends it and keeps the new
    // period's count.
    await inObject(device, (_o, state) =>
      state.storage.put("quota", {
        ...owed,
        digestAt: Date.now() - QUOTA.digestIntervalMs,
      }),
    );
    expectApns(PROD, 200);
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    const digests = apnsRequests().filter(
      (r) => r.headers["apns-collapse-id"] === "digest",
    );
    expect(digests).toHaveLength(3);
    const settled = (await stored<QuotaState>(device, "quota"))!;
    expect(settled.digestPending).toBeUndefined();
    expect(settled).toMatchObject({ forwards: 1, freeForwards: 1 });
  });
});

describe("a dead token", () => {
  it("empties the object when APNs rejects the token in both environments", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, reason("BadDeviceToken"));
    expectApns(SANDBOX, 400, reason("BadDeviceToken"));
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("empties the object an Unregistered token used to deliver to", async () => {
    const device = freshDevice();
    expectApns(PROD, 200);
    expect(await answer(envelope(device))).toBe("202 forwarded");
    expect((await contents(device)).keys).toContain("quota");
    expectApns(PROD, 410, reason("Unregistered"));
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("keeps an entitlement that lifts the quota, and rolls back as usual", async () => {
    const device = freshDevice();
    const now = Date.now();
    const entitlement = liveEntitlement(now);
    const seeded: QuotaState = {
      period: periodKey(now, QUOTA),
      forwards: 4,
      freeForwards: 0,
      digestAt: 0,
    };
    await inObject(device, (_o, state) =>
      state.storage.put({ entitlement, quota: seeded }),
    );
    const body = envelope(device);
    expectApns(PROD, 410, reason("Unregistered"));
    expect((await post("/", body)).status).toBe(410);
    expect(await stored(device, "entitlement")).toEqual(entitlement);
    expect(await stored(device, "quota")).toStrictEqual(seeded);
    const row = (await stored<CollapseState>(
      device,
      `c:${body.collapseId as string}`,
    ))!;
    expect(row.forwards).toEqual([]);
    expect((await contents(device)).alarm).not.toBeNull();
  });

  it("empties the object when its entitlement no longer lifts the quota", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, (_o, state) =>
      state.storage.put("entitlement", {
        ...liveEntitlement(now - 2 * HOUR_MS),
        slotExpiresAt: now - 1,
      }),
    );
    expectApns(PROD, 410, reason("Unregistered"));
    expect((await post("/", envelope(device))).status).toBe(410);
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("empties the object when the quota digest meets a 410", async () => {
    const device = freshDevice();
    await inObject(device, (_o, state) =>
      state.storage.put("quota", atTheBound(Date.now())),
    );
    expectApns(PROD, 410, reason("Unregistered"));
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(apnsRequests()[0]!.headers["apns-collapse-id"]).toBe("digest");
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("empties the object when the burst digest meets a 410", async () => {
    const device = freshDevice();
    // A bucket stamped a minute ahead refills nothing until then.
    await inObject(device, (_o, state) =>
      state.storage.put("bucket", { tokens: 0, ts: Date.now() + 60_000 }),
    );
    expectApns(PROD, 410, reason("Unregistered"));
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("empties the object when the alarm's digest meets a 410", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", {
        ...atTheBound(now),
        digestAt: now - QUOTA.digestIntervalMs,
        digestPending: true,
      } satisfies QuotaState);
      await state.storage.setAlarm(now + 60_000);
    });
    expectApns(PROD, 410, reason("Unregistered"));
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(apnsRequests()).toHaveLength(1);
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("stays empty when a sibling's 410 lands while the alarm's quota digest fails", async () => {
    const device = freshDevice();
    await inObject(device, async (_o, state) => {
      await state.storage.put("quota", owedFromLastPeriod(Date.now()));
      await state.storage.setAlarm(Date.now() + 60_000);
    });
    // As below, with the quota trigger: the sibling lands in the new
    // period, so it forwards and learns that the token is dead.
    expectApns(PROD, 503, reason("ServiceUnavailable"), {
      delayMs: BUDGET_MS * 0.3,
    });
    expectApns(PROD, 410, reason("Unregistered"));
    expectApns(PROD, 503, reason("ServiceUnavailable"));
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    const alarm = runDurableObjectAlarm(stub);
    await sleep(BUDGET_MS * 0.1);
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(await alarm).toBe(true);
    expect(apnsRequests()).toHaveLength(3);
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("stays empty when a sibling's 410 lands while the alarm's digest fails", async () => {
    const device = freshDevice();
    const now = Date.now();
    await inObject(device, async (_o, state) => {
      await state.storage.put("burst", {
        digestAt: now - 3_600_000,
        pendingSince: now - 1_000,
        timeSensitive: true,
      } satisfies BurstState);
      await state.storage.setAlarm(now + 60_000);
    });
    // The alarm's digest meets a slow 503, a forward to the same token
    // learns meanwhile that the token is dead, and the digest's retry
    // fails too.  The dead token already settled the owed digest.
    expectApns(PROD, 503, reason("ServiceUnavailable"), {
      delayMs: BUDGET_MS * 0.3,
    });
    expectApns(PROD, 410, reason("Unregistered"));
    expectApns(PROD, 503, reason("ServiceUnavailable"));
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    const alarm = runDurableObjectAlarm(stub);
    await sleep(BUDGET_MS * 0.1);
    expect(await answer(envelope(device))).toBe(
      "410 device token rejected by APNs",
    );
    expect(await alarm).toBe(true);
    expect(apnsRequests()).toHaveLength(3);
    expect(await contents(device)).toEqual({ keys: [], alarm: null });
  });

  it("keeps an entitled device when the alarm's digest meets a 410", async () => {
    const device = freshDevice();
    const now = Date.now();
    const entitlement = liveEntitlement(now);
    await inObject(device, async (_o, state) => {
      await state.storage.put({
        entitlement,
        burst: {
          digestAt: now - 3_600_000,
          pendingSince: now - 1_000,
          timeSensitive: true,
        } satisfies BurstState,
      });
      await state.storage.setAlarm(now + 60_000);
    });
    expectApns(PROD, 410, reason("Unregistered"));
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(await stored(device, "entitlement")).toEqual(entitlement);
    expect((await stored<BurstState>(device, "burst"))!.pendingSince).toBe(0);
    expect((await contents(device)).alarm).not.toBeNull();
  });
});
