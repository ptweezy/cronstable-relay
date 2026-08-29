/**
 * The monthly quota end to end, in the "quota" vitest project alone
 * (vitest.config.mts): two free forwards per period, a two-second
 * digest interval, six-second periods.  Each period-sensitive case
 * first waits for a fresh period so its posts never straddle a
 * rollover.
 */

import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { digestPayload } from "../src/apns";
import type { DeviceState } from "../src/device";

import {
  apnsRequests,
  expectApns,
  expectNoPendingApns,
  installApnsMock,
  PROD,
  resetApnsMock,
} from "./apns-mock";
import { signTransaction, transaction } from "./appstore-fixture";

beforeEach(() => {
  resetApnsMock();
  installApnsMock();
});

afterEach(() => {
  expectNoPendingApns();
});

const PERIOD_MS = Number(env.RELAY_QUOTA_PERIOD_S) * 1000;

let deviceCounter = 0x2000;

function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

function randCollapse(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function envelope(device: string): Record<string, unknown> {
  return {
    v: 1,
    device,
    ciphertext: "A".repeat(96),
    collapseId: randCollapse(),
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

async function outcome(device: string): Promise<unknown> {
  return (await post("/", envelope(device))).json();
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Wait until just after the next period boundary. */
async function freshPeriod(): Promise<void> {
  await sleep(PERIOD_MS - (Date.now() % PERIOD_MS) + 100);
}

const FORWARDED = { v: 1, outcome: "forwarded" };
const DIGESTED = { v: 1, outcome: "digested" };

describe("monthly quota", () => {
  it("digests past the bound: one passive digest push per interval", async () => {
    await freshPeriod();
    const device = freshDevice();
    for (let i = 0; i < 2; i += 1) {
      expectApns(PROD, 200);
      expect(await outcome(device)).toEqual(FORWARDED);
    }
    expect(await quota(device)).toEqual({ used: 2, limit: 2 });

    // Third alert: digested, and the one digest push goes out.
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(DIGESTED);
    expect(apnsRequests()).toHaveLength(3);
    const digest = apnsRequests()[2]!;
    expect(digest.path).toBe(`/3/device/${device}`);
    expect(digest.headers["apns-priority"]).toBe("5");
    expect(digest.headers["apns-collapse-id"]).toBe("digest");
    expect(digest.headers["apns-push-type"]).toBe("alert");
    expect(JSON.parse(digest.body)).toEqual({
      aps: {
        alert: {
          title: "cronstable",
          body: "Alerts are waiting. Open the app to see them.",
        },
        "interruption-level": "passive",
      },
      v: 1,
      kind: "digest",
    });
    expect(JSON.parse(digest.body)).toEqual(digestPayload());

    // Fourth, inside the digest interval: digested, nothing sent.
    expect(await outcome(device)).toEqual(DIGESTED);
    expect(apnsRequests()).toHaveLength(3);
    // Digests do not count as forwards.
    expect(await quota(device)).toEqual({ used: 2, limit: 2 });

    // Past the interval: another digest.
    await sleep(2_100);
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(DIGESTED);
    expect(apnsRequests()).toHaveLength(4);
    expect(apnsRequests()[3]!.headers["apns-collapse-id"]).toBe("digest");
  }, 20_000);

  it("keeps digesting when APNs refuses the digest, unless the token is dead", async () => {
    await freshPeriod();
    const device = freshDevice();
    for (let i = 0; i < 2; i += 1) {
      expectApns(PROD, 200);
      expect(await outcome(device)).toEqual(FORWARDED);
    }
    expectApns(PROD, 500, JSON.stringify({ reason: "InternalServerError" }));
    expect(await outcome(device)).toEqual(DIGESTED);
    // The digest interval is spent either way; a fresh one next.
    await sleep(2_100);
    expectApns(PROD, 410, JSON.stringify({ reason: "Unregistered" }));
    const dead = await post("/", envelope(device));
    expect(dead.status).toBe(410);
  }, 20_000);

  it("never digests an entitled device", async () => {
    const device = freshDevice();
    const lifted = await post("/entitlement", {
      v: 1,
      device,
      jws: await signTransaction(transaction()),
    });
    expect(lifted.status).toBe(200);
    for (let i = 0; i < 4; i += 1) {
      expectApns(PROD, 200);
      expect(await outcome(device)).toEqual(FORWARDED);
    }
    expect(await quota(device)).toEqual({ used: 4, limit: null });
  });

  it("does not spend quota on a forward APNs refused", async () => {
    await freshPeriod();
    const device = freshDevice();
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(FORWARDED);
    expectApns(PROD, 500, JSON.stringify({ reason: "InternalServerError" }));
    expect((await post("/", envelope(device))).status).toBe(502);
    expect(await quota(device)).toEqual({ used: 1, limit: 2 });
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(FORWARDED);
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(DIGESTED);
  }, 20_000);

  it("rolls the count over at the period boundary", async () => {
    await freshPeriod();
    const device = freshDevice();
    for (let i = 0; i < 2; i += 1) {
      expectApns(PROD, 200);
      expect(await outcome(device)).toEqual(FORWARDED);
    }
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(DIGESTED);
    await freshPeriod();
    expect(await quota(device)).toEqual({ used: 0, limit: 2 });
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(FORWARDED);
  }, 20_000);

  it("sweeps idle delivery state but keeps a live quota and entitlement", async () => {
    await freshPeriod();
    const device = freshDevice();
    expectApns(PROD, 200);
    expect(await outcome(device)).toEqual(FORWARDED);
    const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
    const now = Date.now();
    await runInDurableObject(stub, async (instance, state) => {
      const device = instance as unknown as DeviceState;
      // Age every collapse row past the sweep horizon; add a live
      // entitlement and an expired one on another key to contrast.
      const rows = await state.storage.list<{ lastSeenAt: number }>({
        prefix: "c:",
      });
      for (const [key, row] of rows) {
        await state.storage.put(key, { ...row, lastSeenAt: 0 });
      }
      await state.storage.put("entitlement", {
        originalTransactionId: "x",
        productId: "p",
        expiresAt: now + 60_000,
        environment: "Production",
        verifiedAt: now,
      });
      await device.alarm();
      const keys = [...(await state.storage.list()).keys()];
      expect(keys.sort()).toEqual(["entitlement", "quota"]);
      expect(await state.storage.getAlarm()).not.toBeNull();

      // With the entitlement lapsed and the quota in a past period,
      // nothing is live and the object empties itself.
      await state.storage.put("entitlement", {
        originalTransactionId: "x",
        productId: "p",
        expiresAt: now - 1,
        environment: "Production",
        verifiedAt: now,
      });
      await state.storage.put("quota", {
        period: "old",
        forwards: 2,
        digestAt: 0,
      });
      await device.alarm();
      expect((await state.storage.list()).size).toBe(0);
    });
  }, 20_000);
});
