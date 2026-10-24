/**
 * Entitlement proof: the offline StoreKit verifier against a real
 * three-certificate chain (tests/fixtures/appstore), and the
 * POST /entitlement route in front of it: the grace past expiry, the
 * per-transaction cap and its slot lapse, and revocations.  The relay
 * trusts the test root via RELAY_APPLE_ROOT_CERT; the pinned Apple root
 * is checked by fingerprint.
 */

import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  APPLE_ROOT_CA_G3_B64,
  CLOCK_SKEW_MS,
  entitlementPolicyFromEnv,
  verifyTransaction,
  type VerifyOptions,
} from "../src/appstore";
import type { DeviceState } from "../src/device";
import type { EntitlementState, RevocationMark } from "../src/entitlement";
import { MAX_ENTITLEMENT_BODY_BYTES } from "../src/index";
import { DEFAULT_PRO_GRACE_MS, type EntitlementRecord } from "../src/quota";

import {
  expectNoPendingApns,
  installApnsMock,
  resetApnsMock,
} from "./apns-mock";
import {
  PRO_MONTHLY,
  PRO_YEARLY,
  signTransaction,
  transaction,
} from "./appstore-fixture";

beforeEach(() => {
  resetApnsMock();
  installApnsMock();
});

afterEach(() => {
  expectNoPendingApns();
});

const APPLE_ROOT_SHA256 =
  "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179";

function b64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function options(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { ...entitlementPolicyFromEnv(env), now: Date.now(), ...overrides };
}

async function verify(
  payload: Record<string, unknown>,
  sign: Parameters<typeof signTransaction>[1] = {},
  opts: Partial<VerifyOptions> = {},
) {
  return verifyTransaction(await signTransaction(payload, sign), options(opts));
}

function reasonOf(result: Awaited<ReturnType<typeof verify>>): string {
  if (result.ok) throw new Error("expected a failure");
  return result.reason;
}

let deviceCounter = 0x1000;

function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

async function post(body: unknown, init: RequestInit = {}): Promise<Response> {
  return exports.default.fetch("https://relay.test/entitlement", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
    ...init,
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const DAY_MS = 86_400_000;

/** The lapsed fixture leaf's window (scripts/gen-appstore-fixtures.sh). */
const LAPSED_NOT_BEFORE = Date.UTC(2023, 8, 12);
const LAPSED_NOT_AFTER = Date.UTC(2025, 9, 11);

const lapsedLeaf = () => ({
  leaf: env.TEST_APPSTORE_LEAF_LAPSED,
  leafKey: env.TEST_APPSTORE_LEAF_LAPSED_KEY,
});

async function planOf(device: string): Promise<string> {
  const res = await post({ v: 1, device });
  expect(res.status).toBe(200);
  return ((await res.json()) as { plan: string }).plan;
}

function deviceStub(device: string) {
  return env.DEVICE.get(env.DEVICE.idFromName(device));
}

function transactionStub(originalTransactionId: string) {
  return env.ENTITLEMENT.get(env.ENTITLEMENT.idFromName(originalTransactionId));
}

async function storedEntitlement(
  device: string,
): Promise<EntitlementRecord | undefined> {
  return runInDurableObject(deviceStub(device), (_instance, state) =>
    state.storage.get<EntitlementRecord>("entitlement"),
  );
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Counts the writes a Durable Object makes through `state.storage`. */
function countWrites(state: DurableObjectState): { count: number } {
  const counter = { count: 0 };
  const storage = state.storage as unknown as Record<string, unknown>;
  for (const method of ["put", "delete", "deleteAll", "setAlarm"]) {
    const real = (storage[method] as (...args: unknown[]) => unknown).bind(
      state.storage,
    );
    storage[method] = (...args: unknown[]) => {
      counter.count += 1;
      return real(...args);
    };
  }
  return counter;
}

describe("the pinned Apple root", () => {
  it("is Apple Root CA G3 by SHA-256 fingerprint", async () => {
    const der = b64(APPLE_ROOT_CA_G3_B64);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
    const hex = [...digest]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(APPLE_ROOT_SHA256);
  });

  it("is the default trust anchor, and RELAY_APPLE_ROOT_CERT overrides it", () => {
    const pinned = entitlementPolicyFromEnv({}).rootDer;
    expect(pinned).toEqual(b64(APPLE_ROOT_CA_G3_B64));
    expect(entitlementPolicyFromEnv(env).rootDer).toEqual(
      b64(env.RELAY_APPLE_ROOT_CERT),
    );
    expect(entitlementPolicyFromEnv({}).productIds).toEqual(
      new Set([PRO_MONTHLY, PRO_YEARLY]),
    );
    expect(entitlementPolicyFromEnv({}).acceptSandbox).toBe(true);
    expect(
      entitlementPolicyFromEnv({ RELAY_ACCEPT_SANDBOX_ENTITLEMENTS: "false" })
        .acceptSandbox,
    ).toBe(false);
  });
});

describe("verifyTransaction", () => {
  it("accepts a monthly and a yearly Pro transaction", async () => {
    const payload = transaction();
    const monthly = await verify(payload);
    expect(monthly.ok).toBe(true);
    if (!monthly.ok) return;
    expect(monthly.transaction).toEqual({
      originalTransactionId: "2000000900000001",
      transactionId: "2000000900000001",
      productId: PRO_MONTHLY,
      purchaseDate: payload.purchaseDate,
      signedDate: payload.signedDate,
      expiresAt: payload.expiresDate,
      environment: "Production",
    });
    const yearly = await verify(transaction({ productId: PRO_YEARLY }));
    expect(yearly.ok).toBe(true);
  });

  it("treats a transaction without expiresDate as never expiring", async () => {
    const payload = transaction();
    delete payload.expiresDate;
    const result = await verify(payload);
    expect(result.ok && result.transaction.expiresAt).toBe(null);
  });

  it("rejects the wrong bundle", async () => {
    expect(
      reasonOf(await verify(transaction({ bundleId: "com.other.app" }))),
    ).toBe("bundle id mismatch");
  });

  it("rejects an unknown product", async () => {
    expect(
      reasonOf(
        await verify(transaction({ productId: "com.cronstable.app.tip" })),
      ),
    ).toBe("unknown product");
  });

  it("rejects a transaction expired past the grace", async () => {
    const now = Date.now();
    const grace = entitlementPolicyFromEnv(env).graceMs;
    expect(grace).toBe(DEFAULT_PRO_GRACE_MS);
    expect(
      reasonOf(
        await verify(transaction({ expiresDate: now - grace }), {}, { now }),
      ),
    ).toBe("expired");
  });

  it("accepts a transaction inside the grace past its expiry", async () => {
    // Billing grace: currentEntitlements still yields the latest
    // transaction, whose expiresDate has passed.
    const now = Date.now();
    const grace = entitlementPolicyFromEnv(env).graceMs;
    for (const expiresDate of [now - 3_600_000, now - grace + 1]) {
      const result = await verify(transaction({ expiresDate }), {}, { now });
      expect(result.ok && result.transaction.expiresAt).toBe(expiresDate);
    }
    expect(
      reasonOf(
        await verify(
          transaction({ expiresDate: now - 3_600_000 }),
          {},
          { now, graceMs: 0 },
        ),
      ),
    ).toBe("expired");
  });

  it("rejects a revoked transaction", async () => {
    expect(
      reasonOf(
        await verify(transaction({ revocationDate: Date.now() - 1000 })),
      ),
    ).toBe("revoked");
  });

  it("accepts Sandbox only while the relay is told to", async () => {
    const sandbox = transaction({ environment: "Sandbox" });
    const accepted = await verify(sandbox, {}, { acceptSandbox: true });
    expect(accepted.ok && accepted.transaction.environment).toBe("Sandbox");
    expect(reasonOf(await verify(sandbox, {}, { acceptSandbox: false }))).toBe(
      "sandbox transactions are refused",
    );
    expect(reasonOf(await verify(transaction({ environment: "Xcode" })))).toBe(
      "unknown environment",
    );
  });

  it("rejects a broken signature", async () => {
    expect(
      reasonOf(await verify(transaction(), { corruptSignature: true })),
    ).toBe("signature does not verify");
  });

  it("rejects a chain that does not end in the trusted root", async () => {
    expect(
      reasonOf(
        await verify(transaction(), { root: env.TEST_APPSTORE_OTHER_ROOT }),
      ),
    ).toBe("root is not Apple Root CA G3");
  });

  it("rejects a leaf without the in-app purchase marker", async () => {
    const result = await verify(transaction(), {
      leaf: env.TEST_APPSTORE_LEAF_NOMARKER,
      leafKey: env.TEST_APPSTORE_LEAF_NOMARKER_KEY,
    });
    expect(reasonOf(result)).toBe("leaf lacks the in-app purchase marker");
  });

  it("rejects a leaf outside its validity window at signedDate", async () => {
    const result = await verify(transaction({ signedDate: Date.now() }), {
      leaf: env.TEST_APPSTORE_LEAF_EXPIRED,
      leafKey: env.TEST_APPSTORE_LEAF_EXPIRED_KEY,
    });
    expect(reasonOf(result)).toBe(
      "leaf certificate is outside its validity window",
    );
  });

  it("rejects a leaf signed by a key the intermediate never certified", async () => {
    // The marker leaf's certificate with the no-marker leaf's key: the
    // chain is intact, the JWS signature is not.
    const result = await verify(transaction(), {
      leafKey: env.TEST_APPSTORE_LEAF_NOMARKER_KEY,
    });
    expect(reasonOf(result)).toBe("signature does not verify");
  });

  it("rejects a transaction with no originalTransactionId", async () => {
    expect(
      reasonOf(await verify(transaction({ originalTransactionId: "" }))),
    ).toBe("missing originalTransactionId");
  });

  it("flags structural problems as malformed", async () => {
    const malformed = async (jws: string) => {
      const result = await verifyTransaction(jws, options());
      expect(result.ok).toBe(false);
      return !result.ok && result.malformed;
    };
    expect(await malformed("not.a.jws.at.all")).toBe(true);
    expect(await malformed("eyJ.eyJ")).toBe(true);
    expect(
      await malformed(await signTransaction(transaction(), { alg: "HS256" })),
    ).toBe(true);
    expect(
      await malformed(
        await signTransaction(transaction(), { x5c: ["a", "b"] }),
      ),
    ).toBe(true);
    expect(
      await malformed(
        await signTransaction(transaction(), { x5c: ["AAAA", "AAAA", "AAAA"] }),
      ),
    ).toBe(true);
    // A well-formed JWS that fails to verify is not malformed.
    const wrongBundle = await verifyTransaction(
      await signTransaction(transaction({ bundleId: "x" })),
      options(),
    );
    expect(!wrongBundle.ok && wrongBundle.malformed).toBe(false);
  });
});

describe("certificate windows at signedDate", () => {
  /** A still-paid yearly transaction the lapsed leaf signed. */
  function lapsedYearly(signedDate: number): Record<string, unknown> {
    return transaction({
      productId: PRO_YEARLY,
      purchaseDate: signedDate,
      originalPurchaseDate: signedDate,
      expiresDate: Date.now() + 30 * DAY_MS,
      signedDate,
    });
  }

  it("accepts a transaction signed while its leaf, since rotated out, was valid", async () => {
    // The leaf's window ended before today, inside the CA's windows.
    expect(Date.now()).toBeGreaterThan(LAPSED_NOT_AFTER);
    const signedDate = Date.UTC(2025, 5, 1);
    const result = await verify(lapsedYearly(signedDate), lapsedLeaf());
    expect(result.ok).toBe(true);
    expect(result.ok && result.transaction.signedDate).toBe(signedDate);
  });

  it("allows Apple's 60 s skew at either edge of the leaf's window", async () => {
    for (const signedDate of [
      LAPSED_NOT_BEFORE - CLOCK_SKEW_MS,
      LAPSED_NOT_AFTER + CLOCK_SKEW_MS,
    ]) {
      expect((await verify(lapsedYearly(signedDate), lapsedLeaf())).ok).toBe(
        true,
      );
    }
    for (const signedDate of [
      LAPSED_NOT_BEFORE - CLOCK_SKEW_MS - 1000,
      LAPSED_NOT_AFTER + CLOCK_SKEW_MS + 1000,
    ]) {
      expect(
        reasonOf(await verify(lapsedYearly(signedDate), lapsedLeaf())),
      ).toBe("leaf certificate is outside its validity window");
    }
  });

  it("rejects a transaction signed after its leaf expired", async () => {
    const signedDate = LAPSED_NOT_AFTER + 4 * DAY_MS;
    expect(reasonOf(await verify(lapsedYearly(signedDate), lapsedLeaf()))).toBe(
      "leaf certificate is outside its validity window",
    );
  });

  it("judges the intermediate and the root at signedDate too", async () => {
    // leaf-expired's 2020 window predates the CA's, which begins in 2022.
    const signedDate = Date.UTC(2020, 5, 1);
    const result = await verify(lapsedYearly(signedDate), {
      leaf: env.TEST_APPSTORE_LEAF_EXPIRED,
      leafKey: env.TEST_APPSTORE_LEAF_EXPIRED_KEY,
    });
    expect(reasonOf(result)).toBe(
      "intermediate certificate is outside its validity window",
    );
  });

  it("requires signedDate to be a timestamp", async () => {
    const missing = transaction();
    delete missing.signedDate;
    expect(reasonOf(await verify(missing))).toBe(
      "signedDate is not a timestamp",
    );
    expect(
      reasonOf(await verify(transaction({ signedDate: "2026-01-01" }))),
    ).toBe("signedDate is not a timestamp");
  });

  it("rejects a signedDate past the relay's clock plus the skew", async () => {
    const now = Date.now();
    const ahead = await verify(
      transaction({ signedDate: now + CLOCK_SKEW_MS + 1 }),
      {},
      { now },
    );
    expect(reasonOf(ahead)).toBe("signedDate is in the future");
    const skewed = await verify(
      transaction({ signedDate: now + CLOCK_SKEW_MS }),
      {},
      { now },
    );
    expect(skewed.ok).toBe(true);
  });

  it("lifts a device through POST /entitlement with a lapsed-leaf proof", async () => {
    const device = freshDevice();
    const res = await post({
      v: 1,
      device,
      jws: await signTransaction(
        { ...lapsedYearly(Date.UTC(2025, 5, 1)), originalTransactionId: "2000000900000200" },
        lapsedLeaf(),
      ),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { plan: string }).plan).toBe("pro");
  });
});

describe("POST /entitlement", () => {
  it("answers 405 to anything but POST", async () => {
    const res = await exports.default.fetch("https://relay.test/entitlement");
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
  });

  it("reports the free plan and full quota for an unknown device", async () => {
    const res = await post({ v: 1, device: freshDevice() });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      v: 1,
      plan: "free",
      quota: { used: 0, limit: 500, resetsAt: expect.any(String) },
    });
    const resets = new Date(body.quota!["resetsAt" as never] as string);
    expect(resets.getUTCDate()).toBe(1);
    expect(resets.getTime()).toBeGreaterThan(Date.now());
  });

  it("400s malformed bodies", async () => {
    expect((await post("{nope")).status).toBe(400);
    expect((await post([1])).status).toBe(400);
    expect((await post({ v: 2, device: freshDevice() })).status).toBe(400);
    expect((await post({ v: 1, device: "zz" })).status).toBe(400);
    expect((await post({ v: 1, device: freshDevice(), jws: 7 })).status).toBe(
      400,
    );
    const malformed = await post({ v: 1, device: freshDevice(), jws: "a.b" });
    expect(malformed.status).toBe(400);
    expect(((await malformed.json()) as { reason: string }).reason).toMatch(
      /JWS/,
    );
  });

  it("413s a body over the entitlement limit", async () => {
    const jws = "A".repeat(MAX_ENTITLEMENT_BODY_BYTES);
    const res = await post({ v: 1, device: freshDevice(), jws });
    expect(res.status).toBe(413);
    // Declared length alone is enough to refuse.
    const declared = await post(
      { v: 1, device: freshDevice() },
      { headers: { "content-length": String(MAX_ENTITLEMENT_BODY_BYTES + 1) } },
    );
    expect(declared.status).toBe(413);
  });

  it("lifts a device to Pro on a valid proof, uppercase token included", async () => {
    const device = freshDevice();
    const expiresDate = Date.now() + 86_400_000;
    const jws = await signTransaction(transaction({ expiresDate }));
    const res = await post({ v: 1, device: device.toUpperCase(), jws });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      v: 1,
      plan: "pro",
      expiresAt: new Date(expiresDate).toISOString(),
      environment: "Production",
      quota: { used: 0, limit: null, resetsAt: expect.any(String) },
    });
    // The read-only status agrees.
    const status = await post({ v: 1, device });
    expect(((await status.json()) as { plan: string }).plan).toBe("pro");
  });

  it("reports null expiry for a proof without one", async () => {
    const payload = transaction({ originalTransactionId: "2000000900000002" });
    delete payload.expiresDate;
    const res = await post({
      v: 1,
      device: freshDevice(),
      jws: await signTransaction(payload),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { expiresAt: unknown }).expiresAt).toBe(null);
  });

  it("401s a rejected proof with the reason", async () => {
    const res = await post({
      v: 1,
      device: freshDevice(),
      jws: await signTransaction(transaction({ productId: "nope" })),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      v: 1,
      error: "entitlement rejected",
      reason: "unknown product",
    });
  });

  it("caps one transaction at five devices, refreshing known ones", async () => {
    const originalTransactionId = "2000000900000100";
    const proof = () => signTransaction(transaction({ originalTransactionId }));
    const devices = Array.from({ length: 6 }, freshDevice);
    for (const device of devices.slice(0, 5)) {
      expect((await post({ v: 1, device, jws: await proof() })).status).toBe(
        200,
      );
    }
    const sixth = await post({ v: 1, device: devices[5], jws: await proof() });
    expect(sixth.status).toBe(409);
    expect(await sixth.json()).toEqual({
      v: 1,
      error: "transaction device limit reached",
      limit: 5,
    });
    // An existing device re-posting keeps its slot.
    const again = await post({ v: 1, device: devices[0], jws: await proof() });
    expect(again.status).toBe(200);
    // Slots lapse after RELAY_PRO_DEVICE_SLOT_TTL_S (2 s here) of silence,
    // and a device whose slot lapsed is no longer lifted.
    await sleep(2_100);
    expect(await planOf(devices[1]!)).toBe("free");
    const later = await post({ v: 1, device: devices[5], jws: await proof() });
    expect(later.status).toBe(200);
    expect(await planOf(devices[5]!)).toBe("pro");
  }, 15_000);

  it("lifts a device on a proof inside the grace past its expiry", async () => {
    const device = freshDevice();
    const expiresDate = Date.now() - 3_600_000;
    const res = await post({
      v: 1,
      device,
      jws: await signTransaction(
        transaction({ originalTransactionId: "2000000900000300", expiresDate }),
      ),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      v: 1,
      plan: "pro",
      expiresAt: new Date(expiresDate).toISOString(),
      environment: "Production",
      quota: { used: 0, limit: null, resetsAt: expect.any(String) },
    });
    expect(await planOf(device)).toBe("pro");
  });

  it("keeps a stored entitlement through the grace, then drops it", async () => {
    const device = freshDevice();
    const now = Date.now();
    const record: EntitlementRecord = {
      originalTransactionId: "2000000900000301",
      productId: PRO_MONTHLY,
      expiresAt: now - 1000,
      environment: "Production",
      verifiedAt: now - 30 * DAY_MS,
      purchaseDate: now - 31 * DAY_MS,
      slotExpiresAt: now + 60_000,
    };
    await runInDurableObject(deviceStub(device), (_i, state) =>
      state.storage.put("entitlement", record),
    );
    // The renewal is not re-posted yet: the grace keeps the device Pro.
    expect(await planOf(device)).toBe("pro");
    await runInDurableObject(deviceStub(device), (_i, state) =>
      state.storage.put("entitlement", {
        ...record,
        expiresAt: now - DEFAULT_PRO_GRACE_MS - 1000,
      }),
    );
    expect(await planOf(device)).toBe("free");
  });

  it("stores the slot's expiry on the device record", async () => {
    const device = freshDevice();
    const originalTransactionId = "2000000900000400";
    const res = await post({
      v: 1,
      device,
      jws: await signTransaction(transaction({ originalTransactionId })),
    });
    expect(res.status).toBe(200);
    const slots = await runInDurableObject(
      transactionStub(originalTransactionId),
      (_i, state) => state.storage.get<Record<string, number>>("devices"),
    );
    const seenAt = slots![await sha256Hex(device)]!;
    const record = await storedEntitlement(device);
    expect(record?.slotExpiresAt).toBe(seenAt + 2_000);
    expect(record?.purchaseDate).toEqual(expect.any(Number));
  });
});

describe("per-transaction cap over time", () => {
  /** A yearly proof: expiry a year out, far past the slot TTL. */
  const yearlyProof = (originalTransactionId: string) =>
    signTransaction(
      transaction({
        originalTransactionId,
        transactionId: originalTransactionId,
        productId: PRO_YEARLY,
        expiresDate: Date.now() + 365 * DAY_MS,
      }),
    );

  it("never has more than five devices on Pro from one transaction", async () => {
    const otid = "2000000977700001";
    const devices = Array.from({ length: 10 }, freshDevice);
    for (const device of devices.slice(0, 5)) {
      const res = await post({ v: 1, device, jws: await yearlyProof(otid) });
      expect(res.status).toBe(200);
    }
    const sixth = await post({
      v: 1,
      device: devices[5],
      jws: await yearlyProof(otid),
    });
    expect(sixth.status).toBe(409);
    // The first five go silent past the slot TTL, and five new devices
    // take the freed slots.
    await sleep(2_100);
    for (const device of devices.slice(5)) {
      const res = await post({ v: 1, device, jws: await yearlyProof(otid) });
      expect(res.status).toBe(200);
    }
    const plans = await Promise.all(devices.map(planOf));
    expect(plans.filter((p) => p === "pro")).toHaveLength(5);
    expect(plans.slice(5)).toEqual(Array(5).fill("pro"));
  }, 20_000);

  it("forgets a silent device's entitlement record once its slot lapses", async () => {
    const device = freshDevice();
    const res = await post({
      v: 1,
      device,
      jws: await yearlyProof("2000000977700003"),
    });
    expect(res.status).toBe(200);
    await sleep(2_100);
    const keys = await runInDurableObject(
      deviceStub(device),
      async (instance, state) => {
        await (instance as unknown as DeviceState).alarm();
        return [...(await state.storage.list()).keys()];
      },
    );
    expect(keys).not.toContain("entitlement");
  }, 15_000);

  it("drops a lapsed entitlement while alerts keep the object busy", async () => {
    const device = freshDevice();
    const now = Date.now();
    const keys = await runInDurableObject(
      deviceStub(device),
      async (instance, state) => {
        await state.storage.put({
          [`c:${"ab".repeat(16)}`]: {
            lastSeenAt: now,
            forwards: [now],
            lastForwardAt: now,
          },
          entitlement: {
            originalTransactionId: "2000000977700004",
            productId: PRO_YEARLY,
            expiresAt: now + 300 * DAY_MS,
            environment: "Production",
            verifiedAt: now - 70 * DAY_MS,
          } satisfies EntitlementRecord,
        });
        await (instance as unknown as DeviceState).alarm();
        return [...(await state.storage.list()).keys()];
      },
    );
    expect(keys).toEqual([`c:${"ab".repeat(16)}`]);
  });
});

describe("unchanged re-posts", () => {
  it("write nothing to the slot or the device record", async () => {
    const device = freshDevice();
    const originalTransactionId = "2000000900000500";
    const jws = await signTransaction(transaction({ originalTransactionId }));
    expect((await post({ v: 1, device, jws })).status).toBe(200);
    const before = await storedEntitlement(device);
    const hash = await sha256Hex(device);

    // Straight at the objects, so the count is exact: a claim inside the
    // refresh window and the same record again cost no writes.
    const claimWrites = await runInDurableObject(
      transactionStub(originalTransactionId),
      async (instance, state) => {
        const writes = countWrites(state);
        const result = await (instance as unknown as EntitlementState).claim(
          hash,
          { purchaseDate: before!.purchaseDate ?? null, signedDate: Date.now() },
        );
        expect(result).toEqual({
          admitted: true,
          slotExpiresAt: before!.slotExpiresAt,
        });
        return writes.count;
      },
    );
    expect(claimWrites).toBe(0);
    const recordWrites = await runInDurableObject(
      deviceStub(device),
      async (instance, state) => {
        const writes = countWrites(state);
        await (instance as unknown as DeviceState).setEntitlement({
          ...before!,
          verifiedAt: Date.now(),
        });
        return writes.count;
      },
    );
    expect(recordWrites).toBe(0);

    // Through the route as well: the stored record keeps its verifiedAt.
    expect((await post({ v: 1, device, jws })).status).toBe(200);
    expect(await storedEntitlement(device)).toEqual(before);

    // Past the refresh window (a quarter of the 2 s TTL here) the slot
    // and the record move forward.
    await sleep(600);
    expect((await post({ v: 1, device, jws })).status).toBe(200);
    const after = await storedEntitlement(device);
    expect(after!.slotExpiresAt).toBeGreaterThan(before!.slotExpiresAt!);
    expect(after!.verifiedAt).toBeGreaterThan(before!.verifiedAt);
  }, 10_000);

  it("write nothing on a refused claim", async () => {
    const originalTransactionId = "2000000900000501";
    const proof = () => signTransaction(transaction({ originalTransactionId }));
    for (let i = 0; i < 5; i += 1) {
      expect(
        (await post({ v: 1, device: freshDevice(), jws: await proof() })).status,
      ).toBe(200);
    }
    const sixth = await sha256Hex(freshDevice());
    const writes = await runInDurableObject(
      transactionStub(originalTransactionId),
      async (instance, state) => {
        const writes = countWrites(state);
        const result = await (instance as unknown as EntitlementState).claim(
          sixth,
          { purchaseDate: null, signedDate: Date.now() },
        );
        expect(result).toEqual({ admitted: false, limit: 5 });
        return writes.count;
      },
    );
    expect(writes).toBe(0);
  });
});

describe("revocations", () => {
  const MINUTE = 60_000;

  /** One subscription purchase and the copies of it the App Store signs. */
  function purchase(originalTransactionId: string, purchaseDate: number) {
    const base = {
      transactionId: `${originalTransactionId}${purchaseDate}`,
      originalTransactionId,
      productId: PRO_YEARLY,
      purchaseDate,
      expiresDate: purchaseDate + 365 * DAY_MS,
    };
    return {
      expiresDate: base.expiresDate,
      signed: (signedDate: number, extra: Record<string, unknown> = {}) =>
        signTransaction(transaction({ ...base, signedDate, ...extra })),
      revoked: (signedDate: number, extra: Record<string, unknown> = {}) =>
        signTransaction(
          transaction({
            ...base,
            signedDate,
            revocationDate: signedDate - MINUTE,
            revocationReason: 0,
            ...extra,
          }),
        ),
    };
  }

  async function postStatus(device: string, jws: string): Promise<number> {
    return (await post({ v: 1, device, jws })).status;
  }

  async function transactionStorage(originalTransactionId: string) {
    return runInDurableObject(
      transactionStub(originalTransactionId),
      async (_i, state) => Object.fromEntries(await state.storage.list()),
    );
  }

  it("ends the lift of the device holding the revoked purchase", async () => {
    const now = Date.now();
    const otid = "2000000988800001";
    const bought = purchase(otid, now - 2 * DAY_MS);
    const preRefund = await bought.signed(now - 10 * MINUTE);
    const [device, sibling] = [freshDevice(), freshDevice()];
    expect(await postStatus(device, preRefund)).toBe(200);
    expect(await postStatus(sibling, preRefund)).toBe(200);
    expect(await planOf(device)).toBe("pro");

    const refund = await post({
      v: 1,
      device,
      jws: await bought.revoked(now - MINUTE),
    });
    expect(refund.status).toBe(401);
    expect(await refund.json()).toEqual({
      v: 1,
      error: "entitlement rejected",
      reason: "revoked",
    });
    expect(await storedEntitlement(device)).toBeUndefined();
    expect(await planOf(device)).toBe("free");
    // The transaction remembers the revocation until the revoked
    // purchase's expiry plus the grace.  Both slots stay: a slot lapses
    // with its TTL, never through a revocation, and the sibling's record
    // still lifts it.
    const storage = await transactionStorage(otid);
    expect(storage).toEqual({
      revoked: {
        signedDate: now - MINUTE,
        purchaseDate: now - 2 * DAY_MS,
        until: bought.expiresDate + DEFAULT_PRO_GRACE_MS,
      } satisfies RevocationMark,
      devices: {
        [await sha256Hex(device)]: expect.any(Number),
        [await sha256Hex(sibling)]: expect.any(Number),
      },
    });
    expect(await planOf(sibling)).toBe("pro");
  });

  it("refuses a replayed pre-refund copy afterwards, from any device", async () => {
    const now = Date.now();
    const otid = "2000000988800002";
    const bought = purchase(otid, now - 2 * DAY_MS);
    const preRefund = await bought.signed(now - 10 * MINUTE);
    const [refunded, sibling] = [freshDevice(), freshDevice()];
    expect(await postStatus(refunded, preRefund)).toBe(200);
    expect(await postStatus(sibling, preRefund)).toBe(200);
    expect(await postStatus(refunded, await bought.revoked(now - MINUTE))).toBe(
      401,
    );
    expect(await planOf(sibling)).toBe("pro");

    for (const device of [refunded, sibling]) {
      const replay = await post({ v: 1, device, jws: preRefund });
      expect(replay.status).toBe(401);
      expect(((await replay.json()) as { reason: string }).reason).toBe(
        "revoked",
      );
      expect(await planOf(device)).toBe("free");
    }
    // The refused replay cleared the sibling's record and left both
    // slots to lapse with their TTL.
    const slots = (await transactionStorage(otid)).devices as Record<
      string,
      number
    >;
    expect(Object.keys(slots).sort()).toEqual(
      [await sha256Hex(refunded), await sha256Hex(sibling)].sort(),
    );
    // A copy signed a moment before the revoked one is a replay too.
    expect(
      await postStatus(freshDevice(), await bought.signed(now - MINUTE - 1)),
    ).toBe(401);
  });

  it("holds the cap through re-posted revocations of an earlier period", async () => {
    const now = Date.now();
    const otid = "2000000988800010";
    // An earlier period that Apple refunded, and the current renewal on
    // the same subscription, which the revocation doesn't cover.
    const refunded = purchase(otid, now - 40 * DAY_MS);
    const current = purchase(otid, now - DAY_MS);
    const proof = await current.signed(now - MINUTE);
    const revokedCopy = await refunded.revoked(now - 2 * MINUTE);
    const devices = Array.from({ length: 10 }, freshDevice);
    for (const device of devices.slice(0, 5)) {
      expect(await postStatus(device, proof)).toBe(200);
    }
    // Anyone holding the revoked copy can post it, as often as they
    // like and from tokens that hold no slot.
    for (let i = 0; i < 3; i += 1) {
      expect(await postStatus(freshDevice(), revokedCopy)).toBe(401);
    }
    for (const device of devices.slice(5)) {
      expect(await postStatus(device, proof)).toBe(409);
    }
    const plans = await Promise.all(devices.map(planOf));
    expect(plans.filter((p) => p === "pro").length).toBeLessThanOrEqual(5);
    expect(plans.slice(0, 5)).toEqual(Array(5).fill("pro"));
  });

  it("holds the cap when each device posts the revoked copy and a live proof at once", async () => {
    const now = Date.now();
    const otid = "2000000988800013";
    // The current purchase, which Apple refunds, and the subscriber
    // buying again on the same subscription.
    const refunded = purchase(otid, now - DAY_MS);
    const again = purchase(otid, now - 60 * MINUTE);
    const preRefund = await refunded.signed(now - 30 * MINUTE);
    const revokedCopy = await refunded.revoked(now - 2 * MINUTE);
    const live = await again.signed(now - MINUTE);
    const first = Array.from({ length: 5 }, freshDevice);
    const second = Array.from({ length: 5 }, freshDevice);
    for (const device of first) {
      expect(await postStatus(device, preRefund)).toBe(200);
    }
    // Whichever route lands first, the live proof leaves each device on
    // Pro, so its slot has to stay.
    for (const device of first) {
      const [revoked, accepted] = await Promise.all([
        postStatus(device, revokedCopy),
        postStatus(device, live),
      ]);
      expect([revoked, accepted]).toEqual([401, 200]);
    }
    for (const device of second) {
      expect(await postStatus(device, live)).toBe(409);
    }
    const plans = await Promise.all([...first, ...second].map(planOf));
    expect(plans.filter((p) => p === "pro").length).toBeLessThanOrEqual(5);
    expect(plans.slice(5)).toEqual(Array(5).fill("free"));
  });

  it("changes nothing on the transaction for a lapsed revocation", async () => {
    const now = Date.now();
    const otid = "2000000988800011";
    // Refunded over a year ago: its expiry plus the grace has passed.
    const ancient = purchase(otid, now - 400 * DAY_MS);
    const current = purchase(otid, now - DAY_MS);
    const proof = await current.signed(now - MINUTE);
    const devices = Array.from({ length: 6 }, freshDevice);
    for (const device of devices.slice(0, 5)) {
      expect(await postStatus(device, proof)).toBe(200);
    }
    const before = await transactionStorage(otid);
    expect(
      await postStatus(freshDevice(), await ancient.revoked(now - MINUTE)),
    ).toBe(401);
    expect(await transactionStorage(otid)).toEqual(before);
    expect(await postStatus(devices[5]!, proof)).toBe(409);
  });

  it("accepts a later renewal and a copy signed after the revocation", async () => {
    const now = Date.now();
    const otid = "2000000988800003";
    const first = purchase(otid, now - 40 * DAY_MS);
    const device = freshDevice();
    expect(await postStatus(device, await first.signed(now - 30 * MINUTE))).toBe(
      200,
    );
    expect(await postStatus(device, await first.revoked(now - MINUTE))).toBe(
      401,
    );
    expect(await planOf(device)).toBe("free");

    // A renewal bought after the revoked purchase, even one signed
    // before the revoked copy.
    const renewal = purchase(otid, now - DAY_MS);
    expect(await postStatus(device, await renewal.signed(now - 5 * MINUTE))).toBe(
      200,
    );
    expect(await planOf(device)).toBe("pro");

    // The revoked purchase itself, signed after the revocation: the
    // refund was reversed.
    const other = freshDevice();
    expect(await postStatus(other, await first.signed(now))).toBe(200);
    expect(await planOf(other)).toBe("pro");
    // The mark stays: an older copy is still a replay.
    expect(
      await postStatus(freshDevice(), await first.signed(now - 30 * MINUTE)),
    ).toBe(401);
  });

  it("changes nothing for a transaction an upgrade superseded", async () => {
    const now = Date.now();
    const otid = "2000000988800004";
    const bought = purchase(otid, now - 2 * DAY_MS);
    const device = freshDevice();
    const original = await bought.signed(now - 10 * MINUTE);
    expect(await postStatus(device, original)).toBe(200);
    const before = await storedEntitlement(device);

    const upgraded = await post({
      v: 1,
      device,
      jws: await bought.revoked(now - MINUTE, { isUpgraded: true }),
    });
    expect(upgraded.status).toBe(401);
    expect(((await upgraded.json()) as { reason: string }).reason).toBe(
      "revoked",
    );
    expect(await storedEntitlement(device)).toEqual(before);
    expect(await planOf(device)).toBe("pro");
    expect(await transactionStorage(otid)).not.toHaveProperty("revoked");
    expect(await postStatus(device, original)).toBe(200);
  });

  it("never downgrades a device holding a different transaction", async () => {
    const now = Date.now();
    const held = purchase("2000000988800005", now - 2 * DAY_MS);
    const other = purchase("2000000988800006", now - 2 * DAY_MS);
    const device = freshDevice();
    expect(await postStatus(device, await held.signed(now - 10 * MINUTE))).toBe(
      200,
    );
    const before = await storedEntitlement(device);
    expect(await postStatus(device, await other.revoked(now - MINUTE))).toBe(
      401,
    );
    expect(await storedEntitlement(device)).toEqual(before);
    expect(await planOf(device)).toBe("pro");
  });

  it("keeps a device on a renewal newer than the revoked purchase", async () => {
    const now = Date.now();
    const otid = "2000000988800007";
    const earlier = purchase(otid, now - 40 * DAY_MS);
    const renewal = purchase(otid, now - DAY_MS);
    const device = freshDevice();
    expect(await postStatus(device, await renewal.signed(now - 10 * MINUTE))).toBe(
      200,
    );
    expect(await postStatus(device, await earlier.revoked(now - MINUTE))).toBe(
      401,
    );
    expect(await planOf(device)).toBe("pro");
    // The renewal re-posted after the revocation still verifies.
    expect(await postStatus(device, await renewal.signed(now - 10 * MINUTE))).toBe(
      200,
    );
  });

  it("deletes a pre-existing record without purchaseDate on the id match", async () => {
    const now = Date.now();
    const otid = "2000000988800008";
    const device = freshDevice();
    await runInDurableObject(deviceStub(device), (_i, state) =>
      state.storage.put("entitlement", {
        originalTransactionId: otid,
        productId: PRO_YEARLY,
        expiresAt: now + 300 * DAY_MS,
        environment: "Production",
        verifiedAt: now,
      } satisfies EntitlementRecord),
    );
    expect(await planOf(device)).toBe("pro");
    const bought = purchase(otid, now - 2 * DAY_MS);
    expect(await postStatus(device, await bought.revoked(now - MINUTE))).toBe(
      401,
    );
    expect(await planOf(device)).toBe("free");
  });

  it("lapses with the revoked purchase's expiry plus the grace", async () => {
    const otid = "2000000988800009";
    const now = Date.now();
    const keys = await runInDurableObject(
      transactionStub(otid),
      async (instance, state) => {
        const object = instance as unknown as EntitlementState;
        await object.revoke({
          signedDate: now,
          purchaseDate: now - DAY_MS,
          until: now + 60_000,
        });
        expect(await state.storage.getAlarm()).toBe(now + 60_000);
        await object.alarm();
        expect(await state.storage.get("revoked")).toBeDefined();
        // Past its until, the next wake empties the object.
        await state.storage.put("revoked", {
          signedDate: now,
          purchaseDate: now - DAY_MS,
          until: now - 1,
        });
        await object.alarm();
        return [...(await state.storage.list()).keys()];
      },
    );
    expect(keys).toEqual([]);
  });

  it("wakes at a new slot's lapse ahead of a later mark", async () => {
    const otid = "2000000988800012";
    const now = Date.now();
    await runInDurableObject(transactionStub(otid), async (instance, state) => {
      const object = instance as unknown as EntitlementState;
      // A refunded yearly purchase holds its mark for most of a year.
      const until = now + 280 * DAY_MS;
      await object.revoke({
        signedDate: now - DAY_MS,
        purchaseDate: now - 100 * DAY_MS,
        until,
      });
      expect(await state.storage.getAlarm()).toBe(until);
      // A resubscription on the same transaction: the new slot's hash
      // leaves storage when the slot lapses, not when the mark does.
      const claim = await object.claim("cd".repeat(32), {
        purchaseDate: now - DAY_MS / 2,
        signedDate: Date.now(),
      });
      if (!claim.admitted) throw new Error("expected an admitted claim");
      expect(await state.storage.getAlarm()).toBe(claim.slotExpiresAt);
      // A claim never pushes a sooner alarm back.
      const sooner = claim.slotExpiresAt - 1_000;
      await state.storage.setAlarm(sooner);
      const second = await object.claim("ef".repeat(32), {
        purchaseDate: now - DAY_MS / 2,
        signedDate: Date.now(),
      });
      expect(second.admitted).toBe(true);
      expect(await state.storage.getAlarm()).toBe(sooner);
    });
  });
});
