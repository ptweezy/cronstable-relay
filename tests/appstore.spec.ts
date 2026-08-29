/**
 * Entitlement proof: the offline StoreKit verifier against a real
 * three-certificate chain (tests/fixtures/appstore), and the
 * POST /entitlement route in front of it.  The relay trusts the test
 * root via RELAY_APPLE_ROOT_CERT; the pinned Apple root is checked by
 * fingerprint.
 */

import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  APPLE_ROOT_CA_G3_B64,
  entitlementPolicyFromEnv,
  verifyTransaction,
  type VerifyOptions,
} from "../src/appstore";
import { MAX_ENTITLEMENT_BODY_BYTES } from "../src/index";

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
    const monthly = await verify(transaction());
    expect(monthly.ok).toBe(true);
    if (!monthly.ok) return;
    expect(monthly.transaction).toEqual({
      originalTransactionId: "2000000900000001",
      productId: PRO_MONTHLY,
      expiresAt: expect.any(Number),
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

  it("rejects an expired transaction", async () => {
    expect(
      reasonOf(await verify(transaction({ expiresDate: Date.now() - 1000 }))),
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

  it("rejects a leaf outside its validity window", async () => {
    const result = await verify(transaction(), {
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
    // Slots lapse after RELAY_PRO_DEVICE_SLOT_TTL_S (2 s here) of silence.
    await sleep(2_100);
    const later = await post({ v: 1, device: devices[5], jws: await proof() });
    expect(later.status).toBe(200);
  }, 15_000);
});
