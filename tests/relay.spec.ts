/**
 * End-to-end tests: real worker, real Durable Objects, real JWT
 * signing — only APNs itself is stubbed (tests/apns-mock.ts, which
 * replaces the `fetchMock` removed in the Vitest 4 integration).  The
 * policy windows are shrunk via vitest.config.mts (dedup 2 s, rate
 * capacity 5 at 1 token/s, flap after 3 forwards / 60 s window) so the
 * sleep-based cases stay fast.
 */

import { exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  apnsRequests,
  expectApns,
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

let deviceCounter = 0;

/** A unique token per test: a fresh Durable Object, fresh policy state. */
function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

function randCollapse(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function envelope(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    v: 1,
    device: freshDevice(),
    ciphertext: "A".repeat(96),
    collapseId: randCollapse(),
    priority: "time-sensitive",
    event: false,
    ...overrides,
  };
}

/** Drive the worker's default export directly (the old `SELF.fetch`). */
async function post(body: unknown): Promise<Response> {
  return exports.default.fetch("https://relay.test/", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("HTTP surface", () => {
  it("serves a plain-text description on GET /", async () => {
    const res = await exports.default.fetch("https://relay.test/");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("cronstable-relay");
  });

  it("404s other paths and 405s other methods", async () => {
    const notFound = await exports.default.fetch("https://relay.test/other");
    expect(notFound.status).toBe(404);
    const res = await exports.default.fetch("https://relay.test/", {
      method: "PUT",
    });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, HEAD, POST");
  });

  it("400s malformed JSON and invalid envelopes", async () => {
    expect((await post("{not json")).status).toBe(400);
    const badVersion = await post(envelope({ v: 3 }));
    expect(badVersion.status).toBe(400);
    expect(((await badVersion.json()) as { error: string }).error).toMatch(
      /version/,
    );
    expect((await post(envelope({ collapseId: "nope" }))).status).toBe(400);
  });

  it("413s an oversized body", async () => {
    const res = await post("[" + "1,".repeat(5000) + "1]");
    expect(res.status).toBe(413);
  });
});

describe("forwarding", () => {
  it("forwards a sealed alert to APNs intact", async () => {
    expectApns(PROD, 200);
    const body = envelope();
    const res = await post(body);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ v: 1, outcome: "forwarded" });

    expect(apnsRequests()).toHaveLength(1);
    const sent = apnsRequests()[0]!;
    expect(sent.path).toBe(`/3/device/${body.device}`);
    expect(sent.headers["apns-topic"]).toBe("test.cronstable.app");
    expect(sent.headers["apns-push-type"]).toBe("alert");
    expect(sent.headers["apns-priority"]).toBe("10");
    expect(sent.headers["apns-collapse-id"]).toBe(body.collapseId);
    expect(sent.headers["authorization"]).toMatch(/^bearer .+\..+\..+$/);
    expect(Number(sent.headers["apns-expiration"])).toBeGreaterThan(
      Date.now() / 1000,
    );

    const payload = JSON.parse(sent.body) as {
      aps: Record<string, unknown>;
      v: number;
      ciphertext: string;
    };
    expect(payload.v).toBe(1);
    expect(payload.ciphertext).toBe(body.ciphertext);
    expect(payload.aps["mutable-content"]).toBe(1);
    expect(payload.aps["interruption-level"]).toBe("time-sensitive");
    expect(payload.aps["sound"]).toBe("default");
    expect(new TextEncoder().encode(sent.body).length).toBeLessThanOrEqual(
      4096,
    );
  });

  it("maps passive priority to APNs priority 5, no sound", async () => {
    expectApns(PROD, 200);
    const res = await post(envelope({ priority: "passive" }));
    expect(res.status).toBe(202);
    const sent = apnsRequests()[0]!;
    expect(sent.headers["apns-priority"]).toBe("5");
    const payload = JSON.parse(sent.body) as { aps: Record<string, unknown> };
    expect(payload.aps["interruption-level"]).toBe("passive");
    expect(payload.aps["sound"]).toBeUndefined();
  });

  it("stays under the APNs cap with a maximum-size ciphertext", async () => {
    expectApns(PROD, 200);
    const res = await post(envelope({ ciphertext: "A".repeat(3000) }));
    expect(res.status).toBe(202);
    expect(
      new TextEncoder().encode(apnsRequests()[0]!.body).length,
    ).toBeLessThanOrEqual(4096);
  });
});

describe("delivery policy", () => {
  it("coalesces a cluster's duplicate, then forwards after the window", async () => {
    expectApns(PROD, 200);
    const body = envelope();
    expect(await (await post(body)).json()).toEqual({
      v: 1,
      outcome: "forwarded",
    });
    // Same (device, collapseId) straight after: another node's copy.
    expect(await (await post(body)).json()).toEqual({
      v: 1,
      outcome: "coalesced",
    });
    await sleep(2_100); // past RELAY_DEDUP_WINDOW_S = 2
    expectApns(PROD, 200);
    expect(await (await post(body)).json()).toEqual({
      v: 1,
      outcome: "forwarded",
    });
  }, 10_000);

  it("suppresses a flapping alert after 3 forwards, accepting quietly", async () => {
    const body = envelope();
    for (let i = 0; i < 3; i += 1) {
      expectApns(PROD, 200);
      expect(await (await post(body)).json()).toEqual({
        v: 1,
        outcome: "forwarded",
      });
      await sleep(2_100);
    }
    // Fourth occurrence inside the flap window: no forward, still 2xx.
    const res = await post(body);
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ v: 1, outcome: "suppressed" });
    // And it stays suppressed for the copy right behind it.
    expect(await (await post(body)).json()).toEqual({
      v: 1,
      outcome: "suppressed",
    });
  }, 20_000);

  it("rate-limits a device once the bucket is spent", async () => {
    const device = freshDevice();
    for (let i = 0; i < 5; i += 1) {
      expectApns(PROD, 200);
      const res = await post(envelope({ device }));
      expect(res.status).toBe(202);
    }
    const limited = await post(envelope({ device }));
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThanOrEqual(
      1,
    );
    expect(((await limited.json()) as { error: string }).error).toMatch(
      /rate limited/,
    );
  }, 10_000);
});

describe("APNs environments and errors", () => {
  it("falls back to sandbox on BadDeviceToken and remembers it", async () => {
    const device = freshDevice();
    expectApns(PROD, 400, JSON.stringify({ reason: "BadDeviceToken" }));
    expectApns(SANDBOX, 200);
    const res = await post(envelope({ device }));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ v: 1, outcome: "forwarded" });

    // Next alert for this device goes straight to sandbox: only a
    // sandbox reply is armed, so a production attempt would throw.
    expectApns(SANDBOX, 200);
    const next = await post(envelope({ device }));
    expect(next.status).toBe(202);
    expect(await next.json()).toEqual({ v: 1, outcome: "forwarded" });
    expect(apnsRequests().map((r) => r.origin)).toEqual([
      PROD,
      SANDBOX,
      SANDBOX,
    ]);
  });

  it("410s an Unregistered token without trying the other environment", async () => {
    expectApns(PROD, 410, JSON.stringify({ reason: "Unregistered" }));
    const res = await post(envelope());
    expect(res.status).toBe(410);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.reason).toBe("Unregistered");
    expect(body.error).toMatch(/rejected/);
    expect(apnsRequests()).toHaveLength(1);
  });

  it("502s when APNs rejects the relay's own credentials", async () => {
    expectApns(PROD, 403, JSON.stringify({ reason: "InvalidProviderToken" }));
    const res = await post(envelope());
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: string }).error).toMatch(
      /credentials/,
    );
  });

  it("502s on APNs server trouble and stays deliverable after", async () => {
    const body = envelope();
    expectApns(PROD, 500, JSON.stringify({ reason: "InternalServerError" }));
    expect((await post(body)).status).toBe(502);
    // The failed forward was rolled back: the same alert forwards
    // as soon as APNs recovers, with no dedup shadow.
    expectApns(PROD, 200);
    const retry = await post(body);
    expect(retry.status).toBe(202);
    expect(await retry.json()).toEqual({ v: 1, outcome: "forwarded" });
  });
});
