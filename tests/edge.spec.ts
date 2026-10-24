/**
 * The HTTP edge, in the "relay" project: the byte cap on request bodies
 * and the per-address limiter on POST / (EDGE_LIMITER).
 *
 * A streamed body is a pull-driven ReadableStream, so the request
 * carries no Content-Length (the shape of a chunked HTTP/1.1 or an
 * HTTP/2 upload), and the test counts the bytes the worker pulled.  The
 * limiter cases that need a verdict on demand call the worker's handler
 * with a stub binding; the last case drives the binding wrangler.jsonc
 * declares, which miniflare runs locally.
 */

import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import worker, {
  edgeLimiterKey,
  MAX_ENTITLEMENT_BODY_BYTES,
} from "../src/index";
import type { Env } from "../src/types";
import { MAX_BODY_BYTES } from "../src/validate";

import {
  apnsRequests,
  expectApns,
  expectNoPendingApns,
  installApnsMock,
  PROD,
  resetApnsMock,
} from "./apns-mock";

beforeEach(() => {
  resetApnsMock();
  installApnsMock();
});

afterEach(() => {
  expectNoPendingApns();
  vi.restoreAllMocks();
});

const TOO_LARGE = { v: 1, error: "body too large" };
const NOT_JSON = { v: 1, error: "body is not valid JSON" };
const BAD_LENGTH = {
  v: 1,
  error: "content-length must be a non-negative integer",
};
const LIMITED = { v: 1, error: "too many requests from this address" };

/** Both POST routes and their byte caps. */
const ROUTES: [string, number][] = [
  ["/", MAX_BODY_BYTES],
  ["/entitlement", MAX_ENTITLEMENT_BODY_BYTES],
];

let deviceCounter = 0xed9e0000;

function freshDevice(): string {
  deviceCounter += 1;
  return deviceCounter.toString(16).padStart(64, "0");
}

function randHex(bytes = 16): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function envelope(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    v: 1,
    device: freshDevice(),
    ciphertext: "A".repeat(96),
    collapseId: randHex(),
    priority: "time-sensitive",
    event: false,
    ...overrides,
  };
}

/** A body that answers 202 on POST / (with APNs armed) or 200 on
 * /entitlement (a status query), plus any extra fields. */
function goodBody(
  path: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return path === "/"
    ? envelope(extra)
    : { v: 1, device: freshDevice(), ...extra };
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/** A client address from the IPv6 documentation range, in a /64 of its
 * own per call, so no case shares a limiter counter with another. */
function freshAddress(): string {
  return `2001:db8:${randHex(2)}:${randHex(2)}::${randHex(2)}`;
}

/** Another address in `address`'s /64 (freshAddress's shape). */
function sameSlash64(address: string): string {
  return `${address.slice(0, address.lastIndexOf("::"))}::1:${randHex(2)}`;
}

/**
 * POST `bytes` to `path` as a pull-driven stream of `chunk`-byte pieces.
 * `pulled()` reports how many bytes the worker read.
 */
async function streamPost(
  path: string,
  bytes: Uint8Array,
  { chunk = 64 * 1024, headers = {} as Record<string, string> } = {},
) {
  let offset = 0;
  let pulled = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      const piece = bytes.slice(offset, offset + chunk);
      offset += piece.length;
      pulled += piece.length;
      controller.enqueue(piece);
    },
  });
  const request = new Request(`https://relay.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
  const declared = request.headers.get("content-length");
  const res = await exports.default.fetch(request);
  return { res, declared, pulled: () => pulled };
}

/** POST a fixed body; the runtime sets Content-Length unless `headers`
 * names one. */
async function post(
  path: string,
  body: string | Uint8Array,
  headers: Record<string, string> = {},
): Promise<Response> {
  return exports.default.fetch(`https://relay.test${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

describe("the body cap", () => {
  it.each(ROUTES)(
    "stops reading a streamed body on %s once it passes the cap",
    async (path, limit) => {
      const total = 8 * 1024 * 1024;
      const { res, declared, pulled } = await streamPost(
        path,
        new Uint8Array(total).fill(0x41),
      );
      expect(declared).toBeNull();
      expect(res.status).toBe(413);
      expect(await res.json()).toEqual(TOO_LARGE);
      // A whole read would pull all 8 MiB; one chunk already passes
      // the cap, so the read stops within the runtime's read-ahead.
      expect(pulled()).toBeGreaterThan(limit);
      expect(pulled()).toBeLessThan(1024 * 1024);
    },
  );

  it.each(ROUTES)(
    "counts bytes, not characters, on %s",
    async (path, limit) => {
      // U+20AC is one UTF-16 unit and three UTF-8 bytes.
      const text = JSON.stringify(
        goodBody(path, { pad: "\u20ac".repeat(Math.ceil(limit / 3)) }),
      );
      const bytes = utf8(text);
      expect(text.length).toBeLessThan(limit);
      expect(bytes.length).toBeGreaterThan(limit);

      const streamed = await streamPost(path, bytes);
      expect(streamed.declared).toBeNull();
      expect(streamed.res.status).toBe(413);
      expect(await streamed.res.json()).toEqual(TOO_LARGE);

      // The same bytes with Content-Length stop at the header.
      const declared = await post(path, bytes);
      expect(declared.status).toBe(413);
      expect(apnsRequests()).toHaveLength(0);
    },
  );

  it("takes a body of exactly the cap across chunks that split a character", async () => {
    const fill = (spaces: number) => {
      const body = envelope({ pad: "\u20ac".repeat(2000) });
      const json = JSON.stringify(body);
      return { body, bytes: utf8(json + " ".repeat(spaces)) };
    };
    const base = fill(0).bytes.length;
    expect(base).toBeLessThan(MAX_BODY_BYTES);
    const atCap = fill(MAX_BODY_BYTES - base);
    expect(atCap.bytes.length).toBe(MAX_BODY_BYTES);
    // Some 1000-byte chunk boundary lands inside a three-byte character
    // (a continuation byte starts the next chunk).
    const boundaries = [1000, 2000, 3000, 4000, 5000, 6000, 7000];
    expect(
      boundaries.some((at) => (atCap.bytes[at]! & 0xc0) === 0x80),
    ).toBe(true);

    expectApns(PROD, 200);
    const ok = await streamPost("/", atCap.bytes, { chunk: 1000 });
    expect(ok.declared).toBeNull();
    expect(ok.res.status).toBe(202);
    expect(await ok.res.json()).toEqual({ v: 1, outcome: "forwarded" });
    const sent = apnsRequests()[0]!;
    expect(sent.path).toBe(`/3/device/${atCap.body.device}`);
    expect(sent.headers["apns-collapse-id"]).toBe(atCap.body.collapseId);

    const over = fill(MAX_BODY_BYTES - base + 1);
    expect(over.bytes.length).toBe(MAX_BODY_BYTES + 1);
    const refused = await streamPost("/", over.bytes, { chunk: 1000 });
    expect(refused.res.status).toBe(413);
    expect(apnsRequests()).toHaveLength(1);
  });

  it.each(ROUTES)(
    "400s a Content-Length that is not a non-negative integer on %s",
    async (path) => {
      for (const header of ["abc", "-1", "1e3", "12.5", "0x10", "10, 10"]) {
        const res = await post(path, JSON.stringify(goodBody(path)), {
          "content-length": header,
        });
        expect(res.status, `content-length: ${header}`).toBe(400);
        expect(await res.json()).toEqual(BAD_LENGTH);
      }
      // A bad header in front of an oversized stream is refused unread.
      const { res, declared, pulled } = await streamPost(
        path,
        new Uint8Array(8 * 1024 * 1024).fill(0x41),
        { headers: { "content-length": "abc" } },
      );
      expect(declared).toBe("abc");
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual(BAD_LENGTH);
      expect(pulled()).toBeLessThan(1024 * 1024);
      expect(apnsRequests()).toHaveLength(0);
    },
  );

  it.each(ROUTES)("400s a body that is not UTF-8 on %s", async (path) => {
    // A truncated two-byte sequence, and an encoded lone surrogate.
    for (const invalid of [[0xc3, 0x28], [0xed, 0xa0, 0x80]]) {
      const marker = "@".repeat(invalid.length);
      const text = JSON.stringify(goodBody(path, { pad: marker }));
      const bytes = utf8(text);
      bytes.set(invalid, text.indexOf(marker));

      const declared = await post(path, bytes);
      expect(declared.status).toBe(400);
      expect(await declared.json()).toEqual(NOT_JSON);
      const streamed = await streamPost(path, bytes, { chunk: 7 });
      expect(streamed.res.status).toBe(400);
      expect(await streamed.res.json()).toEqual(NOT_JSON);
    }
    expect(apnsRequests()).toHaveLength(0);
  });

  it.each(ROUTES)("reads a missing body as empty on %s", async (path) => {
    const res = await exports.default.fetch(`https://relay.test${path}`, {
      method: "POST",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(NOT_JSON);
  });

  it("strips a leading byte-order mark", async () => {
    const res = await post(
      "/entitlement",
      "\ufeff" + JSON.stringify({ v: 1, device: freshDevice() }),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as { plan: string }).plan).toBe("free");
  });
});

/** A stand-in limiter that admits the first `admits` calls and records
 * every call's options. */
function limiterStub(admits: number) {
  const calls: RateLimitOptions[] = [];
  const limiter: RateLimit = {
    async limit(options) {
      calls.push(options);
      return { success: calls.length <= admits };
    },
  };
  return { limiter, calls };
}

/** A request to `path`, carrying `address` as cf-connecting-ip. */
function relayRequest(
  path: string,
  init: RequestInit & { address?: string },
): Request {
  const { address, ...rest } = init;
  const headers = new Headers(rest.headers);
  if (address !== undefined) headers.set("cf-connecting-ip", address);
  return new Request(`https://relay.test${path}`, { ...rest, headers });
}

/** Run the worker's handler directly, with `limiter` as EDGE_LIMITER
 * (undefined: a relay deployed without the binding). */
async function handleRequest(
  request: Request,
  limiter: RateLimit | undefined,
): Promise<Response> {
  const relayEnv: Env = { ...(env as unknown as Env), EDGE_LIMITER: limiter };
  return worker.fetch(
    request as Parameters<typeof worker.fetch>[0],
    relayEnv,
  );
}

async function handle(
  path: string,
  init: RequestInit & { address?: string },
  limiter: RateLimit | undefined,
): Promise<Response> {
  return handleRequest(relayRequest(path, init), limiter);
}

const postInit = (body: unknown, address?: string) => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: typeof body === "string" ? body : JSON.stringify(body),
  address,
});

describe("the edge limiter", () => {
  it("answers 429 with Retry-After once it refuses an address", async () => {
    const { limiter, calls } = limiterStub(1);
    const address = "192.0.2.10";

    expectApns(PROD, 200);
    const admitted = await handle("/", postInit(envelope(), address), limiter);
    expect(admitted.status).toBe(202);

    const refused = await handle("/", postInit(envelope(), address), limiter);
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBe("60");
    expect(refused.headers.get("content-type")).toBe("application/json");
    expect(await refused.json()).toEqual(LIMITED);

    // The limiter keys on the client address alone.  The refused
    // envelope never reached its Durable Object, so APNs saw one request.
    expect(calls).toEqual([{ key: address }, { key: address }]);
    expect(apnsRequests()).toHaveLength(1);
  });

  it("keys an IPv4 address as is and an IPv6 address by its /64", async () => {
    const { limiter, calls } = limiterStub(100);
    const keys: Record<string, string> = {
      "198.51.100.7": "198.51.100.7",
      "2001:db8:aaaa:bbbb::1": "2001:db8:aaaa:bbbb::/64",
      "2001:DB8:AAAA:BBBB:0:0:0:2": "2001:db8:aaaa:bbbb::/64",
      "2001:0db8:aaaa:bbbb:ffff:ffff:ffff:ffff": "2001:db8:aaaa:bbbb::/64",
      "2001:db8:aaaa:bbbc::1": "2001:db8:aaaa:bbbc::/64",
      "2001:db8::1": "2001:db8:0:0::/64",
      "2001:db8:1:2:3::": "2001:db8:1:2::/64",
      "::1": "0:0:0:0::/64",
      // An IPv4-mapped address counts against its IPv4 address.
      "::ffff:198.51.100.7": "198.51.100.7",
      "::ffff:c633:6407": "198.51.100.7",
      "64:ff9b::198.51.100.7": "64:ff9b:0:0::/64",
    };
    for (const address of Object.keys(keys)) {
      const res = await handle("/", postInit({}, address), limiter);
      expect(res.status, address).toBe(400);
    }
    expect(calls.map((c) => c.key)).toEqual(Object.values(keys));
    for (const [address, key] of Object.entries(keys)) {
      expect(edgeLimiterKey(address), address).toBe(key);
    }
  });

  it("refuses before reading the body", async () => {
    const { limiter } = limiterStub(0);
    const address = freshAddress();
    const bodies = {
      malformed: postInit("{nope", address),
      oversized: postInit("x".repeat(MAX_BODY_BYTES + 1), address),
      "bad content-length": {
        ...postInit(envelope(), address),
        headers: { "content-length": "abc" },
      },
    };
    for (const [name, init] of Object.entries(bodies)) {
      const request = relayRequest("/", init);
      const res = await handleRequest(request, limiter);
      expect(res.status, name).toBe(429);
      expect(request.bodyUsed, name).toBe(false);
    }
  });

  it("never runs outside POST /", async () => {
    const { limiter, calls } = limiterStub(0);
    const address = freshAddress();
    const answers = {
      "GET /": (await handle("/", { address }, limiter)).status,
      "HEAD /": (await handle("/", { method: "HEAD", address }, limiter))
        .status,
      "PUT /": (await handle("/", { method: "PUT", address }, limiter)).status,
      "POST /entitlement": (
        await handle(
          "/entitlement",
          postInit({ v: 1, device: freshDevice() }, address),
          limiter,
        )
      ).status,
      "GET /privacy": (await handle("/privacy", { address }, limiter)).status,
      "GET /pair": (await handle("/pair", { address }, limiter)).status,
      "POST /elsewhere": (
        await handle("/elsewhere", postInit({}, address), limiter)
      ).status,
    };
    expect(answers).toEqual({
      "GET /": 200,
      "HEAD /": 200,
      "PUT /": 405,
      "POST /entitlement": 200,
      "GET /privacy": 200,
      "GET /pair": 200,
      "POST /elsewhere": 404,
    });
    expect(calls).toEqual([]);
  });

  it("skips the check for a request without a client address", async () => {
    const { limiter, calls } = limiterStub(0);
    expectApns(PROD, 200);
    const res = await handle("/", postInit(envelope()), limiter);
    expect(res.status).toBe(202);
    expect(calls).toEqual([]);
  });

  it("skips the check on a relay deployed without the binding", async () => {
    expectApns(PROD, 200);
    const res = await handle(
      "/",
      postInit(envelope(), freshAddress()),
      undefined,
    );
    expect(res.status).toBe(202);
  });

  it("admits the request when the limiter throws", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const limiter: RateLimit = {
      async limit() {
        throw new Error("limiter unavailable");
      },
    };
    expectApns(PROD, 200);
    const res = await handle(
      "/",
      postInit(envelope(), freshAddress()),
      limiter,
    );
    expect(res.status).toBe(202);
    expect(errors.mock.calls.map((c) => JSON.parse(String(c[0])).evt)).toEqual(
      ["edge_limiter_error"],
    );
  });

  it("holds one address to 6000 POSTs a minute with the configured binding", async () => {
    // The binding counts in windows aligned to the wall clock; start
    // clear of a window's end so the whole case lands in one window.
    const intoWindow = Date.now() % 60_000;
    if (intoWindow > 50_000) {
      await new Promise((r) => setTimeout(r, 60_000 - intoWindow + 250));
    }
    expect(env.EDGE_LIMITER).toBeDefined();
    const address = freshAddress();
    const from = { "cf-connecting-ip": address };

    // The worker's binding and this one share the namespace, so 5999
    // calls here leave the address's /64 one request.
    let admitted = 0;
    for (let i = 0; i < 5_999; i++) {
      const key = edgeLimiterKey(address);
      if ((await env.EDGE_LIMITER.limit({ key })).success) admitted += 1;
    }
    expect(admitted).toBe(5_999);

    const last = await post("/", "{}", from);
    expect(last.status).toBe(400);
    const refused = await post("/", "{}", from);
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toBe("60");
    expect(await refused.json()).toEqual(LIMITED);

    // Another address in the same /64 shares the count.
    const sibling = await post("/", "{}", {
      "cf-connecting-ip": sameSlash64(address),
    });
    expect(sibling.status).toBe(429);

    // Other routes and other /64s are untouched.
    const info = await exports.default.fetch("https://relay.test/", {
      headers: from,
    });
    expect(info.status).toBe(200);
    const status = await post(
      "/entitlement",
      JSON.stringify({ v: 1, device: freshDevice() }),
      from,
    );
    expect(status.status).toBe(200);
    const elsewhere = freshAddress();
    expect(edgeLimiterKey(elsewhere)).not.toBe(edgeLimiterKey(address));
    const other = await post("/", "{}", { "cf-connecting-ip": elsewhere });
    expect(other.status).toBe(400);
  }, 30_000);
});
