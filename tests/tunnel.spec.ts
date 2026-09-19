/**
 * Reach end to end: a mock daemon (tests/daemon-mock.ts) on a real
 * WebSocket to the worker, apps posting through the front Worker, and
 * the per-tunnel Durable Object between them.  Runs in the "reach"
 * vitest project alone (vitest.config.mts), where the timers are
 * seconds and the caps single digits: hello timeout 1 s, first-byte
 * wait 1 s, stale sweep 2 s, stream threshold 1 s, stream lifetime 2 s,
 * 3.5 s of stream time per day, 4 requests in flight, 2 streams, an
 * admit bucket of 6 refilling one per second, 5 strikes per minute.
 * Every test mints its own identity, so each gets a fresh object.
 */

import {
  evictDurableObject,
  runDurableObjectAlarm,
  runInDurableObject,
} from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import worker from "../src/index";
import {
  b64Decode,
  CANCEL_CLIENT_GONE,
  CANCEL_STREAM_CAP,
  CLOSE_BAD_SIGNATURE,
  CLOSE_HELLO_TIMEOUT,
  CLOSE_PROTOCOL_ERROR,
  CLOSE_SUPERSEDED,
  FRAME_CANCEL,
  FRAME_DATA,
  FRAME_WINDOW,
  packFrame,
  SUBPROTOCOL,
  type Frame,
} from "../src/reach";
import type { Env } from "../src/types";

import {
  concat,
  freshIdentity,
  identityFromSeed,
  mintCredential,
  MockDaemon,
  type ConnectOptions,
  type Credential,
  type Identity,
} from "./daemon-mock";

interface Vectors {
  handshake: { hello: string };
  identity: { signSeed: string; tunnelId: string };
  response: { stream: string };
}

const vectors = JSON.parse(env.TEST_REACH_VECTORS) as Vectors;

function bytes(b64: string): Uint8Array {
  const out = b64Decode(b64);
  if (out === null) throw new Error("fixture value is not base64");
  return out;
}

const HELLO_BODY = bytes(vectors.handshake.hello);
const RESPONSE_STREAM = bytes(vectors.response.stream);

const POST_CAP = 1_052_672;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const daemons: MockDaemon[] = [];

afterEach(async () => {
  // Close every daemon and let the object log the close before the test
  // environment goes away.
  const open = daemons.splice(0);
  for (const daemon of open) daemon.close();
  await Promise.race([Promise.all(open.map((d) => d.closed)), sleep(500)]);
});

async function connect(
  identity: Identity,
  opts: ConnectOptions = {},
): Promise<MockDaemon> {
  const daemon = await MockDaemon.connect(identity, opts);
  daemons.push(daemon);
  return daemon;
}

/** A fresh tunnel with one admitted credential and a live daemon. */
async function tunnel(
  opts: ConnectOptions = {},
): Promise<{ identity: Identity; credential: Credential; daemon: MockDaemon }> {
  const identity = await freshIdentity();
  const credential = await mintCredential();
  const daemon = await connect(identity, {
    admit: [credential.admitId],
    ...opts,
  });
  return { identity, credential, daemon };
}

function url(id: string): string {
  return `https://relay.test/v1/reach/${id}`;
}

function post(
  id: string,
  authorization: string | null,
  body: BodyInit | null = HELLO_BODY,
  headers: Record<string, string | null> = {},
  init: RequestInit = {},
): Promise<Response> {
  const h = new Headers({ "content-type": "application/octet-stream" });
  if (authorization !== null) h.set("authorization", authorization);
  for (const [name, value] of Object.entries(headers)) {
    if (value === null) h.delete(name);
    else h.set(name, value);
  }
  return exports.default.fetch(url(id), { method: "POST", headers: h, body, ...init });
}

function status(id: string, authorization: string | null): Promise<Response> {
  const headers = new Headers();
  if (authorization !== null) headers.set("authorization", authorization);
  return exports.default.fetch(url(id), { headers });
}

async function readAll(res: Response): Promise<Uint8Array> {
  return new Uint8Array(await res.arrayBuffer());
}

async function errorOf(res: Response): Promise<string> {
  return ((await res.json()) as { error: string }).error;
}

/** Split the fixture's `(u32 len ‖ chunk)*` stream at its chunk boundaries. */
function chunksOf(stream: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  let offset = 0;
  while (offset < stream.length) {
    const view = new DataView(stream.buffer, stream.byteOffset + offset, 4);
    const length = 4 + view.getUint32(0);
    out.push(stream.subarray(offset, offset + length));
    offset += length;
  }
  return out;
}

/** Script the daemon to answer every OPEN with these DATA frames, then END. */
function answerWith(daemon: MockDaemon, chunks: Uint8Array[]): void {
  daemon.onOpen = (frame) => {
    for (const chunk of chunks) daemon.data(frame.reqId, chunk);
    daemon.end(frame.reqId);
  };
}

function stub(identity: Identity) {
  return env.TUNNEL.get(env.TUNNEL.idFromName(identity.id));
}

describe("daemon socket", () => {
  it("challenges, verifies the hello, and welcomes with the limits", async () => {
    const { daemon, identity } = await tunnel({ node: "nas", agent: "cronstable/1.2.43 reach" });
    expect(daemon.upgradeHeaders.get("sec-websocket-protocol")).toBe(SUBPROTOCOL);
    expect(daemon.challenge).not.toBeNull();
    expect(daemon.challenge!.relay).toBe("relay.test");
    expect(b64Decode(daemon.challenge!.nonce)).toHaveLength(32);
    expect(daemon.welcome).toEqual({
      v: 1,
      type: "welcome",
      limits: {
        maxBody: 1_048_576,
        maxChunk: 65_536,
        maxStreamS: 2,
        maxInflight: 4,
        initialWindow: 262_144,
      },
    });
    // The verified hello is what creates the tunnel record.
    await runInDurableObject(stub(identity), async (_, state) => {
      const meta = await state.storage.get<{ node: string; admit: string[] }>("meta");
      expect(meta?.node).toBe("nas");
      expect(meta?.admit).toHaveLength(1);
    });
  });

  it("serves the fixture identity: the id is the key that signs", async () => {
    const identity = await identityFromSeed(vectors.identity.signSeed);
    expect(identity.id).toBe(vectors.identity.tunnelId);
    const credential = await mintCredential();
    const daemon = await connect(identity, { admit: [credential.admitId] });
    expect(daemon.welcome).not.toBeNull();
    answerWith(daemon, chunksOf(RESPONSE_STREAM));
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    expect(await readAll(res)).toEqual(RESPONSE_STREAM);
  });

  it("closes a bad signature with 4403", async () => {
    const identity = await freshIdentity();
    const daemon = await connect(identity, { badSignature: true });
    expect((await daemon.closed).code).toBe(CLOSE_BAD_SIGNATURE);
    // Nothing was recorded for the id: the app still sees an unknown tunnel.
    const credential = await mintCredential();
    expect((await post(identity.id, credential.header)).status).toBe(404);
  });

  it("closes a socket that never says hello with 4408", async () => {
    const identity = await freshIdentity();
    const daemon = await connect(identity, { hello: "none" });
    const t0 = Date.now();
    const closed = await daemon.closed;
    expect(closed.code).toBe(CLOSE_HELLO_TIMEOUT);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
  }, 10_000);

  it("lets the newest verified socket win, closing the older with 4409", async () => {
    const { identity, credential, daemon: older } = await tunnel();
    const newer = await connect(identity, { admit: [credential.admitId] });
    expect(newer.welcome).not.toBeNull();
    expect((await older.closed).code).toBe(CLOSE_SUPERSEDED);
    answerWith(newer, [new Uint8Array([1, 2, 3])]);
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    expect(await readAll(res)).toEqual(new Uint8Array([1, 2, 3]));
    expect(older.frames).toHaveLength(0);
  });

  it("closes malformed control messages and early frames with 4400", async () => {
    const first = await (await tunnel()).daemon;
    first.sendText("not json");
    expect((await first.closed).code).toBe(CLOSE_PROTOCOL_ERROR);

    const second = (await tunnel()).daemon;
    second.sendText(JSON.stringify({ v: 1, type: "ping" }));
    expect((await second.closed).code).toBe(CLOSE_PROTOCOL_ERROR);

    const third = (await tunnel()).daemon;
    third.sendText(JSON.stringify({ v: 1, type: "hello" }));
    expect((await third.closed).code).toBe(CLOSE_PROTOCOL_ERROR);

    const identity = await freshIdentity();
    const silent = await connect(identity, { hello: "none" });
    silent.sendRaw(packFrame(FRAME_DATA, 1, new Uint8Array([1])));
    expect((await silent.closed).code).toBe(CLOSE_PROTOCOL_ERROR);

    const unverified = await connect(await freshIdentity(), { hello: "none" });
    unverified.admit([]);
    expect((await unverified.closed).code).toBe(CLOSE_PROTOCOL_ERROR);
  });

  it("closes a frame over the payload cap", async () => {
    const { daemon } = await tunnel();
    daemon.sendRaw(packFrame(FRAME_DATA, 1, new Uint8Array(1_114_113)));
    const closed = await daemon.closed;
    // 4400 from the relay; the runtime's own 1009 if it refuses the
    // message before the object sees it.
    expect([CLOSE_PROTOCOL_ERROR, 1009]).toContain(closed.code);
  });

  it("replaces the admit set on admit, revoking the old credential", async () => {
    const { identity, credential, daemon } = await tunnel();
    answerWith(daemon, []);
    expect((await post(identity.id, credential.header)).status).toBe(200);
    const replacement = await mintCredential();
    daemon.admit([replacement.admitId]);
    // The message is processed asynchronously; the new credential
    // becomes valid the moment it lands.
    for (let i = 0; i < 50; i += 1) {
      if ((await status(identity.id, replacement.header)).status === 200) break;
      await sleep(20);
    }
    expect((await status(identity.id, replacement.header)).status).toBe(200);
    expect((await post(identity.id, credential.header)).status).toBe(403);
    expect((await post(identity.id, replacement.header)).status).toBe(200);
  });

  it("takes the daemon offline on bye", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.bye();
    expect((await daemon.closed).code).toBe(1000);
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(503);
    const presence = (await (await status(identity.id, credential.header)).json()) as {
      online: boolean;
      lastSeenAt: string;
    };
    expect(presence.online).toBe(false);
    expect(Date.now() - Date.parse(presence.lastSeenAt)).toBeLessThan(5000);
  });

  it("serves through a socket that survived an eviction of the object", async () => {
    const { identity, credential, daemon } = await tunnel();
    await evictDurableObject(stub(identity));
    answerWith(daemon, [new Uint8Array([9, 9])]);
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    expect(await readAll(res)).toEqual(new Uint8Array([9, 9]));
    // The request counter came back from the attachment: no id reuse.
    expect(daemon.frames.map((f) => f.reqId)).toEqual([1]);
  });

  it("forgets a tunnel after 60 days without its daemon", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.close();
    await daemon.closed;
    // The close armed the expiry; age the record past it and let the
    // alarm find it on a fresh instance.
    await runInDurableObject(stub(identity), async (_, state) => {
      const meta = (await state.storage.get<{ lastSeenAt: number }>("meta"))!;
      await state.storage.put("meta", {
        ...meta,
        lastSeenAt: Date.now() - 61 * 24 * 3600 * 1000,
      });
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
    await evictDurableObject(stub(identity), { webSockets: "close" });
    expect(await runDurableObjectAlarm(stub(identity))).toBe(true);
    await runInDurableObject(stub(identity), async (_, state) => {
      expect((await state.storage.list()).size).toBe(0);
    });
    expect((await status(identity.id, credential.header)).status).toBe(404);
  });

  it("drops frames for unknown requests, cancelling a stray DATA", async () => {
    const { daemon } = await tunnel();
    daemon.data(99, new Uint8Array([1]));
    const cancel = await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(cancel.reqId).toBe(99);
    expect(daemon.cancels(99)).toEqual([CANCEL_CLIENT_GONE]);
    daemon.end(98);
    daemon.reject(97, 1, "x");
    await sleep(100);
    expect(daemon.frames).toHaveLength(1);
    expect(daemon.welcome).not.toBeNull();
  });
});

describe("relayed requests", () => {
  it("admits a credential in the set and refuses one outside it", async () => {
    const { identity, credential, daemon } = await tunnel();
    answerWith(daemon, []);
    const stranger = await mintCredential();
    const refused = await post(identity.id, stranger.header);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ v: 1, error: "reach token not admitted" });
    expect(daemon.frames).toHaveLength(0);
    expect((await post(identity.id, credential.header)).status).toBe(200);
  });

  it("404s an id no daemon has claimed and writes nothing", async () => {
    const identity = await freshIdentity();
    const credential = await mintCredential();
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ v: 1, error: "unknown tunnel" });
    expect((await status(identity.id, credential.header)).status).toBe(404);
    await runInDurableObject(stub(identity), async (_, state) => {
      expect((await state.storage.list()).size).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it("503s with lastSeenAt and Retry-After while the daemon is away", async () => {
    const { identity, credential, daemon } = await tunnel();
    const before = Date.now();
    daemon.close();
    await daemon.closed;
    let res: Response = await post(identity.id, credential.header);
    for (let i = 0; i < 50 && res.status !== 503; i += 1) {
      await sleep(20);
      res = await post(identity.id, credential.header);
    }
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("5");
    const body = (await res.json()) as { error: string; lastSeenAt: string };
    expect(body.error).toBe("daemon offline");
    expect(Date.parse(body.lastSeenAt)).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.parse(body.lastSeenAt)).toBeLessThanOrEqual(Date.now());
  });

  it("hands the body to the daemon verbatim and streams DATA back verbatim", async () => {
    const { identity, credential, daemon } = await tunnel();
    let opened: Frame | null = null;
    daemon.onOpen = (frame) => {
      opened = frame;
      const chunks = chunksOf(RESPONSE_STREAM);
      daemon.data(frame.reqId, chunks[0]!);
      setTimeout(() => {
        daemon.data(frame.reqId, concat(chunks[1]!, chunks[2]!));
        daemon.end(frame.reqId);
      }, 50);
    };
    const res = await post(identity.id, credential.header, HELLO_BODY);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(opened).not.toBeNull();
    expect(opened!.reqId).toBe(1);
    expect(opened!.payload).toEqual(HELLO_BODY);
    expect(await readAll(res)).toEqual(RESPONSE_STREAM);
  });

  it("answers END without DATA as an empty 200", async () => {
    const { identity, credential, daemon } = await tunnel();
    answerWith(daemon, []);
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(await readAll(res)).toHaveLength(0);
  });

  it("maps each REJECT code to its status", async () => {
    const { identity, credential, daemon } = await tunnel();
    const expected: [number, number, string][] = [
      [1, 409, "key mismatch"],
      [2, 409, "replay"],
      [3, 429, "daemon busy"],
      [4, 413, "request too large for the daemon"],
      [5, 502, "daemon aborted"],
    ];
    for (const [code, statusCode, error] of expected) {
      daemon.onOpen = (frame) => daemon.reject(frame.reqId, code, "because");
      const res = await post(identity.id, credential.header);
      expect(res.status, `REJECT ${code}`).toBe(statusCode);
      expect(await res.json()).toEqual({ v: 1, error });
      if (statusCode === 429) expect(res.headers.get("retry-after")).toBe("1");
    }
  });

  it("504s when no first frame arrives, cancelling at the daemon", async () => {
    const { identity, credential, daemon } = await tunnel();
    const t0 = Date.now();
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(504);
    expect(await res.json()).toEqual({ v: 1, error: "no response" });
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
    await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(daemon.cancels(1)).toEqual([CANCEL_CLIENT_GONE]);
    // A late answer is dropped, and the daemon told to stop.
    daemon.data(1, new Uint8Array([1]));
    await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(daemon.cancels(1)).toEqual([CANCEL_CLIENT_GONE, CANCEL_CLIENT_GONE]);
  }, 10_000);

  it("fails an answered request that goes stale", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array([1]));
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    expect((await reader.read()).value).toEqual(new Uint8Array([1]));
    const t0 = Date.now();
    await expect(reader.read()).rejects.toThrow();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1500);
    await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(daemon.cancels(1)).toEqual([CANCEL_CLIENT_GONE]);
  }, 10_000);

  it("502s every pending request when the daemon socket drops", async () => {
    const { identity, credential, daemon } = await tunnel();
    let answered: Frame | null = null;
    daemon.onOpen = (frame) => {
      if (answered === null) {
        answered = frame;
        daemon.data(frame.reqId, new Uint8Array([1]));
      }
    };
    const streaming = await post(identity.id, credential.header);
    expect(streaming.status).toBe(200);
    const waiting = post(identity.id, credential.header);
    await daemon.nextOpen();
    await daemon.nextOpen();
    daemon.close();
    const res = await waiting;
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ v: 1, error: "daemon aborted" });
    const reader = streaming.body!.getReader();
    await reader.read();
    await expect(reader.read()).rejects.toThrow();
  });

  it("sends CANCEL 1 when the client cancels the response body", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array([1]));
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    await res.body!.cancel();
    const cancel = await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(cancel.reqId).toBe(1);
    expect(daemon.cancels(1)).toEqual([CANCEL_CLIENT_GONE]);
  });

  it("sends CANCEL 1 when the client aborts before any answer", async () => {
    const { identity, credential, daemon } = await tunnel();
    const controller = new AbortController();
    const pending = post(identity.id, credential.header, HELLO_BODY, {}, {
      signal: controller.signal,
    });
    await daemon.nextOpen();
    controller.abort();
    await expect(pending).rejects.toThrow();
    const cancel = await daemon.nextFrame((f) => f.type === FRAME_CANCEL);
    expect(cancel.reqId).toBe(1);
    expect(daemon.cancels(1)).toEqual([CANCEL_CLIENT_GONE]);
  });

  it("grants WINDOW credit as the client drains the response", async () => {
    const { identity, credential, daemon } = await tunnel();
    const chunk = new Uint8Array(65_536);
    crypto.getRandomValues(chunk);
    daemon.onOpen = (frame) => {
      // Exactly the initial window, in four full chunks.
      for (let i = 0; i < 4; i += 1) daemon.data(frame.reqId, chunk);
    };
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    await sleep(300);
    const before = daemon.windows(1);
    const reader = res.body!.getReader();
    let received = 0;
    while (received < 4 * chunk.length) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.length;
    }
    expect(received).toBe(4 * chunk.length);
    await daemon.nextFrame((f) => f.type === FRAME_WINDOW);
    const after = daemon.windows(1);
    // One top-up, back to a full window, once the reads drained the queue.
    expect(after.reduce((a, b) => a + b, 0)).toBe(262_144);
    expect(after.length).toBeGreaterThan(before.length);
    expect(before.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(262_144);
    // The credit is usable: the daemon can send another window's worth.
    for (let i = 0; i < 4; i += 1) daemon.data(1, chunk);
    daemon.end(1);
    let rest = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      rest += value.length;
    }
    expect(rest).toBe(4 * chunk.length);
  }, 10_000);

  it("closes the socket when the daemon sends past its credit", async () => {
    const { identity, credential, daemon } = await tunnel();
    // One frame past the whole initial window, before anything could
    // have drained and earned a top-up.
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array(300_000));
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ v: 1, error: "daemon aborted" });
    expect((await daemon.closed).code).toBe(CLOSE_PROTOCOL_ERROR);
  });
});

describe("caps", () => {
  it("429s past the in-flight cap and clears once the daemon answers", async () => {
    const { identity, credential, daemon } = await tunnel();
    const held = [1, 2, 3, 4].map(() => post(identity.id, credential.header));
    for (let i = 0; i < 4; i += 1) await daemon.nextOpen();
    const fifth = await post(identity.id, credential.header);
    expect(fifth.status).toBe(429);
    expect(fifth.headers.get("retry-after")).toBe("1");
    expect(await errorOf(fifth)).toMatch(/in flight/);
    for (const reqId of [1, 2, 3, 4]) daemon.end(reqId);
    for (const res of await Promise.all(held)) expect(res.status).toBe(200);
    answerWith(daemon, []);
    expect((await post(identity.id, credential.header)).status).toBe(200);
  });

  it("429s an admit id whose bucket is spent, with Retry-After", async () => {
    const { identity, credential, daemon } = await tunnel();
    answerWith(daemon, []);
    for (let i = 0; i < 6; i += 1) {
      expect((await post(identity.id, credential.header)).status).toBe(200);
    }
    const limited = await post(identity.id, credential.header);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expect(await errorOf(limited)).toMatch(/rate limited/);
    // Another credential's bucket is its own.
    const other = await mintCredential();
    daemon.admit([credential.admitId, other.admitId]);
    for (let i = 0; i < 50; i += 1) {
      if ((await status(identity.id, other.header)).status === 200) break;
      await sleep(20);
    }
    expect((await post(identity.id, other.header)).status).toBe(200);
  });

  it("429s after the minute's unadmitted credentials, never charging the daemon", async () => {
    const { identity, credential, daemon } = await tunnel();
    answerWith(daemon, []);
    for (let i = 0; i < 5; i += 1) {
      const stranger = await mintCredential();
      expect((await post(identity.id, stranger.header)).status).toBe(403);
    }
    const stranger = await mintCredential();
    const limited = await status(identity.id, stranger.header);
    expect(limited.status).toBe(429);
    const retry = Number(limited.headers.get("retry-after"));
    expect(retry).toBeGreaterThanOrEqual(1);
    expect(retry).toBeLessThanOrEqual(60);
    // The admitted credential and the daemon socket are unaffected.
    expect((await post(identity.id, credential.header)).status).toBe(200);
    expect(daemon.welcome).not.toBeNull();
  });

  it("cuts the newest stream past the concurrent-stream cap with CANCEL 2", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array([1]));
    const first = await post(identity.id, credential.header);
    await sleep(20);
    const second = await post(identity.id, credential.header);
    await sleep(20);
    const third = await post(identity.id, credential.header);
    for (const res of [first, second, third]) expect(res.status).toBe(200);
    const tick = setInterval(() => {
      for (const reqId of [1, 2, 3]) daemon.data(reqId, new Uint8Array([0]));
    }, 300);
    try {
      const cancel = await daemon.nextFrame(
        (f) => f.type === FRAME_CANCEL && f.reqId === 3,
        3000,
      );
      expect(cancel.reqId).toBe(3);
      expect(daemon.cancels(3)).toEqual([CANCEL_STREAM_CAP]);
      expect(daemon.cancels(1)).toEqual([]);
      expect(daemon.cancels(2)).toEqual([]);
      // The third's body closes short; the first two stream on.
      await readAll(third);
    } finally {
      clearInterval(tick);
    }
  }, 10_000);

  it("cuts a stream at its lifetime with CANCEL 2", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array([1]));
    const t0 = Date.now();
    const res = await post(identity.id, credential.header);
    expect(res.status).toBe(200);
    const tick = setInterval(() => daemon.data(1, new Uint8Array([0])), 300);
    try {
      const body = await readAll(res);
      expect(body.length).toBeGreaterThan(1);
      expect(Date.now() - t0).toBeGreaterThanOrEqual(1900);
      expect(Date.now() - t0).toBeLessThan(3500);
      expect(daemon.cancels(1)).toEqual([CANCEL_STREAM_CAP]);
    } finally {
      clearInterval(tick);
    }
  }, 10_000);

  it("429s until midnight UTC once the day's stream allowance is spent", async () => {
    const { identity, credential, daemon } = await tunnel();
    daemon.onOpen = (frame) => daemon.data(frame.reqId, new Uint8Array([1]));
    for (const reqId of [1, 2]) {
      const res = await post(identity.id, credential.header);
      expect(res.status).toBe(200);
      const tick = setInterval(() => daemon.data(reqId, new Uint8Array([0])), 300);
      try {
        await readAll(res);
      } finally {
        clearInterval(tick);
      }
      expect(daemon.cancels(reqId)).toEqual([CANCEL_STREAM_CAP]);
    }
    const limited = await post(identity.id, credential.header);
    expect(limited.status).toBe(429);
    expect(await errorOf(limited)).toMatch(/daily/);
    const retry = Number(limited.headers.get("retry-after"));
    expect(retry).toBeGreaterThanOrEqual(1);
    expect(retry).toBeLessThanOrEqual(86_400);
    await runInDurableObject(stub(identity), async (_, state) => {
      const usage = [...(await state.storage.list<number>({ prefix: "usage:" })).values()];
      expect(usage).toHaveLength(1);
      expect(usage[0]).toBeGreaterThanOrEqual(3500);
    });
  }, 15_000);
});

describe("status", () => {
  it("reports presence to an admitted credential only", async () => {
    const { identity, credential } = await tunnel({ node: "nas" });
    const res = await status(identity.id, credential.header);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ v: 1, online: true, node: "nas" });
    expect(typeof body.lastSeenAt).toBe("string");
    const stranger = await mintCredential();
    expect((await status(identity.id, stranger.header)).status).toBe(403);
    expect((await status(identity.id, null)).status).toBe(400);
    const unknown = await freshIdentity();
    expect((await status(unknown.id, credential.header)).status).toBe(404);
  });
});

describe("front Worker", () => {
  it("400s a malformed tunnel id on both routes", async () => {
    const credential = await mintCredential();
    const { identity } = await tunnel();
    const bad = [
      identity.id.slice(1),
      `${identity.id}A`,
      identity.id.replace(/[-_]/g, "+"),
      "a".repeat(43),
    ];
    for (const id of bad) {
      const res = await post(id, credential.header);
      expect(res.status, id).toBe(400);
      expect(await errorOf(res)).toMatch(/tunnel id/);
      const upgrade = await exports.default.fetch(
        `https://relay.test/v1/tunnel/${id}`,
        {
          headers: { upgrade: "websocket", "sec-websocket-protocol": SUBPROTOCOL },
        },
      );
      expect(upgrade.status, id).toBe(400);
    }
  });

  it("400s an upgrade without Upgrade or without the subprotocol", async () => {
    const identity = await freshIdentity();
    const plain = await exports.default.fetch(
      `https://relay.test/v1/tunnel/${identity.id}`,
    );
    expect(plain.status).toBe(400);
    expect(await errorOf(plain)).toMatch(/upgrade/);
    await expect(
      MockDaemon.connect(identity, { headers: { "sec-websocket-protocol": null } }),
    ).rejects.toThrow(/400/);
    await expect(
      MockDaemon.connect(identity, {
        headers: { "sec-websocket-protocol": "cronstable-reach-v2" },
      }),
    ).rejects.toThrow(/400/);
    const posted = await exports.default.fetch(
      `https://relay.test/v1/tunnel/${identity.id}`,
      { method: "POST" },
    );
    expect(posted.status).toBe(405);
    expect(posted.headers.get("allow")).toBe("GET");
  });

  it("400s a missing or malformed Authorization", async () => {
    const { identity } = await tunnel();
    const missing = await post(identity.id, null);
    expect(missing.status).toBe(400);
    expect(await errorOf(missing)).toMatch(/authorization/i);
    expect((await post(identity.id, "Bearer abc")).status).toBe(400);
    expect((await post(identity.id, "Reach short")).status).toBe(400);
    expect((await status(identity.id, "Reach short")).status).toBe(400);
  });

  it("400s a POST that is not application/octet-stream", async () => {
    const { identity, credential } = await tunnel();
    const res = await post(identity.id, credential.header, HELLO_BODY, {
      "content-type": "application/json",
    });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/octet-stream/);
    const parameterized = await post(identity.id, credential.header, HELLO_BODY, {
      "content-type": "application/octet-stream; charset=binary",
    });
    expect(parameterized.status).not.toBe(400);
  });

  it("411s a POST without Content-Length", async () => {
    const { identity, credential } = await tunnel();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(HELLO_BODY);
        controller.close();
      },
    });
    const res = await post(identity.id, credential.header, body);
    expect(res.status).toBe(411);
  });

  it("pins the POST cap at 1,052,672 bytes", async () => {
    const identity = await freshIdentity();
    const credential = await mintCredential();
    // At the cap the front Worker lets it through (the unknown id
    // answers 404 from the object); one byte more is refused here.
    const atCap = await post(identity.id, credential.header, new Uint8Array(POST_CAP));
    expect(atCap.status).toBe(404);
    const over = await post(
      identity.id,
      credential.header,
      new Uint8Array(POST_CAP + 1),
    );
    expect(over.status).toBe(413);
    expect(await errorOf(over)).toMatch(/large/);
  });

  it("405s other methods on the reach route", async () => {
    const { identity, credential } = await tunnel();
    const res = await exports.default.fetch(url(identity.id), {
      method: "DELETE",
      headers: { authorization: credential.header },
    });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, POST");
  });

  it("404s every /v1 route under the kill switch while push keeps running", async () => {
    const { identity, credential } = await tunnel();
    const off = { ...env, RELAY_REACH_ENABLED: "false" } as unknown as Env;
    const posted = await worker.fetch(
      new Request(url(identity.id), {
        method: "POST",
        headers: {
          authorization: credential.header,
          "content-type": "application/octet-stream",
        },
        body: HELLO_BODY,
      }),
      off,
    );
    expect(posted.status).toBe(404);
    expect(await posted.json()).toEqual({ v: 1, error: "unknown tunnel" });
    const upgrade = await worker.fetch(
      new Request(`https://relay.test/v1/tunnel/${identity.id}`, {
        headers: { upgrade: "websocket", "sec-websocket-protocol": SUBPROTOCOL },
      }),
      off,
    );
    expect(upgrade.status).toBe(404);
    const other = await worker.fetch(new Request("https://relay.test/v1/other"), off);
    expect(other.status).toBe(404);
    // Push is untouched: the banner and the envelope route still answer.
    const info = await worker.fetch(new Request("https://relay.test/"), off);
    expect(info.status).toBe(200);
    expect(await info.text()).toContain("Reach");
    const envelope = await worker.fetch(
      new Request("https://relay.test/", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{not json",
      }),
      off,
    );
    expect(envelope.status).toBe(400);
    // With the switch on, the same request is served.
    expect((await status(identity.id, credential.header)).status).toBe(200);
  });
});
