/**
 * A daemon stand-in for the Reach suite.  It connects to the worker
 * under test over a real WebSocket (the loopback `exports.default`
 * binding, the same path tests/relay.spec.ts drives HTTP through),
 * answers the challenge with Ed25519 the way cronstable/reach.py does,
 * and records every frame the relay sends.  A test scripts the answers
 * to OPEN frames: DATA and END, a REJECT, a delay, or silence.
 *
 * Keys: `identityFromSeed` turns the fixture's 32-byte signing seed into
 * a WebCrypto key through the PKCS#8 wrapper (a fixed 16-byte DER prefix
 * plus the seed), and `freshIdentity` mints a throwaway pair so each
 * test gets its own tunnel object.
 */

import { exports } from "cloudflare:workers";

import {
  admitIdOf,
  b64Decode,
  b64Encode,
  b64urlEncode,
  challengeMessage,
  decodeKey43,
  FRAME_CANCEL,
  FRAME_DATA,
  FRAME_END,
  FRAME_OPEN,
  FRAME_REJECT,
  FRAME_WINDOW,
  packFrame,
  parseFrame,
  SUBPROTOCOL,
  type Frame,
} from "../src/reach";

export interface Identity {
  /** The tunnel id: the raw Ed25519 public key, base64url. */
  id: string;
  idBytes: Uint8Array;
  /** The signing half. */
  key: CryptoKey;
}

/** PKCS#8 wrapper for an Ed25519 seed: `302e020100300506032b657004220420 ‖ seed`. */
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export async function identityFromSeed(seedB64: string): Promise<Identity> {
  const seed = b64Decode(seedB64);
  if (seed === null || seed.length !== 32) throw new Error("seed is 32 bytes");
  const der = concat(hexToBytes(PKCS8_ED25519_PREFIX), seed);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  // The JWK's `x` is the raw public key, base64url without padding:
  // exactly the tunnel id's encoding.
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  const id = jwk.x;
  if (typeof id !== "string") throw new Error("no public half exported");
  const idBytes = decodeKey43(id);
  if (idBytes === null) throw new Error("exported key is not 32 bytes");
  return { id, idBytes, key };
}

export async function freshIdentity(): Promise<Identity> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer,
  );
  return { id: b64urlEncode(raw), idBytes: raw, key: pair.privateKey };
}

export async function signChallenge(
  identity: Identity,
  relay: string,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.sign("Ed25519", identity.key, challengeMessage(relay, nonce)),
  );
}

export interface Credential {
  /** The `Authorization` header value. */
  header: string;
  raw: Uint8Array;
  /** What the daemon puts in its admit set. */
  admitId: string;
}

/** A random credential and the admit id that admits it. */
export async function mintCredential(): Promise<Credential> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return { header: `Reach ${b64urlEncode(raw)}`, raw, admitId: await admitIdOf(raw) };
}

export interface ConnectOptions {
  admit?: string[];
  node?: string;
  agent?: string;
  maxBody?: number;
  /** "auto" answers the challenge (the default); "none" stays silent. */
  hello?: "auto" | "none";
  /** Answer with a corrupted signature. */
  badSignature?: boolean;
  /** Extra upgrade headers, or overrides (a null value drops one). */
  headers?: Record<string, string | null>;
}

export interface Closed {
  code: number;
  reason: string;
}

const CONNECT_TIMEOUT_MS = 3000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class MockDaemon {
  /** Every binary frame from the relay, in order. */
  readonly frames: Frame[] = [];
  /** Every control message from the relay, in order. */
  readonly controls: Record<string, unknown>[] = [];
  challenge: { nonce: string; relay: string } | null = null;
  welcome: Record<string, unknown> | null = null;
  /** Resolves when the socket closes, with the relay's code. */
  readonly closed: Promise<Closed>;
  /** Called for every OPEN frame; the test's script. */
  onOpen: ((frame: Frame) => void | Promise<void>) | null = null;
  private readonly queue: Frame[] = [];
  private readonly waiters: {
    filter: (frame: Frame) => boolean;
    resolve: (frame: Frame) => void;
  }[] = [];
  private isClosed = false;

  private constructor(
    readonly identity: Identity,
    readonly response: Response,
    private readonly ws: WebSocket,
    private readonly opts: ConnectOptions,
  ) {
    this.closed = new Promise((resolve) => {
      ws.addEventListener("close", (event) => {
        this.isClosed = true;
        resolve({ code: event.code, reason: event.reason });
      });
      ws.addEventListener("error", () => {
        this.isClosed = true;
        resolve({ code: 1006, reason: "error" });
      });
    });
    // The client side of the pair hands binary messages over as Blobs,
    // whose bytes arrive asynchronously; chaining keeps frames in order.
    let inbox: Promise<void> = Promise.resolve();
    ws.addEventListener("message", (event) => {
      const data: unknown = event.data;
      inbox = inbox
        .then(() => this.receive(data))
        .catch((err: unknown) => {
          this.failure = err instanceof Error ? err : new Error(String(err));
        });
    });
  }

  /** The first error raised while handling a relay message, if any. */
  failure: Error | null = null;

  /** Dial the worker; resolves once the welcome (or a close) arrives. */
  static async connect(
    identity: Identity,
    opts: ConnectOptions = {},
  ): Promise<MockDaemon> {
    const headers = new Headers({
      upgrade: "websocket",
      connection: "Upgrade",
      "sec-websocket-protocol": SUBPROTOCOL,
      "user-agent": "cronstable/0.0.0 reach",
    });
    for (const [name, value] of Object.entries(opts.headers ?? {})) {
      if (value === null) headers.delete(name);
      else headers.set(name, value);
    }
    const response = await exports.default.fetch(
      `https://relay.test/v1/tunnel/${identity.id}`,
      { headers },
    );
    if (response.status !== 101 || response.webSocket === null) {
      throw new Error(
        `upgrade refused: ${response.status} ${await response.text()}`,
      );
    }
    const ws = response.webSocket;
    ws.accept();
    const daemon = new MockDaemon(identity, response, ws, opts);
    await daemon.settled();
    return daemon;
  }

  /** The upgrade's 101 headers (the echoed subprotocol lives here). */
  get upgradeHeaders(): Headers {
    return this.response.headers;
  }

  private async settled(): Promise<void> {
    const deadline = Date.now() + CONNECT_TIMEOUT_MS;
    const wantWelcome = (this.opts.hello ?? "auto") === "auto";
    while (Date.now() < deadline) {
      if (this.isClosed) return;
      if (wantWelcome ? this.welcome !== null : this.challenge !== null) return;
      await sleep(10);
    }
    throw new Error("the relay never finished the handshake");
  }

  private async receive(data: unknown): Promise<void> {
    if (typeof data === "string") {
      const msg = JSON.parse(data) as Record<string, unknown>;
      this.controls.push(msg);
      if (msg.type === "challenge") {
        this.challenge = { nonce: String(msg.nonce), relay: String(msg.relay) };
        if ((this.opts.hello ?? "auto") === "auto") await this.hello();
      } else if (msg.type === "welcome") {
        this.welcome = msg;
      }
      return;
    }
    const buffer =
      data instanceof ArrayBuffer ? data : await (data as Blob).arrayBuffer();
    const frame = parseFrame(buffer);
    if ("error" in frame) throw new Error(frame.error);
    this.frames.push(frame);
    const index = this.waiters.findIndex((w) => w.filter(frame));
    if (index >= 0) {
      const waiter = this.waiters.splice(index, 1)[0]!;
      waiter.resolve(frame);
    } else {
      this.queue.push(frame);
    }
    if (frame.type === FRAME_OPEN && this.onOpen !== null) await this.onOpen(frame);
  }

  /** Answer the challenge the way the daemon does. */
  async hello(): Promise<void> {
    if (this.challenge === null) throw new Error("no challenge yet");
    const nonce = b64Decode(this.challenge.nonce);
    if (nonce === null) throw new Error("challenge nonce is not base64");
    const sig = await signChallenge(this.identity, this.challenge.relay, nonce);
    if (this.opts.badSignature) sig[0] = sig[0]! ^ 0xff;
    this.sendText(
      JSON.stringify({
        v: 1,
        type: "hello",
        sig: b64Encode(sig),
        agent: this.opts.agent ?? "cronstable/0.0.0 reach",
        node: this.opts.node ?? "nas",
        admit: this.opts.admit ?? [],
        limits: { maxBody: this.opts.maxBody ?? 1_048_576 },
      }),
    );
  }

  /**
   * The next relay frame matching `filter`, earliest first; frames that
   * arrived before the call and were not handed out yet count.
   */
  nextFrame(
    filter: (frame: Frame) => boolean = () => true,
    timeoutMs = 3000,
  ): Promise<Frame> {
    const index = this.queue.findIndex(filter);
    if (index >= 0) return Promise.resolve(this.queue.splice(index, 1)[0]!);
    return new Promise((resolve, reject) => {
      const waiter = { filter, resolve };
      this.waiters.push(waiter);
      setTimeout(() => {
        const at = this.waiters.indexOf(waiter);
        if (at >= 0) {
          this.waiters.splice(at, 1);
          reject(new Error(`no frame within ${timeoutMs} ms`));
        }
      }, timeoutMs);
    });
  }

  /** The next OPEN frame. */
  nextOpen(timeoutMs?: number): Promise<Frame> {
    return this.nextFrame((f) => f.type === FRAME_OPEN, timeoutMs);
  }

  /** Every WINDOW frame seen so far for `reqId`, as credit values. */
  windows(reqId: number): number[] {
    return this.frames
      .filter((f) => f.type === FRAME_WINDOW && f.reqId === reqId)
      .map((f) => new DataView(f.payload.buffer, f.payload.byteOffset).getUint32(0));
  }

  /** The CANCEL reasons seen so far for `reqId`. */
  cancels(reqId: number): number[] {
    return this.frames
      .filter((f) => f.type === FRAME_CANCEL && f.reqId === reqId)
      .map((f) => new DataView(f.payload.buffer, f.payload.byteOffset).getUint16(0));
  }

  sendText(text: string): void {
    this.ws.send(text);
  }

  sendRaw(bytes: Uint8Array): void {
    this.ws.send(bytes);
  }

  send(type: number, reqId: number, payload?: Uint8Array): void {
    this.sendRaw(packFrame(type, reqId, payload));
  }

  data(reqId: number, bytes: Uint8Array): void {
    this.send(FRAME_DATA, reqId, bytes);
  }

  end(reqId: number): void {
    this.send(FRAME_END, reqId);
  }

  reject(reqId: number, code: number, reason = ""): void {
    const text = new TextEncoder().encode(reason);
    const payload = new Uint8Array(2 + text.length);
    new DataView(payload.buffer).setUint16(0, code);
    payload.set(text, 2);
    this.send(FRAME_REJECT, reqId, payload);
  }

  admit(ids: string[]): void {
    this.sendText(JSON.stringify({ v: 1, type: "admit", admit: ids }));
  }

  bye(): void {
    this.sendText(JSON.stringify({ v: 1, type: "bye" }));
  }

  close(code = 1000, reason = "test over"): void {
    if (this.isClosed) return;
    try {
      this.ws.close(code, reason);
    } catch {
      // Already closed by the relay.
    }
  }
}
