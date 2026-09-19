/**
 * One Durable Object per Reach tunnel (docs/reach-protocol.md in the
 * cronstable repo), keyed by the tunnel id: the daemon's WebSocket, the
 * admit set, and every request in flight between an app and that
 * daemon.  The relay copies sealed bytes in both directions and never
 * parses the inside of a frame.
 *
 * Storage layout (SQLite-backed KV):
 *   meta         -> Meta         node, agent, admit set, seen times;
 *                                written at the first verified hello and
 *                                never for an id no daemon has claimed
 *   strikes      -> StrikeState  this minute's unadmitted credentials
 *   usage:<day>  -> number       open-stream milliseconds that UTC day
 *
 * The daemon socket is a hibernatable WebSocket: between frames the
 * object can leave memory, so per-socket state (phase, nonce, request
 * counter) rides in the socket's attachment, and everything a request
 * needs while the daemon is offline is in `meta`.  Requests in flight
 * live in memory only: a streaming response keeps the object awake,
 * and a wake that finds no pending map has nothing to resume, so a
 * DATA frame for a request it does not know is answered with
 * `CANCEL 1`.  The object's alarm serves the hello timeout and the
 * record's expiry; per-request timers are ordinary timers, which is
 * fine for the same reason.
 *
 * A tunnel whose daemon has been away for RECORD_TTL_MS forgets
 * everything, so an abandoned identity leaves nothing behind.
 */

import { DurableObject } from "cloudflare:workers";

import {
  admitIdOf,
  b64Decode,
  b64Encode,
  bucketTake,
  CANCEL_CLIENT_GONE,
  CANCEL_STREAM_CAP,
  CLOSE_BAD_SIGNATURE,
  CLOSE_HELLO_TIMEOUT,
  CLOSE_PROTOCOL_ERROR,
  CLOSE_SUPERSEDED,
  FRAME_DATA,
  FRAME_END,
  FRAME_OPEN,
  FRAME_REJECT,
  frameBucketTake,
  jsonResponse as json,
  limitsFromEnv,
  maxPostBytes,
  nextReqId,
  offersSubprotocol,
  packCancel,
  packFrame,
  packWindow,
  parseControl,
  parseCredential,
  parseFrame,
  parseReachPath,
  parseReject,
  parseTunnelId,
  rejectToStatus,
  secondsUntilUtcMidnight,
  strike,
  STREAM_HIGH_WATER_MARK,
  SUBPROTOCOL,
  sweepIntervalMs,
  tunnelLogId,
  usageKey,
  verifyHello,
  welcomeLimits,
  type Bucket,
  type ReachLimits,
  type StrikeState,
} from "./reach";
import type { Env } from "./types";

/**
 * A socket is `challenged` until its hello verifies, `ready` while it
 * serves requests, and `closed` once the relay has closed it (the
 * runtime drops it from getWebSockets() shortly after).
 */
type Phase = "challenged" | "ready" | "closed";

/** Per-socket state; rides in the socket's attachment (16 KiB cap; this
 * stays under 1 KiB: the names are capped at MAX_NAME_CHARS). */
interface Attachment {
  /** The tunnel id, so a hibernation wake knows whose socket this is. */
  id: string;
  /** The host named in the challenge, part of the signed message. */
  relay: string;
  phase: Phase;
  /** The challenge nonce, base64. */
  nonce: string;
  /** Accept time, epoch ms. */
  since: number;
  node: string;
  agent: string;
  /** The last request id handed out on this socket (u32, never 0). */
  reqSeq: number;
}

/** What the relay keeps about a tunnel while the daemon is offline. */
interface Meta {
  node: string;
  agent: string;
  /** Admit ids, base64 of SHA-256 over each credential. */
  admit: string[];
  firstSeenAt: number;
  lastSeenAt: number;
}

interface Pending {
  reqId: number;
  ws: WebSocket;
  opened: number;
  lastFrameAt: number;
  /** The first daemon frame arrived and the Response has been returned. */
  answered: boolean;
  /** Open past the stream threshold. */
  stream: boolean;
  /** DATA credit granted and consumed, in bytes. */
  granted: number;
  received: number;
  bytesIn: number;
  bytesOut: number;
  controller: ReadableStreamDefaultController<Uint8Array> | null;
  /** Resolves the fetch handler's wait for the first frame. */
  answer: (response: Response) => void;
  done: boolean;
  signal: AbortSignal | null;
  onAbort: (() => void) | null;
}

/** How a pending request ends. */
interface Settle {
  /** For the log line. */
  outcome: string;
  /** The HTTP status an unanswered request returns (200 once answered). */
  status: number;
  /** A CANCEL reason to send the daemon, when it is still listening. */
  cancel?: number;
  /** What an unanswered request answers with; 502 by default. */
  response?: Response;
  /** Error (rather than close) an answered stream with this message. */
  error?: string;
}

const STREAM_HEADERS = {
  "content-type": "application/octet-stream",
  "cache-control": "no-store",
};

/** Refresh `meta.lastSeenAt` from a relayed request at most this often. */
const SEEN_REFRESH_MS = 60_000;

/** A tunnel no daemon has connected to for this long is deleted. */
const RECORD_TTL_MS = 60 * 24 * 3600 * 1000;

function offline(): Response {
  return json(502, { v: 1, error: "daemon aborted" });
}

export class TunnelState extends DurableObject<Env> {
  private readonly limits: ReachLimits;
  private readonly attachments = new WeakMap<WebSocket, Attachment>();
  private readonly frameBuckets = new WeakMap<WebSocket, Bucket>();
  private readonly admitBuckets = new Map<string, Bucket>();
  private readonly pending = new Map<number, Pending>();
  /** `undefined` until loaded; `null` when no daemon has ever claimed the id. */
  private meta: Meta | null | undefined;
  private strikes: StrikeState | undefined;
  private usage: { key: string; ms: number } | null = null;
  private usageLoading: { key: string; promise: Promise<{ key: string; ms: number }> } | null =
    null;
  private sweep: ReturnType<typeof setInterval> | null = null;
  private tunnelId = "";
  private logId = "";

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.limits = limitsFromEnv(env);
  }

  // ------------------------------------------------------------- routes

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const route = parseReachPath(url.pathname);
    if (route === null || parseTunnelId(route.id) === null) {
      return json(400, { v: 1, error: "malformed tunnel id" });
    }
    await this.identify(route.id);
    if (route.kind === "tunnel") return this.upgrade(request, url);
    if (request.method === "GET") return this.status(request);
    if (request.method !== "POST") {
      return json(405, { v: 1, error: "method not allowed" }, { allow: "GET, POST" });
    }
    return this.relay(request);
  }

  /**
   * GET /v1/tunnel/{id}: accept the daemon's socket and challenge it.
   * The socket serves nothing until its hello verifies.
   */
  private async upgrade(request: Request, url: URL): Promise<Response> {
    if ((request.headers.get("upgrade") ?? "").toLowerCase() !== "websocket") {
      return json(400, { v: 1, error: "websocket upgrade required" });
    }
    if (!offersSubprotocol(request.headers.get("sec-websocket-protocol"))) {
      return json(400, { v: 1, error: `subprotocol ${SUBPROTOCOL} required` });
    }
    const now = Date.now();
    const nonce = new Uint8Array(32);
    crypto.getRandomValues(nonce);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const att: Attachment = {
      id: this.tunnelId,
      relay: url.host,
      phase: "challenged",
      nonce: b64Encode(nonce),
      since: now,
      node: "",
      agent: "",
      reqSeq: 0,
    };
    this.ctx.acceptWebSocket(server, ["daemon"]);
    this.save(server, att);
    server.send(
      JSON.stringify({ v: 1, type: "challenge", nonce: att.nonce, relay: url.host }),
    );
    await this.armAlarm(now + this.limits.helloTimeoutMs);
    this.log("tunnel", { event: "challenge" });
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "sec-websocket-protocol": SUBPROTOCOL },
    });
  }

  /** GET /v1/reach/{id}: presence, behind the same admission as a request. */
  private async status(request: Request): Promise<Response> {
    const t0 = Date.now();
    const credential = parseCredential(request.headers.get("authorization"));
    if (credential === null) {
      return this.reply(400, { v: 1, error: "authorization must be Reach <credential>" }, t0);
    }
    const meta = await this.loadMeta();
    if (meta === null) return this.reply(404, { v: 1, error: "unknown tunnel" }, t0);
    if (!meta.admit.includes(await admitIdOf(credential))) return this.refuse(t0);
    const online = this.daemonSocket() !== null;
    return this.reply(
      200,
      {
        v: 1,
        online,
        lastSeenAt: new Date(online ? t0 : meta.lastSeenAt).toISOString(),
        node: meta.node === "" ? null : meta.node,
      },
      t0,
    );
  }

  /**
   * POST /v1/reach/{id}: admit the caller, hand the sealed body to the
   * daemon as one OPEN frame, and answer with whatever the daemon's
   * first frame says: a streaming 200 fed by DATA frames, an empty 200
   * on a bare END, or the status a REJECT maps to.
   */
  private async relay(request: Request): Promise<Response> {
    const t0 = Date.now();
    const l = this.limits;
    const credential = parseCredential(request.headers.get("authorization"));
    if (credential === null) {
      return this.reply(400, { v: 1, error: "authorization must be Reach <credential>" }, t0);
    }
    const meta = await this.loadMeta();
    if (meta === null) return this.reply(404, { v: 1, error: "unknown tunnel" }, t0);
    const admitId = await admitIdOf(credential);
    if (!meta.admit.includes(admitId)) return this.refuse(t0);
    const ws = this.daemonSocket();
    if (ws === null) {
      return this.reply(
        503,
        {
          v: 1,
          error: "daemon offline",
          lastSeenAt: new Date(meta.lastSeenAt).toISOString(),
        },
        t0,
        { "retry-after": "5" },
      );
    }
    if (this.pending.size >= l.maxInflight) {
      return this.reply(
        429,
        { v: 1, error: "too many requests in flight" },
        t0,
        { "retry-after": "1" },
      );
    }
    const bucket = bucketTake(
      this.admitBuckets.get(admitId),
      t0,
      l.admitBurst,
      l.admitRefillPerS,
    );
    this.admitBuckets.set(admitId, bucket.bucket);
    if (!bucket.ok) {
      return this.reply(
        429,
        { v: 1, error: "reach token is rate limited" },
        t0,
        { "retry-after": String(bucket.retryAfterS) },
      );
    }
    if ((await this.usageMs(t0)) >= l.dailyStreamMs) {
      return this.reply(
        429,
        { v: 1, error: "daily stream allowance exhausted" },
        t0,
        { "retry-after": String(secondsUntilUtcMidnight(t0)) },
      );
    }
    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > maxPostBytes(l)) {
      return this.reply(413, { v: 1, error: "body too large" }, t0);
    }
    if (meta.lastSeenAt < t0 - SEEN_REFRESH_MS) {
      meta.lastSeenAt = t0;
      void this.ctx.storage.put("meta", meta);
    }

    const att = this.attachment(ws);
    if (att === null) return this.reply(503, { v: 1, error: "daemon offline" }, t0);
    att.reqSeq = nextReqId(att.reqSeq);
    this.save(ws, att);
    const reqId = att.reqSeq;
    let answer: (response: Response) => void = () => {};
    const first = new Promise<Response>((resolve) => {
      answer = resolve;
    });
    const p: Pending = {
      reqId,
      ws,
      opened: t0,
      lastFrameAt: t0,
      answered: false,
      stream: false,
      granted: l.initialWindow,
      received: 0,
      bytesIn: body.length,
      bytesOut: 0,
      controller: null,
      answer,
      done: false,
      signal: request.signal ?? null,
      onAbort: null,
    };
    // The caller hanging up ends the request at the daemon too.  The
    // signal fires on a client disconnect under the enable_request_signal
    // compatibility flag; a consumer that cancels the response body is
    // caught by the stream's cancel() below.
    p.onAbort = () => {
      this.settle(p, { outcome: "client", status: 499, cancel: CANCEL_CLIENT_GONE });
    };
    p.signal?.addEventListener("abort", p.onAbort);
    this.pending.set(reqId, p);
    this.ensureSweep();
    if (!this.sendSafe(ws, packFrame(FRAME_OPEN, reqId, body))) {
      this.settle(p, { outcome: "abort", status: 502, response: offline() });
      return first;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), l.firstByteMs);
      });
      const response = await Promise.race([first, timeout]);
      if (response !== null) return response;
      this.settle(p, {
        outcome: "timeout",
        status: 504,
        cancel: CANCEL_CLIENT_GONE,
        response: json(504, { v: 1, error: "no response" }),
      });
      return await first;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /** An unadmitted credential: 403, or 429 once the minute's strikes are spent. */
  private async refuse(t0: number): Promise<Response> {
    const stored =
      this.strikes ?? (await this.ctx.storage.get<StrikeState>("strikes"));
    const result = strike(stored, t0, this.limits.strikesPerMinute);
    this.strikes = result.state;
    await this.ctx.storage.put("strikes", result.state);
    if (result.limited) {
      return this.reply(
        429,
        { v: 1, error: "too many unadmitted credentials" },
        t0,
        { "retry-after": String(result.retryAfterS) },
      );
    }
    return this.reply(403, { v: 1, error: "reach token not admitted" }, t0);
  }

  // ------------------------------------------------------------- socket

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const att = this.attachment(ws);
    if (att === null) {
      this.closeQuietly(ws, CLOSE_PROTOCOL_ERROR, "no socket state");
      return;
    }
    await this.identify(att.id);
    const now = Date.now();
    const taken = frameBucketTake(
      this.frameBuckets.get(ws),
      now,
      this.limits.frameRatePerS,
      this.limits.frameBurst,
    );
    this.frameBuckets.set(ws, taken.bucket);
    if (!taken.ok) {
      this.drop(ws, att, CLOSE_PROTOCOL_ERROR, "frame rate exceeded", "frame_rate");
      return;
    }
    if (typeof message === "string") await this.control(ws, att, message, now);
    else this.frame(ws, att, message, now);
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    await this.gone(ws, code);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.gone(ws, 1006);
  }

  /**
   * The daemon's side closed or broke: fail its requests, note the
   * time, and finish the closing handshake.  With the hibernation API
   * the reciprocal Close frame is this handler's to send; without it
   * the daemon waits out its own timeout and records a 1006.
   */
  private async gone(ws: WebSocket, code: number): Promise<void> {
    const att = this.attachment(ws);
    if (att !== null) await this.identify(att.id);
    this.failPending(ws);
    const wasReady = att !== null && att.phase === "ready";
    if (att !== null) {
      att.phase = "closed";
      this.save(ws, att);
    }
    const reply = code === 1000 || (code >= 3000 && code <= 4999) ? code : 1000;
    this.closeQuietly(ws, reply, "closed");
    if (wasReady) {
      const now = Date.now();
      await this.touchMeta(now);
      await this.armAlarm(now + RECORD_TTL_MS);
    }
    this.log("tunnel", { event: "close", code });
  }

  private async control(
    ws: WebSocket,
    att: Attachment,
    text: string,
    now: number,
  ): Promise<void> {
    const msg = parseControl(text);
    if ("error" in msg) {
      this.drop(ws, att, CLOSE_PROTOCOL_ERROR, msg.error, "protocol_error");
      return;
    }
    switch (msg.type) {
      case "hello": {
        if (att.phase !== "challenged") {
          this.drop(ws, att, CLOSE_PROTOCOL_ERROR, "hello repeated", "protocol_error");
          return;
        }
        const nonce = b64Decode(att.nonce);
        const idBytes = parseTunnelId(att.id);
        const ok =
          nonce !== null &&
          idBytes !== null &&
          (await verifyHello(idBytes, att.relay, nonce, msg.sig));
        if (!ok) {
          this.drop(ws, att, CLOSE_BAD_SIGNATURE, "bad signature", "bad_signature");
          return;
        }
        // Newest wins: an earlier verified socket for this id goes away.
        for (const other of this.ctx.getWebSockets("daemon")) {
          if (other === ws) continue;
          const otherAtt = this.attachment(other);
          if (otherAtt !== null && otherAtt.phase === "ready") {
            this.drop(other, otherAtt, CLOSE_SUPERSEDED, "superseded", "superseded");
          }
        }
        att.phase = "ready";
        att.node = msg.node;
        att.agent = msg.agent;
        this.save(ws, att);
        const meta = await this.loadMeta();
        this.meta = {
          node: msg.node,
          agent: msg.agent,
          admit: msg.admit,
          firstSeenAt: meta?.firstSeenAt ?? now,
          lastSeenAt: now,
        };
        await this.ctx.storage.put("meta", this.meta);
        void this.pruneUsage(now);
        await this.armAlarm(now + RECORD_TTL_MS);
        this.sendSafe(
          ws,
          JSON.stringify({ v: 1, type: "welcome", limits: welcomeLimits(this.limits) }),
        );
        this.log("tunnel", { event: "hello", admit: msg.admit.length });
        return;
      }
      case "admit": {
        if (att.phase !== "ready") {
          this.drop(ws, att, CLOSE_PROTOCOL_ERROR, "admit before hello", "protocol_error");
          return;
        }
        const meta = await this.loadMeta();
        if (meta === null) return;
        meta.admit = msg.admit;
        meta.lastSeenAt = now;
        await this.ctx.storage.put("meta", meta);
        this.log("tunnel", { event: "admit", admit: msg.admit.length });
        return;
      }
      case "bye": {
        // The daemon is stopping: nothing sent now would be served.
        const wasReady = att.phase === "ready";
        att.phase = "closed";
        this.save(ws, att);
        this.failPending(ws);
        if (wasReady) await this.touchMeta(now);
        this.closeQuietly(ws, 1000, "bye");
        this.log("tunnel", { event: "bye" });
        return;
      }
    }
  }

  private frame(ws: WebSocket, att: Attachment, data: ArrayBuffer, now: number): void {
    const parsed = parseFrame(data, this.limits.maxFramePayload);
    if ("error" in parsed) {
      this.drop(ws, att, CLOSE_PROTOCOL_ERROR, parsed.error, "protocol_error");
      return;
    }
    if (att.phase !== "ready") {
      this.drop(ws, att, CLOSE_PROTOCOL_ERROR, "frame before hello", "protocol_error");
      return;
    }
    const { type, reqId, payload } = parsed;
    const found = this.pending.get(reqId);
    const p = found !== undefined && found.ws === ws && !found.done ? found : null;
    switch (type) {
      case FRAME_DATA:
        // A stream nobody waits for: tell the daemon to stop.
        if (p === null) {
          this.sendSafe(ws, packCancel(reqId, CANCEL_CLIENT_GONE));
          return;
        }
        this.data(p, payload, now);
        return;
      case FRAME_END:
        if (p === null) return;
        this.settle(p, { outcome: "end", status: 200, response: this.emptyOk() });
        return;
      case FRAME_REJECT: {
        if (p === null) return;
        const reject = parseReject(payload);
        if (reject === null) {
          this.drop(ws, att, CLOSE_PROTOCOL_ERROR, "malformed REJECT", "protocol_error");
          return;
        }
        if (p.answered) {
          // Only valid before DATA; after it, the response is broken.
          this.settle(p, { outcome: "reject", status: 502, error: "daemon aborted" });
          return;
        }
        const mapped = rejectToStatus(reject.code);
        this.settle(p, {
          outcome: "reject",
          status: mapped.status,
          response: json(
            mapped.status,
            { v: 1, error: mapped.error },
            mapped.status === 429 ? { "retry-after": "1" } : {},
          ),
        });
        return;
      }
      default:
        this.drop(ws, att, CLOSE_PROTOCOL_ERROR, `unexpected frame type ${type}`, "protocol_error");
    }
  }

  /** One DATA frame: answer the request on the first, then feed the stream. */
  private data(p: Pending, payload: Uint8Array, now: number): void {
    p.lastFrameAt = now;
    p.received += payload.length;
    if (p.received > p.granted) {
      // Past its credit: the one way the daemon could grow this object's
      // buffers without bound, so the socket goes rather than the bytes.
      this.drop(p.ws, this.attachment(p.ws), CLOSE_PROTOCOL_ERROR, "DATA past the window", "protocol_error");
      return;
    }
    if (!p.answered) {
      p.answered = true;
      const source = new ReadableStream<Uint8Array>(
        {
          start: (controller) => {
            p.controller = controller;
          },
          pull: () => {
            this.topUp(p);
          },
          cancel: () => {
            this.settle(p, { outcome: "client", status: 499, cancel: CANCEL_CLIENT_GONE });
          },
        },
        new ByteLengthQueuingStrategy({ highWaterMark: STREAM_HIGH_WATER_MARK }),
      );
      // The body is the native side of an identity pipe fed by pump()
      // rather than the JS source itself, so a failure on either side
      // (the daemon aborting the stream, the app hanging up) is handled
      // by code that owns every promise involved; the runtime's own pump
      // reports such failures as uncaught rejections.  A write completes
      // only as the app reads, so the source's queue, and with it
      // pull(), still track the app's pace.
      const { readable, writable } = new IdentityTransformStream();
      void this.pump(source, writable);
      p.answer(new Response(readable, { status: 200, headers: STREAM_HEADERS }));
    }
    try {
      p.controller?.enqueue(payload);
    } catch {
      // The consumer is gone; the stream's cancel() has settled it.
      return;
    }
    p.bytesOut += payload.length;
    if ((p.controller?.desiredSize ?? 0) > 0) this.topUp(p);
  }

  /** Copy a response source into its body, failing each side for the other. */
  private async pump(
    source: ReadableStream<Uint8Array>,
    writable: WritableStream<Uint8Array>,
  ): Promise<void> {
    const reader = source.getReader();
    const writer = writable.getWriter();
    reader.closed.catch(() => {});
    writer.closed.catch(() => {});
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          await writer.close();
          return;
        }
        await writer.write(value);
      }
    } catch (err) {
      // The source was failed by settle() (the daemon aborted), or the
      // app went away mid-body; whichever it was, the other side hears.
      // Cancelling the source runs its cancel(), which sends CANCEL 1.
      await reader.cancel(err).catch(() => {});
      await writer.abort(err).catch(() => {});
    }
  }

  /**
   * Flow control: once the daemon's outstanding credit for a request
   * has fallen to half the window or less, grant enough to fill it
   * again.  Called from the stream's pull() (the consumer is reading)
   * and after an enqueue that left room below the high-water mark, so
   * credit follows the app's reads rather than the relay's memory.
   */
  private topUp(p: Pending): void {
    if (p.done) return;
    const window = this.limits.initialWindow;
    const outstanding = p.granted - p.received;
    if (outstanding > window / 2) return;
    const credit = window - outstanding;
    p.granted += credit;
    this.sendSafe(p.ws, packWindow(p.reqId, credit));
  }

  /** End a request exactly once, whichever side ended it. */
  private settle(p: Pending, how: Settle): void {
    if (p.done) return;
    p.done = true;
    this.pending.delete(p.reqId);
    if (p.onAbort !== null) p.signal?.removeEventListener("abort", p.onAbort);
    if (how.cancel !== undefined) this.sendSafe(p.ws, packCancel(p.reqId, how.cancel));
    if (p.answered) {
      try {
        if (how.error !== undefined) p.controller?.error(new Error(how.error));
        else p.controller?.close();
      } catch {
        // Already closed, or cancelled by the consumer.
      }
    } else {
      p.answer(how.response ?? offline());
    }
    const now = Date.now();
    if (p.stream) void this.charge(now, now - p.opened);
    this.log("reach", {
      status: p.answered ? 200 : how.status,
      outcome: how.outcome,
      in: p.bytesIn,
      out: p.bytesOut,
      ms: now - p.opened,
    });
    if (this.pending.size === 0) this.stopSweep();
  }

  private failPending(ws: WebSocket): void {
    for (const p of [...this.pending.values()]) {
      if (p.ws === ws) {
        this.settle(p, { outcome: "abort", status: 502, error: "daemon aborted", response: offline() });
      }
    }
  }

  /** Close a daemon socket from this side, failing whatever it carried. */
  private drop(
    ws: WebSocket,
    att: Attachment | null,
    code: number,
    reason: string,
    event: string,
  ): void {
    this.failPending(ws);
    if (att !== null) {
      const wasReady = att.phase === "ready";
      att.phase = "closed";
      this.save(ws, att);
      if (wasReady) void this.touchMeta(Date.now());
    }
    this.closeQuietly(ws, code, reason);
    this.log("tunnel", { event, code });
  }

  /** The verified, still-open socket; the newest when the runtime lists two. */
  private daemonSocket(): WebSocket | null {
    let best: WebSocket | null = null;
    let bestSince = -1;
    for (const ws of this.ctx.getWebSockets("daemon")) {
      if (ws.readyState !== WebSocket.READY_STATE_OPEN) continue;
      const att = this.attachment(ws);
      if (att === null || att.phase !== "ready") continue;
      if (att.since > bestSince) {
        best = ws;
        bestSince = att.since;
      }
    }
    return best;
  }

  private attachment(ws: WebSocket): Attachment | null {
    const cached = this.attachments.get(ws);
    if (cached !== undefined) return cached;
    const stored = ws.deserializeAttachment() as Attachment | null;
    if (stored !== null && typeof stored === "object") {
      this.attachments.set(ws, stored);
      return stored;
    }
    return null;
  }

  private save(ws: WebSocket, att: Attachment): void {
    this.attachments.set(ws, att);
    try {
      ws.serializeAttachment(att);
    } catch {
      // A socket already closed keeps nothing; the in-memory copy serves
      // the rest of this event.
    }
  }

  private sendSafe(ws: WebSocket, data: string | Uint8Array): boolean {
    try {
      ws.send(data);
      return true;
    } catch {
      return false;
    }
  }

  private closeQuietly(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch {
      // Already closed.
    }
  }

  // -------------------------------------------------------------- sweep

  /**
   * While requests are pending, a timer walks them: a request with no
   * daemon frame for `staleMs` fails; a request open past the stream
   * threshold becomes a stream, or is cut when the concurrent-stream cap
   * is full (oldest keep their slots); a stream past its lifetime, or
   * every stream once the day's allowance is spent, is cut.  The cuts
   * send `CANCEL 2` and close the response body short, which the app
   * reads as a truncated response and reattaches from.
   */
  private sweepPending(): void {
    const now = Date.now();
    if (this.pending.size === 0) {
      this.stopSweep();
      return;
    }
    const l = this.limits;
    const cut: Settle = { outcome: "cut", status: 200, cancel: CANCEL_STREAM_CAP };
    for (const p of [...this.pending.values()]) {
      if (now - p.lastFrameAt >= l.staleMs) {
        this.settle(p, {
          outcome: "stale",
          status: 502,
          cancel: CANCEL_CLIENT_GONE,
          error: "daemon aborted",
          response: offline(),
        });
      }
    }
    const ordered = [...this.pending.values()].sort((a, b) => a.opened - b.opened);
    let streams = ordered.filter((p) => p.stream).length;
    for (const p of ordered) {
      if (p.stream || !p.answered || now - p.opened < l.streamThresholdMs) continue;
      if (streams >= l.maxStreams) {
        this.settle(p, cut);
        continue;
      }
      p.stream = true;
      streams += 1;
    }
    for (const p of ordered) {
      if (p.stream && !p.done && now - p.opened >= l.maxStreamMs) this.settle(p, cut);
    }
    if (this.usage !== null) {
      let open = 0;
      for (const p of this.pending.values()) if (p.stream) open += now - p.opened;
      if (this.usage.ms + open >= l.dailyStreamMs) {
        for (const p of [...this.pending.values()]) if (p.stream) this.settle(p, cut);
      }
    }
  }

  private ensureSweep(): void {
    if (this.sweep !== null) return;
    this.sweep = setInterval(() => this.sweepPending(), sweepIntervalMs(this.limits));
  }

  private stopSweep(): void {
    if (this.sweep === null) return;
    clearInterval(this.sweep);
    this.sweep = null;
  }

  // -------------------------------------------------------------- alarm

  /** Bring the alarm forward to `at`; a later one is replaced, an earlier one kept. */
  private async armAlarm(at: number): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null || existing > at) await this.ctx.storage.setAlarm(at);
  }

  /**
   * The hello timeout, closing every socket still unverified past it,
   * and the record's expiry: with no daemon for RECORD_TTL_MS, every
   * key goes.  Whatever is still pending is rescheduled.
   */
  async alarm(): Promise<void> {
    const now = Date.now();
    let next: number | null = null;
    let online = false;
    for (const ws of this.ctx.getWebSockets("daemon")) {
      const att = this.attachment(ws);
      if (att === null) continue;
      await this.identify(att.id);
      if (att.phase === "ready" && ws.readyState === WebSocket.READY_STATE_OPEN) {
        online = true;
        continue;
      }
      if (att.phase !== "challenged") continue;
      const deadline = att.since + this.limits.helloTimeoutMs;
      if (deadline <= now + 50) {
        this.drop(ws, att, CLOSE_HELLO_TIMEOUT, "hello timeout", "timeout");
      } else {
        next = next === null ? deadline : Math.min(next, deadline);
      }
    }
    const meta = await this.loadMeta();
    if (meta !== null) {
      const expiry = (online ? now : meta.lastSeenAt) + RECORD_TTL_MS;
      if (!online && expiry <= now) {
        await this.ctx.storage.deleteAll();
        this.meta = null;
        this.strikes = undefined;
        this.usage = null;
        this.log("tunnel", { event: "expired" });
      } else {
        next = next === null ? expiry : Math.min(next, expiry);
      }
    }
    if (next !== null) await this.ctx.storage.setAlarm(next);
  }

  // ------------------------------------------------------------ storage

  private async loadMeta(): Promise<Meta | null> {
    if (this.meta === undefined) {
      this.meta = (await this.ctx.storage.get<Meta>("meta")) ?? null;
    }
    return this.meta;
  }

  private async touchMeta(now: number): Promise<void> {
    const meta = await this.loadMeta();
    if (meta === null) return;
    meta.lastSeenAt = now;
    await this.ctx.storage.put("meta", meta);
  }

  /** Today's usage record, loaded once per day. */
  private async usageRecord(now: number): Promise<{ key: string; ms: number }> {
    const key = usageKey(now);
    if (this.usage !== null && this.usage.key === key) return this.usage;
    if (this.usageLoading === null || this.usageLoading.key !== key) {
      const promise = (async () => {
        const ms = (await this.ctx.storage.get<number>(key)) ?? 0;
        const record = { key, ms };
        this.usage = record;
        if (this.usageLoading?.key === key) this.usageLoading = null;
        return record;
      })();
      this.usageLoading = { key, promise };
    }
    return this.usageLoading.promise;
  }

  /** Committed usage plus the open streams' elapsed time. */
  private async usageMs(now: number): Promise<number> {
    const record = await this.usageRecord(now);
    let open = 0;
    for (const p of this.pending.values()) if (p.stream) open += now - p.opened;
    return record.ms + open;
  }

  /** Account a finished stream's full duration to the day it ended in. */
  private async charge(now: number, ms: number): Promise<void> {
    const record = await this.usageRecord(now);
    record.ms += ms;
    await this.ctx.storage.put(record.key, record.ms);
  }

  /** Drop usage records of past days. */
  private async pruneUsage(now: number): Promise<void> {
    const today = usageKey(now);
    const keys = [...(await this.ctx.storage.list({ prefix: "usage:" })).keys()];
    const stale = keys.filter((k) => k !== today);
    if (stale.length > 0) await this.ctx.storage.delete(stale);
  }

  // ---------------------------------------------------------------- misc

  private async identify(id: string): Promise<void> {
    if (this.tunnelId === id) return;
    this.tunnelId = id;
    this.logId = await tunnelLogId(id);
  }

  private emptyOk(): Response {
    return new Response(new Uint8Array(0), { status: 200, headers: STREAM_HEADERS });
  }

  private reply(
    status: number,
    body: Record<string, unknown>,
    t0: number,
    headers: Record<string, string> = {},
  ): Response {
    this.log("reach", { status, in: 0, out: 0, ms: Date.now() - t0 });
    return json(status, body, headers);
  }

  /** Never the tunnel id or a credential: the log id is a hash prefix. */
  private log(evt: "reach" | "tunnel", fields: Record<string, unknown>): void {
    console.log(JSON.stringify({ evt, tunnel: this.logId, ...fields }));
  }
}
