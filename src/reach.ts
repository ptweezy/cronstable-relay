/**
 * Reach (docs/reach-protocol.md v1 in the cronstable repo): the pure
 * half of the relay-brokered control channel.
 *
 * A daemon holds one WebSocket open at /v1/tunnel/{id}; the app POSTs
 * sealed requests to /v1/reach/{id}; the per-tunnel Durable Object
 * (tunnel.ts) matches the two and copies bytes between them.  Every
 * request and reply is sealed between the app and the daemon, so this
 * relay handles ciphertext and routing metadata only.
 *
 * Everything in this module is deterministic in its inputs and free of
 * I/O, so it unit-tests without a Durable Object: the id and credential
 * grammars, the binary frame codec, the control-message parser, the
 * limits table, the location hint, the token buckets, and the log id.
 */

/** The WebSocket subprotocol the daemon offers and the relay echoes. */
export const SUBPROTOCOL = "cronstable-reach-v1";

/** `L`: the label every signature message starts with. */
export const LABEL = new TextEncoder().encode("cronstable-reach-v1");

/** Binary frame types (`u8 type ‖ u32 reqId ‖ payload`). */
export const FRAME_OPEN = 0x01;
export const FRAME_DATA = 0x02;
export const FRAME_END = 0x03;
export const FRAME_CANCEL = 0x04;
export const FRAME_REJECT = 0x05;
export const FRAME_WINDOW = 0x06;

/** CANCEL reasons (relay to daemon). */
export const CANCEL_CLIENT_GONE = 1;
export const CANCEL_STREAM_CAP = 2;
export const CANCEL_RELAY_STOPPING = 3;

/** REJECT codes (daemon to relay). */
export const REJECT_CANNOT_DECRYPT = 1;
export const REJECT_REPLAY = 2;
export const REJECT_BUSY = 3;
export const REJECT_TOO_LARGE = 4;
export const REJECT_INTERNAL = 5;

/** WebSocket close codes the relay sends. */
export const CLOSE_PROTOCOL_ERROR = 4400;
export const CLOSE_BAD_SIGNATURE = 4403;
export const CLOSE_HELLO_TIMEOUT = 4408;
export const CLOSE_SUPERSEDED = 4409;

export const FRAME_HEADER_BYTES = 5;

/** A `hello` or `admit` carries at most this many admit ids. */
export const MAX_ADMIT_IDS = 64;

/**
 * The POST body cap is the daemon's inner body cap plus this much
 * framing: the sealed REQ's own header, the padded request head, and
 * the AEAD tag.  1,048,576 + 4,096 = 1,052,672, the protocol's number.
 */
export const REQUEST_FRAMING_BYTES = 4096;

/** A control message (text frame) larger than this is a protocol error. */
export const MAX_CONTROL_CHARS = 65536;

/** Node and agent strings are display-only; longer ones are cut here. */
export const MAX_NAME_CHARS = 200;

/** Byte-length high-water mark of every relayed response stream. */
export const STREAM_HIGH_WATER_MARK = 65536;

const EMPTY = new Uint8Array(0);

// ---------------------------------------------------------------- limits

export interface ReachLimits {
  /** A socket that sends no `hello` within this closes with 4408. */
  helloTimeoutMs: number;
  /** The daemon's inner request body cap, advertised in `welcome`. */
  maxBody: number;
  /** The largest BODY record the daemon emits, advertised in `welcome`. */
  maxChunk: number;
  /** A stream open this long is cut with `CANCEL 2`. */
  maxStreamMs: number;
  /** Requests in flight per tunnel. */
  maxInflight: number;
  /** Bytes of DATA credit every request starts with. */
  initialWindow: number;
  /** Requests open past `streamThresholdMs` at the same time. */
  maxStreams: number;
  /** A request open longer than this counts as a stream. */
  streamThresholdMs: number;
  /** Open-stream time per tunnel per UTC day. */
  dailyStreamMs: number;
  /** Per-admit-id request bucket. */
  admitBurst: number;
  admitRefillPerS: number;
  /** Per-daemon-socket frame bucket. */
  frameRatePerS: number;
  frameBurst: number;
  /** Unadmitted credentials per tunnel per minute before 429. */
  strikesPerMinute: number;
  /** No first daemon frame within this answers 504. */
  firstByteMs: number;
  /** No daemon frame at all for this long fails the request. */
  staleMs: number;
  /** Frame payload cap; a frame over it closes the socket with 4400. */
  maxFramePayload: number;
}

/** The protocol document's limits table, verbatim. */
export const DEFAULT_LIMITS: ReachLimits = {
  helloTimeoutMs: 15_000,
  maxBody: 1_048_576,
  maxChunk: 65_536,
  maxStreamMs: 1_800_000,
  maxInflight: 32,
  initialWindow: 262_144,
  maxStreams: 4,
  streamThresholdMs: 15_000,
  dailyStreamMs: 10_800_000,
  admitBurst: 120,
  admitRefillPerS: 2,
  frameRatePerS: 30,
  frameBurst: 200,
  strikesPerMinute: 30,
  firstByteMs: 8_000,
  staleMs: 120_000,
  maxFramePayload: 1_114_112,
};

/** The env vars that tune Reach (numbers as strings; seconds may be fractional). */
export interface ReachEnv {
  RELAY_REACH_ENABLED?: string;
  RELAY_REACH_HELLO_TIMEOUT_S?: string;
  RELAY_REACH_MAX_BODY?: string;
  RELAY_REACH_MAX_CHUNK?: string;
  RELAY_REACH_MAX_STREAM_S?: string;
  RELAY_REACH_MAX_INFLIGHT?: string;
  RELAY_REACH_INITIAL_WINDOW?: string;
  RELAY_REACH_MAX_STREAMS?: string;
  RELAY_REACH_STREAM_THRESHOLD_S?: string;
  RELAY_REACH_DAILY_STREAM_S?: string;
  RELAY_REACH_ADMIT_BURST?: string;
  RELAY_REACH_ADMIT_REFILL_PER_S?: string;
  RELAY_REACH_FRAME_RATE_PER_S?: string;
  RELAY_REACH_FRAME_BURST?: string;
  RELAY_REACH_STRIKES_PER_MIN?: string;
  RELAY_REACH_FIRST_BYTE_S?: string;
  RELAY_REACH_STALE_S?: string;
  RELAY_REACH_MAX_FRAME_PAYLOAD?: string;
}

function num(raw: string | undefined, fallback: number): number {
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Seconds in the var, milliseconds internally. */
function secs(raw: string | undefined, fallbackMs: number): number {
  return Math.round(num(raw, fallbackMs / 1000) * 1000);
}

/** Limits from env vars; every knob falls back to the protocol default. */
export function limitsFromEnv(env: ReachEnv): ReachLimits {
  const d = DEFAULT_LIMITS;
  return {
    helloTimeoutMs: secs(env.RELAY_REACH_HELLO_TIMEOUT_S, d.helloTimeoutMs),
    maxBody: num(env.RELAY_REACH_MAX_BODY, d.maxBody),
    maxChunk: num(env.RELAY_REACH_MAX_CHUNK, d.maxChunk),
    maxStreamMs: secs(env.RELAY_REACH_MAX_STREAM_S, d.maxStreamMs),
    maxInflight: num(env.RELAY_REACH_MAX_INFLIGHT, d.maxInflight),
    initialWindow: num(env.RELAY_REACH_INITIAL_WINDOW, d.initialWindow),
    maxStreams: num(env.RELAY_REACH_MAX_STREAMS, d.maxStreams),
    streamThresholdMs: secs(
      env.RELAY_REACH_STREAM_THRESHOLD_S,
      d.streamThresholdMs,
    ),
    dailyStreamMs: secs(env.RELAY_REACH_DAILY_STREAM_S, d.dailyStreamMs),
    admitBurst: num(env.RELAY_REACH_ADMIT_BURST, d.admitBurst),
    admitRefillPerS: num(env.RELAY_REACH_ADMIT_REFILL_PER_S, d.admitRefillPerS),
    frameRatePerS: num(env.RELAY_REACH_FRAME_RATE_PER_S, d.frameRatePerS),
    frameBurst: num(env.RELAY_REACH_FRAME_BURST, d.frameBurst),
    strikesPerMinute: num(env.RELAY_REACH_STRIKES_PER_MIN, d.strikesPerMinute),
    firstByteMs: secs(env.RELAY_REACH_FIRST_BYTE_S, d.firstByteMs),
    staleMs: secs(env.RELAY_REACH_STALE_S, d.staleMs),
    maxFramePayload: num(env.RELAY_REACH_MAX_FRAME_PAYLOAD, d.maxFramePayload),
  };
}

/** The kill switch: `RELAY_REACH_ENABLED=false` turns every /v1/* route into a 404. */
export function reachEnabled(env: ReachEnv): boolean {
  return (env.RELAY_REACH_ENABLED ?? "true").trim().toLowerCase() !== "false";
}

/** The largest POST /v1/reach body the front Worker lets through. */
export function maxPostBytes(limits: ReachLimits): number {
  return limits.maxBody + REQUEST_FRAMING_BYTES;
}

/**
 * How often the tunnel object walks its pending requests for the stale,
 * stream-threshold, and stream-lifetime checks: a tenth of the shortest
 * of those windows, between 50 ms and 5 s.
 */
export function sweepIntervalMs(limits: ReachLimits): number {
  const shortest = Math.min(
    limits.staleMs,
    limits.streamThresholdMs,
    limits.maxStreamMs,
  );
  return Math.min(5000, Math.max(50, Math.floor(shortest / 10)));
}

/** What `welcome` carries. */
export function welcomeLimits(limits: ReachLimits): Record<string, number> {
  return {
    maxBody: limits.maxBody,
    maxChunk: limits.maxChunk,
    maxStreamS: Math.floor(limits.maxStreamMs / 1000),
    maxInflight: limits.maxInflight,
    initialWindow: limits.initialWindow,
  };
}

// ------------------------------------------------------------- encodings

const B64URL_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function binaryToBytes(bin: string): Uint8Array {
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBinary(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return bin;
}

/** RFC 4648 standard alphabet with padding (the JSON encoding). */
export function b64Encode(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

/** Strict inverse of `b64Encode`; null for anything else. */
export function b64Decode(text: string): Uint8Array | null {
  if (text.length % 4 !== 0 || !B64_RE.test(text)) return null;
  try {
    return binaryToBytes(atob(text));
  } catch {
    return null;
  }
}

/** RFC 4648 URL-safe alphabet, padding stripped (ids and credentials). */
export function b64urlEncode(bytes: Uint8Array): string {
  return b64Encode(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

/**
 * A 43-character base64url string as the 32 bytes it encodes, or null
 * when it is not the canonical encoding of 32 bytes (the two spare bits
 * in the last character must be zero, so one key has exactly one id).
 */
export function decodeKey43(text: string): Uint8Array | null {
  if (!B64URL_KEY_RE.test(text)) return null;
  const std = text.replaceAll("-", "+").replaceAll("_", "/") + "=";
  const bytes = b64Decode(std);
  if (bytes === null || bytes.length !== 32) return null;
  return b64urlEncode(bytes) === text ? bytes : null;
}

/** The tunnel id is the daemon's raw Ed25519 public key, base64url. */
export function parseTunnelId(id: string): Uint8Array | null {
  return decodeKey43(id);
}

/** Cheap grammar check for the front Worker (no decoding). */
export function isTunnelId(id: string): boolean {
  return decodeKey43(id) !== null;
}

/** The credential behind `Authorization: Reach <base64url 32 bytes>`. */
export function parseCredential(header: string | null): Uint8Array | null {
  if (header === null) return null;
  const m = /^\s*Reach\s+([A-Za-z0-9_-]{43})\s*$/.exec(header);
  if (m === null) return null;
  return decodeKey43(m[1]!);
}

/** The route behind a /v1/ path. */
export function parseReachPath(
  pathname: string,
): { kind: "tunnel" | "reach"; id: string } | null {
  const m = /^\/v1\/(tunnel|reach)\/([^/]+)$/.exec(pathname);
  if (m === null) return null;
  return { kind: m[1] as "tunnel" | "reach", id: m[2]! };
}

/** Whether a `Sec-WebSocket-Protocol` offer includes ours. */
export function offersSubprotocol(header: string | null): boolean {
  if (header === null) return false;
  return header
    .split(",")
    .map((p) => p.trim())
    .includes(SUBPROTOCOL);
}

// ------------------------------------------------------------- admission

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer));
}

/** What the relay compares: base64 of SHA-256 over the raw credential. */
export async function admitIdOf(credential: Uint8Array): Promise<string> {
  return b64Encode(await sha256(credential));
}

/**
 * The log correlation id: the first 8 hex characters of SHA-256 over
 * the tunnel id string, the same shape the push route uses for device
 * tokens.  Never the id itself, which is a routable address.
 */
export async function tunnelLogId(tunnelId: string): Promise<string> {
  const digest = await sha256(new TextEncoder().encode(tunnelId));
  return [...digest.subarray(0, 4)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ------------------------------------------------------------- challenge

function concat(...parts: Uint8Array[]): Uint8Array {
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

/** The bytes the daemon signs: `L ‖ 0x00 ‖ relay ‖ 0x00 ‖ nonce`. */
export function challengeMessage(
  relayHost: string,
  nonce: Uint8Array,
): Uint8Array {
  return concat(
    LABEL,
    new Uint8Array([0]),
    new TextEncoder().encode(relayHost),
    new Uint8Array([0]),
    nonce,
  );
}

/** Ed25519 over the challenge message, under the tunnel id's key. */
export async function verifyHello(
  tunnelIdBytes: Uint8Array,
  relayHost: string,
  nonce: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (nonce.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      tunnelIdBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signature,
      challengeMessage(relayHost, nonce),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- frames

export interface Frame {
  type: number;
  reqId: number;
  payload: Uint8Array;
}

/** `u8 type ‖ u32 reqId ‖ payload`. */
export function packFrame(
  type: number,
  reqId: number,
  payload: Uint8Array = EMPTY,
): Uint8Array {
  const out = new Uint8Array(FRAME_HEADER_BYTES + payload.length);
  const view = new DataView(out.buffer);
  view.setUint8(0, type);
  view.setUint32(1, reqId);
  out.set(payload, FRAME_HEADER_BYTES);
  return out;
}

/** The inverse of `packFrame`; an error for a short or oversize frame. */
export function parseFrame(
  data: ArrayBuffer | Uint8Array,
  maxPayload: number = DEFAULT_LIMITS.maxFramePayload,
): Frame | { error: string } {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.length < FRAME_HEADER_BYTES) {
    return { error: "frame shorter than its header" };
  }
  if (bytes.length - FRAME_HEADER_BYTES > maxPayload) {
    return { error: "frame payload over the cap" };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    type: view.getUint8(0),
    reqId: view.getUint32(1),
    payload: bytes.subarray(FRAME_HEADER_BYTES),
  };
}

export function packCancel(reqId: number, reason: number): Uint8Array {
  const payload = new Uint8Array(2);
  new DataView(payload.buffer).setUint16(0, reason);
  return packFrame(FRAME_CANCEL, reqId, payload);
}

export function packWindow(reqId: number, credit: number): Uint8Array {
  const payload = new Uint8Array(4);
  new DataView(payload.buffer).setUint32(0, credit);
  return packFrame(FRAME_WINDOW, reqId, payload);
}

/** `u16 code ‖ UTF-8 reason`. */
export function parseReject(
  payload: Uint8Array,
): { code: number; reason: string } | null {
  if (payload.length < 2) return null;
  const view = new DataView(payload.buffer, payload.byteOffset, 2);
  return {
    code: view.getUint16(0),
    reason: new TextDecoder().decode(payload.subarray(2)),
  };
}

/** The HTTP status and error string a REJECT code maps to. */
export function rejectToStatus(code: number): { status: number; error: string } {
  switch (code) {
    case REJECT_CANNOT_DECRYPT:
      return { status: 409, error: "key mismatch" };
    case REJECT_REPLAY:
      return { status: 409, error: "replay" };
    case REJECT_BUSY:
      return { status: 429, error: "daemon busy" };
    case REJECT_TOO_LARGE:
      return { status: 413, error: "request too large for the daemon" };
    default:
      return { status: 502, error: "daemon aborted" };
  }
}

/** The next request id: u32, never 0, wrapping. */
export function nextReqId(previous: number): number {
  const next = (previous + 1) >>> 0;
  return next === 0 ? 1 : next;
}

// ------------------------------------------------------ control messages

export type Control =
  | {
      type: "hello";
      sig: Uint8Array;
      agent: string;
      node: string;
      admit: string[];
      maxBody: number;
    }
  | { type: "admit"; admit: string[] }
  | { type: "bye" };

function parseAdmit(raw: unknown): string[] | { error: string } {
  if (!Array.isArray(raw)) return { error: "admit must be an array" };
  if (raw.length > MAX_ADMIT_IDS) {
    return { error: `admit holds more than ${MAX_ADMIT_IDS} ids` };
  }
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string") return { error: "admit ids are strings" };
    const bytes = b64Decode(entry);
    if (bytes === null || bytes.length !== 32) {
      return { error: "admit ids are base64 of 32 bytes" };
    }
    if (!out.includes(entry)) out.push(entry);
  }
  return out;
}

function name(raw: unknown, field: string): string | { error: string } {
  if (typeof raw !== "string") return { error: `${field} must be a string` };
  return raw.length > MAX_NAME_CHARS ? raw.slice(0, MAX_NAME_CHARS) : raw;
}

/**
 * A text frame from the daemon.  Every message has `v: 1` and a
 * `type`; unknown fields are ignored, an unknown type or a missing
 * field is a protocol error (the socket closes with 4400).
 */
export function parseControl(text: string): Control | { error: string } {
  if (text.length > MAX_CONTROL_CHARS) return { error: "message too large" };
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { error: "message is not JSON" };
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { error: "message must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) return { error: "unsupported message version" };
  switch (o.type) {
    case "hello": {
      if (typeof o.sig !== "string") return { error: "hello lacks sig" };
      const sig = b64Decode(o.sig);
      if (sig === null || sig.length !== 64) {
        return { error: "sig must be base64 of 64 bytes" };
      }
      const agent = name(o.agent, "agent");
      if (typeof agent !== "string") return agent;
      const node = name(o.node, "node");
      if (typeof node !== "string") return node;
      const admit = parseAdmit(o.admit);
      if (!Array.isArray(admit)) return admit;
      const limits = o.limits;
      if (typeof limits !== "object" || limits === null) {
        return { error: "hello lacks limits" };
      }
      const maxBody = (limits as Record<string, unknown>).maxBody;
      if (
        typeof maxBody !== "number" ||
        !Number.isInteger(maxBody) ||
        maxBody <= 0
      ) {
        return { error: "limits.maxBody must be a positive integer" };
      }
      return { type: "hello", sig, agent, node, admit, maxBody };
    }
    case "admit": {
      const admit = parseAdmit(o.admit);
      if (!Array.isArray(admit)) return admit;
      return { type: "admit", admit };
    }
    case "bye":
      return { type: "bye" };
    default:
      return { error: "unknown message type" };
  }
}

// --------------------------------------------------------------- buckets

export interface Bucket {
  tokens: number;
  ts: number;
}

/**
 * Take one token from a bucket (a fresh one starts full).  `ok` is
 * false when none was available; `retryAfterS` then says how long
 * until one is.
 */
export function bucketTake(
  bucket: Bucket | undefined,
  now: number,
  capacity: number,
  refillPerS: number,
): { bucket: Bucket; ok: boolean; retryAfterS: number } {
  const refilled: Bucket = bucket
    ? {
        tokens: Math.min(
          capacity,
          bucket.tokens + (Math.max(0, now - bucket.ts) / 1000) * refillPerS,
        ),
        ts: now,
      }
    : { tokens: capacity, ts: now };
  if (refilled.tokens < 1) {
    return {
      bucket: refilled,
      ok: false,
      retryAfterS: Math.max(1, Math.ceil((1 - refilled.tokens) / refillPerS)),
    };
  }
  refilled.tokens -= 1;
  return { bucket: refilled, ok: true, retryAfterS: 0 };
}

/**
 * The per-socket frame bucket may run into debt: frames past the
 * allowance are still processed (a dropped frame would corrupt a
 * stream), but once the debt exceeds one full burst the daemon has
 * kept sending for at least `burst / rate` seconds past its allowance
 * and the caller closes the socket.
 */
export function frameBucketTake(
  bucket: Bucket | undefined,
  now: number,
  ratePerS: number,
  burst: number,
): { bucket: Bucket; ok: boolean } {
  const refilled: Bucket = bucket
    ? {
        tokens: Math.min(
          burst,
          bucket.tokens + (Math.max(0, now - bucket.ts) / 1000) * ratePerS,
        ),
        ts: now,
      }
    : { tokens: burst, ts: now };
  refilled.tokens -= 1;
  return { bucket: refilled, ok: refilled.tokens >= -burst };
}

export interface StrikeState {
  windowStart: number;
  count: number;
}

const STRIKE_WINDOW_MS = 60_000;

/**
 * Count one unadmitted credential.  `limited` once the minute's
 * allowance is spent; `retryAfterS` is the rest of the minute.
 */
export function strike(
  state: StrikeState | undefined,
  now: number,
  perMinute: number,
): { state: StrikeState; limited: boolean; retryAfterS: number } {
  const current =
    state && now - state.windowStart < STRIKE_WINDOW_MS
      ? { windowStart: state.windowStart, count: state.count + 1 }
      : { windowStart: now, count: 1 };
  return {
    state: current,
    limited: current.count > perMinute,
    retryAfterS: Math.max(
      1,
      Math.ceil((current.windowStart + STRIKE_WINDOW_MS - now) / 1000),
    ),
  };
}

// ------------------------------------------------------------------ days

/** "usage:YYYY-MM-DD" for the UTC day of `now`. */
export function usageKey(now: number): string {
  return `usage:${new Date(now).toISOString().slice(0, 10)}`;
}

/** Seconds until the next 00:00 UTC (at least 1). */
export function secondsUntilUtcMidnight(now: number): number {
  const d = new Date(now);
  const midnight = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
  return Math.max(1, Math.ceil((midnight - now) / 1000));
}

// -------------------------------------------------------- location hint

export type LocationHint =
  | "wnam"
  | "enam"
  | "sam"
  | "weur"
  | "eeur"
  | "apac"
  | "oc"
  | "afr"
  | "me";

const MIDDLE_EAST = new Set([
  "AE", "BH", "IL", "IQ", "IR", "JO", "KW", "LB", "OM", "PS", "QA", "SA", "SY", "YE",
]);

const EASTERN_EUROPE_ASIA = new Set(["TR", "GE", "AM", "AZ", "CY"]);

/**
 * The Durable Object location hint for a daemon's upgrade request,
 * from `request.cf`: the tunnel object is created near the daemon so
 * every relayed request pays one hop to it rather than two.  A hint
 * matters only on the first `get()` that creates the object; later
 * calls find it where it already lives.  Undefined when `cf` is absent
 * or says nothing usable, which lets the runtime choose.
 */
export function locationHintFromCf(cf: unknown): LocationHint | undefined {
  if (typeof cf !== "object" || cf === null) return undefined;
  const o = cf as Record<string, unknown>;
  const continent = typeof o.continent === "string" ? o.continent : "";
  const country = typeof o.country === "string" ? o.country : "";
  const longitude = Number(o.longitude);
  switch (continent) {
    case "NA":
      return Number.isFinite(longitude) && longitude < -100 ? "wnam" : "enam";
    case "SA":
      return "sam";
    case "EU":
      return Number.isFinite(longitude) && longitude > 17 ? "eeur" : "weur";
    case "AS":
      if (MIDDLE_EAST.has(country)) return "me";
      if (EASTERN_EUROPE_ASIA.has(country)) return "eeur";
      return "apac";
    case "OC":
      return "oc";
    case "AF":
      return "afr";
    default:
      return undefined;
  }
}

// -------------------------------------------------------------- responses

/** A JSON error body in the relay's envelope shape. */
export function jsonResponse(
  status: number,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}
