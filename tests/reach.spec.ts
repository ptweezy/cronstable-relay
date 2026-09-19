/**
 * The pure half of Reach (src/reach.ts) against the cronstable repo's
 * shared vectors: the frame codec byte for byte, the challenge
 * signature as PyNaCl produced it, the admission credentials, the id
 * grammar, the control-message parser, and the limits table.
 */

import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  admitIdOf,
  b64Decode,
  b64Encode,
  b64urlEncode,
  bucketTake,
  challengeMessage,
  DEFAULT_LIMITS,
  FRAME_CANCEL,
  FRAME_DATA,
  frameBucketTake,
  limitsFromEnv,
  locationHintFromCf,
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
  reachEnabled,
  rejectToStatus,
  secondsUntilUtcMidnight,
  strike,
  sweepIntervalMs,
  tunnelLogId,
  usageKey,
  verifyHello,
  welcomeLimits,
} from "../src/reach";

import { identityFromSeed, signChallenge } from "./daemon-mock";

interface Vectors {
  admission: {
    admitId: string;
    authorization: string;
    bearer: string;
    reachToken: string;
  }[];
  challenge: { message: string; nonce: string; relay: string; signature: string };
  frames: {
    bytes: string;
    name: string;
    payload: string;
    reqId: number;
    type: number;
  }[];
  identity: { signPublic: string; signSeed: string; tunnelId: string };
}

const vectors = JSON.parse(env.TEST_REACH_VECTORS) as Vectors;

function bytes(b64: string): Uint8Array {
  const out = b64Decode(b64);
  if (out === null) throw new Error(`fixture value is not base64: ${b64}`);
  return out;
}

describe("frame codec", () => {
  it("packs and parses every fixture frame byte-exact", () => {
    for (const frame of vectors.frames) {
      const packed = packFrame(frame.type, frame.reqId, bytes(frame.payload));
      expect(b64Encode(packed), frame.name).toBe(frame.bytes);
      const parsed = parseFrame(bytes(frame.bytes));
      if ("error" in parsed) throw new Error(parsed.error);
      expect(parsed.type, frame.name).toBe(frame.type);
      expect(parsed.reqId, frame.name).toBe(frame.reqId);
      expect(b64Encode(parsed.payload), frame.name).toBe(frame.payload);
    }
  });

  it("builds CANCEL and WINDOW frames as the vectors spell them", () => {
    const cancel = vectors.frames.find((f) => f.name === "cancel")!;
    expect(b64Encode(packCancel(7, 2))).toBe(cancel.bytes);
    const window = vectors.frames.find((f) => f.name === "window")!;
    expect(b64Encode(packWindow(7, 262_144))).toBe(window.bytes);
  });

  it("reads a REJECT payload", () => {
    const reject = vectors.frames.find((f) => f.name === "reject")!;
    expect(parseReject(bytes(reject.payload))).toEqual({
      code: 2,
      reason: "replay",
    });
    expect(parseReject(new Uint8Array([0]))).toBeNull();
    expect(parseReject(new Uint8Array([0, 5]))).toEqual({ code: 5, reason: "" });
  });

  it("maps REJECT codes to the protocol's statuses", () => {
    expect(rejectToStatus(1)).toEqual({ status: 409, error: "key mismatch" });
    expect(rejectToStatus(2)).toEqual({ status: 409, error: "replay" });
    expect(rejectToStatus(3).status).toBe(429);
    expect(rejectToStatus(4).status).toBe(413);
    expect(rejectToStatus(5)).toEqual({ status: 502, error: "daemon aborted" });
    expect(rejectToStatus(99).status).toBe(502);
  });

  it("refuses frames shorter than the header or over the payload cap", () => {
    expect(parseFrame(new Uint8Array(4))).toHaveProperty("error");
    const header = packFrame(FRAME_DATA, 1);
    expect(parseFrame(header)).toMatchObject({ type: FRAME_DATA, reqId: 1 });
    const big = new Uint8Array(5 + 11);
    expect(parseFrame(big, 10)).toHaveProperty("error");
    expect(parseFrame(big, 11)).toMatchObject({ reqId: 0 });
  });

  it("allocates request ids as a u32 that skips zero and wraps", () => {
    expect(nextReqId(0)).toBe(1);
    expect(nextReqId(7)).toBe(8);
    expect(nextReqId(0xffffffff)).toBe(1);
  });
});

describe("challenge signature", () => {
  it("signs the vectors' message and agrees with PyNaCl's signature", async () => {
    const identity = await identityFromSeed(vectors.identity.signSeed);
    expect(identity.id).toBe(vectors.identity.tunnelId);
    expect(b64Encode(identity.idBytes)).toBe(vectors.identity.signPublic);
    const nonce = bytes(vectors.challenge.nonce);
    expect(b64Encode(challengeMessage(vectors.challenge.relay, nonce))).toBe(
      vectors.challenge.message,
    );
    // Ed25519 is deterministic: the same seed and message give PyNaCl's bytes.
    const sig = await signChallenge(identity, vectors.challenge.relay, nonce);
    expect(b64Encode(sig)).toBe(vectors.challenge.signature);
  });

  it("verifies the fixture signature and nothing else", async () => {
    const pub = bytes(vectors.identity.signPublic);
    const nonce = bytes(vectors.challenge.nonce);
    const sig = bytes(vectors.challenge.signature);
    expect(await verifyHello(pub, vectors.challenge.relay, nonce, sig)).toBe(true);
    expect(await verifyHello(pub, "other.example", nonce, sig)).toBe(false);
    expect(await verifyHello(pub, vectors.challenge.relay, nonce, new Uint8Array(64)))
      .toBe(false);
    const flipped = sig.slice();
    flipped[3] = flipped[3]! ^ 0x01;
    expect(await verifyHello(pub, vectors.challenge.relay, nonce, flipped)).toBe(false);
    expect(await verifyHello(pub, vectors.challenge.relay, nonce.subarray(1), sig))
      .toBe(false);
    expect(await verifyHello(new Uint8Array(31), vectors.challenge.relay, nonce, sig))
      .toBe(false);
  });
});

describe("admission", () => {
  it("derives every fixture admit id from its Authorization header", async () => {
    for (const row of vectors.admission) {
      const credential = parseCredential(row.authorization);
      expect(credential, row.bearer).not.toBeNull();
      expect(b64urlEncode(credential!)).toBe(row.reachToken);
      expect(await admitIdOf(credential!)).toBe(row.admitId);
    }
  });

  it("refuses other schemes and malformed credentials", () => {
    expect(parseCredential(null)).toBeNull();
    expect(parseCredential("Bearer abc")).toBeNull();
    expect(parseCredential("Reach !!!")).toBeNull();
    expect(parseCredential("Reach")).toBeNull();
    const token = vectors.admission[0]!.reachToken;
    expect(parseCredential(`Reach ${token.slice(1)}`)).toBeNull();
    expect(parseCredential(`Reach ${token}A`)).toBeNull();
    expect(parseCredential(`reach ${token}`)).toBeNull();
    expect(parseCredential(`  Reach   ${token}  `)).not.toBeNull();
  });
});

describe("tunnel id grammar", () => {
  it("decodes the fixture id to the signing key", () => {
    const id = parseTunnelId(vectors.identity.tunnelId);
    expect(id).not.toBeNull();
    expect(b64Encode(id!)).toBe(vectors.identity.signPublic);
  });

  it("rejects the wrong length, alphabet, or a non-canonical last character", () => {
    const id = vectors.identity.tunnelId;
    expect(parseTunnelId(id.slice(1))).toBeNull();
    expect(parseTunnelId(`${id}A`)).toBeNull();
    expect(parseTunnelId(id.replace("-", "+"))).toBeNull();
    expect(parseTunnelId(id.replace("-", "/"))).toBeNull();
    // The last character carries four data bits and two that must be
    // zero; "s" (44) is canonical here, "t" (45) is not.
    expect(id.endsWith("s")).toBe(true);
    expect(parseTunnelId(`${id.slice(0, -1)}t`)).toBeNull();
    expect(parseTunnelId("")).toBeNull();
  });

  it("routes only the two Reach paths", () => {
    expect(parseReachPath("/v1/tunnel/abc")).toEqual({ kind: "tunnel", id: "abc" });
    expect(parseReachPath("/v1/reach/abc")).toEqual({ kind: "reach", id: "abc" });
    expect(parseReachPath("/v1/reach/abc/more")).toBeNull();
    expect(parseReachPath("/v1/other/abc")).toBeNull();
    expect(parseReachPath("/v1/reach/")).toBeNull();
  });

  it("recognizes the subprotocol in an offer list", () => {
    expect(offersSubprotocol("cronstable-reach-v1")).toBe(true);
    expect(offersSubprotocol("foo, cronstable-reach-v1")).toBe(true);
    expect(offersSubprotocol("cronstable-reach-v2")).toBe(false);
    expect(offersSubprotocol(null)).toBe(false);
  });
});

describe("control messages", () => {
  const sig = b64Encode(new Uint8Array(64));
  const admit = vectors.admission.map((row) => row.admitId);

  function hello(overrides: Record<string, unknown> = {}): string {
    return JSON.stringify({
      v: 1,
      type: "hello",
      sig,
      agent: "cronstable/1.2.43 reach",
      node: "nas",
      admit,
      limits: { maxBody: 1_048_576 },
      ...overrides,
    });
  }

  function errorOf(text: string): string {
    const parsed = parseControl(text);
    if (!("error" in parsed)) throw new Error("expected a protocol error");
    return parsed.error;
  }

  it("parses hello, admit, and bye", () => {
    expect(parseControl(hello())).toMatchObject({
      type: "hello",
      agent: "cronstable/1.2.43 reach",
      node: "nas",
      admit,
      maxBody: 1_048_576,
    });
    expect(parseControl(JSON.stringify({ v: 1, type: "admit", admit }))).toEqual({
      type: "admit",
      admit,
    });
    expect(parseControl(JSON.stringify({ v: 1, type: "bye", extra: 1 }))).toEqual({
      type: "bye",
    });
  });

  it("ignores unknown fields and dedupes admit ids", () => {
    expect(parseControl(hello({ future: "field" }))).toMatchObject({ type: "hello" });
    const doubled = parseControl(
      JSON.stringify({ v: 1, type: "admit", admit: [admit[0], admit[0]] }),
    );
    expect(doubled).toEqual({ type: "admit", admit: [admit[0]] });
  });

  it("refuses malformed messages, missing fields, and unknown types", () => {
    expect(errorOf("{nope")).toMatch(/JSON/);
    expect(errorOf("[]")).toMatch(/object/);
    expect(errorOf(JSON.stringify({ v: 2, type: "bye" }))).toMatch(/version/);
    expect(errorOf(JSON.stringify({ v: 1, type: "ping" }))).toMatch(/unknown/);
    expect(errorOf(JSON.stringify({ v: 1 }))).toMatch(/unknown/);
    expect(errorOf(hello({ sig: undefined }))).toMatch(/sig/);
    expect(errorOf(hello({ sig: b64Encode(new Uint8Array(63)) }))).toMatch(/64/);
    expect(errorOf(hello({ node: 7 }))).toMatch(/node/);
    expect(errorOf(hello({ agent: undefined }))).toMatch(/agent/);
    expect(errorOf(hello({ admit: "x" }))).toMatch(/admit/);
    expect(errorOf(hello({ admit: ["not base64!"] }))).toMatch(/admit/);
    expect(errorOf(hello({ admit: [b64Encode(new Uint8Array(31))] }))).toMatch(
      /32 bytes/,
    );
    expect(errorOf(hello({ admit: Array(65).fill(admit[0]) }))).toMatch(/64/);
    expect(errorOf(hello({ limits: undefined }))).toMatch(/limits/);
    expect(errorOf(hello({ limits: { maxBody: "big" } }))).toMatch(/maxBody/);
    expect(errorOf(hello({ limits: { maxBody: 0 } }))).toMatch(/maxBody/);
    expect(errorOf("x".repeat(70_000))).toMatch(/large/);
  });

  it("cuts display names that would not fit an attachment", () => {
    const parsed = parseControl(hello({ node: "n".repeat(1000) }));
    if ("error" in parsed || parsed.type !== "hello") throw new Error("expected hello");
    expect(parsed.node).toHaveLength(200);
  });
});

describe("limits", () => {
  it("defaults to the protocol document's table", () => {
    expect(limitsFromEnv({})).toEqual(DEFAULT_LIMITS);
    expect(DEFAULT_LIMITS).toEqual({
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
    });
  });

  it("pins the POST body cap at 1,052,672 bytes", () => {
    expect(maxPostBytes(limitsFromEnv({}))).toBe(1_052_672);
  });

  it("advertises the welcome limits in the protocol's names", () => {
    expect(welcomeLimits(DEFAULT_LIMITS)).toEqual({
      maxBody: 1_048_576,
      maxChunk: 65_536,
      maxStreamS: 1800,
      maxInflight: 32,
      initialWindow: 262_144,
    });
  });

  it("reads every RELAY_REACH_* var, seconds as fractions allowed", () => {
    const limits = limitsFromEnv({
      RELAY_REACH_HELLO_TIMEOUT_S: "0.5",
      RELAY_REACH_MAX_BODY: "2048",
      RELAY_REACH_MAX_CHUNK: "512",
      RELAY_REACH_MAX_STREAM_S: "60",
      RELAY_REACH_MAX_INFLIGHT: "3",
      RELAY_REACH_INITIAL_WINDOW: "1024",
      RELAY_REACH_MAX_STREAMS: "1",
      RELAY_REACH_STREAM_THRESHOLD_S: "2",
      RELAY_REACH_DAILY_STREAM_S: "100",
      RELAY_REACH_ADMIT_BURST: "5",
      RELAY_REACH_ADMIT_REFILL_PER_S: "0.5",
      RELAY_REACH_FRAME_RATE_PER_S: "10",
      RELAY_REACH_FRAME_BURST: "20",
      RELAY_REACH_STRIKES_PER_MIN: "2",
      RELAY_REACH_FIRST_BYTE_S: "1.5",
      RELAY_REACH_STALE_S: "4",
      RELAY_REACH_MAX_FRAME_PAYLOAD: "4096",
    });
    expect(limits).toEqual({
      helloTimeoutMs: 500,
      maxBody: 2048,
      maxChunk: 512,
      maxStreamMs: 60_000,
      maxInflight: 3,
      initialWindow: 1024,
      maxStreams: 1,
      streamThresholdMs: 2000,
      dailyStreamMs: 100_000,
      admitBurst: 5,
      admitRefillPerS: 0.5,
      frameRatePerS: 10,
      frameBurst: 20,
      strikesPerMinute: 2,
      firstByteMs: 1500,
      staleMs: 4000,
      maxFramePayload: 4096,
    });
    expect(maxPostBytes(limits)).toBe(2048 + 4096);
    // Garbage falls back to the default rather than to zero.
    expect(limitsFromEnv({ RELAY_REACH_MAX_INFLIGHT: "-1" }).maxInflight).toBe(32);
    expect(limitsFromEnv({ RELAY_REACH_STALE_S: "soon" }).staleMs).toBe(120_000);
  });

  it("sweeps at a tenth of the shortest window, within bounds", () => {
    expect(sweepIntervalMs(DEFAULT_LIMITS)).toBe(1500);
    expect(sweepIntervalMs({ ...DEFAULT_LIMITS, streamThresholdMs: 100 })).toBe(50);
    expect(sweepIntervalMs({ ...DEFAULT_LIMITS, streamThresholdMs: 900_000 }))
      .toBe(5000);
  });

  it("treats only an explicit false as the kill switch", () => {
    expect(reachEnabled({})).toBe(true);
    expect(reachEnabled({ RELAY_REACH_ENABLED: "true" })).toBe(true);
    expect(reachEnabled({ RELAY_REACH_ENABLED: "false" })).toBe(false);
    expect(reachEnabled({ RELAY_REACH_ENABLED: " False " })).toBe(false);
    expect(reachEnabled({ RELAY_REACH_ENABLED: "0" })).toBe(true);
  });
});

describe("buckets and strikes", () => {
  const T0 = 1_700_000_000_000;

  it("drains a request bucket and refills it with time", () => {
    let state = bucketTake(undefined, T0, 2, 1);
    expect(state.ok).toBe(true);
    state = bucketTake(state.bucket, T0, 2, 1);
    expect(state.ok).toBe(true);
    state = bucketTake(state.bucket, T0, 2, 1);
    expect(state.ok).toBe(false);
    expect(state.retryAfterS).toBe(1);
    state = bucketTake(state.bucket, T0 + 1000, 2, 1);
    expect(state.ok).toBe(true);
    expect(bucketTake(state.bucket, T0 + 1000, 2, 0.5).retryAfterS).toBe(2);
  });

  it("lets a frame bucket run one burst into debt before it fails", () => {
    let bucket = frameBucketTake(undefined, T0, 30, 200).bucket;
    let ok = true;
    let frames = 1;
    while (ok && frames < 1000) {
      const taken = frameBucketTake(bucket, T0, 30, 200);
      bucket = taken.bucket;
      ok = taken.ok;
      frames += 1;
    }
    // The burst plus one more burst of debt, then the next frame fails.
    expect(frames).toBe(401);
    // Refilled past the debt after enough quiet, frames flow again.
    expect(frameBucketTake(bucket, T0 + 20_000, 30, 200).ok).toBe(true);
  });

  it("limits after the minute's strikes and says how long to wait", () => {
    let state = strike(undefined, T0, 2);
    expect(state.limited).toBe(false);
    state = strike(state.state, T0 + 1000, 2);
    expect(state.limited).toBe(false);
    state = strike(state.state, T0 + 2000, 2);
    expect(state.limited).toBe(true);
    expect(state.retryAfterS).toBe(58);
    state = strike(state.state, T0 + 60_000, 2);
    expect(state.limited).toBe(false);
    expect(state.state.count).toBe(1);
  });
});

describe("days", () => {
  it("keys usage by UTC day and counts down to midnight", () => {
    const at = Date.UTC(2026, 8, 17, 23, 59, 30);
    expect(usageKey(at)).toBe("usage:2026-09-17");
    expect(secondsUntilUtcMidnight(at)).toBe(30);
    expect(secondsUntilUtcMidnight(Date.UTC(2026, 8, 17, 0, 0, 0))).toBe(86_400);
    expect(secondsUntilUtcMidnight(Date.UTC(2026, 8, 17, 23, 59, 59, 900))).toBe(1);
  });
});

describe("location hint", () => {
  it("maps request.cf onto the Durable Object regions", () => {
    expect(locationHintFromCf({ continent: "NA", longitude: "-122.4", country: "US" }))
      .toBe("wnam");
    expect(locationHintFromCf({ continent: "NA", longitude: "-74.0", country: "US" }))
      .toBe("enam");
    expect(locationHintFromCf({ continent: "NA", country: "CA" })).toBe("enam");
    expect(locationHintFromCf({ continent: "SA", country: "BR" })).toBe("sam");
    expect(locationHintFromCf({ continent: "EU", longitude: "2.3", country: "FR" }))
      .toBe("weur");
    expect(locationHintFromCf({ continent: "EU", longitude: "21.0", country: "PL" }))
      .toBe("eeur");
    expect(locationHintFromCf({ continent: "AS", longitude: "139.7", country: "JP" }))
      .toBe("apac");
    expect(locationHintFromCf({ continent: "AS", country: "AE" })).toBe("me");
    expect(locationHintFromCf({ continent: "AS", country: "TR" })).toBe("eeur");
    expect(locationHintFromCf({ continent: "OC", country: "AU" })).toBe("oc");
    expect(locationHintFromCf({ continent: "AF", country: "ZA" })).toBe("afr");
    expect(locationHintFromCf({ continent: "AN" })).toBeUndefined();
    expect(locationHintFromCf({})).toBeUndefined();
    expect(locationHintFromCf(undefined)).toBeUndefined();
  });
});

describe("log id", () => {
  it("is the first 8 hex characters of SHA-256 over the id", async () => {
    const id = vectors.identity.tunnelId;
    const logId = await tunnelLogId(id);
    expect(logId).toMatch(/^[0-9a-f]{8}$/);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(id)),
    );
    const hex = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex.startsWith(logId)).toBe(true);
    expect(logId).not.toContain(id.slice(0, 8));
  });

  it("frame type constants match the protocol", () => {
    expect(FRAME_CANCEL).toBe(4);
  });
});
