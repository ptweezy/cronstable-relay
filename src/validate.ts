/**
 * Inbound envelope validation (relay-protocol.md, "Inbound request").
 *
 * Every bound here is part of the daemon's published contract: the
 * ciphertext cap keeps the final APNs JSON under Apple's 4096-byte
 * limit, the collapseId shape is the daemon's truncated keyed hash,
 * and unknown extra fields are ignored so v1 relays tolerate additive
 * evolution.  Error strings are returned verbatim in 400 bodies and
 * land in the daemon operator's log (which keeps at most 512 bytes),
 * so they are short and name the offending field.
 */

import type { Envelope } from "./types";

/** Inbound bodies are one envelope; far under this in practice. */
export const MAX_BODY_BYTES = 8192;

/**
 * relay-protocol.md, "Size budget": 4096 (the APNs cap) minus the 189
 * bytes this relay's own APNs envelope serializes to, minus a 107-byte
 * reserve for protocol fields added later.  tests/apns-size.spec.ts
 * asserts the 189 against the envelope apnsPayload() really builds, so
 * this constant rests on a measurement rather than an estimate.
 */
export const MAX_CIPHERTEXT_CHARS = 3800;

/**
 * A sealed box is a 32-byte ephemeral public key plus a 16-byte MAC
 * around at least `{}`; anything shorter cannot be one (50 bytes → 68
 * base64 chars).  Cheap garbage rejection, not cryptographic checking.
 */
const MIN_CIPHERTEXT_CHARS = 68;

/** relay-protocol.md: an absent suite means x25519. */
const DEFAULT_SUITE = "x25519";

/**
 * relay-protocol.md, "Suites": a suite identifier is 1 to SUITE_MAX_CHARS
 * characters of [a-z0-9-], starting with a letter or digit.  Bounded
 * because the token lands in the APNs payload, where an unbounded string
 * would eat the size budget the cap above depends on; the daemon's
 * reserve absorbs the widest token this allows (tests/apns-size.spec.ts
 * pins that).
 */
export const SUITE_MAX_CHARS = 16;
const SUITE_RE = new RegExp(`^[a-z0-9][a-z0-9-]{0,${SUITE_MAX_CHARS - 1}}$`);

/**
 * APNs device tokens are hex (64 chars today; Apple says treat the
 * length as variable).  The relay only routes to APNs in v1, so a
 * non-hex "token" can never be routable and is rejected outright.
 */
export const DEVICE_RE = /^[0-9a-fA-F]{16,512}$/;

/**
 * A device token as every route stores it: validated against DEVICE_RE
 * and lowercased so one physical device is one Durable Object no matter
 * how the token's hex was cased.  Null when the value is not a token.
 */
export function parseDevice(raw: unknown): string | null {
  if (typeof raw !== "string" || !DEVICE_RE.test(raw)) return null;
  return raw.toLowerCase();
}

const COLLAPSE_RE = /^[0-9a-f]{32}$/;

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export type ParseResult = { envelope: Envelope } | { error: string };

export function parseEnvelope(raw: unknown): ParseResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { error: "body must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) {
    return { error: "unsupported protocol version (expected v: 1)" };
  }
  const device = parseDevice(o.device);
  if (device === null) {
    return { error: "device must be a hex APNs device token" };
  }
  const rawSuite = o.suite;
  if (rawSuite !== undefined && typeof rawSuite !== "string") {
    return { error: "suite must be a string" };
  }
  const suite = rawSuite === undefined ? DEFAULT_SUITE : rawSuite;
  if (!SUITE_RE.test(suite)) {
    return { error: "suite is not a valid suite identifier" };
  }
  const ciphertext = o.ciphertext;
  if (typeof ciphertext !== "string" || ciphertext.length === 0) {
    return { error: "ciphertext is required" };
  }
  if (ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    return {
      error: `ciphertext exceeds ${MAX_CIPHERTEXT_CHARS} characters`,
    };
  }
  if (
    ciphertext.length % 4 !== 0 ||
    !BASE64_RE.test(ciphertext) ||
    ciphertext.length < MIN_CIPHERTEXT_CHARS
  ) {
    return { error: "ciphertext is not a base64 sealed box" };
  }
  const collapseId = o.collapseId;
  if (typeof collapseId !== "string" || !COLLAPSE_RE.test(collapseId)) {
    return { error: "collapseId must be 32 lowercase hex characters" };
  }
  const priority = o.priority;
  if (priority !== "time-sensitive" && priority !== "passive") {
    return { error: 'priority must be "time-sensitive" or "passive"' };
  }
  const event = o.event;
  if (typeof event !== "boolean") {
    return { error: "event must be a boolean" };
  }
  return {
    envelope: {
      v: 1,
      device,
      ciphertext,
      collapseId,
      priority,
      event,
      suite,
    },
  };
}
