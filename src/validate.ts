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

/** relay-protocol.md: "at most 3000 characters". */
export const MAX_CIPHERTEXT_CHARS = 3000;

/**
 * A sealed box is a 32-byte ephemeral public key plus a 16-byte MAC
 * around at least `{}`; anything shorter cannot be one (50 bytes → 68
 * base64 chars).  Cheap garbage rejection, not cryptographic checking.
 */
const MIN_CIPHERTEXT_CHARS = 68;

/**
 * APNs device tokens are hex (64 chars today; Apple says treat the
 * length as variable).  The relay only routes to APNs in v1, so a
 * non-hex "token" can never be routable and is rejected outright.
 */
const DEVICE_RE = /^[0-9a-fA-F]{16,512}$/;

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
  const device = o.device;
  if (typeof device !== "string" || !DEVICE_RE.test(device)) {
    return { error: "device must be a hex APNs device token" };
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
      // Lowercased so one physical device is one Durable Object no
      // matter how the token's hex was cased at pairing time.
      device: device.toLowerCase(),
      ciphertext,
      collapseId,
      priority,
      event,
    },
  };
}
