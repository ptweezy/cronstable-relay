import { describe, expect, it } from "vitest";

import {
  MAX_CIPHERTEXT_CHARS,
  SUITE_MAX_CHARS,
  parseEnvelope,
} from "../src/validate";

function valid(): Record<string, unknown> {
  return {
    v: 1,
    device: "ab".repeat(32),
    ciphertext: "A".repeat(96),
    collapseId: "0123456789abcdef0123456789abcdef",
    priority: "time-sensitive",
    event: false,
  };
}

function errorOf(body: unknown): string {
  const res = parseEnvelope(body);
  if (!("error" in res)) throw new Error("expected a validation error");
  return res.error;
}

describe("parseEnvelope", () => {
  it("accepts a valid envelope", () => {
    const res = parseEnvelope(valid());
    expect("envelope" in res).toBe(true);
  });

  it("normalizes the device token to lowercase", () => {
    const res = parseEnvelope({ ...valid(), device: "AB".repeat(32) });
    if (!("envelope" in res)) throw new Error("expected success");
    expect(res.envelope.device).toBe("ab".repeat(32));
  });

  it("ignores unknown extra fields (additive evolution)", () => {
    const res = parseEnvelope({ ...valid(), future: "field" });
    expect("envelope" in res).toBe(true);
  });

  it("rejects non-objects", () => {
    expect(errorOf([])).toMatch(/JSON object/);
    expect(errorOf("x")).toMatch(/JSON object/);
    expect(errorOf(null)).toMatch(/JSON object/);
  });

  it("rejects other protocol versions", () => {
    expect(errorOf({ ...valid(), v: 2 })).toMatch(/version/);
    expect(errorOf({ ...valid(), v: "1" })).toMatch(/version/);
  });

  it("rejects non-hex or out-of-bounds device tokens", () => {
    expect(errorOf({ ...valid(), device: "zz".repeat(32) })).toMatch(/device/);
    expect(errorOf({ ...valid(), device: "abcd" })).toMatch(/device/);
    expect(errorOf({ ...valid(), device: "ab".repeat(300) })).toMatch(
      /device/,
    );
    expect(errorOf({ ...valid(), device: 7 })).toMatch(/device/);
  });

  it("rejects bad ciphertexts", () => {
    expect(errorOf({ ...valid(), ciphertext: "" })).toMatch(/ciphertext/);
    // Sized off the cap, not a literal: a fixed 3004 stopped
    // overflowing the moment the cap was raised, and the assertion kept
    // passing while testing nothing.
    expect(
      errorOf({
        ...valid(),
        ciphertext: "A".repeat(MAX_CIPHERTEXT_CHARS + 4),
      }),
    ).toMatch(/exceeds/);
    expect(errorOf({ ...valid(), ciphertext: "ab!d".repeat(24) })).toMatch(
      /base64/,
    );
    // Base64-valid but shorter than any sealed box can be.
    expect(errorOf({ ...valid(), ciphertext: "AAAA" })).toMatch(/sealed/);
    // Length not a multiple of 4.
    expect(errorOf({ ...valid(), ciphertext: "A".repeat(97) })).toMatch(
      /base64|sealed/,
    );
  });

  it("rejects malformed collapse ids", () => {
    expect(
      errorOf({ ...valid(), collapseId: "0123456789ABCDEF0123456789ABCDEF" }),
    ).toMatch(/collapseId/);
    expect(errorOf({ ...valid(), collapseId: "abc" })).toMatch(/collapseId/);
    expect(errorOf({ ...valid(), collapseId: 12 })).toMatch(/collapseId/);
  });

  it("rejects unknown priorities", () => {
    expect(errorOf({ ...valid(), priority: "urgent" })).toMatch(/priority/);
    expect(errorOf({ ...valid(), priority: null })).toMatch(/priority/);
  });

  it("rejects non-boolean event flags", () => {
    expect(errorOf({ ...valid(), event: "yes" })).toMatch(/event/);
    expect(errorOf({ ...valid(), event: undefined })).toMatch(/event/);
  });
});

describe("parseEnvelope suites", () => {
  function envelopeOf(body: unknown) {
    const res = parseEnvelope(body);
    if (!("envelope" in res)) {
      throw new Error(`expected an envelope, got: ${res.error}`);
    }
    return res.envelope;
  }

  it("defaults an absent suite to x25519", () => {
    // A daemon that sends no suite means x25519.
    const body = valid();
    delete body.suite;
    expect(envelopeOf(body).suite).toBe("x25519");
  });

  it("keeps an explicit suite", () => {
    expect(envelopeOf({ ...valid(), suite: "x25519" }).suite).toBe("x25519");
  });

  it("forwards an unknown suite rather than rejecting it", () => {
    // relay-protocol.md: the relay treats `suite` as opaque routing
    // metadata.  A relay that rejected unknown suites would break every
    // deployment whose daemon upgraded before the relay did -- on the one
    // channel whose job is to page someone.
    expect(envelopeOf({ ...valid(), suite: "suite9" }).suite).toBe("suite9");
  });

  it("rejects suites that are not short lowercase identifiers", () => {
    // Bounded because the value lands in the APNs payload, where an
    // unbounded string would eat the size budget the ciphertext cap is
    // derived from.
    expect(errorOf({ ...valid(), suite: 7 })).toMatch(/suite/);
    expect(errorOf({ ...valid(), suite: "A".repeat(64) })).toMatch(/suite/);
    // Exactly the grammar's edge: SUITE_MAX_CHARS is in, one more is out.
    expect(envelopeOf({ ...valid(), suite: "s".repeat(SUITE_MAX_CHARS) }).suite)
      .toBe("s".repeat(SUITE_MAX_CHARS));
    expect(
      errorOf({ ...valid(), suite: "s".repeat(SUITE_MAX_CHARS + 1) }),
    ).toMatch(/suite/);
    expect(errorOf({ ...valid(), suite: "Has Spaces" })).toMatch(/suite/);
    expect(errorOf({ ...valid(), suite: "" })).toMatch(/suite/);
  });

  it("holds each known suite to its own minimum ciphertext length", () => {
    // 96 chars is a plausible sealed box and far too short to be an
    // X-Wing ciphertext (1120 bytes + tag), so the same body is accepted
    // under one suite and binned under the other.
    expect(envelopeOf({ ...valid(), suite: "x25519" }).suite).toBe("x25519");
    expect(errorOf({ ...valid(), suite: "xwing" })).toMatch(/sealed/);
    expect(
      envelopeOf({
        ...valid(),
        suite: "xwing",
        ciphertext: "A".repeat(1520),
      }).suite,
    ).toBe("xwing");
  });
});
