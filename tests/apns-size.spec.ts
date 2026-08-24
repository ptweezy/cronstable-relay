/**
 * The size budget in relay-protocol.md, asserted rather than assumed.
 *
 * The daemon's CIPHERTEXT_B64_MAX is derived from three numbers: Apple's
 * 4096-byte cap, the bytes this relay's own APNs envelope costs, and a
 * reserve for future protocol fields.  Only the relay can measure the
 * middle one, and getting it wrong is expensive in both directions: too
 * high wastes payload out of every notification sent, too low makes APNs
 * reject max-length alerts outright.
 *
 * So this file pins it to the payload apnsPayload() really builds.
 */

import { describe, expect, it } from "vitest";

import { APNS_PAYLOAD_MAX, ENVELOPE_BYTES, apnsPayload } from "../src/apns";
import { MAX_CIPHERTEXT_CHARS, SUITE_MAX_CHARS } from "../src/validate";

/** The daemon's RELAY_ENVELOPE_RESERVE (cronstable/push.py). */
const DAEMON_RESERVE = 107;

const SUITES = ["x25519", "xwing"];

function envelopeBytes(suite: string): number {
  const json = JSON.stringify(
    apnsPayload({
      deviceToken: "a".repeat(64),
      ciphertext: "",
      collapseId: "0".repeat(32),
      priority: "time-sensitive",
      topic: "com.example.app",
      suite,
    }),
  );
  return new TextEncoder().encode(json).length;
}

describe("APNs size budget", () => {
  it("ENVELOPE_BYTES matches the widest envelope really built", () => {
    const widest = Math.max(...SUITES.map(envelopeBytes));
    expect(ENVELOPE_BYTES).toBe(widest);
  });

  it("a max-length ciphertext still fits Apple's cap", () => {
    for (const suite of SUITES) {
      const json = JSON.stringify(
        apnsPayload({
          deviceToken: "a".repeat(64),
          ciphertext: "A".repeat(MAX_CIPHERTEXT_CHARS),
          collapseId: "0".repeat(32),
          priority: "time-sensitive",
          topic: "com.example.app",
          suite,
        }),
      );
      const size = new TextEncoder().encode(json).length;
      expect(size, `suite ${suite}`).toBeLessThanOrEqual(APNS_PAYLOAD_MAX);
    }
  });

  it("the reserve the daemon budgets for is really there", () => {
    // The daemon computes its cap as 4096 - ENVELOPE_BYTES - reserve and
    // rounds down; if this relay ever grows the envelope past what the
    // reserve absorbs, this fails here rather than at Apple.
    expect(
      ENVELOPE_BYTES + MAX_CIPHERTEXT_CHARS + DAEMON_RESERVE,
    ).toBeLessThanOrEqual(APNS_PAYLOAD_MAX);
  });

  it("the widest suite token the grammar allows still fits", () => {
    // ENVELOPE_BYTES is measured with the known suites' tokens; a suite
    // this relay has never heard of can be SUITE_MAX_CHARS long and is
    // forwarded, so the reserve has to cover what the extra characters
    // cost on top of a max-length ciphertext.
    const json = JSON.stringify(
      apnsPayload({
        deviceToken: "a".repeat(64),
        ciphertext: "A".repeat(MAX_CIPHERTEXT_CHARS),
        collapseId: "0".repeat(32),
        priority: "time-sensitive",
        topic: "com.example.app",
        suite: "s".repeat(SUITE_MAX_CHARS),
      }),
    );
    const size = new TextEncoder().encode(json).length;
    expect(size).toBeLessThanOrEqual(APNS_PAYLOAD_MAX);
  });

  it("the passive variant is never wider than the time-sensitive one", () => {
    // time-sensitive adds `sound`, so it is the one ENVELOPE_BYTES must
    // describe; a future change that inverts that would silently break
    // the bound above.
    const passive = JSON.stringify(
      apnsPayload({
        deviceToken: "a".repeat(64),
        ciphertext: "",
        collapseId: "0".repeat(32),
        priority: "passive",
        topic: "com.example.app",
        suite: "x25519",
      }),
    ).length;
    expect(passive).toBeLessThanOrEqual(ENVELOPE_BYTES);
  });
});
