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

import { apnsPayload } from "../src/apns";
import { MAX_CIPHERTEXT_CHARS, SUITE_MAX_CHARS } from "../src/validate";

/** APNs rejects notifications whose final JSON exceeds this. */
const APNS_PAYLOAD_MAX = 4096;

/**
 * What everything in apnsPayload() except the ciphertext serializes to,
 * with the longest suite token in play.  The daemon hardcodes the same
 * number as RELAY_ENVELOPE_BYTES (cronstable/push.py) and derives its
 * ciphertext cap from it, so the pin below measures it against the real
 * payload rather than letting the two drift.
 */
const ENVELOPE_BYTES = 189;

/** The daemon's RELAY_ENVELOPE_RESERVE (cronstable/push.py). */
const DAEMON_RESERVE = 107;

const SUITES = ["x25519", "xwing"];

const PRIORITIES = ["time-sensitive", "passive"] as const;

function envelopeBytes(
  suite: string,
  priority: (typeof PRIORITIES)[number],
): number {
  const json = JSON.stringify(
    apnsPayload({
      deviceToken: "a".repeat(64),
      ciphertext: "",
      collapseId: "0".repeat(32),
      priority,
      topic: "com.example.app",
      suite,
    }),
  );
  return new TextEncoder().encode(json).length;
}

describe("APNs size budget", () => {
  it("ENVELOPE_BYTES matches the widest envelope really built", () => {
    // Widest across both axes: time-sensitive adds `sound`, so it is the
    // branch ENVELOPE_BYTES describes, and taking the maximum keeps the
    // pin right if that ever inverts.
    const widest = Math.max(
      ...SUITES.flatMap((suite) =>
        PRIORITIES.map((priority) => envelopeBytes(suite, priority)),
      ),
    );
    expect(ENVELOPE_BYTES).toBe(widest);
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
});
