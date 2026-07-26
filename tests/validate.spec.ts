import { describe, expect, it } from "vitest";

import { parseEnvelope } from "../src/validate";

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
    expect(errorOf({ ...valid(), ciphertext: "A".repeat(3004) })).toMatch(
      /exceeds/,
    );
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
