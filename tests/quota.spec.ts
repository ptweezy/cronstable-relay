import { describe, expect, it } from "vitest";

import {
  claimSlot,
  deviceCapFromEnv,
  DEFAULT_DEVICE_CAP,
} from "../src/entitlement";
import {
  countForward,
  currentQuota,
  DEFAULT_QUOTA,
  digestDue,
  entitlementValid,
  markDigest,
  periodEndsAt,
  periodKey,
  quotaExhausted,
  quotaFromEnv,
  uncountForward,
  type QuotaConfig,
} from "../src/quota";

const CFG: QuotaConfig = {
  freeMonthlyForwards: 3,
  digestIntervalMs: 60_000,
  periodMs: null,
};

// 2026-08-31T23:59:59Z: one second before a month rollover.
const LAST_SECOND = Date.UTC(2026, 7, 31, 23, 59, 59);

describe("quota periods", () => {
  it("keys periods by UTC calendar month", () => {
    expect(periodKey(Date.UTC(2026, 0, 15), CFG)).toBe("2026-01");
    expect(periodKey(LAST_SECOND, CFG)).toBe("2026-08");
    expect(periodKey(LAST_SECOND + 1000, CFG)).toBe("2026-09");
  });

  it("rolls over at 00:00 UTC on the first, including into a new year", () => {
    expect(periodEndsAt(LAST_SECOND, CFG)).toBe(Date.UTC(2026, 8, 1));
    expect(periodEndsAt(Date.UTC(2026, 11, 25), CFG)).toBe(
      Date.UTC(2027, 0, 1),
    );
  });

  it("uses fixed buckets under a test period", () => {
    const cfg = { ...CFG, periodMs: 10_000 };
    expect(periodKey(25_000, cfg)).toBe("2");
    expect(periodKey(29_999, cfg)).toBe("2");
    expect(periodKey(30_000, cfg)).toBe("3");
    expect(periodEndsAt(25_000, cfg)).toBe(30_000);
  });

  it("reads a stored count from another period as zero", () => {
    const stored = { period: "2026-08", forwards: 3, digestAt: LAST_SECOND };
    expect(currentQuota(stored, LAST_SECOND, CFG)).toBe(stored);
    expect(currentQuota(stored, LAST_SECOND + 1000, CFG)).toEqual({
      period: "2026-09",
      forwards: 0,
      digestAt: 0,
    });
    expect(currentQuota(undefined, LAST_SECOND, CFG).forwards).toBe(0);
  });
});

describe("quota counting", () => {
  it("counts forwards up to the bound and uncounts on rollback", () => {
    let q = currentQuota(undefined, LAST_SECOND, CFG);
    for (let i = 0; i < 3; i += 1) {
      expect(quotaExhausted(q, CFG)).toBe(false);
      q = countForward(q);
    }
    expect(quotaExhausted(q, CFG)).toBe(true);
    q = uncountForward(q);
    expect(quotaExhausted(q, CFG)).toBe(false);
    expect(q.forwards).toBe(2);
  });

  it("never uncounts below zero", () => {
    const q = currentQuota(undefined, LAST_SECOND, CFG);
    expect(uncountForward(q).forwards).toBe(0);
  });

  it("allows one digest per interval", () => {
    const q = currentQuota(undefined, LAST_SECOND, CFG);
    expect(digestDue(q, LAST_SECOND, CFG)).toBe(true);
    const marked = markDigest(q, LAST_SECOND);
    expect(digestDue(marked, LAST_SECOND + 59_999, CFG)).toBe(false);
    expect(digestDue(marked, LAST_SECOND + 60_000, CFG)).toBe(true);
  });
});

describe("entitlement validity", () => {
  const record = {
    originalTransactionId: "1",
    productId: "p",
    expiresAt: LAST_SECOND,
    environment: "Production" as const,
    verifiedAt: 0,
  };

  it("is valid until expiry, forever without one", () => {
    expect(entitlementValid(undefined, 0)).toBe(false);
    expect(entitlementValid(record, LAST_SECOND - 1)).toBe(true);
    expect(entitlementValid(record, LAST_SECOND)).toBe(false);
    expect(entitlementValid({ ...record, expiresAt: null }, 1e15)).toBe(true);
  });
});

describe("quotaFromEnv", () => {
  it("defaults to 500 forwards, hourly digests, calendar months", () => {
    expect(quotaFromEnv({})).toEqual(DEFAULT_QUOTA);
    expect(DEFAULT_QUOTA.freeMonthlyForwards).toBe(500);
    expect(DEFAULT_QUOTA.digestIntervalMs).toBe(3_600_000);
  });

  it("reads seconds and rejects junk", () => {
    expect(
      quotaFromEnv({
        RELAY_FREE_MONTHLY_FORWARDS: "2",
        RELAY_DIGEST_INTERVAL_S: "2",
        RELAY_QUOTA_PERIOD_S: "6",
      }),
    ).toEqual({
      freeMonthlyForwards: 2,
      digestIntervalMs: 2000,
      periodMs: 6000,
    });
    expect(
      quotaFromEnv({
        RELAY_FREE_MONTHLY_FORWARDS: "-1",
        RELAY_DIGEST_INTERVAL_S: "nope",
        RELAY_QUOTA_PERIOD_S: "0",
      }),
    ).toEqual(DEFAULT_QUOTA);
  });
});

describe("per-transaction device slots", () => {
  const cap = { devicesPerTransaction: 2, slotTtlMs: 1000 };

  it("admits up to the cap, refreshes known devices, refuses new ones", () => {
    let slots = {};
    let r = claimSlot(slots, "a", 100, cap);
    expect(r.result).toEqual({ admitted: true });
    slots = r.slots;
    r = claimSlot(slots, "b", 200, cap);
    expect(r.result).toEqual({ admitted: true });
    slots = r.slots;
    r = claimSlot(slots, "c", 300, cap);
    expect(r.result).toEqual({ admitted: false, limit: 2 });
    r = claimSlot(slots, "a", 400, cap);
    expect(r.result).toEqual({ admitted: true });
    expect(r.slots).toEqual({ a: 400, b: 200 });
  });

  it("frees a slot after the TTL of silence", () => {
    const slots = { a: 100, b: 200 };
    const r = claimSlot(slots, "c", 1100, cap);
    expect(r.result).toEqual({ admitted: true });
    expect(r.slots).toEqual({ b: 200, c: 1100 });
  });

  it("defaults to 5 devices and 60 days", () => {
    expect(deviceCapFromEnv({})).toEqual(DEFAULT_DEVICE_CAP);
    expect(DEFAULT_DEVICE_CAP).toEqual({
      devicesPerTransaction: 5,
      slotTtlMs: 60 * 86_400_000,
    });
    expect(
      deviceCapFromEnv({
        RELAY_PRO_DEVICES_PER_TRANSACTION: "3",
        RELAY_PRO_DEVICE_SLOT_TTL_S: "10",
      }),
    ).toEqual({ devicesPerTransaction: 3, slotTtlMs: 10_000 });
  });
});
