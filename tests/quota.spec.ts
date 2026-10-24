import { describe, expect, it } from "vitest";

import {
  claimSlot,
  deviceCapFromEnv,
  DEFAULT_DEVICE_CAP,
  mergeMarks,
  revokedBy,
  slotRefreshMs,
  type RevocationMark,
} from "../src/entitlement";
import {
  burstDigestDueAt,
  burstDigestIntervalFromEnv,
  burstSent,
  countForward,
  currentQuota,
  DEFAULT_BURST_DIGEST_INTERVAL_MS,
  DEFAULT_PRO_GRACE_MS,
  DEFAULT_QUOTA,
  digestDue,
  entitlementValid,
  foldBurst,
  freeForwards,
  liftEndsAt,
  markDigest,
  markDigestPending,
  periodEndsAt,
  periodKey,
  proGraceFromEnv,
  quotaDigestDueAt,
  quotaExhausted,
  quotaFromEnv,
  quotaWorthKeeping,
  uncountForward,
  type EntitlementRecord,
  type LiftConfig,
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
      freeForwards: 0,
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
      q = countForward(q, true);
    }
    expect(quotaExhausted(q, CFG)).toBe(true);
    q = uncountForward(q, true);
    expect(quotaExhausted(q, CFG)).toBe(false);
    expect(q.forwards).toBe(2);
    expect(freeForwards(q)).toBe(2);
  });

  it("never uncounts below zero", () => {
    const q = currentQuota(undefined, LAST_SECOND, CFG);
    expect(uncountForward(q, true).forwards).toBe(0);
    expect(freeForwards(uncountForward(q, true))).toBe(0);
  });

  it("keeps lifted forwards off the free bound", () => {
    let q = currentQuota(undefined, LAST_SECOND, CFG);
    for (let i = 0; i < 5; i += 1) q = countForward(q, false);
    expect(q.forwards).toBe(5);
    expect(freeForwards(q)).toBe(0);
    expect(quotaExhausted(q, CFG)).toBe(false);
    q = countForward(q, true);
    expect({ forwards: q.forwards, free: freeForwards(q) }).toEqual({
      forwards: 6,
      free: 1,
    });
  });

  it("uncounts exactly the counters the forward bumped", () => {
    const start = { period: "2026-08", forwards: 4, freeForwards: 1, digestAt: 0 };
    const lifted = uncountForward(countForward(start, false), false);
    expect(lifted).toEqual(start);
    const free = uncountForward(countForward(start, true), true);
    expect(free).toEqual(start);
  });

  it("reads a row without freeForwards as all forwards counting", () => {
    const row = { period: "2026-08", forwards: 3, digestAt: 0 };
    expect(freeForwards(row)).toBe(3);
    expect(quotaExhausted(row, CFG)).toBe(true);
    // A lifted forward on such a row leaves the free count where it was.
    const lifted = countForward(row, false);
    expect({ forwards: lifted.forwards, free: freeForwards(lifted) }).toEqual({
      forwards: 4,
      free: 3,
    });
    expect(freeForwards(uncountForward(lifted, false))).toBe(3);
    expect(uncountForward(lifted, false).forwards).toBe(3);
  });

  it("allows one digest per interval", () => {
    const q = currentQuota(undefined, LAST_SECOND, CFG);
    expect(digestDue(q, LAST_SECOND, CFG)).toBe(true);
    const marked = markDigest(q, LAST_SECOND);
    expect(digestDue(marked, LAST_SECOND + 59_999, CFG)).toBe(false);
    expect(digestDue(marked, LAST_SECOND + 60_000, CFG)).toBe(true);
  });
});

describe("the owed quota digest", () => {
  const sent = { period: "2026-08", forwards: 3, digestAt: LAST_SECOND - 10_000 };

  it("comes due one interval after the last digest", () => {
    expect(quotaDigestDueAt(sent, CFG)).toBeNull();
    const owed = markDigestPending(sent);
    expect(quotaDigestDueAt(owed, CFG)).toBe(LAST_SECOND + 50_000);
    expect(quotaDigestDueAt(undefined, CFG)).toBeNull();
  });

  it("is settled by the next digest", () => {
    const settled = markDigest(markDigestPending(sent), LAST_SECOND);
    expect(settled).toEqual({ ...sent, digestAt: LAST_SECOND });
    expect(quotaDigestDueAt(settled, CFG)).toBeNull();
  });

  it("survives a period rollover", () => {
    const owed = markDigestPending(sent);
    expect(currentQuota(owed, LAST_SECOND + 1000, CFG)).toEqual({
      period: "2026-09",
      forwards: 0,
      freeForwards: 0,
      digestAt: sent.digestAt,
      digestPending: true,
    });
  });

  it("keeps a row only while it carries something", () => {
    const now = LAST_SECOND;
    const zero = { period: "2026-08", forwards: 0, digestAt: 0 };
    expect(quotaWorthKeeping(undefined, now, CFG)).toBe(false);
    expect(quotaWorthKeeping(zero, now, CFG)).toBe(false);
    expect(quotaWorthKeeping({ ...zero, forwards: 1 }, now, CFG)).toBe(true);
    expect(quotaWorthKeeping({ ...zero, digestAt: 1 }, now, CFG)).toBe(true);
    // A past period's count reads as zero, but a digest it owes stays.
    expect(quotaWorthKeeping(sent, now + 1000, CFG)).toBe(false);
    expect(quotaWorthKeeping(markDigestPending(sent), now + 1000, CFG)).toBe(
      true,
    );
  });
});

describe("the burst digest", () => {
  const INTERVAL = 300_000;
  const T = LAST_SECOND;

  it("sends at once when none was sent within the interval", () => {
    const first = foldBurst(undefined, T, INTERVAL, false);
    expect(first).toEqual({
      state: { digestAt: T, pendingSince: 0, timeSensitive: false },
      send: "passive",
      write: true,
    });
    expect(foldBurst(undefined, T, INTERVAL, true).send).toBe("time-sensitive");
    const later = foldBurst(first.state, T + INTERVAL, INTERVAL, false);
    expect(later.send).toBe("passive");
  });

  it("owes one digest for folds inside the interval, written once", () => {
    const sent = burstSent(T);
    const owed = foldBurst(sent, T + 1_000, INTERVAL, false);
    expect(owed).toEqual({
      state: { digestAt: T, pendingSince: T + 1_000, timeSensitive: false },
      send: null,
      write: true,
    });
    expect(burstDigestDueAt(owed.state, INTERVAL)).toBe(T + INTERVAL);
    const again = foldBurst(owed.state, T + 2_000, INTERVAL, false);
    expect(again).toEqual({ state: owed.state, send: null, write: false });
  });

  it("escalates the owed digest to time-sensitive", () => {
    const owed = foldBurst(burstSent(T), T + 1_000, INTERVAL, false).state;
    const urgent = foldBurst(owed, T + 2_000, INTERVAL, true);
    expect(urgent.write).toBe(true);
    expect(urgent.state).toEqual({ ...owed, timeSensitive: true });
    expect(foldBurst(urgent.state, T + 3_000, INTERVAL, false).write).toBe(
      false,
    );
    // A leading digest covers what was owed, at the owed level.
    const leading = foldBurst(urgent.state, T + INTERVAL, INTERVAL, false);
    expect(leading.send).toBe("time-sensitive");
    expect(leading.state).toEqual(burstSent(T + INTERVAL));
  });

  it("owes nothing once sent", () => {
    expect(burstDigestDueAt(burstSent(T), INTERVAL)).toBeNull();
    expect(burstDigestDueAt(undefined, INTERVAL)).toBeNull();
  });

  it("reads its interval from RELAY_BURST_DIGEST_INTERVAL_S, five minutes by default", () => {
    expect(DEFAULT_BURST_DIGEST_INTERVAL_MS).toBe(300_000);
    expect(burstDigestIntervalFromEnv({})).toBe(300_000);
    expect(
      burstDigestIntervalFromEnv({ RELAY_BURST_DIGEST_INTERVAL_S: "60" }),
    ).toBe(60_000);
    expect(
      burstDigestIntervalFromEnv({ RELAY_BURST_DIGEST_INTERVAL_S: "0" }),
    ).toBe(300_000);
  });
});

describe("entitlement validity", () => {
  const DAY = 86_400_000;
  const lift: LiftConfig = { graceMs: 16 * DAY, slotTtlMs: 60 * DAY };
  const record: EntitlementRecord = {
    originalTransactionId: "1",
    productId: "p",
    expiresAt: LAST_SECOND,
    environment: "Production",
    verifiedAt: LAST_SECOND - 10 * DAY,
    slotExpiresAt: LAST_SECOND + 50 * DAY,
  };

  it("lifts through the grace past expiry", () => {
    expect(entitlementValid(undefined, 0, lift)).toBe(false);
    expect(entitlementValid(record, LAST_SECOND - 1, lift)).toBe(true);
    expect(entitlementValid(record, LAST_SECOND + 1, lift)).toBe(true);
    const graceEnds = LAST_SECOND + 16 * DAY;
    expect(liftEndsAt(record, lift)).toBe(graceEnds);
    expect(entitlementValid(record, graceEnds - 1, lift)).toBe(true);
    expect(entitlementValid(record, graceEnds, lift)).toBe(false);
  });

  it("ends when the device's slot lapses, whatever the expiry", () => {
    const yearly = { ...record, expiresAt: LAST_SECOND + 300 * DAY };
    const slotEnds = record.slotExpiresAt!;
    expect(liftEndsAt(yearly, lift)).toBe(slotEnds);
    expect(entitlementValid(yearly, slotEnds - 1, lift)).toBe(true);
    expect(entitlementValid(yearly, slotEnds, lift)).toBe(false);
  });

  it("is bound by the slot alone without an expiry", () => {
    const forever = { ...record, expiresAt: null };
    expect(liftEndsAt(forever, lift)).toBe(record.slotExpiresAt);
    expect(entitlementValid(forever, record.slotExpiresAt! - 1, lift)).toBe(
      true,
    );
    expect(entitlementValid(forever, 1e15, lift)).toBe(false);
  });

  it("falls back to verifiedAt plus the slot TTL without slotExpiresAt", () => {
    const { slotExpiresAt: _, ...bare } = record;
    const yearly = { ...bare, expiresAt: LAST_SECOND + 300 * DAY };
    expect(liftEndsAt(yearly, lift)).toBe(record.verifiedAt + 60 * DAY);
    expect(liftEndsAt({ ...bare, expiresAt: null }, lift)).toBe(
      record.verifiedAt + 60 * DAY,
    );
  });

  it("reads the grace from RELAY_PRO_GRACE_S, sixteen days by default", () => {
    expect(DEFAULT_PRO_GRACE_MS).toBe(16 * DAY);
    expect(proGraceFromEnv({})).toBe(16 * DAY);
    expect(proGraceFromEnv({ RELAY_PRO_GRACE_S: "259200" })).toBe(3 * DAY);
    expect(proGraceFromEnv({ RELAY_PRO_GRACE_S: "0" })).toBe(0);
    expect(proGraceFromEnv({ RELAY_PRO_GRACE_S: "-1" })).toBe(16 * DAY);
    expect(proGraceFromEnv({ RELAY_PRO_GRACE_S: "" })).toBe(16 * DAY);
    expect(proGraceFromEnv({ RELAY_PRO_GRACE_S: "soon" })).toBe(16 * DAY);
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
    expect(r.result).toEqual({ admitted: true, slotExpiresAt: 1100 });
    expect(r.write).toBe(true);
    slots = r.slots;
    r = claimSlot(slots, "b", 200, cap);
    expect(r.result).toEqual({ admitted: true, slotExpiresAt: 1200 });
    slots = r.slots;
    r = claimSlot(slots, "c", 300, cap);
    expect(r.result).toEqual({ admitted: false, limit: 2 });
    expect(r.write).toBe(false);
    r = claimSlot(slots, "a", 400, cap);
    expect(r.result).toEqual({ admitted: true, slotExpiresAt: 1400 });
    expect(r.write).toBe(true);
    expect(r.slots).toEqual({ a: 400, b: 200 });
  });

  it("leaves a recently refreshed slot as stored", () => {
    // A quarter of the TTL here (250 ms); a day in production.
    expect(slotRefreshMs(cap)).toBe(250);
    expect(slotRefreshMs(DEFAULT_DEVICE_CAP)).toBe(86_400_000);
    const slots = { a: 100, b: 200 };
    const fresh = claimSlot(slots, "a", 349, cap);
    expect(fresh).toEqual({
      slots,
      result: { admitted: true, slotExpiresAt: 1100 },
      write: false,
    });
    const due = claimSlot(slots, "a", 350, cap);
    expect(due.write).toBe(true);
    expect(due.result).toEqual({ admitted: true, slotExpiresAt: 1350 });
  });

  it("writes a refusal only when it pruned a slot", () => {
    expect(claimSlot({ a: 100, b: 200 }, "c", 900, cap).write).toBe(false);
    // At 1150 "a" has lapsed, and "b" and "c" still fill the cap.
    const pruned = claimSlot({ a: 100, b: 1000, c: 1050 }, "d", 1150, cap);
    expect(pruned.result).toEqual({ admitted: false, limit: 2 });
    expect(pruned.write).toBe(true);
    expect(pruned.slots).toEqual({ b: 1000, c: 1050 });
  });

  it("stores a pruned slot even when the device's own is fresh", () => {
    const pruned = claimSlot({ a: 100, b: 1000 }, "b", 1150, cap);
    expect(pruned.result).toEqual({ admitted: true, slotExpiresAt: 2000 });
    expect(pruned.write).toBe(true);
    expect(pruned.slots).toEqual({ b: 1000 });
  });

  it("frees a slot after the TTL of silence", () => {
    const slots = { a: 100, b: 200 };
    const r = claimSlot(slots, "c", 1100, cap);
    expect(r.result).toEqual({ admitted: true, slotExpiresAt: 2100 });
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

describe("revocation marks", () => {
  const mark: RevocationMark = {
    signedDate: 5_000,
    purchaseDate: 1_000,
    until: 10_000,
  };

  it("refuses a covered proof signed before the revocation", () => {
    expect(revokedBy(mark, { purchaseDate: 1_000, signedDate: 4_999 }, 0)).toBe(
      true,
    );
    expect(revokedBy(mark, { purchaseDate: 500, signedDate: 2_000 }, 0)).toBe(
      true,
    );
    expect(revokedBy(mark, { purchaseDate: null, signedDate: 2_000 }, 0)).toBe(
      true,
    );
  });

  it("passes a later renewal and a copy signed after the revocation", () => {
    expect(revokedBy(mark, { purchaseDate: 1_001, signedDate: 2_000 }, 0)).toBe(
      false,
    );
    expect(revokedBy(mark, { purchaseDate: 1_000, signedDate: 5_000 }, 0)).toBe(
      false,
    );
  });

  it("lapses with its until, or never without one", () => {
    const replay = { purchaseDate: 1_000, signedDate: 2_000 };
    expect(revokedBy(mark, replay, 9_999)).toBe(true);
    expect(revokedBy(mark, replay, 10_000)).toBe(false);
    expect(revokedBy({ ...mark, until: null }, replay, 1e15)).toBe(true);
    expect(
      revokedBy({ ...mark, purchaseDate: null }, { ...replay, purchaseDate: 9e9 }, 0),
    ).toBe(true);
  });

  it("merges two revocations into one that refuses what either refuses", () => {
    expect(mergeMarks(undefined, mark)).toEqual(mark);
    const later = { signedDate: 7_000, purchaseDate: 800, until: 9_000 };
    expect(mergeMarks(mark, later)).toEqual({
      signedDate: 7_000,
      purchaseDate: 1_000,
      until: 10_000,
    });
    expect(mergeMarks(mark, { ...later, until: null }).until).toBe(null);
    expect(mergeMarks(mark, { ...later, purchaseDate: null }).purchaseDate).toBe(
      null,
    );
  });
});
