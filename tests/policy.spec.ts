import { describe, expect, it } from "vitest";

import {
  admit,
  DEFAULT_POLICY,
  forwardRows,
  policyFromEnv,
  recordForward,
  type BucketState,
  type CollapseState,
  type PolicyConfig,
} from "../src/policy";

// Small, readable numbers; every case pins a window edge explicitly.
const CFG: PolicyConfig = {
  dedupWindowMs: 10_000,
  rateCapacity: 3,
  rateRefillPerSec: 1,
  flapMaxForwards: 3,
  flapWindowMs: 100_000,
  cooldownIntervalMs: 50_000,
  flapResetMs: 200_000,
};

const T0 = 1_700_000_000_000;

function forwarded(times: number[], cfg = CFG): CollapseState {
  let state: CollapseState | undefined;
  let bucket: BucketState | undefined;
  for (const t of times) {
    const res = admit(state, bucket, t, cfg);
    expect(res.decision).toBe("forward");
    state = recordForward(res.collapse, t);
    bucket = res.bucket;
  }
  return state!;
}

describe("admit: dedup", () => {
  it("forwards a first-seen alert", () => {
    const res = admit(undefined, undefined, T0, CFG);
    expect(res.decision).toBe("forward");
    expect(res.bucket.tokens).toBe(CFG.rateCapacity - 1);
  });

  it("coalesces inside the dedup window of the last forward", () => {
    const state = forwarded([T0]);
    const res = admit(state, undefined, T0 + 9_999, CFG);
    expect(res.decision).toBe("coalesce");
  });

  it("forwards again once the dedup window has passed", () => {
    const state = forwarded([T0]);
    const res = admit(state, undefined, T0 + 10_000, CFG);
    expect(res.decision).toBe("forward");
  });

  it("measures dedup from the last FORWARD, not the last post", () => {
    // A stateless install re-reporting the same failure every 6 s:
    // coalesced posts must not slide the window forever.
    let state = forwarded([T0]);
    let res = admit(state, undefined, T0 + 6_000, CFG);
    expect(res.decision).toBe("coalesce");
    state = res.collapse;
    res = admit(state, undefined, T0 + 12_000, CFG);
    expect(res.decision).toBe("forward");
  });

  it("does not spend a rate token on a coalesced post", () => {
    const state = forwarded([T0]);
    const res = admit(
      state,
      { tokens: 2, ts: T0 },
      T0 + 1_000,
      CFG,
    );
    expect(res.decision).toBe("coalesce");
    expect(res.bucket.tokens).toBe(3); // refilled by 1s, untouched
  });
});

describe("admit: flap suppression", () => {
  it("suppresses once the window holds the configured forwards", () => {
    const state = forwarded([T0, T0 + 20_000, T0 + 40_000]);
    const res = admit(state, undefined, T0 + 55_000, CFG);
    expect(res.decision).toBe("suppress");
    expect(res.collapse.cooledUntil).toBe(T0 + 55_000 + CFG.flapResetMs);
  });

  it("keeps suppressing inside the cooldown interval", () => {
    const state = forwarded([T0, T0 + 20_000, T0 + 40_000]);
    const first = admit(state, undefined, T0 + 55_000, CFG);
    const again = admit(first.collapse, undefined, T0 + 70_000, CFG);
    expect(again.decision).toBe("suppress");
    // ... and every post keeps the id cooled.
    expect(again.collapse.cooledUntil).toBe(T0 + 70_000 + CFG.flapResetMs);
  });

  it("lets one heartbeat through per cooldown interval while cooled", () => {
    const state = forwarded([T0, T0 + 20_000, T0 + 40_000]);
    const cooled = admit(state, undefined, T0 + 55_000, CFG).collapse;
    // 50s (cooldownIntervalMs) after the last forward at T0+40s:
    const res = admit(cooled, undefined, T0 + 90_000, CFG);
    expect(res.decision).toBe("forward");
    expect(res.collapse.cooledUntil).toBeGreaterThan(T0 + 90_000);
  });

  it("suppresses again after the heartbeat", () => {
    const state = forwarded([T0, T0 + 20_000, T0 + 40_000]);
    let cooled = admit(state, undefined, T0 + 55_000, CFG).collapse;
    const heartbeat = admit(cooled, undefined, T0 + 90_000, CFG);
    cooled = recordForward(heartbeat.collapse, T0 + 90_000);
    const after = admit(cooled, undefined, T0 + 105_000, CFG);
    expect(after.decision).toBe("suppress");
  });

  it("returns to normal after flapReset of silence", () => {
    const state = forwarded([T0, T0 + 20_000, T0 + 40_000]);
    const cooled = admit(state, undefined, T0 + 55_000, CFG).collapse;
    const later = T0 + 55_000 + CFG.flapResetMs + 1;
    const res = admit(cooled, undefined, later, CFG);
    // Old forwards fell out of the flap window; cooldown expired.
    expect(res.decision).toBe("forward");
  });

  it("prunes forwards outside the flap window before counting", () => {
    const state = forwarded([T0, T0 + 20_000]);
    // Third forward far enough out that the first left the window.
    const res = admit(state, undefined, T0 + 110_000, CFG);
    expect(res.decision).toBe("forward");
    const after = recordForward(res.collapse, T0 + 110_000);
    expect(after.forwards).toEqual([T0 + 20_000, T0 + 110_000]);
  });
});

describe("admit: flap suppression keyed on a flapId", () => {
  /** Forward a fresh collapse id per run, all sharing one flap row. */
  function runs(times: number[], cfg = CFG) {
    let flap: CollapseState | undefined;
    const decisions: string[] = [];
    for (const t of times) {
      const res = admit(undefined, undefined, t, cfg, { row: flap });
      decisions.push(res.decision);
      flap = res.decision === "forward" ? forwardRows(res, t).flap : res.flap;
    }
    return { decisions, flap: flap! };
  }

  it("counts forwards across collapse ids on the flap row", () => {
    const { decisions, flap } = runs([T0, T0 + 20_000, T0 + 40_000, T0 + 55_000]);
    expect(decisions).toEqual(["forward", "forward", "forward", "suppress"]);
    expect(flap.cooledUntil).toBe(T0 + 55_000 + CFG.flapResetMs);
  });

  it("heartbeats on the flap row's last forward", () => {
    const { flap } = runs([T0, T0 + 20_000, T0 + 40_000, T0 + 55_000]);
    // A new run 50 s (cooldownIntervalMs) after the last forward.
    const res = admit(undefined, undefined, T0 + 90_000, CFG, { row: flap });
    expect(res.decision).toBe("forward");
  });

  it("keeps dedup on the collapse row", () => {
    const first = admit(undefined, undefined, T0, CFG, { row: undefined });
    const rows = forwardRows(first, T0);
    // The same run reported again: coalesced, whatever the flap row says.
    const again = admit(rows.collapse, first.bucket, T0 + 1_000, CFG, {
      row: rows.flap,
    });
    expect(again.decision).toBe("coalesce");
    // The collapse row keeps no history of its own; the flap row does.
    expect(rows.collapse.forwards).toEqual([]);
    expect(rows.collapse.lastForwardAt).toBe(T0);
    expect(rows.flap!.forwards).toEqual([T0]);
  });

  it("leaves the flap row out without a flapId", () => {
    const res = admit(undefined, undefined, T0, CFG);
    expect(res.flap).toBeUndefined();
    expect(forwardRows(res, T0)).toEqual({
      collapse: recordForward(res.collapse, T0),
    });
  });

  it("bounds a job failing every minute to a few pages an hour", () => {
    // Defaults; a fresh collapse id per run, as the daemon's per-run ids
    // give, and one flapId for them all.  Bounded by flapMaxForwards plus
    // one heartbeat per cooldownInterval.
    const minute = 60_000;
    const times = Array.from({ length: 60 }, (_, m) => T0 + m * minute);
    const keyed = runs(times, DEFAULT_POLICY).decisions;
    const bound =
      DEFAULT_POLICY.flapMaxForwards +
      Math.ceil(3_600_000 / DEFAULT_POLICY.cooldownIntervalMs);
    expect(keyed.filter((d) => d === "forward").length).toBeLessThanOrEqual(
      bound,
    );
    // Without the flapId each run starts from a fresh history.
    let bucket: BucketState | undefined;
    let unkeyed = 0;
    for (const t of times) {
      const res = admit(undefined, bucket, t, DEFAULT_POLICY);
      bucket = res.bucket;
      if (res.decision === "forward") unkeyed += 1;
    }
    expect(unkeyed).toBe(60);
  });
});

describe("admit: rate limiting", () => {
  it("starts with a full bucket", () => {
    const res = admit(undefined, undefined, T0, CFG);
    expect(res.bucket.tokens).toBe(CFG.rateCapacity - 1);
  });

  it("rate-limits when the bucket is empty, without spending", () => {
    const res = admit(
      undefined,
      { tokens: 0.5, ts: T0 },
      T0,
      CFG,
    );
    expect(res.decision).toBe("rate_limit");
    expect(res.bucket).toEqual({ tokens: 0.5, ts: T0 });
  });

  it("refills at the configured rate up to capacity", () => {
    const res = admit(
      undefined,
      { tokens: 0, ts: T0 },
      T0 + 2_500,
      CFG,
    );
    // 2.5 tokens refilled, one spent by this forward.
    expect(res.decision).toBe("forward");
    expect(res.bucket.tokens).toBeCloseTo(1.5, 5);
    const capped = admit(
      undefined,
      { tokens: 0, ts: T0 },
      T0 + 60_000,
      CFG,
    );
    expect(capped.bucket.tokens).toBe(CFG.rateCapacity - 1);
  });
});

describe("policyFromEnv", () => {
  it("returns the defaults for an empty environment", () => {
    expect(policyFromEnv({})).toEqual(DEFAULT_POLICY);
  });

  it("applies overrides and ignores garbage", () => {
    const cfg = policyFromEnv({
      RELAY_DEDUP_WINDOW_S: "2",
      RELAY_RATE_CAPACITY: "5",
      RELAY_FLAP_MAX_FORWARDS: "not a number",
      RELAY_FLAP_WINDOW_S: "-3",
    });
    expect(cfg.dedupWindowMs).toBe(2_000);
    expect(cfg.rateCapacity).toBe(5);
    expect(cfg.flapMaxForwards).toBe(DEFAULT_POLICY.flapMaxForwards);
    expect(cfg.flapWindowMs).toBe(DEFAULT_POLICY.flapWindowMs);
  });
});
