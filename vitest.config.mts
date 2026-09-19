import { readFileSync } from "node:fs";

import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// The integration tests need timing-sensitive policy windows small
// enough to cross with sub-second sleeps, and a real (test-only) ES256
// key so the JWT path runs for real; only APNs itself is mocked.
//
// Three projects share one worker: "relay" runs every suite with the
// monthly quota at its default (500 forwards, far above what any test
// sends), "quota" runs tests/quota-relay.spec.ts alone with the quota
// shrunk to two forwards, a two-second digest interval and six-second
// periods, so the digest and rollover paths are crossed with sleeps,
// and "reach" runs tests/tunnel.spec.ts alone with the Reach timers
// and caps shrunk to seconds and single digits for the same reason.

const fixture = (name: string, encoding: "utf8" | "base64" = "utf8") =>
  readFileSync(new URL(`./tests/fixtures/${name}`, import.meta.url)).toString(
    encoding,
  );

const bindings = {
  APNS_TEAM_ID: "TESTTEAM99",
  APNS_KEY_ID: "TESTKEY999",
  APNS_AUTH_KEY: fixture("test-apns-key.p8"),
  APNS_TOPIC: "test.cronstable.app",
  APNS_ENVIRONMENT: "auto",
  RELAY_DEDUP_WINDOW_S: "2",
  RELAY_RATE_CAPACITY: "5",
  RELAY_RATE_REFILL_PER_S: "1",
  RELAY_FLAP_MAX_FORWARDS: "3",
  RELAY_FLAP_WINDOW_S: "60",
  RELAY_COOLDOWN_INTERVAL_S: "60",
  RELAY_FLAP_RESET_S: "120",
  RELAY_PRO_DEVICES_PER_TRANSACTION: "5",
  RELAY_PRO_DEVICE_SLOT_TTL_S: "2",

  // The entitlement suite's test-only certificate chain
  // (scripts/gen-appstore-fixtures.sh).  The relay trusts the test root
  // in place of Apple's; everything else is handed to the tests to
  // build x5c headers and sign with.
  RELAY_APPLE_ROOT_CERT: fixture("appstore/root.der", "base64"),
  TEST_APPSTORE_INTERMEDIATE: fixture("appstore/intermediate.der", "base64"),
  TEST_APPSTORE_LEAF: fixture("appstore/leaf.der", "base64"),
  TEST_APPSTORE_LEAF_KEY: fixture("appstore/leaf.key.pem"),
  TEST_APPSTORE_LEAF_NOMARKER: fixture("appstore/leaf-nomarker.der", "base64"),
  TEST_APPSTORE_LEAF_NOMARKER_KEY: fixture("appstore/leaf-nomarker.key.pem"),
  TEST_APPSTORE_LEAF_EXPIRED: fixture("appstore/leaf-expired.der", "base64"),
  TEST_APPSTORE_LEAF_EXPIRED_KEY: fixture("appstore/leaf-expired.key.pem"),
  TEST_APPSTORE_OTHER_ROOT: fixture("appstore/other-root.der", "base64"),

  // The cronstable repo's byte-exact Reach vectors
  // (tests/fixtures/reach/vectors.json there), copied verbatim.
  TEST_REACH_VECTORS: fixture("reach-vectors.json"),
};

const QUOTA_SPEC = "tests/quota-relay.spec.ts";
const REACH_SPEC = "tests/tunnel.spec.ts";

function project(
  name: string,
  extra: Record<string, string>,
  include: string[],
  exclude: string[] = [],
) {
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: { bindings: { ...bindings, ...extra } },
      }),
    ],
    test: { name, include, exclude },
  };
}

export default defineConfig({
  test: {
    projects: [
      project("relay", {}, ["tests/**/*.spec.ts"], [QUOTA_SPEC, REACH_SPEC]),
      project(
        "quota",
        {
          RELAY_FREE_MONTHLY_FORWARDS: "2",
          RELAY_DIGEST_INTERVAL_S: "2",
          RELAY_QUOTA_PERIOD_S: "6",
        },
        [QUOTA_SPEC],
      ),
      project(
        "reach",
        {
          RELAY_REACH_HELLO_TIMEOUT_S: "1",
          RELAY_REACH_FIRST_BYTE_S: "1",
          RELAY_REACH_STALE_S: "2",
          RELAY_REACH_STREAM_THRESHOLD_S: "1",
          RELAY_REACH_MAX_STREAM_S: "2",
          RELAY_REACH_DAILY_STREAM_S: "3.5",
          RELAY_REACH_MAX_INFLIGHT: "4",
          RELAY_REACH_MAX_STREAMS: "2",
          RELAY_REACH_ADMIT_BURST: "6",
          RELAY_REACH_ADMIT_REFILL_PER_S: "1",
          RELAY_REACH_STRIKES_PER_MIN: "5",
        },
        [REACH_SPEC],
      ),
    ],
  },
});
