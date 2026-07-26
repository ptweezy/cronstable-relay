import { readFileSync } from "node:fs";

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// The integration tests need timing-sensitive policy windows small
// enough to cross with sub-second sleeps, and a real (test-only) ES256
// key so the JWT path runs for real; only APNs itself is mocked.
export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            APNS_TEAM_ID: "TESTTEAM99",
            APNS_KEY_ID: "TESTKEY999",
            APNS_AUTH_KEY: readFileSync(
              new URL("./tests/fixtures/test-apns-key.p8", import.meta.url),
              "utf8",
            ),
            APNS_TOPIC: "test.cronstable.app",
            APNS_ENVIRONMENT: "auto",
            RELAY_DEDUP_WINDOW_S: "2",
            RELAY_RATE_CAPACITY: "5",
            RELAY_RATE_REFILL_PER_S: "1",
            RELAY_FLAP_MAX_FORWARDS: "3",
            RELAY_FLAP_WINDOW_S: "60",
            RELAY_COOLDOWN_INTERVAL_S: "60",
            RELAY_FLAP_RESET_S: "120",
          },
        },
      },
    },
  },
});
