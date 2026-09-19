// The APNs credentials are secrets, so they are absent from the
// bindings `wrangler types` can see in wrangler.jsonc; the test worker
// supplies them from vitest.config.mts, along with the test-only
// certificate chain the entitlement suite signs with and the shared
// Reach vectors. Declaration merging adds them to the generated
// Cloudflare.Env so `env` is typed in tests.
declare namespace Cloudflare {
  interface Env {
    APNS_TEAM_ID: string;
    APNS_KEY_ID: string;
    APNS_AUTH_KEY: string;
    RELAY_APPLE_ROOT_CERT: string;
    RELAY_FREE_MONTHLY_FORWARDS?: string;
    RELAY_DIGEST_INTERVAL_S?: string;
    RELAY_QUOTA_PERIOD_S?: string;
    RELAY_REACH_HELLO_TIMEOUT_S?: string;
    RELAY_REACH_FIRST_BYTE_S?: string;
    RELAY_REACH_STALE_S?: string;
    RELAY_REACH_STREAM_THRESHOLD_S?: string;
    RELAY_REACH_MAX_STREAM_S?: string;
    RELAY_REACH_DAILY_STREAM_S?: string;
    RELAY_REACH_MAX_INFLIGHT?: string;
    RELAY_REACH_MAX_STREAMS?: string;
    RELAY_REACH_ADMIT_BURST?: string;
    RELAY_REACH_ADMIT_REFILL_PER_S?: string;
    RELAY_REACH_STRIKES_PER_MIN?: string;
    /** tests/fixtures/reach-vectors.json, the cronstable repo's shared vectors. */
    TEST_REACH_VECTORS: string;
    TEST_APPSTORE_INTERMEDIATE: string;
    TEST_APPSTORE_LEAF: string;
    TEST_APPSTORE_LEAF_KEY: string;
    TEST_APPSTORE_LEAF_NOMARKER: string;
    TEST_APPSTORE_LEAF_NOMARKER_KEY: string;
    TEST_APPSTORE_LEAF_EXPIRED: string;
    TEST_APPSTORE_LEAF_EXPIRED_KEY: string;
    TEST_APPSTORE_OTHER_ROOT: string;
  }
}
