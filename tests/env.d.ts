// The APNs credentials are secrets, so they are absent from the
// bindings `wrangler types` can see in wrangler.jsonc; the test worker
// supplies them from vitest.config.mts, along with the test-only
// certificate chain the entitlement suite signs with. Declaration
// merging adds them to the generated Cloudflare.Env so `env` is typed
// in tests.
declare namespace Cloudflare {
  interface Env {
    APNS_TEAM_ID: string;
    APNS_KEY_ID: string;
    APNS_AUTH_KEY: string;
    RELAY_APPLE_ROOT_CERT: string;
    RELAY_FREE_MONTHLY_FORWARDS?: string;
    RELAY_DIGEST_INTERVAL_S?: string;
    RELAY_QUOTA_PERIOD_S?: string;
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
