// The APNs credentials are secrets, so they are absent from the
// bindings `wrangler types` can see in wrangler.jsonc; the test worker
// supplies them from vitest.config.mts. Declaration merging adds them
// to the generated Cloudflare.Env so `env` is typed in tests.
declare namespace Cloudflare {
  interface Env {
    APNS_TEAM_ID: string;
    APNS_KEY_ID: string;
    APNS_AUTH_KEY: string;
  }
}
