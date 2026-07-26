import type { Env } from "../src/types";

declare module "cloudflare:test" {
  // The bindings vitest.config.mts provides to the test worker.
  interface ProvidedEnv extends Env {}
}
