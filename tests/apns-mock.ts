/**
 * A small APNs stand-in built on `globalThis.fetch`.
 *
 * The pool's `fetchMock` (undici's MockAgent) was removed in the Vitest
 * 4 integration, and mocking the global is now the supported way to
 * intercept a Worker's outbound requests: the worker under test runs in
 * the same isolate as the test, so it calls this stub instead of Apple.
 *
 * Usage mirrors the old interceptor model — arm one reply per expected
 * request, then assert none were left unused:
 *
 *     expectApns(PROD, 200);
 *     ...
 *     expectNoPendingApns();   // afterEach
 */

import { expect, vi } from "vitest";

export const PROD = "https://api.push.apple.com";
export const SANDBOX = "https://api.sandbox.push.apple.com";

/** One captured outbound request to APNs. */
export interface ApnsRequest {
  origin: string;
  path: string;
  headers: Record<string, string>;
  body: string;
}

interface Reply {
  origin: string;
  status: number;
  body: string;
}

const queued: Reply[] = [];
let captured: ApnsRequest[] = [];

/** Arm one reply for the next request to `origin`. */
export function expectApns(origin: string, status: number, body = ""): void {
  queued.push({ origin, status, body });
}

/** Every APNs request seen since the last reset, in order. */
export function apnsRequests(): readonly ApnsRequest[] {
  return captured;
}

export function resetApnsMock(): void {
  queued.length = 0;
  captured = [];
}

/** Fail the test if an armed reply went unused (an expected send never happened). */
export function expectNoPendingApns(): void {
  expect(
    queued.map((r) => `${r.origin} -> ${r.status}`),
    "armed APNs replies were never used",
  ).toEqual([]);
}

/**
 * Install the stub for the whole test file. Requests to anything other
 * than APNs, or to APNs with no reply armed, throw: an unexpected
 * outbound request should fail loudly rather than reach the network.
 */
export function installApnsMock(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url,
      );
      const origin = url.origin;
      if (origin !== PROD && origin !== SANDBOX) {
        throw new Error(`unexpected outbound request to ${origin}`);
      }
      const index = queued.findIndex((r) => r.origin === origin);
      if (index === -1) {
        throw new Error(`unexpected APNs request to ${origin}${url.pathname}`);
      }
      const reply = queued.splice(index, 1)[0]!;
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      captured.push({
        origin,
        path: url.pathname,
        headers,
        body: typeof init?.body === "string" ? init.body : "",
      });
      return new Response(reply.body, { status: reply.status });
    }),
  );
}
