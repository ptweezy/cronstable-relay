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
 *
 * Replies to one origin are used in the order they were armed, so
 * `expectApns(PROD, 500); expectApns(PROD, 200);` scripts a retry.  A
 * reply can also arrive late (`delayMs`), fail the connection
 * (`expectApnsError`), or never come (`expectApnsHang`).  The stub
 * honors the request's `signal` the way fetch does: an abort rejects
 * the pending request with the signal's reason.  Every wait happens
 * inside the stub, in the caller's own I/O context, because a promise
 * settled from the test's context cannot reach into a Durable Object.
 */

import { expect, vi } from "vitest";

export const PROD = "https://api.push.apple.com";
export const SANDBOX = "https://api.sandbox.push.apple.com";

/** How long a request APNs never answers waits for its signal before
 * failing on its own, so a send with no deadline fails its test rather
 * than hanging it. */
const HANG_LIMIT_MS = 30_000;

/** One captured outbound request to APNs. */
export interface ApnsRequest {
  origin: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  /** Whether the relay passed fetch a signal. */
  signalled: boolean;
  /** Whether the signal fired while the request waited for its reply.
   * The stub records it because a signal belongs to the Durable Object
   * that made it, and reading one from a test's context throws. */
  aborted: boolean;
  /** True when no reply was armed for it; the stub then fails it. */
  unexpected: boolean;
}

interface Reply {
  origin: string;
  /** An HTTP answer, a failed connection, or no answer at all. */
  kind: "answer" | "error" | "hang";
  status: number;
  body: string;
  delayMs: number;
}

const queued: Reply[] = [];
let captured: ApnsRequest[] = [];

/** Arm one reply for the next request to `origin`, `delayMs` late. */
export function expectApns(
  origin: string,
  status: number,
  body = "",
  { delayMs = 0 }: { delayMs?: number } = {},
): void {
  queued.push({ origin, kind: "answer", status, body, delayMs });
}

/** Arm a failed connection for the next request to `origin`: fetch
 * throws, as it does on a reset. */
export function expectApnsError(
  origin: string,
  { delayMs = 0 }: { delayMs?: number } = {},
): void {
  queued.push({ origin, kind: "error", status: 0, body: "", delayMs });
}

/** Arm a request to `origin` that APNs never answers: it settles only
 * when its signal fires. */
export function expectApnsHang(origin: string): void {
  queued.push({ origin, kind: "hang", status: 0, body: "", delayMs: 0 });
}

/** Every APNs request seen since the last reset, in order, including
 * requests no reply was armed for. */
export function apnsRequests(): readonly ApnsRequest[] {
  return captured;
}

export function resetApnsMock(): void {
  queued.length = 0;
  captured = [];
}

/**
 * Wait until `count` APNs requests have been seen, then assert exactly
 * that many.  A Durable Object alarm sends on its own schedule, so a
 * test that leaves one to fire waits for its request rather than
 * sleeping a guessed interval.
 */
export async function waitForApns(
  count: number,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (captured.length < count && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  expect(captured.length, "APNs requests seen").toBe(count);
}

/** Fail the test if an armed reply went unused (an expected send never
 * happened) or a request arrived with no reply armed. */
export function expectNoPendingApns(): void {
  expect(
    queued.map((r) => `${r.origin} -> ${r.kind} ${r.status}`),
    "armed APNs replies were never used",
  ).toEqual([]);
  expect(
    captured.filter((r) => r.unexpected).map((r) => r.origin + r.path),
    "APNs requests arrived with no reply armed",
  ).toEqual([]);
}

function settle(
  reply: Reply,
  signal: AbortSignal | null,
  request: ApnsRequest,
): Promise<Response> {
  const outcome = (): Promise<Response> =>
    reply.kind === "answer"
      ? Promise.resolve(new Response(reply.body, { status: reply.status }))
      : Promise.reject(
          new TypeError(
            reply.kind === "hang"
              ? "Network connection lost after a stall."
              : "Network connection lost.",
          ),
        );
  if (reply.kind !== "hang" && reply.delayMs === 0) return outcome();
  return new Promise<Response>((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      request.aborted = true;
      reject(signal!.reason);
    };
    const timer = setTimeout(
      () => {
        signal?.removeEventListener("abort", onAbort);
        outcome().then(resolve, reject);
      },
      reply.kind === "hang" ? HANG_LIMIT_MS : reply.delayMs,
    );
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Install the stub for the whole test file.  A request to anything
 * other than APNs fails without being recorded.  A request to APNs with
 * no reply armed is recorded, marked `unexpected`, and then fails: an
 * unexpected outbound request should fail loudly rather than reach the
 * network, and a count of `apnsRequests()` still sees it.
 */
export function installApnsMock(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url,
      );
      const origin = url.origin;
      if (origin !== PROD && origin !== SANDBOX) {
        return Promise.reject(
          new Error(`unexpected outbound request to ${origin}`),
        );
      }
      const signal = init?.signal ?? null;
      // An aborted signal stops fetch before anything is sent.
      if (signal?.aborted) return Promise.reject(signal.reason);
      const index = queued.findIndex((r) => r.origin === origin);
      const reply = index === -1 ? null : queued.splice(index, 1)[0]!;
      const headers: Record<string, string> = {};
      new Headers(init?.headers).forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      const request: ApnsRequest = {
        origin,
        path: url.pathname,
        headers,
        body: typeof init?.body === "string" ? init.body : "",
        signalled: signal !== null,
        aborted: false,
        unexpected: reply === null,
      };
      captured.push(request);
      if (reply === null) {
        return Promise.reject(
          new Error(`unexpected APNs request to ${origin}${url.pathname}`),
        );
      }
      return settle(reply, signal, request);
    }),
  );
}
