/**
 * cronstable-relay: the hosted push relay for cronstable's end-to-end
 * encrypted alerts (docs/relay-protocol.md v1 in the cronstable repo).
 *
 * POST / takes one envelope per (alert, device) from a daemon, applies
 * the delivery policy in a per-device Durable Object, and forwards the
 * still-sealed ciphertext to APNs.  The relay never sees plaintext:
 * job names, hosts and log lines exist only inside the sealed box the
 * target device alone can open.
 */

import { MAX_BODY_BYTES, parseEnvelope } from "./validate";
import { PAIR_AASA, PAIR_HTML } from "./pair";
import { PRIVACY_HTML } from "./privacy";
import type { DeliverOutcome, Env } from "./types";

export { DeviceState } from "./device";

const INFO = `cronstable-relay

End-to-end encrypted push relay for cronstable (https://github.com/ptweezy/cronstable).
Daemons POST sealed alert ciphertexts here (relay protocol v1); the relay
coalesces, rate-limits and forwards them to APNs. Alert plaintext never
exists on this service.

Source:   https://github.com/ptweezy/cronstable-relay
Protocol: https://github.com/ptweezy/cronstable/blob/main/docs/relay-protocol.md
`;

function json(
  status: number,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

/** First 8 hex chars of SHA-256(token): log correlation without
 * writing a routable device token into logs. */
async function deviceLogId(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return [...new Uint8Array(digest).slice(0, 4)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/privacy") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(405, { v: 1, error: "method not allowed" }, { allow: "GET, HEAD" });
      }
      return new Response(PRIVACY_HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    // The dashboard QR's landing page (src/pair.ts).  The pairing payload
    // is in the URL fragment, so it never appears in these requests.
    if (url.pathname === "/pair") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(405, { v: 1, error: "method not allowed" }, { allow: "GET, HEAD" });
      }
      return new Response(PAIR_HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    // Apple's CDN fetches this to activate /pair as a universal link.
    if (url.pathname === "/.well-known/apple-app-site-association") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(405, { v: 1, error: "method not allowed" }, { allow: "GET, HEAD" });
      }
      return new Response(PAIR_AASA, {
        headers: { "content-type": "application/json" },
      });
    }
    if (url.pathname !== "/") {
      return json(404, { v: 1, error: "not found" });
    }
    if (request.method === "GET" || request.method === "HEAD") {
      return new Response(INFO, {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    if (request.method !== "POST") {
      return json(
        405,
        { v: 1, error: "method not allowed" },
        { allow: "GET, HEAD, POST" },
      );
    }
    const declared = Number(request.headers.get("content-length") ?? "0");
    if (declared > MAX_BODY_BYTES) {
      return json(413, { v: 1, error: "body too large" });
    }
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return json(413, { v: 1, error: "body too large" });
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      return json(400, { v: 1, error: "body is not valid JSON" });
    }
    const parsed = parseEnvelope(raw);
    if ("error" in parsed) {
      return json(400, { v: 1, error: parsed.error });
    }
    const envelope = parsed.envelope;

    let outcome: DeliverOutcome;
    try {
      const stub = env.DEVICE.get(env.DEVICE.idFromName(envelope.device));
      outcome = await stub.deliver(envelope);
    } catch (err) {
      console.error(
        JSON.stringify({ evt: "deliver_error", err: String(err) }),
      );
      outcome = { status: 502, body: { v: 1, error: "relay internal error" } };
    }
    console.log(
      JSON.stringify({
        evt: "deliver",
        status: outcome.status,
        outcome: outcome.body.outcome ?? outcome.body.error ?? null,
        device: await deviceLogId(envelope.device),
        collapse: envelope.collapseId.slice(0, 8),
        priority: envelope.priority,
        event: envelope.event,
      }),
    );
    const headers: Record<string, string> = {};
    if (outcome.retryAfterS !== undefined) {
      headers["retry-after"] = String(outcome.retryAfterS);
    }
    return json(outcome.status, outcome.body, headers);
  },
} satisfies ExportedHandler<Env>;
