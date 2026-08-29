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

import { entitlementPolicyFromEnv, verifyTransaction } from "./appstore";
import { MAX_BODY_BYTES, parseDevice, parseEnvelope } from "./validate";
import { PAIR_AASA, PAIR_HTML } from "./pair";
import { PRIVACY_HTML } from "./privacy";
import type { DeliverOutcome, DeviceStatus, Env } from "./types";

export { DeviceState } from "./device";
export { EntitlementState } from "./entitlement";

/** POST /entitlement bodies carry a JWS with a three-certificate chain,
 * which is larger than an envelope but still well under this. */
export const MAX_ENTITLEMENT_BODY_BYTES = 16384;

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

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** First 8 hex chars of SHA-256(token): log correlation without
 * writing a routable device token into logs. */
async function deviceLogId(token: string): Promise<string> {
  return (await sha256Hex(token)).slice(0, 8);
}

/**
 * Read a JSON body no larger than `limit` bytes.  Returns the parsed
 * value, or the response to send instead.
 */
async function readJson(
  request: Request,
  limit: number,
): Promise<{ value: unknown } | { response: Response }> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > limit) {
    return { response: json(413, { v: 1, error: "body too large" }) };
  }
  const text = await request.text();
  if (text.length > limit) {
    return { response: json(413, { v: 1, error: "body too large" }) };
  }
  try {
    return { value: JSON.parse(text) };
  } catch {
    return { response: json(400, { v: 1, error: "body is not valid JSON" }) };
  }
}

function statusBody(status: DeviceStatus): Record<string, unknown> {
  const iso = (ms: number) => new Date(ms).toISOString();
  return {
    v: 1,
    plan: status.plan,
    ...(status.plan === "pro"
      ? {
          expiresAt:
            status.expiresAt === null || status.expiresAt === undefined
              ? null
              : iso(status.expiresAt),
          environment: status.environment,
        }
      : {}),
    quota: {
      used: status.used,
      limit: status.limit,
      resetsAt: iso(status.resetsAt),
    },
  };
}

/**
 * POST /entitlement (relay-protocol.md, "Entitlement proof"): verify a
 * StoreKit signed transaction offline, hold the device's slot on the
 * transaction, and record the entitlement on the device; or, without a
 * JWS, just report the device's plan and quota.
 */
async function entitlement(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return json(405, { v: 1, error: "method not allowed" }, { allow: "POST" });
  }
  const read = await readJson(request, MAX_ENTITLEMENT_BODY_BYTES);
  if ("response" in read) return read.response;
  const raw = read.value;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return json(400, { v: 1, error: "body must be a JSON object" });
  }
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) {
    return json(400, {
      v: 1,
      error: "unsupported protocol version (expected v: 1)",
    });
  }
  const device = parseDevice(o.device);
  if (device === null) {
    return json(400, { v: 1, error: "device must be a hex APNs device token" });
  }
  if (
    o.jws !== undefined &&
    (typeof o.jws !== "string" || o.jws.length === 0)
  ) {
    return json(400, { v: 1, error: "jws must be a non-empty string" });
  }
  const stub = env.DEVICE.get(env.DEVICE.idFromName(device));
  const log = async (fields: Record<string, unknown>) =>
    console.log(
      JSON.stringify({
        evt: "entitlement",
        device: await deviceLogId(device),
        ...fields,
      }),
    );

  if (o.jws === undefined) {
    const status = await stub.status();
    await log({ status: 200, plan: status.plan, proof: false });
    return json(200, statusBody(status));
  }

  const now = Date.now();
  const verified = await verifyTransaction(o.jws, {
    ...entitlementPolicyFromEnv(env),
    now,
  });
  if (!verified.ok) {
    const status = verified.malformed ? 400 : 401;
    await log({ status, reason: verified.reason });
    return json(status, {
      v: 1,
      error: verified.malformed ? "malformed jws" : "entitlement rejected",
      reason: verified.reason,
    });
  }
  const tx = verified.transaction;
  // The transaction's own object holds device-token hashes, never tokens.
  const slot = env.ENTITLEMENT.get(
    env.ENTITLEMENT.idFromName(tx.originalTransactionId),
  );
  const claim = await slot.claim(await sha256Hex(device));
  if (!claim.admitted) {
    await log({ status: 409, limit: claim.limit });
    return json(409, {
      v: 1,
      error: "transaction device limit reached",
      limit: claim.limit,
    });
  }
  const status = await stub.setEntitlement({
    originalTransactionId: tx.originalTransactionId,
    productId: tx.productId,
    expiresAt: tx.expiresAt,
    environment: tx.environment,
    verifiedAt: now,
  });
  await log({
    status: 200,
    plan: status.plan,
    proof: true,
    product: tx.productId,
  });
  return json(200, statusBody(status));
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/privacy") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(
          405,
          { v: 1, error: "method not allowed" },
          { allow: "GET, HEAD" },
        );
      }
      return new Response(PRIVACY_HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    // The dashboard QR's landing page (src/pair.ts).  The pairing payload
    // is in the URL fragment, so it never appears in these requests.
    if (url.pathname === "/pair") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(
          405,
          { v: 1, error: "method not allowed" },
          { allow: "GET, HEAD" },
        );
      }
      return new Response(PAIR_HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    // Apple's CDN fetches this to activate /pair as a universal link.
    if (url.pathname === "/.well-known/apple-app-site-association") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json(
          405,
          { v: 1, error: "method not allowed" },
          { allow: "GET, HEAD" },
        );
      }
      return new Response(PAIR_AASA, {
        headers: { "content-type": "application/json" },
      });
    }
    if (url.pathname === "/entitlement") {
      try {
        return await entitlement(request, env);
      } catch (err) {
        console.error(
          JSON.stringify({ evt: "entitlement_error", err: String(err) }),
        );
        return json(502, { v: 1, error: "relay internal error" });
      }
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
    const read = await readJson(request, MAX_BODY_BYTES);
    if ("response" in read) return read.response;
    const parsed = parseEnvelope(read.value);
    if ("error" in parsed) {
      return json(400, { v: 1, error: parsed.error });
    }
    const envelope = parsed.envelope;

    let outcome: DeliverOutcome;
    try {
      const stub = env.DEVICE.get(env.DEVICE.idFromName(envelope.device));
      outcome = await stub.deliver(envelope);
    } catch (err) {
      console.error(JSON.stringify({ evt: "deliver_error", err: String(err) }));
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
