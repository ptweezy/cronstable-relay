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
 *
 * A declared Content-Length over the limit is refused without reading
 * the body.  A chunked or HTTP/2 request can omit the header, so the
 * bytes are also counted as they stream, and reading stops at the first
 * chunk past the limit.  The bytes must be UTF-8, as JSON requires.
 */
async function readJson(
  request: Request,
  limit: number,
): Promise<{ value: unknown } | { response: Response }> {
  const tooLarge = () => ({
    response: json(413, { v: 1, error: "body too large" }),
  });
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    if (!/^[0-9]+$/.test(declared)) {
      return {
        response: json(400, {
          v: 1,
          error: "content-length must be a non-negative integer",
        }),
      };
    }
    if (Number(declared) > limit) return tooLarge();
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  if (request.body !== null) {
    const reader = request.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        return tooLarge();
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  // `fatal` throws on invalid UTF-8; `ignoreBOM: false` strips a
  // leading byte-order mark.
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  try {
    return { value: JSON.parse(utf8.decode(bytes)) };
  } catch {
    return { response: json(400, { v: 1, error: "body is not valid JSON" }) };
  }
}

/** Seconds a client refused by the edge limiter waits: the limiter's
 * whole window (wrangler.jsonc, EDGE_LIMITER). */
const EDGE_RETRY_AFTER_S = 60;

/**
 * The edge limiter's key for a client address: an IPv4 address as is,
 * and an IPv6 address as its /64 prefix (`2001:db8:0:1::/64`), because
 * one IPv6 host routinely holds a whole /64 and can post from any
 * address in it.  An IPv4-mapped IPv6 address keys as its IPv4 address.
 * Anything that doesn't parse as IPv6 keys as is.
 */
export function edgeLimiterKey(address: string): string {
  const groups = ipv6Groups(address);
  if (groups === null) return address;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [high, low] = [groups[6]!, groups[7]!];
    return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
  }
  const prefix = groups.slice(0, 4).map((g) => g.toString(16));
  return `${prefix.join(":")}::/64`;
}

/** The eight 16-bit groups of an IPv6 address, or null for anything
 * else (an IPv4 address included). */
function ipv6Groups(address: string): number[] | null {
  if (!address.includes(":")) return null;
  let text = address.toLowerCase();
  // A dotted IPv4 tail fills the last two groups.
  const dotted = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(
    text,
  );
  if (dotted) {
    const octets = dotted.slice(2).map(Number);
    if (octets.some((o) => o > 255)) return null;
    const [a, b, c, d] = octets as [number, number, number, number];
    text = `${dotted[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parts = (half: string) => (half === "" ? [] : half.split(":"));
  const head = parts(halves[0]!);
  const tail = halves.length === 2 ? parts(halves[1]!) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (!all.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return all.map((g) => parseInt(g, 16));
}

/**
 * Whether the edge limiter admits one more POST / from this client
 * address (`edgeLimiterKey`).  The per-device bucket cannot see a
 * sender that varies the device token, so this bounds what one address
 * can spend on Durable Objects and APNs.  The check is skipped for a
 * relay without the binding, a request without the header, and a
 * limiter that throws, so a broken counter never costs an alert.
 */
async function edgeAdmits(request: Request, env: Env): Promise<boolean> {
  const limiter = env.EDGE_LIMITER;
  const address = request.headers.get("cf-connecting-ip");
  if (limiter === undefined || address === null) return true;
  try {
    return (await limiter.limit({ key: edgeLimiterKey(address) })).success;
  } catch (err) {
    console.error(
      JSON.stringify({ evt: "edge_limiter_error", err: String(err) }),
    );
    return true;
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
 *
 * An authentic transaction that carries a revocation (a refund, or
 * Apple revoking it) answers 401 "revoked" and also ends the lift it
 * granted: the posting device's record goes when it holds that
 * purchase.  The transaction's object records the revocation, which
 * refuses a replayed pre-refund copy from any device and clears that
 * device the same way.  A revocation past its purchase's expiry plus the
 * grace leaves the transaction's object as it is.  Neither a revocation
 * nor a refused replay frees a slot: every slot lapses with its TTL, 60
 * days after the device's last proof (EntitlementState.revoke says
 * why).  Apple also revokes a transaction an upgrade superseded
 * (`isUpgraded`); the upgrade keeps the subscription, so that one
 * changes nothing.
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
  const policy = entitlementPolicyFromEnv(env);
  const verified = await verifyTransaction(o.jws, { ...policy, now });
  // The transaction's own object holds device-token hashes, never tokens.
  const slotOf = (originalTransactionId: string) =>
    env.ENTITLEMENT.get(env.ENTITLEMENT.idFromName(originalTransactionId));
  const deviceHash = await sha256Hex(device);
  if (!verified.ok) {
    const status = verified.malformed ? 400 : 401;
    const revoked = verified.authentic;
    let cleared: boolean | undefined;
    if (verified.reason === "revoked" && revoked && !revoked.isUpgraded) {
      cleared = await stub.revoke(
        revoked.originalTransactionId,
        revoked.purchaseDate,
      );
      await slotOf(revoked.originalTransactionId).revoke({
        signedDate: revoked.signedDate,
        purchaseDate: revoked.purchaseDate,
        until:
          revoked.expiresAt === null ? null : revoked.expiresAt + policy.graceMs,
      });
    }
    await log({
      status,
      reason: verified.reason,
      ...(cleared === undefined ? {} : { cleared }),
    });
    return json(status, {
      v: 1,
      error: verified.malformed ? "malformed jws" : "entitlement rejected",
      reason: verified.reason,
    });
  }
  const tx = verified.transaction;
  const claim = await slotOf(tx.originalTransactionId).claim(deviceHash, {
    purchaseDate: tx.purchaseDate,
    signedDate: tx.signedDate,
  });
  if (!claim.admitted && "revoked" in claim) {
    // A copy signed before a recorded revocation: a replay of the
    // pre-refund proof.  It ends the device's lift like the revoked copy
    // itself would, and its slot lapses with its TTL.
    const cleared = await stub.revoke(
      tx.originalTransactionId,
      claim.revoked.purchaseDate,
    );
    await log({ status: 401, reason: "revoked", cleared });
    return json(401, {
      v: 1,
      error: "entitlement rejected",
      reason: "revoked",
    });
  }
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
    purchaseDate: tx.purchaseDate,
    slotExpiresAt: claim.slotExpiresAt,
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
    if (!(await edgeAdmits(request, env))) {
      return json(
        429,
        { v: 1, error: "too many requests from this address" },
        { "retry-after": String(EDGE_RETRY_AFTER_S) },
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
    return json(outcome.status, outcome.body);
  },
} satisfies ExportedHandler<Env>;
