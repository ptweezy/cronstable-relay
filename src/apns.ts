/**
 * The APNs leg: provider-token auth (ES256 JWT over the .p8 key) and
 * the HTTP/2 POST to Apple, one notification per envelope.
 *
 * What Apple receives is deliberately empty of meaning: a fixed alert
 * stub (shown only if the app's Notification Service Extension somehow
 * never runs), the sealed ciphertext, and mutable-content: 1 so the
 * NSE decrypts and renders the real alert on the device.  Interruption
 * level and APNs priority both derive from the envelope's `priority`.
 */

export type ApnsEnvironment = "production" | "sandbox";

export const APNS_HOSTS: Record<ApnsEnvironment, string> = {
  production: "https://api.push.apple.com",
  sandbox: "https://api.sandbox.push.apple.com",
};

export interface ApnsAuth {
  teamId: string;
  keyId: string;
  /** PEM contents of the .p8 auth key. */
  privateKeyPem: string;
}

export interface ApnsMessage {
  deviceToken: string;
  ciphertext: string;
  collapseId: string;
  priority: "time-sensitive" | "passive";
  topic: string;
  /** Forwarded verbatim so the app's NSE knows which key opens the
   * ciphertext without inferring the algorithm from its length. */
  suite: string;
}

/**
 * The quota digest (relay-protocol.md, "Delivery quota"): a fixed,
 * passive push with no ciphertext, sent once per digest interval to a
 * device past its monthly bound.  Distinguished from an alert by the
 * absence of `ciphertext`.
 */
export interface ApnsDigest {
  deviceToken: string;
  topic: string;
}

/** The digest's own collapse id; every digest replaces the last. */
export const DIGEST_COLLAPSE_ID = "digest";

export interface ApnsResult {
  status: number;
  /** Apple's error reason (e.g. "BadDeviceToken"), when not a 200. */
  reason: string | null;
}

/**
 * Alerts age out of usefulness fast: the sealed payload's `ts` renders
 * as stale after 10 minutes (relay-protocol.md), so there is no point
 * asking APNs to hold an undeliverable notification any longer.
 */
const APNS_EXPIRATION_S = 600;

/**
 * Apple accepts provider tokens 20–60 minutes old; refresh at 45 so a
 * token is never presented near the edge.  Cached per isolate.
 */
const JWT_MAX_AGE_S = 2700;

interface JwtCache {
  token: string;
  issuedAt: number;
  cacheKey: string;
}

let jwtCache: JwtCache | null = null;

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function importP8(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace(/-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

/**
 * The bearer JWT for one team/key pair, reused until it nears Apple's
 * age limit.  WebCrypto's ECDSA output is already the raw r||s JOSE
 * signature shape, so no DER re-packing is needed.
 */
export async function providerToken(
  auth: ApnsAuth,
  nowS: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const cacheKey = `${auth.teamId}/${auth.keyId}`;
  if (
    jwtCache &&
    jwtCache.cacheKey === cacheKey &&
    nowS - jwtCache.issuedAt < JWT_MAX_AGE_S
  ) {
    return jwtCache.token;
  }
  const key = await importP8(auth.privateKeyPem);
  const header = base64url(
    utf8(JSON.stringify({ alg: "ES256", kid: auth.keyId })),
  );
  const claims = base64url(
    utf8(JSON.stringify({ iss: auth.teamId, iat: nowS })),
  );
  const signingInput = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    utf8(signingInput),
  );
  const token = `${signingInput}.${base64url(new Uint8Array(signature))}`;
  jwtCache = { token, issuedAt: nowS, cacheKey };
  return token;
}

/** Exposed for tests only: drop the cached provider token. */
export function resetProviderTokenCache(): void {
  jwtCache = null;
}

/**
 * APNs rejects notifications whose final JSON exceeds this.  The whole
 * size budget in relay-protocol.md hangs off it.
 */
export const APNS_PAYLOAD_MAX = 4096;

/**
 * What everything in apnsPayload() except the ciphertext serializes to,
 * with the longest suite token in play.  The daemon derives its own
 * ciphertext cap from this number, so tests/apns-size.spec.ts asserts it
 * against the real payload rather than letting the two drift.
 */
export const ENVELOPE_BYTES = 189;

/** Build the notification JSON APNs receives (exported for tests). */
export function apnsPayload(msg: ApnsMessage): Record<string, unknown> {
  const interruption =
    msg.priority === "passive" ? "passive" : "time-sensitive";
  return {
    aps: {
      // The stub the user sees only if the NSE never got to run; it
      // must be useful without leaking anything (there is nothing to
      // leak: the relay never has plaintext to include).
      alert: {
        title: "cronstable",
        body: "New alert. Open to view.",
      },
      "mutable-content": 1,
      "interruption-level": interruption,
      ...(interruption === "time-sensitive" ? { sound: "default" } : {}),
    },
    v: 1,
    suite: msg.suite,
    ciphertext: msg.ciphertext,
  };
}

/**
 * The digest notification.  No mutable-content: there is nothing to
 * decrypt, so the app's NSE stays out of it and the system shows the
 * text as is; `kind` lets the app route the tap.
 */
export function digestPayload(): Record<string, unknown> {
  return {
    aps: {
      alert: {
        title: "cronstable",
        body: "Alerts are waiting. Open the app to see them.",
      },
      "interruption-level": "passive",
    },
    v: 1,
    kind: "digest",
  };
}

export async function sendToApns(
  host: string,
  auth: ApnsAuth,
  msg: ApnsMessage | ApnsDigest,
  nowS: number = Math.floor(Date.now() / 1000),
): Promise<ApnsResult> {
  const jwt = await providerToken(auth, nowS);
  const alert = "ciphertext" in msg ? msg : null;
  const response = await fetch(`${host}/3/device/${msg.deviceToken}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      "apns-topic": msg.topic,
      "apns-push-type": "alert",
      "apns-priority": alert && alert.priority !== "passive" ? "10" : "5",
      "apns-collapse-id": alert ? alert.collapseId : DIGEST_COLLAPSE_ID,
      "apns-expiration": String(nowS + APNS_EXPIRATION_S),
      "content-type": "application/json",
    },
    body: JSON.stringify(alert ? apnsPayload(alert) : digestPayload()),
  });
  const text = await response.text();
  if (response.status === 200) return { status: 200, reason: null };
  let reason: string | null = null;
  try {
    const parsed = JSON.parse(text) as { reason?: unknown };
    if (typeof parsed.reason === "string") reason = parsed.reason;
  } catch {
    // Non-JSON error body; the status alone will have to do.
  }
  return { status: response.status, reason };
}
