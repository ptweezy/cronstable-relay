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
}

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
  const claims = base64url(utf8(JSON.stringify({ iss: auth.teamId, iat: nowS })));
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

/** Build the notification JSON APNs receives (exported for tests). */
export function apnsPayload(msg: ApnsMessage): Record<string, unknown> {
  const interruption =
    msg.priority === "passive" ? "passive" : "time-sensitive";
  return {
    aps: {
      // The stub the user sees only if the NSE never got to run; it
      // must be useful without leaking anything (there is nothing to
      // leak — the relay never has plaintext to include).
      alert: {
        title: "cronstable",
        body: "New alert — open to view.",
      },
      "mutable-content": 1,
      "interruption-level": interruption,
      ...(interruption === "time-sensitive" ? { sound: "default" } : {}),
    },
    v: 1,
    ciphertext: msg.ciphertext,
  };
}

export async function sendToApns(
  host: string,
  auth: ApnsAuth,
  msg: ApnsMessage,
  nowS: number = Math.floor(Date.now() / 1000),
): Promise<ApnsResult> {
  const jwt = await providerToken(auth, nowS);
  const response = await fetch(`${host}/3/device/${msg.deviceToken}`, {
    method: "POST",
    headers: {
      authorization: `bearer ${jwt}`,
      "apns-topic": msg.topic,
      "apns-push-type": "alert",
      "apns-priority": msg.priority === "passive" ? "5" : "10",
      "apns-collapse-id": msg.collapseId,
      "apns-expiration": String(nowS + APNS_EXPIRATION_S),
      "content-type": "application/json",
    },
    body: JSON.stringify(apnsPayload(msg)),
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
