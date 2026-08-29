/**
 * Builds StoreKit-shaped signed transactions from the test-only chain
 * in tests/fixtures/appstore (scripts/gen-appstore-fixtures.sh), which
 * vitest.config.mts hands the worker as bindings.  The relay trusts the
 * fixture root in place of Apple Root CA G3 via RELAY_APPLE_ROOT_CERT.
 */

import { env } from "cloudflare:workers";

export const PRO_MONTHLY = "com.cronstable.app.pro.monthly";
export const PRO_YEARLY = "com.cronstable.app.pro.yearly";

const DAY_MS = 86_400_000;

export function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function importPkcs8(pem: string): Promise<CryptoKey> {
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

/** A transaction payload with the fields the relay reads, all valid. */
export function transaction(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = Date.now();
  return {
    transactionId: "2000000900000001",
    originalTransactionId: "2000000900000001",
    bundleId: "test.cronstable.app",
    productId: PRO_MONTHLY,
    purchaseDate: now - DAY_MS,
    originalPurchaseDate: now - DAY_MS,
    expiresDate: now + 30 * DAY_MS,
    type: "Auto-Renewable Subscription",
    inAppOwnershipType: "PURCHASED",
    environment: "Production",
    signedDate: now,
    ...overrides,
  };
}

export interface SignOptions {
  /** x5c[0] and its key; default the marker-bearing leaf. */
  leaf?: string;
  leafKey?: string;
  /** x5c[2]; default the trusted test root. */
  root?: string;
  /** Header alg; default ES256. */
  alg?: string;
  /** Flip a signature byte so it fails to verify. */
  corruptSignature?: boolean;
  /** Replace the x5c array wholesale (for shape tests). */
  x5c?: unknown;
}

/** A compact JWS over `payload`, signed with the fixture leaf. */
export async function signTransaction(
  payload: Record<string, unknown>,
  opts: SignOptions = {},
): Promise<string> {
  const x5c = opts.x5c ?? [
    opts.leaf ?? env.TEST_APPSTORE_LEAF,
    env.TEST_APPSTORE_INTERMEDIATE,
    opts.root ?? env.RELAY_APPLE_ROOT_CERT,
  ];
  const header = b64url(
    utf8(JSON.stringify({ alg: opts.alg ?? "ES256", x5c })),
  );
  const body = b64url(utf8(JSON.stringify(payload)));
  const key = await importPkcs8(opts.leafKey ?? env.TEST_APPSTORE_LEAF_KEY);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      utf8(`${header}.${body}`),
    ),
  );
  if (opts.corruptSignature) signature[10] = signature[10]! ^ 0xff;
  return `${header}.${body}.${b64url(signature)}`;
}
