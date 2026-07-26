import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import {
  providerToken,
  resetProviderTokenCache,
  type ApnsAuth,
} from "../src/apns";

const NOW_S = 1_800_000_000;

function auth(overrides: Partial<ApnsAuth> = {}): ApnsAuth {
  return {
    teamId: "TESTTEAM99",
    keyId: "TESTKEY999",
    privateKeyPem: env.APNS_AUTH_KEY!,
    ...overrides,
  };
}

function b64urlDecode(part: string): Uint8Array {
  const b64 = part.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function decodeJson(part: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
}

async function publicKeyFromPem(pem: string): Promise<CryptoKey> {
  const body = pem
    .replace(/-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  delete jwk.d;
  jwk.key_ops = ["verify"];
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

beforeEach(() => resetProviderTokenCache());

describe("providerToken", () => {
  it("emits an ES256 JWT with Apple's header and claims", async () => {
    const token = await providerToken(auth(), NOW_S);
    const [header, claims, signature] = token.split(".");
    expect(signature).toBeTruthy();
    expect(decodeJson(header!)).toEqual({ alg: "ES256", kid: "TESTKEY999" });
    expect(decodeJson(claims!)).toEqual({ iss: "TESTTEAM99", iat: NOW_S });
  });

  it("signs with the configured key (signature verifies)", async () => {
    const token = await providerToken(auth(), NOW_S);
    const [header, claims, signature] = token.split(".");
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await publicKeyFromPem(env.APNS_AUTH_KEY!),
      b64urlDecode(signature!),
      new TextEncoder().encode(`${header}.${claims}`),
    );
    expect(verified).toBe(true);
  });

  it("reuses a fresh token and refreshes a stale one", async () => {
    const first = await providerToken(auth(), NOW_S);
    const cached = await providerToken(auth(), NOW_S + 2_000);
    expect(cached).toBe(first);
    const refreshed = await providerToken(auth(), NOW_S + 2_701);
    expect(refreshed).not.toBe(first);
    expect(decodeJson(refreshed.split(".")[1]!)).toEqual({
      iss: "TESTTEAM99",
      iat: NOW_S + 2_701,
    });
  });

  it("does not serve one team's token to another", async () => {
    const first = await providerToken(auth(), NOW_S);
    const other = await providerToken(auth({ teamId: "OTHERTEAM1" }), NOW_S);
    expect(other).not.toBe(first);
    expect(decodeJson(other.split(".")[1]!).iss).toBe("OTHERTEAM1");
  });
});
