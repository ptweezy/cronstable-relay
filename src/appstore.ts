/**
 * Offline verification of a StoreKit 2 signed transaction
 * (relay-protocol.md, "Entitlement proof").
 *
 * A transaction's `jwsRepresentation` is a compact ES256 JWS whose header
 * carries an `x5c` chain of three DER certificates: the App Store's
 * receipt-signing leaf, Apple's Worldwide Developer Relations
 * intermediate, and Apple Root CA G3.  Verification needs no network and
 * no key of the relay's own: it pins the root by its exact DER bytes,
 * checks each link with the issuer's key, requires Apple's in-app
 * purchase marker extension on the leaf, and checks the JWS signature
 * with the leaf key.  Only then does it read the payload's claims.
 *
 * The DER walker below is the minimum X.509 needs: tag/length/value
 * with long-form lengths, OIDs, UTCTime/GeneralizedTime, and the fixed
 * field order of an X.509 v3 TBSCertificate.  It rejects anything it
 * does not understand rather than guessing.  Everything cryptographic
 * is WebCrypto.
 */

/** Apple Root CA G3, DER, base64.  SHA-256 of the DER:
 * 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179
 * (https://www.apple.com/certificateauthority/). */
export const APPLE_ROOT_CA_G3_B64 =
  "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUg" +
  "Um9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTET" +
  "MBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkw" +
  "NDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFw" +
  "cGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYD" +
  "VQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHc" +
  "FBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dv" +
  "MVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr" +
  "MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD" +
  "6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK" +
  "1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==";

/** Apple's in-app purchase receipt-signing marker. */
const IN_APP_PURCHASE_MARKER_OID = "1.2.840.113635.100.6.11.1";

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";

const CURVE_BY_OID: Record<string, Curve> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
};

const COORDINATE_BYTES: Record<Curve, number> = { "P-256": 32, "P-384": 48 };

type Curve = "P-256" | "P-384";

export interface VerifiedTransaction {
  originalTransactionId: string;
  productId: string;
  /** Epoch ms, or null when the transaction carries no expiresDate. */
  expiresAt: number | null;
  environment: "Production" | "Sandbox";
}

export type VerifyResult =
  | { ok: true; transaction: VerifiedTransaction }
  /** `malformed` separates "this is not a JWS with a 3-cert x5c" (400)
   * from "it is one, and it does not verify" (401). */
  | { ok: false; malformed: boolean; reason: string };

export interface EntitlementPolicy {
  /** DER of the trusted root; the leaf's chain must end in exactly it. */
  rootDer: Uint8Array;
  /** The bundle id the transaction must belong to. */
  bundleId: string;
  productIds: ReadonlySet<string>;
  acceptSandbox: boolean;
}

export type VerifyOptions = EntitlementPolicy & { now: number };

const DEFAULT_PRODUCT_IDS =
  "com.cronstable.app.pro.monthly,com.cronstable.app.pro.yearly";

/** Verification policy from env vars (see README, "Environment"). */
export function entitlementPolicyFromEnv(env: {
  APNS_TOPIC?: string;
  RELAY_APPLE_ROOT_CERT?: string;
  RELAY_PRO_PRODUCT_IDS?: string;
  RELAY_ACCEPT_SANDBOX_ENTITLEMENTS?: string;
}): EntitlementPolicy {
  const rootB64 = env.RELAY_APPLE_ROOT_CERT?.trim() || APPLE_ROOT_CA_G3_B64;
  const list = (raw: string): string[] =>
    raw
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
  const products = list(env.RELAY_PRO_PRODUCT_IDS ?? "");
  return {
    rootDer: base64Decode(rootB64),
    bundleId: env.APNS_TOPIC ?? "com.cronstable.app",
    productIds: new Set(
      products.length > 0 ? products : list(DEFAULT_PRODUCT_IDS),
    ),
    acceptSandbox: env.RELAY_ACCEPT_SANDBOX_ENTITLEMENTS !== "false",
  };
}

// ---------------------------------------------------------------- base64

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function base64Decode(text: string): Uint8Array {
  if (text.length === 0 || text.length % 4 !== 0 || !BASE64_RE.test(text)) {
    throw new Error("not base64");
  }
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function base64urlDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const b64 = text.replaceAll("-", "+").replaceAll("_", "/");
  return base64Decode(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

// ------------------------------------------------------------------- DER

class DerError extends Error {}

/** One tag/length/value triple: `start`..`end` bounds the value. */
interface Tlv {
  tag: number;
  /** Offset of the tag byte (the element's own start). */
  at: number;
  start: number;
  end: number;
}

function readTlv(bytes: Uint8Array, at: number, limit: number): Tlv {
  if (at + 2 > limit) throw new DerError("truncated element");
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("multi-byte tag");
  let length = bytes[at + 1]!;
  let start = at + 2;
  if (length & 0x80) {
    const octets = length & 0x7f;
    if (octets === 0 || octets > 4 || start + octets > limit) {
      throw new DerError("bad length");
    }
    length = 0;
    for (let i = 0; i < octets; i += 1) {
      length = length * 256 + bytes[start + i]!;
    }
    start += octets;
  }
  if (start + length > limit) throw new DerError("element overruns");
  return { tag, at, start, end: start + length };
}

/** The elements inside a constructed value, in order. */
function children(bytes: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.start;
  while (at < parent.end) {
    const child = readTlv(bytes, at, parent.end);
    out.push(child);
    at = child.end;
  }
  return out;
}

function expectTag(tlv: Tlv | undefined, tag: number, what: string): Tlv {
  if (!tlv || tlv.tag !== tag) throw new DerError(`expected ${what}`);
  return tlv;
}

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;
const TAG_CONTEXT_3 = 0xa3;

function slice(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.start, tlv.end);
}

/** Whole element including its tag and length (what signatures cover). */
function whole(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  return bytes.subarray(tlv.at, tlv.end);
}

function decodeOid(bytes: Uint8Array, tlv: Tlv): string {
  const value = slice(bytes, tlv);
  if (value.length === 0) throw new DerError("empty OID");
  const parts = [Math.floor(value[0]! / 40), value[0]! % 40];
  let acc = 0;
  for (let i = 1; i < value.length; i += 1) {
    const b = value[i]!;
    acc = acc * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  if (acc !== 0) throw new DerError("unterminated OID arc");
  return parts.join(".");
}

/** UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) to epoch ms. */
function decodeTime(bytes: Uint8Array, tlv: Tlv): number {
  const text = String.fromCharCode(...slice(bytes, tlv));
  let m: RegExpMatchArray | null;
  let year: number;
  if (tlv.tag === TAG_UTC_TIME) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new DerError("bad UTCTime");
    const yy = Number(m[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  } else if (tlv.tag === TAG_GENERALIZED_TIME) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (!m) throw new DerError("bad GeneralizedTime");
    year = Number(m[1]);
  } else {
    throw new DerError("expected a time");
  }
  return Date.UTC(
    year,
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    Number(m[6]),
  );
}

/** The BIT STRING's payload with its unused-bits octet stripped. */
function bitStringBytes(bytes: Uint8Array, tlv: Tlv): Uint8Array {
  const value = slice(bytes, tlv);
  if (value.length === 0 || value[0] !== 0) {
    throw new DerError("bit string with unused bits");
  }
  return value.subarray(1);
}

/** The AlgorithmIdentifier's algorithm OID (parameters are ignored). */
function algorithmOid(bytes: Uint8Array, tlv: Tlv | undefined): string {
  const [oid] = children(
    bytes,
    expectTag(tlv, TAG_SEQUENCE, "AlgorithmIdentifier"),
  );
  return decodeOid(bytes, expectTag(oid, TAG_OID, "algorithm OID"));
}

interface ParsedCert {
  /** The DER of tbsCertificate, tag and length included. */
  tbs: Uint8Array;
  signatureAlgorithm: string;
  /** The signatureValue: a DER ECDSA-Sig-Value. */
  signature: Uint8Array;
  notBefore: number;
  notAfter: number;
  /** The whole SubjectPublicKeyInfo DER (what importKey("spki") takes). */
  spki: Uint8Array;
  curve: Curve;
  extensionOids: string[];
}

function parseCertificate(der: Uint8Array): ParsedCert {
  const cert = expectTag(
    readTlv(der, 0, der.length),
    TAG_SEQUENCE,
    "Certificate",
  );
  if (cert.end !== der.length) throw new DerError("trailing bytes");
  const [tbs, sigAlg, sigValue] = children(der, cert);
  const tbsSeq = expectTag(tbs, TAG_SEQUENCE, "tbsCertificate");

  // TBSCertificate: [0] version?, serial, signature, issuer, validity,
  // subject, subjectPublicKeyInfo, [1]?, [2]?, [3] extensions?.
  const fields = children(der, tbsSeq);
  let i = 0;
  if (fields[i]?.tag === TAG_CONTEXT_0) i += 1;
  expectTag(fields[i], TAG_INTEGER, "serialNumber");
  i += 1;
  i += 1; // signature AlgorithmIdentifier (the outer one is what counts)
  expectTag(fields[i], TAG_SEQUENCE, "issuer");
  i += 1;
  const validity = expectTag(fields[i], TAG_SEQUENCE, "validity");
  i += 1;
  expectTag(fields[i], TAG_SEQUENCE, "subject");
  i += 1;
  const spki = expectTag(fields[i], TAG_SEQUENCE, "subjectPublicKeyInfo");
  i += 1;
  const [notBefore, notAfter] = children(der, validity);
  if (!notBefore || !notAfter) throw new DerError("bad validity");

  const [keyAlg] = children(der, spki);
  const keyAlgSeq = expectTag(keyAlg, TAG_SEQUENCE, "key AlgorithmIdentifier");
  const [keyOid, curveOid] = children(der, keyAlgSeq);
  if (
    decodeOid(der, expectTag(keyOid, TAG_OID, "key type")) !== OID_EC_PUBLIC_KEY
  ) {
    throw new DerError("not an EC public key");
  }
  const curve =
    CURVE_BY_OID[decodeOid(der, expectTag(curveOid, TAG_OID, "curve"))];
  if (!curve) throw new DerError("unsupported curve");

  const extensionOids: string[] = [];
  const ext = fields.slice(i).find((f) => f.tag === TAG_CONTEXT_3);
  if (ext) {
    const [list] = children(der, ext);
    for (const extension of children(
      der,
      expectTag(list, TAG_SEQUENCE, "extensions"),
    )) {
      const [oid] = children(
        der,
        expectTag(extension, TAG_SEQUENCE, "Extension"),
      );
      extensionOids.push(
        decodeOid(der, expectTag(oid, TAG_OID, "extension OID")),
      );
      // The value is an OCTET STRING, with an optional BOOLEAN before it;
      // only the OID is needed here.
    }
  }

  return {
    tbs: whole(der, tbsSeq),
    signatureAlgorithm: algorithmOid(der, sigAlg),
    signature: bitStringBytes(
      der,
      expectTag(sigValue, TAG_BIT_STRING, "signatureValue"),
    ),
    notBefore: decodeTime(der, notBefore),
    notAfter: decodeTime(der, notAfter),
    spki: whole(der, spki),
    curve,
    extensionOids,
  };
}

/** DER ECDSA-Sig-Value (SEQUENCE of two INTEGERs) to the raw r||s
 * WebCrypto verifies, each half left-padded to the curve's width. */
function derSignatureToRaw(
  sig: Uint8Array,
  coordinateBytes: number,
): Uint8Array {
  const seq = expectTag(
    readTlv(sig, 0, sig.length),
    TAG_SEQUENCE,
    "ECDSA-Sig-Value",
  );
  const [r, s] = children(sig, seq);
  const out = new Uint8Array(coordinateBytes * 2);
  for (const [index, part] of [r, s].entries()) {
    let value = slice(sig, expectTag(part, TAG_INTEGER, "signature integer"));
    while (value.length > 0 && value[0] === 0) value = value.subarray(1);
    if (value.length > coordinateBytes)
      throw new DerError("signature integer too wide");
    out.set(value, index * coordinateBytes + (coordinateBytes - value.length));
  }
  return out;
}

async function importPublicKey(cert: ParsedCert): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    cert.spki,
    { name: "ECDSA", namedCurve: cert.curve },
    false,
    ["verify"],
  );
}

/** Whether `cert`'s signature was made by `issuer`'s key, using the
 * hash the certificate's own signatureAlgorithm names. */
async function signedBy(
  cert: ParsedCert,
  issuer: ParsedCert,
): Promise<boolean> {
  let hash: string;
  if (cert.signatureAlgorithm === OID_ECDSA_SHA256) hash = "SHA-256";
  else if (cert.signatureAlgorithm === OID_ECDSA_SHA384) hash = "SHA-384";
  else return false;
  let raw: Uint8Array;
  try {
    raw = derSignatureToRaw(cert.signature, COORDINATE_BYTES[issuer.curve]);
  } catch {
    return false;
  }
  return crypto.subtle.verify(
    { name: "ECDSA", hash },
    await importPublicKey(issuer),
    raw,
    cert.tbs,
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

// ------------------------------------------------------------------- JWS

function malformed(reason: string): VerifyResult {
  return { ok: false, malformed: true, reason };
}

function rejected(reason: string): VerifyResult {
  return { ok: false, malformed: false, reason };
}

function jsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

export async function verifyTransaction(
  jws: string,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const parts = jws.split(".");
  if (parts.length !== 3) return malformed("jws is not a compact JWS");
  const [headerB64, payloadB64, signatureB64] = parts as [
    string,
    string,
    string,
  ];

  let header: Record<string, unknown> | null;
  let payload: Record<string, unknown> | null;
  let signature: Uint8Array;
  try {
    header = jsonObject(base64urlDecode(headerB64));
    payload = jsonObject(base64urlDecode(payloadB64));
    signature = base64urlDecode(signatureB64);
  } catch {
    return malformed("jws segments are not base64url");
  }
  if (!header) return malformed("jws header is not a JSON object");
  if (!payload) return malformed("jws payload is not a JSON object");
  if (header.alg !== "ES256") return malformed("jws alg must be ES256");
  const x5c = header.x5c;
  if (
    !Array.isArray(x5c) ||
    x5c.length !== 3 ||
    !x5c.every((c) => typeof c === "string")
  ) {
    return malformed("jws x5c must hold three certificates");
  }

  let chain: ParsedCert[];
  let rootDer: Uint8Array;
  try {
    const ders = (x5c as string[]).map(base64Decode);
    rootDer = ders[2]!;
    chain = ders.map(parseCertificate);
  } catch {
    return malformed("x5c certificates are not valid DER");
  }
  const [leaf, intermediate, root] = chain as [
    ParsedCert,
    ParsedCert,
    ParsedCert,
  ];

  // Chain: pinned root, validity windows, then each link's signature.
  if (!bytesEqual(rootDer, opts.rootDer)) {
    return rejected("root is not Apple Root CA G3");
  }
  for (const [name, cert] of [
    ["leaf", leaf],
    ["intermediate", intermediate],
    ["root", root],
  ] as const) {
    if (opts.now < cert.notBefore || opts.now > cert.notAfter) {
      return rejected(`${name} certificate is outside its validity window`);
    }
  }
  if (!(await signedBy(intermediate, root))) {
    return rejected("intermediate is not signed by the root");
  }
  if (!(await signedBy(leaf, intermediate))) {
    return rejected("leaf is not signed by the intermediate");
  }
  if (!leaf.extensionOids.includes(IN_APP_PURCHASE_MARKER_OID)) {
    return rejected("leaf lacks the in-app purchase marker");
  }
  if (leaf.curve !== "P-256") return rejected("leaf key is not P-256");

  // The JWS signature is raw r||s over the signing input, ES256 style.
  if (signature.length !== 64) return rejected("signature is not ES256");
  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    await importPublicKey(leaf),
    signature,
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );
  if (!verified) return rejected("signature does not verify");

  // Claims.
  if (payload.bundleId !== opts.bundleId) return rejected("bundle id mismatch");
  const productId = payload.productId;
  if (typeof productId !== "string" || !opts.productIds.has(productId)) {
    return rejected("unknown product");
  }
  const originalTransactionId = payload.originalTransactionId;
  if (
    typeof originalTransactionId !== "string" ||
    originalTransactionId.length === 0
  ) {
    return rejected("missing originalTransactionId");
  }
  if (payload.revocationDate !== undefined) return rejected("revoked");
  let expiresAt: number | null = null;
  if (payload.expiresDate !== undefined) {
    if (
      typeof payload.expiresDate !== "number" ||
      !Number.isFinite(payload.expiresDate)
    ) {
      return rejected("expiresDate is not a timestamp");
    }
    if (payload.expiresDate <= opts.now) return rejected("expired");
    expiresAt = payload.expiresDate;
  }
  const environment = payload.environment;
  if (environment === "Sandbox") {
    if (!opts.acceptSandbox)
      return rejected("sandbox transactions are refused");
  } else if (environment !== "Production") {
    return rejected("unknown environment");
  }

  return {
    ok: true,
    transaction: { originalTransactionId, productId, expiresAt, environment },
  };
}
