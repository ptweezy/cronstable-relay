#!/usr/bin/env node
/**
 * Smoke-test a deployed relay without a paired device.
 *
 *   npm run smoke -- https://relay.cronstable.com/
 *
 * Sends a well-formed envelope with a synthetic device token. A
 * healthy, correctly credentialed relay answers 410: APNs accepted the
 * relay's provider token, then rejected the unknown device. 502 means
 * APNs credentials/connectivity need attention; 202 would mean the
 * token was somehow real (never with this token).
 */

const url = process.argv[2];
if (!url) {
  console.error("usage: npm run smoke -- <relay url>");
  process.exit(2);
}

const rand = (n) =>
  [...crypto.getRandomValues(new Uint8Array(n))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const info = await fetch(url);
console.log(`GET ${url} -> ${info.status}`);

const envelope = {
  v: 1,
  device: rand(32),
  // 96 base64 chars of random bytes: shaped like a small sealed box.
  ciphertext: Buffer.from(crypto.getRandomValues(new Uint8Array(72))).toString(
    "base64",
  ),
  collapseId: rand(16),
  priority: "time-sensitive",
  event: false,
};

const res = await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(envelope),
});
const body = await res.text();
console.log(`POST ${url} -> ${res.status} ${body}`);

if (res.status === 410) {
  console.log("OK: relay authenticated to APNs; unknown token rejected.");
} else if (res.status === 502) {
  console.error("FAIL: relay could not deliver; check APNS_* secrets.");
  process.exit(1);
} else {
  console.log("Unexpected status for a synthetic token; inspect above.");
}
