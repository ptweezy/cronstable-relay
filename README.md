# cronstable-relay

The push relay for [cronstable](https://github.com/ptweezy/cronstable)'s
end-to-end encrypted alerts: a Cloudflare Worker with one Durable Object
per device. This is the exact source of the hosted instance at
**`https://relay.cronstable.com/`**, published so anyone can audit what
their alert traffic passes through.

```
daemon ──sealed box──▶ this relay ──APNs──▶ device (NSE decrypts locally)
app ──sealed request──▶ this relay ──WebSocket──▶ daemon (Reach, sealed reply back)
```

A cronstable daemon seals every alert to each paired device's public
key (by default a libsodium sealed box over X25519; the envelope's
`suite` names the algorithm) before it leaves the machine, then
POSTs one envelope per (alert, device) here. The relay coalesces
duplicates, suppresses flapping, rate-limits, and forwards the
still-sealed ciphertext to Apple. The app's Notification Service
Extension decrypts and renders the real alert on the device.

## What the relay can and cannot see

The relay is not a trusted party, by design:

- **Never present here:** job names, hostnames, schedules, log lines,
  exit codes, event details. They exist only inside the sealed box; the
  relay holds no key material.
- **What an envelope carries:** an APNs device token, the ciphertext,
  a `collapseId` (a truncated SHA-256, keyed with a per-installation
  salt the relay never sees, so not invertible even for guessable job
  names), a `priority` hint, an `event` routing flag, and a `suite`
  naming the sealing algorithm (so the app knows which key opens the
  ciphertext without guessing from its length). None of them says
  anything about what the alert is.
- **Logs:** outcome, priority, the first 8 hex chars of the device
  token's SHA-256, and a `collapseId` prefix. Device tokens and
  ciphertexts are never logged.
- **Reach (remote access):** a daemon's tunnel id (its public signing
  key), the daemon's IP address, connection times, node name, and agent
  string; the app's IP address and the SHA-256 of its credential; and
  the timing and sizes of relayed requests and replies. Every request
  and reply is sealed between the app and the daemon, so the relay
  never sees a URL path, a header, a job name, or a log line. Logs
  record a hash prefix of the tunnel id, a status, byte counts, and
  latency. See "Reach: remote access through the relay".
- **Per-device state:** delivery counters keyed by the push token
  (dedup and flap history per alert id, the rate bucket, the APNs
  environment), this month's forward count, and for Pro devices the
  verified entitlement's transaction id, product, expiry, environment,
  and verification time. Per transaction, the SHA-256 of each device
  token it lifts with a last-seen time. All of it expires on its own:
  delivery state after a day of silence, quota with the month,
  entitlement records with their expiry or 60 days of silence.

The wire contract is
[`docs/relay-protocol.md`](https://github.com/ptweezy/cronstable/blob/main/docs/relay-protocol.md)
(v1) in the cronstable repo; the daemon, this relay, and the app all
implement that document.

## Protocol conformance

`POST /` accepts one envelope per (alert, device). Responses follow the
protocol's semantics (the daemon never retries; delivery past acceptance
is the relay's responsibility):

| Status | Body | Meaning |
| --- | --- | --- |
| 202 | `{"v":1,"outcome":"forwarded"}` | Handed to APNs. |
| 202 | `{"v":1,"outcome":"coalesced"}` | Duplicate of an alert forwarded moments ago (e.g. another cluster node's copy); accepted, not re-sent. |
| 202 | `{"v":1,"outcome":"suppressed"}` | Flap suppression is holding this alert id; accepted, not sent. |
| 202 | `{"v":1,"outcome":"digested"}` | The device is past its monthly free quota; accepted, and at most one digest push per hour goes out in place of the alerts. |
| 400 | `{"v":1,"error":…}` | Malformed envelope (the error names the field). |
| 410 | `{"v":1,"error":…,"reason":…}` | APNs permanently rejected the device token (`Unregistered`, `BadDeviceToken`, …); the pairing is dead. |
| 413 | `{"v":1,"error":…}` | Body over 8 KB. |
| 429 | `{"v":1,"error":…}` + `Retry-After` | Per-device rate limit (or APNs itself throttled the device). |
| 502 | `{"v":1,"error":…}` | APNs unreachable, or the relay's own APNs credentials are broken. |

Notifications carry `mutable-content: 1` (so the app's NSE runs and
decrypts), `apns-collapse-id` from the envelope's `collapseId`,
`apns-priority` 10/5 and `interruption-level`
`time-sensitive`/`passive` from the envelope's `priority`, and a 10-minute
`apns-expiration` to match the protocol's replay-staleness window,
past which the payload would render as outdated anyway.

## Delivery policy

v1 takes no daemon credentials: admission control is per-device, keyed
on the opaque device token, with all state in that token's Durable
Object. relay-protocol.md leaves the numbers to the relay; these are
this relay's, each overridable with a Worker var:

| Behavior | Default | Var |
| --- | --- | --- |
| Coalesce duplicates of an already-forwarded alert | 75 s window | `RELAY_DEDUP_WINDOW_S` |
| Flap suppression: max forwards per alert id before cooling | 6 per 30 min | `RELAY_FLAP_MAX_FORWARDS`, `RELAY_FLAP_WINDOW_S` |
| While cooled: one reminder forward per interval | 30 min | `RELAY_COOLDOWN_INTERVAL_S` |
| Cooling expires after silence | 2 h | `RELAY_FLAP_RESET_S` |
| Per-device token bucket | burst 60, +1 token / 2 s | `RELAY_RATE_CAPACITY`, `RELAY_RATE_REFILL_PER_S` |

Coalesced, suppressed, and digested posts still answer 2xx: the relay
has taken responsibility, and delivering nothing *is* the policy. Only
the rate limiter says 429. The relay rolls back a forward that fails at APNs,
so the same alert stays eligible the moment APNs recovers, and the
failed send costs no quota.

## Monthly quota and Cronstable Pro

Each device gets `RELAY_FREE_MONTHLY_FORWARDS` (500) forwards per UTC
calendar month. Only alerts that reach APNs count: coalesced,
suppressed, rate-limited, and failed envelopes do not, and neither do
digests. Past the bound the relay answers `digested` and sends the
device one fixed digest push (passive, collapse id `digest`, no
ciphertext, `"kind": "digest"` in the payload) at most once per
`RELAY_DIGEST_INTERVAL_S` (3600) while alerts keep arriving.

A Cronstable Pro entitlement lifts the bound. The app proves it with
`POST /entitlement` carrying the App Store's own signed transaction
(a StoreKit 2 `jwsRepresentation`), which the relay verifies offline in
`src/appstore.ts`: the `x5c` chain against the pinned Apple Root CA G3
(by exact DER bytes), each certificate's validity window and signature,
Apple's in-app purchase marker extension on the leaf, then the ES256
signature and the claims (`bundleId` = `APNS_TOPIC`, `productId` in
`RELAY_PRO_PRODUCT_IDS`, no `revocationDate`, `expiresDate` in the
future, and `environment` Production, or Sandbox unless
`RELAY_ACCEPT_SANDBOX_ENTITLEMENTS` is `false`). Without a `jws` the
route only reports the device's plan and quota. One transaction lifts at
most `RELAY_PRO_DEVICES_PER_TRANSACTION` (5) devices; a device's slot
lapses after `RELAY_PRO_DEVICE_SLOT_TTL_S` (60 days) without a re-post.
The relay keeps the transaction id, product, expiry, environment, and
verification time per device, and a hash of each device token per
transaction, and never stores the JWS.

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `{"v":1,"plan":…,"expiresAt":…,"environment":…,"quota":{"used":…,"limit":…,"resetsAt":…}}` | The device's plan and this month's quota; `expiresAt`/`environment` only on `pro`, `limit` null when unlimited. |
| 400 | `{"v":1,"error":…}` | Malformed body, device, or JWS. |
| 401 | `{"v":1,"error":"entitlement rejected","reason":…}` | The transaction does not verify; `reason` names the failed check. |
| 409 | `{"v":1,"error":…,"limit":5}` | The transaction already lifts its maximum number of devices. |
| 413 | `{"v":1,"error":…}` | Body over 16 KB. |

## Reach: remote access through the relay

Reach lets the app reach a daemon that has no address the phone can
dial, such as a machine behind NAT or a cloud box with a closed
firewall. The daemon dials out and holds one WebSocket open at
`/v1/tunnel/{id}`, the app posts each request to `/v1/reach/{id}`, and
a Durable Object per tunnel (`src/tunnel.ts`) matches the two and
copies bytes between them. The wire contract is
[`docs/reach-protocol.md`](https://github.com/ptweezy/cronstable/blob/main/docs/reach-protocol.md)
in the cronstable repo; the daemon, this relay, and the app implement
it.

The tunnel id is the daemon's Ed25519 public key, so the relay verifies
possession with a signed challenge and stores no key material. Every
request and every reply is sealed between the app and the daemon with
keys the relay never holds. The relay admits a request when the SHA-256
of its credential is in the set the daemon published, forwards the
sealed body to the daemon as one frame, and streams the daemon's sealed
reply frames back as the response body. It never parses the inside of a
frame.

### Routes

`GET /v1/tunnel/{id}` is the daemon's WebSocket upgrade, with the
subprotocol `cronstable-reach-v1`. `POST /v1/reach/{id}` carries one
sealed request with `Authorization: Reach <credential>`,
`Content-Type: application/octet-stream`, and a `Content-Length` of at
most 1,052,672 bytes. `GET /v1/reach/{id}` with the same header reports
presence. The id is 43 base64url characters; anything else is a `400`
before any tunnel object is touched.

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `application/octet-stream`, `Cache-Control: no-store`, streamed | The sealed reply. The relay answers the moment the daemon's first frame arrives. |
| 200 | `{"v":1,"online":…,"lastSeenAt":…,"node":…}` | `GET`: presence, for an admitted credential only, so the id alone is never a presence oracle. |
| 400 | `{"v":1,"error":…}` | Malformed id, missing or malformed `Authorization`, wrong content type, or an upgrade without the subprotocol. |
| 403 | `{"v":1,"error":"reach token not admitted"}` | The credential is outside the daemon's admit set: the token was rotated or removed. |
| 404 | `{"v":1,"error":"unknown tunnel"}` | No daemon has connected under that id, or `RELAY_REACH_ENABLED` is `false`. The relay writes nothing for an unknown id. |
| 409 | `{"v":1,"error":"key mismatch"}` or `{"v":1,"error":"replay"}` | The daemon rejected the request (`REJECT 1` or `REJECT 2`). |
| 411 | `{"v":1,"error":…}` | A `POST` without `Content-Length`. |
| 413 | `{"v":1,"error":…}` | The body is over the cap, refused before any daemon traffic, or the daemon rejected it as too large. |
| 429 | `{"v":1,"error":…}` + `Retry-After` | A limit in the table below, or the daemon is busy (`REJECT 3`). |
| 502 | `{"v":1,"error":"daemon aborted"}` | The daemon socket dropped mid-request, the request went stale, or the daemon failed internally (`REJECT 5`). |
| 503 | `{"v":1,"error":"daemon offline","lastSeenAt":…}` + `Retry-After: 5` | The daemon socket is absent. |
| 504 | `{"v":1,"error":"no response"}` | No first frame within the first-byte wait. |

A reply the relay cuts short (a stream past its lifetime or the day's
allowance, or a slot lost to the concurrent-stream cap) ends the body
without the protocol's final END record, which the app treats as a
transport error and reattaches from. A reply whose daemon drops or goes
silent after its first frame fails the body outright.

### Limits

Every limit applies per tunnel, defaults to the protocol document's
value, and takes a Worker var (seconds may be fractional).

| Limit | Default | Var |
| --- | --- | --- |
| Hello timeout: an unverified socket closes with `4408` | 15 s | `RELAY_REACH_HELLO_TIMEOUT_S` |
| Requests in flight | 32 | `RELAY_REACH_MAX_INFLIGHT` |
| Stream threshold: a request open longer than this is a stream | 15 s | `RELAY_REACH_STREAM_THRESHOLD_S` |
| Concurrent streams | 4 | `RELAY_REACH_MAX_STREAMS` |
| Stream lifetime, then `CANCEL 2` | 30 min | `RELAY_REACH_MAX_STREAM_S` |
| Open-stream time per UTC day | 3 h | `RELAY_REACH_DAILY_STREAM_S` |
| Requests per admit id | burst 120, +2 per s | `RELAY_REACH_ADMIT_BURST`, `RELAY_REACH_ADMIT_REFILL_PER_S` |
| Frames per daemon socket | 30 per s, burst 200 | `RELAY_REACH_FRAME_RATE_PER_S`, `RELAY_REACH_FRAME_BURST` |
| Unadmitted credentials per minute, then `429` for the caller | 30 | `RELAY_REACH_STRIKES_PER_MIN` |
| First-byte wait, then `504` | 8 s | `RELAY_REACH_FIRST_BYTE_S` |
| Stale request: no daemon frame for this long fails it | 120 s | `RELAY_REACH_STALE_S` |
| Frame payload | 1,114,112 bytes | `RELAY_REACH_MAX_FRAME_PAYLOAD` |
| Inner request body, advertised to the daemon; the `POST` cap is this plus 4,096 | 1 MiB | `RELAY_REACH_MAX_BODY` |
| Largest reply chunk, advertised to the daemon | 64 KiB | `RELAY_REACH_MAX_CHUNK` |
| Initial flow-control window | 256 KiB | `RELAY_REACH_INITIAL_WINDOW` |

The oldest streams keep their slots: when a request crosses the
threshold while every slot is taken, the relay cuts it with `CANCEL 2`.
The day's usage counts the full duration of every request that lasted
past the threshold. Once the allowance is spent, the relay cuts the
open streams and answers new requests with `429` and a `Retry-After`
that reaches 00:00 UTC. A daemon socket that overruns its frame rate by
more than one extra burst closes with `4400`. Unadmitted credentials
count against the tunnel's strikes, never against the daemon socket,
and an admitted credential keeps working while the relay refuses
strangers.

### Flow control

Every request starts with the initial window of credit. The daemon never has more reply bytes in flight for a request
than its remaining credit, and the relay grants more with `WINDOW`
frames as the app drains the response body: whenever the outstanding
credit has fallen to half the window or less and the body's queue has
room (a 64 KiB high-water mark), the relay tops the credit back up to a
full window. A slow cellular link therefore cannot grow the relay's
buffers, and a long log replay waits for the phone rather than for the
relay's memory. A daemon that sends past its credit loses the socket
with `4400`.

### Daemon sockets and deploys

The daemon socket is a hibernatable WebSocket: an idle tunnel object leaves memory between frames and wakes
on the next one, with its state in the socket's attachment and in
storage. Every deploy of the relay drops every daemon socket; each
daemon reconnects on its own with jittered backoff, so a deploy costs
each tunnel a few seconds of `503`. The hosted relay runs on Workers
Paid: Durable Object requests, which include every relayed request and
every daemon frame, count against the same daily request allowance the
push path uses, and on the Free plan a busy tunnel would exhaust that
allowance and take push down with it. A tunnel record (node name,
credential hashes, last-seen time) expires after 60 days without its
daemon.

### Logs

Reach log lines record the first 8 hex characters of SHA-256 over the
tunnel id, a status, byte counts, and latency. The tunnel id
itself and the credential never appear, and the Worker's invocation
logs, which would retain request URLs, are off
(`observability.logs.invocation_logs` in `wrangler.jsonc`).

## Environment

Every knob has a default in code; `wrangler.jsonc` sets only the ones
worth seeing at a glance.

| Var | Default | Meaning |
| --- | --- | --- |
| `APNS_TOPIC` | `com.cronstable.app` | Bundle id the notifications and entitlements belong to. |
| `APNS_ENVIRONMENT` | `auto` | See "APNs environments". |
| `RELAY_FREE_MONTHLY_FORWARDS` | `500` | Free forwards per device per UTC month. |
| `RELAY_DIGEST_INTERVAL_S` | `3600` | Minimum seconds between digest pushes to one device. |
| `RELAY_PRO_PRODUCT_IDS` | `com.cronstable.app.pro.monthly,com.cronstable.app.pro.yearly` | Product ids that count as Pro. |
| `RELAY_ACCEPT_SANDBOX_ENTITLEMENTS` | `true` | `false` refuses Sandbox (TestFlight, Xcode) transactions. |
| `RELAY_PRO_DEVICES_PER_TRANSACTION` | `5` | Devices one transaction may lift. |
| `RELAY_PRO_DEVICE_SLOT_TTL_S` | `5184000` | Seconds of silence after which a device's slot lapses. |
| `RELAY_APPLE_ROOT_CERT` | Apple Root CA G3 | Test hook: base64 DER of the root to trust instead. |
| `RELAY_QUOTA_PERIOD_S` | unset | Test hook: fixed-length quota periods instead of calendar months. |
| `RELAY_REACH_ENABLED` | `true` | The Reach kill switch: `false` answers `404` on every `/v1/*` route while push keeps running. |
| `RELAY_REACH_*` | the protocol's limits | See "Reach: remote access through the relay". |

See "Delivery policy" for the delivery-policy windows and "Reach" for
the Reach limits.

## APNs environments

`APNS_ENVIRONMENT` is `production`, `sandbox`, or `auto` (default).
In `auto`, the relay tries production first; if APNs answers
`BadDeviceToken`/`DeviceTokenNotForTopic` (the token belongs to the
other environment, e.g. a development build), it retries against
sandbox once and remembers the working environment per device. One
deployment then serves App Store, TestFlight and Xcode builds.

## Self-hosting

Anything that implements relay-protocol.md can serve as the relay a
daemon's `push.relay.url` points at. Deployments own their admission
policy, and this repo is MIT-licensed so you can run your own.

Caveat: **APNs provider keys are team-scoped.** A relay can only push
to apps signed by the Apple Developer team whose `.p8` key it holds,
so self-hosting serves *your own app builds* (a fork of the companion
app under your team, or another client implementing the sealed-box
contract). Alerts for the official cronstable app can only transit the
official relay. That is why its source is published and its payloads
are sealed: you don't have to trust it with anything.

The MIT License covers this code, not the cronstable name or logo. If
you run a public deployment or distribute a fork, please give it a
distinct name so users can tell it apart from the official relay: the
brand appears in the landing banner (`INFO` in `src/index.ts`) and in
the fallback alert title (`src/apns.ts`), and both should change. See
[TRADEMARKS.md](https://github.com/ptweezy/cronstable/blob/main/TRADEMARKS.md)
in the core repository.

### Deploy

Prerequisites: a Cloudflare account (the Free plan serves push; a relay
that also carries Reach traffic belongs on Workers Paid, see "Reach"),
Node 22+ (CI builds on the 24 LTS), and an Apple Developer account for
the APNs key.

1. Create the APNs auth key: developer.apple.com → Certificates,
   Identifiers & Profiles → Keys → add a key with the **Apple Push
   Notifications service (APNs)** capability. Download the `.p8` (one
   chance) and note the Key ID and your Team ID.
2. `npx wrangler login`
3. In `wrangler.jsonc`, set `APNS_TOPIC` to the target app's bundle id.
4. Store the credentials as secrets:

   ```sh
   npx wrangler secret put APNS_TEAM_ID
   npx wrangler secret put APNS_KEY_ID
   npx wrangler secret put APNS_AUTH_KEY < AuthKey_XXXXXXXXXX.p8
   ```

   The auth key is a multi-line PEM, so feed it the file rather than
   pasting at the prompt.

5. `npm run deploy`. First deploy on a fresh account fails with "You
   need a workers.dev subdomain" until you have opened Workers & Pages
   in the dashboard once, which creates it.
6. Custom domain: point the zone's nameservers at Cloudflare, then set
   `routes` in `wrangler.jsonc` to your hostname and deploy again. The
   DNS record and certificate are created for you; the certificate takes
   a few minutes, during which TLS handshakes to it fail.
7. Deploy the relay before you upgrade the daemons that post to it. A
   daemon fits alerts to the ciphertext cap it was built with. In front
   of a relay that enforces a smaller cap, the daemon gets a 400 for its
   largest alerts and falls back to the protocol's 3000-character floor
   for them, so the page lands with fewer log lines. A current relay
   never triggers that fallback.
8. Point daemons at it:

   ```yaml
   push:
     relay:
       url: https://relay.cronstable.com/   # or your deployment
   ```

   A daemon with a `web.reach` section dials the same origin for its
   tunnel socket unless `web.reach.relay` names another.

9. Rate-limit the Reach routes per address. In the zone's Security
   settings, add a rate limiting rule for requests whose URI path starts
   with `/v1/`, keyed by IP address (for example 300 requests per 10
   seconds, then block for 10 seconds). The relay's own limits are per
   tunnel and per credential; this rule bounds what one address can send
   at every Reach route before a tunnel object sees it.
10. Exempt the tunnel upgrade from challenges. Add a WAF custom rule for
    requests whose URI path starts with `/v1/tunnel/` that skips the
    managed rulesets and bot management. A challenge cannot be solved on
    a WebSocket upgrade request; a daemon that gets a `403` or `503`
    carrying `cf-mitigated` parks with hourly retries.

### Smoke test

`npm run smoke -- https://relay.cronstable.com/` POSTs a well-formed
envelope carrying a synthetic device token. A healthy, correctly
credentialed relay answers **410**: APNs authenticated the relay, then
rejected the unknown token. Anything 5xx means the APNs credentials or
connectivity need attention. Full end-to-end delivery is verified from
a daemon once a real device has paired: `POST /push/devices/{id}/test`
on the daemon, or the dashboard's test button.

## Development

```sh
npm install
npm run types     # regenerate worker-configuration.d.ts from wrangler.jsonc
npm run typecheck # runs `npm run types` first, so this is enough on its own
npm test          # vitest + workerd; only APNs is stubbed
npm run dev       # local relay on http://localhost:8787
```

Binding and runtime types come from `wrangler types`, which supersedes
`@cloudflare/workers-types`. The generated `worker-configuration.d.ts`
is *not* committed (half a megabyte of machine-written declarations
would drown every diff): `npm run typecheck` regenerates it, and editors
pick it up after one `npm run types`. Rerun it after changing
`wrangler.jsonc`.

`.dev.vars` (gitignored) can hold the `APNS_*` secrets for `wrangler
dev` against real sandbox APNs.

To dial a local relay from a daemon, start it as
`npx wrangler dev --port 8787 --host 127.0.0.1:8787`. `wrangler dev`
rewrites every request URL to the configured route (`relay.cronstable.com`),
so without `--host` the tunnel challenge names that host, and a daemon
that dialed `http://127.0.0.1:8787` refuses it, as the protocol requires.

The entitlement suite signs with a test-only certificate chain in
`tests/fixtures/appstore/` (leaf private keys included; none of it is
registered with Apple). `sh scripts/gen-appstore-fixtures.sh`
regenerates it with OpenSSL 3.

The Reach suites check the codec, the challenge signature, and the
admission credentials against `tests/fixtures/reach-vectors.json`, a
verbatim copy of `tests/fixtures/reach/vectors.json` in the cronstable
repo (`python -m tests.reach_vectors` there regenerates it). Copy the
file over again when that one changes. `tests/tunnel.spec.ts` runs in
its own vitest project with the Reach timers shrunk to seconds.

## License

MIT; see [LICENSE](LICENSE). Contributions are DCO-certified
(`git commit -s`), same as cronstable itself; see
[CONTRIBUTING.md](CONTRIBUTING.md).

cronstable™ and the cronstable logo are trademarks of Parker Loflin and
are not licensed by the MIT grant; see
[TRADEMARKS.md](https://github.com/ptweezy/cronstable/blob/main/TRADEMARKS.md).
