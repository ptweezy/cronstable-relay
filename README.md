# cronstable-relay

The push relay for [cronstable](https://github.com/ptweezy/cronstable)'s
end-to-end encrypted alerts: a Cloudflare Worker with one Durable Object
per device. This is the exact source of the hosted instance at
**`https://relay.cronstable.com/`**, published so anyone can audit what
their alert traffic passes through.

```
daemon ──sealed box──▶ this relay ──APNs──▶ device (NSE decrypts locally)
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
  names), an optional `flapId` (the same kind of keyed hash, over the
  alert's source across runs rather than one run), a `priority` hint,
  an `event` routing flag, and a `suite` naming the sealing algorithm
  (so the app knows which key opens the ciphertext without guessing
  from its length). None of them says anything about what the alert is.
- **Logs:** one line per delivery (status, outcome, priority, the
  `event` flag, and a `collapseId` prefix) and one per entitlement post
  (status, and the plan and product or the refusal reason), each with
  the first 8 hex chars of the device token's SHA-256. Device tokens and
  ciphertexts are never logged. Workers Logs keeps these lines, tagged
  with the request's URL, method, and path, and nothing else from the
  request: `wrangler.jsonc` turns off invocation logs, which would add
  the request's headers, the client address among them.
- **Client addresses:** the edge limiter keys its counters on the
  posting server's IP address (`cf-connecting-ip`), an IPv4 address as
  is and an IPv6 address by its /64 prefix. The relay uses it only as
  that transient key, and no storage row or Workers Logs line holds an
  address. Cloudflare's own request and security analytics for the zone
  do record client addresses, for up to 31 days.
- **Per-device state:** delivery counters keyed by the push token
  (dedup history per `collapseId`, flap history per `flapId` or
  `collapseId`, a rate bucket per lane, the APNs environment, and when
  the last digest went out), this month's forward count, and for Pro
  devices the verified entitlement's transaction id, product, purchase
  date, expiry, environment, verification time, and slot expiry. Per
  transaction, the SHA-256 of each device token it lifts with a
  last-seen time, and after a refund or revocation, the revocation's
  signing and purchase dates. All of it expires on its own: delivery
  state within about 30 hours of the last alert; quota with the month; a
  device's entitlement record at the purchase's expiry plus the grace
  (16 days) or after 60 days without a fresh proof, whichever comes
  first; a transaction's device hashes after 60 days of silence; and a
  revocation mark at the revoked purchase's expiry plus the grace (never,
  for a product without an expiry). A
  token APNs rejects for good (410) loses its per-device state at once,
  unless an entitlement still lifts its quota.

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
| 202 | `{"v":1,"outcome":"suppressed"}` | Flap suppression is holding this alert's flap key; accepted, not sent. |
| 202 | `{"v":1,"outcome":"digested"}` | The device is past its monthly free quota, or the envelope's rate bucket is empty; accepted, and a digest push goes out in place of the alerts (see "Digests"). |
| 400 | `{"v":1,"error":…}` | Malformed envelope (the error names the field), a body that isn't valid UTF-8 JSON, or a `Content-Length` that isn't a non-negative integer. |
| 410 | `{"v":1,"error":…,"reason":…}` | APNs permanently rejected the device token (`Unregistered`, `BadDeviceToken`, …); the pairing is dead. |
| 413 | `{"v":1,"error":…}` | Body over 8 KB (8192 bytes), counted as it arrives, with or without `Content-Length`. |
| 429 | `{"v":1,"error":…}` + `Retry-After` | The client address went over the edge limiter's 6000 POSTs a minute (see "Delivery policy"). |
| 429 | `{"v":1,"error":…,"reason":…}` | APNs throttled the device; `reason` is Apple's, and no `Retry-After` comes with it. |
| 502 | `{"v":1,"error":…}` | APNs unreachable or silent past `RELAY_APNS_TIMEOUT_S`, or the relay's own APNs credentials are broken. |

Notifications carry `mutable-content: 1` (so the app's NSE runs and
decrypts), `apns-collapse-id` from the envelope's `collapseId`,
`apns-priority` 10/5 and `interruption-level`
`time-sensitive`/`passive` from the envelope's `priority`, and a 10-minute
`apns-expiration` to match the protocol's replay-staleness window,
past which the payload would render as outdated anyway. A digest has no
timestamp to go stale, so APNs holds it for a day (86400 s), and its
collapse id `digest` keeps one copy on the device.

## Delivery policy

v1 takes no daemon credentials: admission control is per-device, keyed
on the opaque device token, with all state in that token's Durable
Object, behind an edge limiter per client address. relay-protocol.md
leaves the numbers to the relay; these are this relay's, each
overridable with a Worker var:

| Behavior | Default | Var |
| --- | --- | --- |
| Coalesce duplicates of an already-forwarded alert | 75 s window | `RELAY_DEDUP_WINDOW_S` |
| Flap suppression: max forwards per flap key before cooling | 6 per 30 min | `RELAY_FLAP_MAX_FORWARDS`, `RELAY_FLAP_WINDOW_S` |
| While cooled: one reminder forward per interval | 30 min | `RELAY_COOLDOWN_INTERVAL_S` |
| Cooling expires after silence | 2 h | `RELAY_FLAP_RESET_S` |
| Per-device token bucket, one per lane | burst 60, +1 token / 2 s | `RELAY_RATE_CAPACITY`, `RELAY_RATE_REFILL_PER_S` |
| Burst digest while a lane's bucket is empty: at most one per interval | 5 min | `RELAY_BURST_DIGEST_INTERVAL_S` |

Dedup keys on `collapseId`. Flap suppression keys on the envelope's
`flapId`, which the daemon derives from the alert's source with the
per-run fields left out, or on `collapseId` for an envelope without
one. A job that fails every minute therefore pages six times, then
reminds once per 30 minutes for as long as it keeps failing, and the
cooling ends after 2 hours of quiet. A per-run `collapseId` alone starts
every run from a fresh history, so suppression across runs needs the
`flapId`.

Daemon events (`event: true`) and alerts each draw from a bucket of
their own, with the same capacity and refill, so a flood of job alerts
can't starve an approval gate.

Coalesced, suppressed, and digested posts still answer 2xx: the relay
has taken responsibility, and delivering nothing *is* the policy. The
daemon never retries a relay POST, so an envelope that finds its lane's
bucket empty folds into a digest instead of being refused. Each APNs
send runs inside one budget, `RELAY_APNS_TIMEOUT_S` (8 s, under the
daemon's default 10 s relay timeout), and retries once against the same
host after a dropped or timed-out connection or an APNs 500 or 503, when
the budget leaves room. It never retries a 4xx. A retried push that APNs
had in fact accepted arrives under the same `apns-collapse-id`, so the
second copy replaces the first. The relay rolls back a forward that
still fails, so the same alert stays eligible the moment APNs recovers,
and the failed send costs no quota.

Ahead of any Durable Object, the `EDGE_LIMITER` binding admits 6000
POSTs to `/` per minute from one client address (`cf-connecting-ip`).
It keys an IPv4 address as is and an IPv6 address by its /64 prefix,
because one IPv6 host can post from any address in its /64. Past the
limit, the relay answers 429 with `Retry-After: 60` and doesn't read the
body. A daemon never retries a 429, so every envelope refused there is
lost. That's why the limit sits far above any honest burst: a daemon
posts one envelope per paired device for each alert, so 6000 a minute
covers an incident of 60 alerts to 100 devices. The limiter is there to
stop a sender that sprays envelopes across random device tokens, which
no per-device bucket can see. Daemons that share an egress address
(NAT, CGNAT) share one count. The event lane doesn't protect against
the limiter: past it, an approval gate from that address gets a 429
like any other envelope. The binding counts per Cloudflare location and
approximately, so it slows a flood rather than capping it. The zone
rate-limiting rule in "Deploy" stops a flood before it reaches the
Worker. The limiter applies to `POST /` alone.

### Digests

A digest is one fixed push with no ciphertext (collapse id `digest`,
`"kind": "digest"` in the payload) that stands in for envelopes the
relay answered `digested`. Two triggers send it, each with its own
interval and last-sent time:

| Trigger | Interval | Interruption level |
| --- | --- | --- |
| Quota: a free device past its monthly bound | `RELAY_DIGEST_INTERVAL_S` (3600) | `passive` |
| Burst: an envelope folded because its lane's bucket is empty | `RELAY_BURST_DIGEST_INTERVAL_S` (300) | `time-sensitive` (with sound) when any envelope folded since the last burst digest was, `passive` otherwise |

When a trigger's interval has run out, the digest goes out with the
envelope that triggers it. An envelope digested while the interval is
still running marks one digest as owed, and the device's alarm sends it
when the interval ends, so the last alerts of a burst still produce a
push. One push covers both triggers when both are owed at once, and a
month rollover keeps an owed quota digest. A digest that APNs doesn't
take for a reason worth retrying (no answer, or a 500 or 503 after the
send's one retry) stays owed, and the alarm sends it after a backoff of
five minutes, or the trigger's interval when that's shorter, and never
less than a minute. Any other refusal spends the interval.

## Monthly quota and Cronstable Pro

Each device gets `RELAY_FREE_MONTHLY_FORWARDS` (500) forwards per UTC
calendar month. Only alerts that reach APNs count: coalesced,
suppressed, folded, and failed envelopes do not, and neither do
digests or forwards made while a Pro entitlement lifts the bound. Past
the bound the relay answers `digested` and sends the device the quota
digest (see "Digests"), passive, at most once per
`RELAY_DIGEST_INTERVAL_S` (3600).

A Cronstable Pro entitlement lifts the bound. The app proves it with
`POST /entitlement` carrying the App Store's own signed transaction
(a StoreKit 2 `jwsRepresentation`), which the relay verifies offline in
`src/appstore.ts`: the `x5c` chain against the pinned Apple Root CA G3
(by exact DER bytes), each certificate's signature and validity window,
Apple's in-app purchase marker extension on the leaf, then the ES256
signature and the claims (`bundleId` = `APNS_TOPIC`, `productId` in
`RELAY_PRO_PRODUCT_IDS`, no `revocationDate`, `expiresDate` no more than
`RELAY_PRO_GRACE_S` (16 days) in the past, and `environment` Production,
or Sandbox unless `RELAY_ACCEPT_SANDBOX_ENTITLEMENTS` is `false`). The
relay judges each validity window at the payload's `signedDate`, with
Apple's 60-second skew either way, as Apple's own offline verifier
does, so a transaction signed under a receipt-signing certificate that
Apple has since rotated out still verifies. `signedDate` must be a
timestamp no more than 60 seconds past the relay's clock. Without a
`jws` the route only reports the device's plan and quota. One
transaction lifts at most `RELAY_PRO_DEVICES_PER_TRANSACTION` (5)
devices; a device's slot lapses after `RELAY_PRO_DEVICE_SLOT_TTL_S`
(60 days) without a re-post.

A device's lift ends at the purchase's expiry plus the grace, or when
its slot lapses, whichever comes first. The grace covers the gap
between a renewal and the device's next proof, and Apple's billing
grace period. Delivery, the status report, and the device's alarm all
apply that one rule. Forwards made during the lift don't count toward
the free bound, so a device whose lift ends mid-month starts from the
free forwards it has used. In the status body, `quota.used` is this
month's forwards that count toward the bound on `free`, and every
forward this month on `pro`.

An authentic transaction that carries a `revocationDate` (a refund, or
Apple revoking the purchase) answers 401 `revoked` and ends the lift it
granted. The relay marks the transaction revoked until the revoked
purchase's expiry plus the grace (a product without an expiry keeps
the mark for good). When the posting device's record names the same
transaction and a purchase no later than the revoked one, the relay
also deletes that record. While the mark stands, a copy of the
transaction that the App Store signed before the revocation (a
replayed pre-refund proof) answers 401 `revoked` from any device and
clears that device the same way. A later renewal, or a copy signed
after the revocation (a reversed refund), verifies as usual. A
revocation whose purchase's expiry plus the grace has passed leaves the
transaction as it is. Apple also revokes a transaction that an upgrade
superseded (`isUpgraded`); that one answers 401 and changes nothing
else.

Neither a revocation nor a refused replay frees a slot. Every slot
counts against the cap until it lapses, 60 days after the device's
last proof, and a device's lift never outlasts its slot. So the cap
holds in whatever order a device's posts land, including when it sends
a revoked copy and a live proof at once. A device that buys again on
the same transaction keeps its own slot; only a new device waits for a
slot to lapse.

Re-posting an unchanged proof is cheap. A slot refreshed within the
last day (or a quarter of the slot TTL, when that is shorter) keeps its
stored time, and a device record that would change only its
verification time stays as stored, so a repeat proof skips both writes.
A refused (409) proof writes nothing unless it prunes lapsed slots.
The relay keeps the transaction id, product, purchase date, expiry,
environment, verification time, and slot expiry per device, a hash of
each device token and a revocation mark per transaction, and never
stores the JWS.

| Status | Body | Meaning |
| --- | --- | --- |
| 200 | `{"v":1,"plan":…,"expiresAt":…,"environment":…,"quota":{"used":…,"limit":…,"resetsAt":…}}` | The device's plan and this month's quota; `expiresAt`/`environment` only on `pro` (`expiresAt` is in the past during the grace), `limit` null when unlimited. |
| 400 | `{"v":1,"error":…}` | Malformed body (including invalid UTF-8 or a bad `Content-Length`), device, or JWS. |
| 401 | `{"v":1,"error":"entitlement rejected","reason":…}` | The transaction does not verify; `reason` names the failed check, and `revoked` covers a replayed copy signed before a recorded revocation. |
| 409 | `{"v":1,"error":…,"limit":5}` | The transaction already lifts its maximum number of devices. |
| 413 | `{"v":1,"error":…}` | Body over 16 KB (16384 bytes), with or without `Content-Length`. |

## Environment

Every knob has a default in code; `wrangler.jsonc` sets only the ones
worth seeing at a glance.

| Var | Default | Meaning |
| --- | --- | --- |
| `APNS_TOPIC` | `com.cronstable.app` | Bundle id the notifications and entitlements belong to. |
| `APNS_ENVIRONMENT` | `auto` | See "APNs environments". |
| `RELAY_FREE_MONTHLY_FORWARDS` | `500` | Free forwards per device per UTC month. |
| `RELAY_DIGEST_INTERVAL_S` | `3600` | Minimum seconds between quota digests to one device. |
| `RELAY_PRO_PRODUCT_IDS` | `com.cronstable.app.pro.monthly,com.cronstable.app.pro.yearly` | Product ids that count as Pro. |
| `RELAY_ACCEPT_SANDBOX_ENTITLEMENTS` | `true` | `false` refuses Sandbox (TestFlight, Xcode) transactions. |
| `RELAY_PRO_DEVICES_PER_TRANSACTION` | `5` | Devices one transaction may lift. |
| `RELAY_PRO_DEVICE_SLOT_TTL_S` | `5184000` | Seconds without a re-post after which a device's slot, and its lift, lapse. |
| `RELAY_PRO_GRACE_S` | `1382400` | Seconds past a transaction's `expiresDate` that it still verifies and lifts the quota (16 days; `0` allowed). |
| `RELAY_APNS_TIMEOUT_S` | `8` | Seconds one APNs send may take, its retry and the auto-mode environment hop included. |
| `RELAY_APPLE_ROOT_CERT` | Apple Root CA G3 | Test hook: base64 DER of the root to trust instead. |
| `RELAY_QUOTA_PERIOD_S` | unset | Test hook: fixed-length quota periods instead of calendar months. |

See "Delivery policy" for the delivery-policy windows, the burst digest
interval among them.

The edge limiter is a binding, not a var: the `EDGE_LIMITER` entry under
`ratelimits` in `wrangler.jsonc` sets its limit and period. Rate-limit
bindings that share a `namespace_id` share their counters across every
Worker in the Cloudflare account, so a self-hosted relay picks an id no
other Worker on its account uses. A relay deployed without the binding
skips the check.

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

Prerequisites: a Cloudflare account, Node 22+ (CI builds on the 24
LTS), and an Apple Developer account for the APNs key.

The Durable Objects here are SQLite-backed, so the Workers Free plan
runs the relay, and it suits a personal relay with a few devices. A
public relay needs Workers Paid. The Free plan caps Worker requests,
Durable Object requests, and Durable Object rows written at 100,000 a
day each, and past any one cap those operations fail hard until 00:00
UTC. Daemons never retry, so every alert posted in that time is lost.
Each envelope costs a Worker request and a Durable Object request
whatever the relay then decides, so one job failing every minute spends
1,440 of each a day per paired device, even once the device's monthly
quota has run out. On either plan, set up Cloudflare usage
notifications for Durable Object requests and rows written.

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
7. Add a rate-limiting rule to the zone's WAF for `POST /` on the
   relay's hostname, counting by IP. This step is required. The rule
   runs before the Worker, so it's the only layer that keeps a flood off
   the Worker and Durable Object request budgets; the `EDGE_LIMITER`
   binding only slows one down once it's inside. Set the threshold to
   at least the binding's 6000 requests, over whatever period the rule
   counts, so the rule never refuses what the binding admits. A daemon
   sends one POST per paired device for each alert, up to 100 at once,
   an incident's 60 alerts can land within seconds, the daemons and
   cluster nodes behind one address share the count, and a daemon never
   retries a 429. Match as much of `POST /` and the hostname as the
   zone's plan allows: a Free zone matches the path alone over a
   10-second period, Pro adds the hostname, and Business adds the
   method.
8. Deploy the relay before you upgrade the daemons that post to it. A
   daemon fits alerts to the ciphertext cap it was built with. In front
   of a relay that enforces a smaller cap, the daemon gets a 400 for its
   largest alerts and falls back to the protocol's 3000-character floor
   for them, so the page lands with fewer log lines. A current relay
   never triggers that fallback.
9. Point daemons at it:

   ```yaml
   push:
     relay:
       url: https://relay.cronstable.com/   # or your deployment
   ```

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

The entitlement suite signs with a test-only certificate chain in
`tests/fixtures/appstore/` (leaf private keys included; none of it is
registered with Apple). `sh scripts/gen-appstore-fixtures.sh`
regenerates it with OpenSSL 3.4 or later.

## License

MIT; see [LICENSE](LICENSE). Contributions are DCO-certified
(`git commit -s`), same as cronstable itself; see
[CONTRIBUTING.md](CONTRIBUTING.md).

cronstable™ and the cronstable logo are trademarks of Parker Loflin and
are not licensed by the MIT grant; see
[TRADEMARKS.md](https://github.com/ptweezy/cronstable/blob/main/TRADEMARKS.md).
