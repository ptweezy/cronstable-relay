# cronstable-relay

The push relay for [cronstable](https://github.com/ptweezy/cronstable)'s
end-to-end encrypted alerts, as a Cloudflare Worker with one Durable
Object per device. This is the exact source of the hosted instance at
**`https://relay.cronstable.com/`** — published so anyone can audit what
their alert traffic passes through.

```
daemon ──sealed box──▶ this relay ──APNs──▶ device (NSE decrypts locally)
```

A cronstable daemon seals every alert to each paired device's X25519
public key (libsodium sealed box) before it leaves the machine, then
POSTs one envelope per (alert, device) here. The relay coalesces
duplicates, suppresses flapping, rate-limits, and forwards the — still
sealed — ciphertext to Apple. The receiving app's Notification Service
Extension decrypts on the device and renders the real alert.

## What the relay can and cannot see

The relay is designed to not be a trusted party:

- **Never present here:** job names, hostnames, schedules, log lines,
  exit codes, event details. They exist only inside the sealed box; the
  relay has no key material at all.
- **What an envelope carries:** an APNs device token, the ciphertext,
  a `collapseId` (a truncated SHA-256 keyed with a per-installation
  salt the relay never sees — not invertible even for guessable job
  names), a `priority` hint, and an `event` routing flag.
- **Logs:** outcome, priority, the first 8 hex chars of a SHA-256 of
  the device token, and a `collapseId` prefix. Device tokens and
  ciphertexts are never logged.

The wire contract is
[`docs/relay-protocol.md`](https://github.com/ptweezy/cronstable/blob/main/docs/relay-protocol.md)
(v1) in the cronstable repo — the daemon side, this relay, and the app
all implement that document.

## Protocol conformance

`POST /` accepts one envelope per (alert, device). Responses follow the
protocol's semantics (the daemon never retries; delivery past acceptance
is the relay's responsibility):

| Status | Body | Meaning |
| --- | --- | --- |
| 202 | `{"v":1,"outcome":"forwarded"}` | Handed to APNs. |
| 202 | `{"v":1,"outcome":"coalesced"}` | Duplicate of an alert forwarded moments ago (e.g. another cluster node's copy); accepted, not re-sent. |
| 202 | `{"v":1,"outcome":"suppressed"}` | Flap suppression is holding this alert id; accepted, not sent. |
| 400 | `{"v":1,"error":…}` | Malformed envelope (the error names the field). |
| 410 | `{"v":1,"error":…,"reason":…}` | APNs permanently rejected the device token (`Unregistered`, `BadDeviceToken`, …) — the pairing is dead. |
| 413 | `{"v":1,"error":…}` | Body over 8 KB. |
| 429 | `{"v":1,"error":…}` + `Retry-After` | Per-device rate limit (or APNs itself throttled the device). |
| 502 | `{"v":1,"error":…}` | APNs unreachable, or the relay's own APNs credentials are broken. |

Notifications are sent with `mutable-content: 1` (so the app's NSE runs
and decrypts), `apns-collapse-id` set to the envelope's `collapseId`,
`apns-priority` 10/5 and `interruption-level`
`time-sensitive`/`passive` from the envelope's `priority`, and a
10-minute `apns-expiration` — matching the protocol's replay-staleness
window, after which the payload would render as outdated anyway.

## Delivery policy

v1 takes no daemon credentials; admission control is per-device, keyed
on the (opaque) device token, with all state in that device's Durable
Object. relay-protocol.md leaves the numbers to the relay; these are
this relay's, each overridable with a Worker var:

| Behavior | Default | Var |
| --- | --- | --- |
| Coalesce duplicates of an already-forwarded alert | 75 s window | `RELAY_DEDUP_WINDOW_S` |
| Flap suppression: max forwards per alert id before cooling | 6 per 30 min | `RELAY_FLAP_MAX_FORWARDS`, `RELAY_FLAP_WINDOW_S` |
| While cooled: one reminder forward per interval | 30 min | `RELAY_COOLDOWN_INTERVAL_S` |
| Cooling expires after silence | 2 h | `RELAY_FLAP_RESET_S` |
| Per-device token bucket | burst 60, +1 token / 2 s | `RELAY_RATE_CAPACITY`, `RELAY_RATE_REFILL_PER_S` |

Coalesced and suppressed posts still answer 2xx: the relay has taken
responsibility, and delivering nothing *is* the policy. Only the rate
limiter says 429. A forward that fails at APNs is rolled back, so the
same alert stays eligible the moment APNs recovers.

## APNs environments

`APNS_ENVIRONMENT` is `production`, `sandbox`, or `auto` (default).
In `auto`, the relay tries production first; if APNs answers
`BadDeviceToken`/`DeviceTokenNotForTopic` (the token belongs to the
other environment — e.g. a development build), it retries against
sandbox once and remembers the working environment per device. One
deployment then serves App Store, TestFlight and Xcode builds.

## Self-hosting

Anything that implements relay-protocol.md can serve as the relay a
daemon's `push.relay.url` points at — deployments own their admission
policy, and this repo is MIT-licensed precisely so you can run your own.

One honest caveat first: **APNs provider keys are team-scoped.** A
relay can only push to apps signed by the Apple Developer team whose
`.p8` key it holds. Self-hosting this relay therefore serves *your own
app builds* (a fork of the companion app under your team, or another
client implementing the sealed-box contract). Alerts destined for the
official cronstable app can only transit the official relay — which is
why its source is published and why the payloads it handles are sealed:
you don't have to trust it with anything.

### Deploy

Prerequisites: a Cloudflare account (free plan is enough — the Durable
Objects used here are SQLite-backed), Node 20+, and an Apple Developer
account for the APNs key.

1. Create the APNs auth key: developer.apple.com → Certificates,
   Identifiers & Profiles → Keys → add a key with the **Apple Push
   Notifications service (APNs)** capability. Download the `.p8` once
   and note the Key ID and your Team ID.
2. `npx wrangler login`
3. Set the app you are pushing to in `wrangler.jsonc` (`APNS_TOPIC` =
   the app's bundle id).
4. Store the credentials as secrets:

   ```sh
   npx wrangler secret put APNS_TEAM_ID
   npx wrangler secret put APNS_KEY_ID
   npx wrangler secret put APNS_AUTH_KEY   # paste the whole .p8 file, BEGIN/END lines included
   ```

5. `npm run deploy` — the relay is live on your `workers.dev` subdomain.
6. Custom domain (optional): with your zone active on the Cloudflare
   account, uncomment the `routes` line in `wrangler.jsonc`, set
   `workers_dev` to `false`, and deploy again.
7. Point daemons at it:

   ```yaml
   push:
     relay:
       url: https://relay.cronstable.com/   # or your deployment
   ```

### Smoke test

`npm run smoke -- https://relay.cronstable.com/` POSTs a well-formed
envelope carrying a synthetic device token. A healthy, correctly
credentialed relay answers **410** (APNs authenticated the relay, then
rejected the unknown token) — anything 5xx means the APNs credentials
or connectivity need attention. Full end-to-end delivery is verified
from a daemon once a real device has paired: `POST
/push/devices/{id}/test` on the daemon, or the dashboard's test button.

## Development

```sh
npm install
npm run typecheck
npm test          # vitest + workerd; APNs is mocked at the network edge
npm run dev       # local relay on http://localhost:8787
```

`.dev.vars` (gitignored) can hold the `APNS_*` secrets for `wrangler
dev` against real sandbox APNs.

## License

MIT — see [LICENSE](LICENSE). Contributions are DCO-certified
(`git commit -s`), same as cronstable itself; see
[CONTRIBUTING.md](CONTRIBUTING.md).
