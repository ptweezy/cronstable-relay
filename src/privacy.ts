/**
 * GET /privacy: the privacy policy for the Cronstable iOS app and the
 * hosted relay/demo services.  Served from the relay because it is the
 * one piece of developer-operated infrastructure the app talks to, so
 * the policy lives next to the thing it describes.  App Store Connect
 * references this URL as the app's privacy policy.
 *
 * Self-contained HTML: no scripts, no external assets, theme-aware.
 */

const EFFECTIVE = "August 16, 2026";

export const PRIVACY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Cronstable Privacy Policy</title>
<style>
  :root { color-scheme: light dark; }
  body {
    margin: 0 auto; padding: 2.5rem 1.25rem 4rem; max-width: 42rem;
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: Canvas; color: CanvasText;
  }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.15rem; margin: 2rem 0 .5rem; }
  p, li { margin: .5rem 0; }
  .meta { opacity: .65; font-size: .9rem; margin-bottom: 1.5rem; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
  a { color: LinkText; }
</style>
</head>
<body>
<h1>Cronstable Privacy Policy</h1>
<p class="meta">Effective ${EFFECTIVE}. Applies to the Cronstable app for
iPhone, iPad, and Apple Watch, and to the hosted services it can use:
the push relay (relay.cronstable.com) and the demo server
(demo.cronstable.com).</p>

<h2>The short version</h2>
<ul>
  <li>No accounts, no sign-up, no analytics, no ads, no trackers, and no
  third-party SDKs that phone home.</li>
  <li>Your monitoring data flows directly between the app and servers
  <em>you</em> run. It never passes through us.</li>
  <li>Push notifications are end-to-end encrypted. Our relay forwards
  sealed ciphertext it cannot read and does not store.</li>
</ul>

<h2>Your servers, your data</h2>
<p>Cronstable is a client for the open-source
<a href="https://github.com/ptweezy/cronstable">cronstable</a> scheduler
you install on your own machines. The app fetches job names, schedules,
run history, logs, and metrics straight from your servers over your own
network connection (LAN, VPN, or HTTPS). This data never reaches us.</p>
<p>The app keeps your server API tokens in the device Keychain and sends
each token only to the server it belongs to.</p>

<h2>Push notifications and the relay</h2>
<p>If you enable push, your server encrypts each alert on your hardware
using a public key that belongs to your device. The private key never
leaves your device. Your server then hands the sealed message to our
relay, which forwards it to Apple Push Notification service for
delivery. The alert's content (job names, hostnames, log lines) exists
only inside the sealed message, and only your device can open it. The
relay forwards the message still sealed and keeps no copy.</p>
<p>The relay processes your device's Apple push token and keeps a small
amount of per-device delivery state: rate-limit and de-duplication
counters and the APNs environment, keyed by the push token. The relay
deletes this state automatically as it expires. Service logs record
only a truncated cryptographic hash of the token, which is useless for
sending notifications. The relay's source is public:
<a href="https://github.com/ptweezy/cronstable-relay">github.com/ptweezy/cronstable-relay</a>.</p>
<p>Apple receives the encrypted payload and your push token to deliver
notifications; Apple's own privacy terms govern that delivery.</p>

<h2>The demo</h2>
<p>The optional "Try the demo" mode connects the app read-only to a
sample fleet at demo.cronstable.com. Like any web server, it sees
standard request metadata (IP address, user agent) while serving you.
The demo creates no account or identifier for you, and its operational
logs are short-lived.</p>

<h2>Device permissions</h2>
<ul>
  <li><strong>Camera</strong>: used only to scan the pairing QR code
  shown by your server. Scanning happens on the device, and camera
  frames stay there.</li>
  <li><strong>Local network (Bonjour)</strong>: used only to discover
  cronstable servers on your own network; discovery happens on the
  device.</li>
  <li><strong>Notifications</strong>: used to show the alerts described
  above.</li>
</ul>

<h2>Retention and deletion</h2>
<p>Unpair a device from your server (in the app, or with
<code>cronstable push unpair</code> on the server) and alerts stop
immediately. Relay delivery state is transient and expires on its own;
deleting the app invalidates the push token entirely. We hold no
account and no content, so unpairing and deleting the app remove
everything there ever was.</p>

<h2>Children</h2>
<p>Cronstable is a server-administration tool; its audience is people
who run their own servers, and we direct nothing in the app or its
marketing at children.</p>

<h2>Changes</h2>
<p>The current policy always lives at this URL; material changes update
the effective date above.</p>

<h2>Contact</h2>
<p>Parker Loflin &middot;
<a href="mailto:parker@cronstable.dev">parker@cronstable.dev</a> &middot;
or open an issue on
<a href="https://github.com/ptweezy/cronstable/issues">GitHub</a>.</p>
</body>
</html>
`;
