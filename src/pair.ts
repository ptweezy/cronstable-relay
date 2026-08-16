/**
 * GET /pair: the landing page behind the dashboard's pairing QR, plus the
 * apple-app-site-association document that makes /pair a universal link.
 *
 * The QR encodes `https://relay.cronstable.com/pair#<base64url(payload)>`.
 * On a phone with the Cronstable app installed, iOS opens the app directly
 * and this page is never fetched.  Without the app, the browser lands here;
 * the page explains the situation, offers install pointers, and carries a
 * `cronstable://pair#<fragment>` button for retrying once the app exists.
 *
 * The pairing payload (daemon address + bearer token) rides in the URL
 * fragment, which browsers never send with the request: this worker serves
 * static bytes and never sees it.  The page's script decodes the fragment
 * locally to show which daemon the code points at, and renders the daemon's
 * name and host only — never the token.
 */

/** appID = <Team ID>.<bundle id>; the bundle id is fixed (APNs topic). */
export const PAIR_AASA = JSON.stringify({
  applinks: {
    details: [
      {
        appIDs: ["6392RHBP25.com.cronstable.app"],
        components: [{ "/": "/pair", comment: "device pairing deep link" }],
      },
    ],
  },
});

export const PAIR_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>Pair with Cronstable</title>
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
  .server {
    margin: 1.25rem 0; padding: .75rem 1rem; border-radius: .6rem;
    border: 1px solid color-mix(in srgb, CanvasText 20%, transparent);
  }
  .server .name { font-weight: 600; }
  .server .host { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; opacity: .75; }
  .open {
    display: inline-block; margin: .5rem 0 0; padding: .6rem 1.2rem;
    border-radius: .6rem; background: LinkText; color: Canvas;
    text-decoration: none; font-weight: 600;
  }
</style>
</head>
<body>
<h1>Pair with Cronstable</h1>
<p class="meta">This is the landing page for the pairing QR a cronstable
dashboard shows. When the Cronstable app is installed, scanning that QR
opens it directly and skips this page.</p>

<div class="server" id="server" hidden>
  <div class="name" id="serverName"></div>
  <div class="host" id="serverHost"></div>
</div>

<p id="withCode" hidden>To finish pairing, install the app, come back to
this page, and tap the button:</p>
<p id="withoutCode">There is no pairing code in this page's address. To
pair a device, open your dashboard's <strong>Pair a device</strong> panel
and scan the QR it shows.</p>
<p><a class="open" id="openApp" href="#" hidden>Open in the Cronstable app</a></p>

<h2>Getting the app</h2>
<p>Cronstable for iPhone, iPad, and Apple Watch is the companion app for
the open-source
<a href="https://github.com/ptweezy/cronstable">cronstable</a> scheduler:
your jobs on your servers, with end-to-end encrypted push alerts. Install
it from the App Store, then scan the dashboard QR again.</p>

<h2>Your pairing code stays on this device</h2>
<p>The code rides in the part of the address after <code>#</code>, which
your browser never sends to any server, this one included. This page
decodes it locally to show which daemon it points at, and displays only
the daemon's name and address.</p>

<script>
  (function () {
    var frag = location.hash.slice(1);
    if (!frag) return;
    var payload = null;
    try {
      var b64 = frag.replace(/-/g, "+").replace(/_/g, "/");
      payload = JSON.parse(atob(b64));
    } catch (_) { return; }
    if (!payload || payload.v !== 1 || !payload.url) return;
    document.getElementById("withoutCode").hidden = true;
    document.getElementById("withCode").hidden = false;
    var open = document.getElementById("openApp");
    open.href = "cronstable://pair#" + frag;
    open.hidden = false;
    var host = "";
    try { host = new URL(payload.url).host; } catch (_) {}
    document.getElementById("serverName").textContent = String(payload.name || host || "cronstable");
    document.getElementById("serverHost").textContent = host;
    document.getElementById("server").hidden = false;
  })();
</script>
</body>
</html>
`;
