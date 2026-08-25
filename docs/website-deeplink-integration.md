# Handing a VPN config to the VPN Client from the web — integration spec

For the team that maintains the config download site. The desktop client
registers a custom URL scheme at install time; a link in that scheme makes the
client import a profile instead of the browser dropping a file in `Downloads`.

Scope: **inline payload only** — the config travels inside the link. Nothing has
to be built or changed server-side; no new endpoint, no tokens, no API. A
fetch-by-URL variant is planned for later (§6) and will not require reworking
anything described here.

Nothing breaks if the client is old or not installed — the existing download
link stays exactly as it is and remains the fallback.

## 1. The link

    itmvpn://import?data=<base64url>&ext=<ini|scx|tgb|pro>&name=<display name>

| parameter | required | meaning |
|-----------|----------|---------|
| `data` | yes | the profile file's **raw bytes**, base64url encoded. Padding may be stripped. |
| `ext`  | no  | the file's extension, without the dot: `ini`, `scx`, `tgb`, `pro`. Defaults to `ini`. The client dispatches on file *content*, so a wrong `ext` still imports correctly — it only affects how the file is named on disk. |
| `name` | no  | the name the profile gets in the client. Defaults to the filename you would otherwise have served. |

`.pro` provisioning files work too: the client recognises the content and opens
its portal sign-in dialog instead of importing a connection directly.

## 2. Building the link

Base64url means the standard alphabet with `+` becoming `-`, `/` becoming `_`,
and `=` padding removed. Do that rather than relying on percent-encoding: a `+`
in a query string is ambiguous (it can decode as a space).

Encode the **raw file bytes**, not a re-encoded string — that keeps the file
byte-identical to what the download link serves.

```js
function toBase64Url(bytes) {                 // bytes: Uint8Array
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importLink(fileUrl, displayName, ext) {
  // The browser is signed in, so this fetch carries the session — which is
  // exactly why no server-side token endpoint is needed for this phase.
  const res = await fetch(fileUrl, { credentials: 'same-origin' });
  const bytes = new Uint8Array(await res.arrayBuffer());
  return 'itmvpn://import?data=' + toBase64Url(bytes)
       + '&ext=' + encodeURIComponent(ext)
       + '&name=' + encodeURIComponent(displayName);
}
```

Server-side templating works just as well — base64 the file when rendering the
page and put the finished link straight into the markup.

Run `encodeURIComponent` over `name` and `ext`. `data` needs no further encoding
once it is base64url.

## 3. Size

Not a constraint for the formats in the catalogue:

| file | typical size | in the link |
|------|--------------|-------------|
| `.pro` | 271–310 B | ~370–415 chars |
| `.ini` | 547–612 B | ~750–820 chars |
| `.scx` | 874–947 B | ~1.2 KB |
| `.tgb` | 2266 B | ~3.0 KB |

The Windows command line takes 32,767 characters and the client's own IPC is
dynamically sized, so the only uncertain link in the chain is the browser's
handling of long external-protocol URLs. Worth a one-off check in Chrome, Edge
and Firefox for the `.tgb` case. (The often-quoted 2083-character ceiling is
Internet Explorer's and does not apply here.)

The one format that could genuinely run out of room is an SSL VPN `.ovpn` with
inline certificates and keys, at 5–15 KB. Those are out of scope here — they
will use the fetch-by-URL variant (§6) when it lands.

## 4. The button

Protocol launches must come from a real user gesture. Browsers block them from
`onload`, timers and similar.

```html
<a id="dl" href="https://configs.example.de/d/kanzlei.scx">Download config</a>
<button id="imp" type="button">Import into VPN Client</button>
```

```js
document.getElementById('imp').addEventListener('click', async () => {
  window.location.href = await importLink(fileUrl, displayName, 'scx');
});

// Optional shortcut: shift-click on the normal download link does the same.
document.getElementById('dl').addEventListener('click', async (e) => {
  if (!e.shiftKey) return;                    // plain click = normal download
  e.preventDefault();
  window.location.href = await importLink(fileUrl, displayName, 'scx');
});
```

* **Ship the visible button.** Shift-click alone is undiscoverable; treat it as a
  shortcut for people who already know about it.
* The browser shows its own "Open VPN Client?" confirmation with an "Always
  allow" checkbox. That prompt is expected and cannot be suppressed.
* **Success and failure are not detectable.** If the client is not installed the
  browser simply reports that no app is associated. Do not build a timeout-based
  detector — put a static line under the button instead: *"Requires the VPN
  Client (version X or newer) — install it here"*, and leave the ordinary
  download as the fallback.
* If you build the link with `fetch`, keep both the fetch and the
  `window.location.href` assignment inside the click handler. An `await` between
  them is fine; moving the navigation into a `setTimeout` is not.

## 5. What the client does with it

1. The window comes to the front — launching the app if it was not running, or
   handing the link to the already-running instance (never a second copy).
2. The payload is decoded and **parsed before anything is written to disk**.
   Anything that is not a recognisable profile is rejected with an error.
3. A confirmation dialog names the profile, the gateway and the networks it
   would add. The user has to confirm. This is the only gate — anyone can put an
   `itmvpn://` link on a page — so it is deliberately explicit and cannot be
   skipped.
4. On confirm the profile is imported. The client **never connects on its own**.
   If a profile of that name is already installed the dialog says so before the
   user commits: the same format is replaced in place, and a different format
   under the same name is refused outright.

### One thing to be aware of

The link becomes the client process's command line, and command lines are
captured by default by EDR agents (Defender for Endpoint, CrowdStrike, Sysmon
event 1) and by Windows security event 4688 where command-line auditing is
enabled. A profile containing a live pre-shared key is therefore recorded in
cleartext wherever those logs land.

A `data=` link is also the credential itself: it does not expire and cannot be
revoked once bookmarked or forwarded.

That is accepted for this phase. `.pro` files are unaffected — they carry no
secret, only the portal address, and the user still signs in inside the client.

## 6. Later: fetch-by-URL

The planned second form is `itmvpn://import?url=<https URL>&name=<name>`, where
the client downloads the profile itself from a short-lived one-time token URL.
It removes both caveats above (only a throwaway token reaches the command line)
and lifts the size limit, at the cost of a small endpoint on your side.

When it lands the client will accept both forms, so nothing built for this spec
has to be thrown away or migrated.

## 7. What we need from you

* A quick browser check of the `.tgb`-sized link (~3 KB) in Chrome, Edge and
  Firefox once the client ships.
* The client version you should name in the "requires the VPN Client" line under
  the button — we will confirm it when the release goes out.

The scheme name is settled: `itmvpn://`. It is written into the installer's
registry entries, so it will not change.
