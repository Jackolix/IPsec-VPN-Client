# cross-platform-vpn

Desktop IPsec VPN client wrapping strongSwan. Imports NCP-style `.ini`
profiles and Sophos `.scx` / `.tgb` exports. See
`ipsec-vpn-client-plan.md` for the full build plan;
this repo is at **Phase 2** — a Tauri desktop app whose Rust backend parses
profiles natively and drives charon over the vici control protocol
(connect / status / disconnect). Verified end-to-end against a LANCOM
vRouter, including from a native Windows build over a TCP vici socket.

**Windows and macOS** both terminate the tunnel on the host, with their own
bundled strongSwan and a privileged helper that keeps the GUI unprivileged.
They share the profile importers, the vici client and the connection logic;
everything below that is each platform's own — see *Native Windows tunnel* and
*Native macOS tunnel*. Linux is a development target only, driving charon in a
container.

## Security rules (read first)

- Profile exports contain a **live pre-shared key in plaintext** — NCP `.ini`
  in `Secret=`, Sophos `.scx` in `remote_auth.psk.secret`, Sophos `.tgb` in
  the peer's `Authentication`. `*.ini`, `*.scx`, `*.tgb` and `*.pro` are
  gitignored, as is `Sophos-configs/` where customer-supplied files land;
  never commit one, never log the `Secret` value. The only exceptions are the
  redacted test fixtures (`crates/*/tests/fixtures/*.redacted.*`), whose
  keys and addresses are replaced.
- Generated `*.swanctl.conf` files (in `out/`) contain the PSK too and are
  gitignored as well.
- **Connect dials the gateway named in the profile.** The desktop app connects
  straight to it — there's no lab-only lock. The `vpn-agent` CLI keeps an
  optional `--gateway-override HOST` to aim a profile at a different responder
  for testing. During development, only the authorized LANCOM lab target
  (`192.168.100.10`) was ever contacted.

## Layout

| Crate | Purpose |
|---|---|
| `crates/vpn-core` | Internal config model (importer-independent) + `swanctl.conf` rendering. `Secret` type redacts itself in all Debug/Display output. |
| `crates/ncp-profile` | NCP ini importer + the documented numeric code tables (`src/codes.rs`, each mapping carries a confidence level); warns on every unconfirmed mapping. The ini parser it is built on lives in `vpn-core`, shared with the `.tgb` importer. |
| `crates/sophos-profile` | Sophos importers: `.scx` (Sophos Connect — JSON, close to a serialised swanctl connection), `.tgb` (legacy Cyberoam/TheGreenBow — ini-shaped, IKEv1, algorithms reached through a chain of section references) and `.pro` (a pointer to a user portal, not a connection). Same policy as the NCP importer: hard error on anything safety-critical it cannot map, warning on anything merely unconfirmed. |
| `crates/vici` | Hand-rolled client for strongSwan's vici control protocol: a cross-platform message codec plus packet framing and a blocking request/event client (Unix and TCP transports). |
| `crates/vpn-control` | Shared connection logic used by both the CLI and the GUI: the config→vici bridge, `list-sa` status parsing, and the connect/status/disconnect flows over a `Transport` (Unix socket or TCP). `connect_logged` registers for charon's `log` event around `initiate` and returns the captured handshake transcript. |
| `crates/vpn-desktop` | Tauri desktop app. Rust backend interprets profiles natively and calls `vpn-control`; the web UI (`ui/`) drives it via `invoke`. Native file-picker + drag-drop import, system tray, DNS-over-tunnel (NRPT), PSK in the OS keychain (`src/creds.rs`, `keyring`) taking precedence over the plaintext `.ini`. Run headlessly with `--selftest`; drive the backend flows with `--dev <cmd>`. |
| `crates/vpn-broker` | The privileged helper, on both platforms. **Windows**: a LocalSystem **service** that supervises `charon-svc.exe` and applies/reverts NRPT DNS rules for the unelevated GUI over an ACL'd named pipe (`src/ipc.rs`), registered by the installer. **macOS**: a launchd **LaunchDaemon** (`src/launchd.rs`) serving the same requests over a Unix socket (`src/unix_ipc.rs`), doing charon's lifecycle and `/etc/resolver` DNS (`src/privileged.rs`). The `protocol` is shared because the shape is (one request, one response, newline JSON); `src/openvpn.rs`, the SSL VPN supervisor, is shared too — only its adapter handling is Windows-specific. On both, the GUI falls back to an elevation prompt when the helper isn't installed. |
| `crates/vpn-agent` | CLI agent over `vpn-control`: imports a profile and drives charon (`connect` / `status` / `disconnect`). The PSK is pushed via `load-shared` in memory — no swanctl.conf with the secret is written to disk. |
| `crates/vpn-cli` | Phase 0 CLI: `show` (redacted interpretation) and `generate` (writes swanctl.conf). Kept for inspection/debugging. |
| `docker/vici-tcp` | Dev backend: charon with its vici socket published on `127.0.0.1:45022` so a host desktop build can drive it. |
| `docker/strongswan-windows` | MinGW cross-build of strongSwan's **native** Windows daemon `charon-svc.exe` (kernel-wfp / kernel-iph / socket-win / vici, monolithic, OpenSSL). The tunnel terminates on the Windows host via the Windows Filtering Platform - no container. Built + exported by `scripts/build-strongswan-windows.ps1`, launched (elevated) by `scripts/run-charon-windows.ps1`; vici on `127.0.0.1:4502`. |
| `macos/` | `strongswan.conf` for the native macOS daemon. Built by `scripts/build-strongswan-macos.sh` (kernel-libipsec / kernel-pfroute / tun-device over utun, monolithic, OpenSSL) into `out/strongswan-macos`; OpenVPN for the SSL datapath comes from `scripts/build-openvpn-macos.sh` into `out/openvpn-macos`. Launched by `scripts/run-charon-macos.sh` or by the helper; vici on a Unix socket. |
| `docker/agent` | Multi-stage image running `vpn-agent` beside charon (Linux client during development). |
| `docker/initiator` | Legacy Phase 0 container that shells out to `swanctl`. |

## Quickstart

The snippets below are PowerShell — on a Mac, skip to *Native macOS tunnel*,
which is self-contained. `cargo test --workspace` is the one command that is
the same everywhere.

```powershell
# Desktop GUI: starts the charon backend container and launches the app
# (profiles are read from the repo root by default). Needs Docker Desktop
# and WebView2 (bundled with Windows 11).
.\scripts\run-desktop.ps1

# Headless check of the desktop backend (interprets profiles, lists SAs):
$env:VPN_PROFILE_DIR = "$PWD"; .\target\debug\vpn-desktop.exe --selftest

# CLI equivalents over the same TCP vici backend:
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 connect --profile .\TEST-1.ini
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 status
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 disconnect --name vRouter-TEST-1

# Inspect how a profile is interpreted (secret stays redacted). The format is
# picked from the file's contents, so this works for .ini, .scx and .tgb alike;
# a .pro prints the user portal to sign in to instead.
cargo run -p vpn-cli -- show .\TEST-1.ini
cargo run -p vpn-cli -- show .\Sophos-configs\example.scx

# Tests (run on any platform; the vici/control logic is cross-platform):
cargo test --workspace
```

### Native Windows tunnel (no container)

The tunnel terminates on the Windows host itself, via strongSwan's native
`charon-svc.exe`. This is needed because Windows' built-in IKEv2 client can't
negotiate the profile's suite (PSK auth + DH group 15 / modp3072).

ESP runs in **userland** (`kernel-libipsec`) over a Wintun adapter, with
`kernel-iph` managing addresses and routes. Windows' own IPsec engine
(`kernel-wfp`) is deliberately not built: it drops UDP-encapsulated ESP in
tunnel mode, and behind NAT that encapsulation is not optional — so it cannot
carry a road-warrior tunnel at all. See the rationale at the top of
`docker/strongswan-windows/Dockerfile`.

```powershell
# 1. Cross-build charon-svc.exe + plugins (Docker + MinGW) and export to out\:
.\scripts\build-strongswan-windows.ps1

# 2a. Desktop app against the native backend (no container). The app starts
#     charon-svc itself - hit Connect (or the sidebar Start button) and approve
#     the UAC prompt; the GUI runs unelevated and talks to vici on loopback:
.\scripts\run-desktop-native.ps1

# 2b. …or drive it from the CLI. Launch the daemon ELEVATED (WFP needs
#     Administrator; vici on 127.0.0.1:4502) and drive it unelevated:
.\scripts\run-charon-windows.ps1        # accepts -Install / -Uninstall for a service
cargo run -p vpn-agent -- --tcp 127.0.0.1:4502 connect --profile .\TEST-1.ini
cargo run -p vpn-agent -- --tcp 127.0.0.1:4502 status
```

The desktop app spawns/stops the native daemon over UAC (`start_daemon` /
`stop_daemon` commands; `daemon.rs`) and otherwise drives it exactly like the
container backend. `charon-svc.exe` + its DLLs ship as bundled app resources
(`tauri.conf.json` -> `charon/`), so a packaged app is self-contained; in dev
they resolve from `out\strongswan-windows`. Run
`scripts\build-strongswan-windows.ps1` before `tauri build` so the artifacts
exist to bundle. Verified against the LANCOM: IKEv2/PSK/modp3072 negotiated,
virtual IP and route installed on a Wintun adapter (libipsec + IP Helper), ESP
data plane live.

#### Running several tunnels at once

Several tunnels can be connected together — IPsec and SSL, in any mix. Only one
of them may be a *full* tunnel, since there is one default route to take; that
is refused up front rather than resolved silently by interface metric.

**Every tunnel needs its own adapter, and this is not cosmetic.** Windows
selects a source address **per interface, not per route**, and uses the strong
host model on send. Put two virtual IPs on one adapter and Windows hands the
first one to every destination; the second tunnel's packets then match none of
its own policies, libipsec drops them, and the tunnel sits there reporting
established while carrying nothing. So:

- SSL gets one `openvpn` process and one adapter per slot (`OpenVPN Data
  Channel`, ` 2`, ` 3`, …).
- IPsec gets one Wintun adapter per virtual IP, via
  `0003-per-tunnel-wintun-adapter.patch`. `kernel_libipsec_router` keys its TUN
  devices by virtual IP and names the route interface from that, so a tunnel's
  routes follow its address onto its own adapter.

`kernel-libipsec` still creates one device for itself at startup, which takes
the `strongSwan` name and stays idle; tunnels get `strongSwan 2`, `strongSwan
3`, and so on. The ceiling is 8 concurrent IPsec tunnels
(`WINTUN_MAX_ADAPTERS`).

If a tunnel is ever up and reachable only with `ping -S <its virtual IP>`, this
is what regressed: check that its routes and its address are on the *same*
adapter (`Get-NetRoute -InterfaceAlias 'strongSwan*'`).

If the app icons are ever regenerated: `powershell.exe -File scripts\gen-icons.ps1`.

### Native macOS tunnel (no container)

Like Windows, the tunnel terminates on the Mac itself and the app bundles its
own strongSwan. The datapath is the same shape — ESP in userland
(`kernel-libipsec`) over a virtual adapter — but almost nothing else is, and
none of the Windows workarounds carry over:

* **utun is in the kernel.** strongSwan's `tun_device` drives it directly and
  opens a fresh one per instance, so all three Wintun patches the Windows
  cross-build carries (a TUN plugin, one adapter per tunnel, virtual IPs on
  `kernel-iph`) have no counterpart here. `kernel-pfroute` installs addresses
  and routes.
* **The build is native.** No Docker, no MinGW — just Xcode Command Line Tools.
* **`kernel-pfkey` is deliberately not built**, for the same reason
  `kernel-wfp` isn't on Windows: its UDP-encapsulated ESP support in tunnel
  mode is incomplete, and behind NAT that encapsulation is not optional.

**arm64 only.** macOS builds are not universal and Intel Macs are not a target.
Both build scripts take an `ARCH` override, and each verifies every staged
Mach-O is the architecture it claims, so revisiting this is one variable and a
`lipo -create` pass — not a rewrite.

```bash
# 1. Build the daemons into out/ (OpenSSL is pinned and built from source;
#    pass OPENSSL_PREFIX to reuse one instead of building it twice).
./scripts/build-strongswan-macos.sh
OPENSSL_PREFIX="$PWD/build/strongswan-macos/arm64/prefix" \
  ./scripts/build-openvpn-macos.sh          # SSL VPN datapath (optional)

# 2. Install the privileged helper. One authorization prompt, once — after
#    this, connect and disconnect never prompt again.
cargo build --release -p vpn-broker
sudo ./target/release/vpn-broker install    # reports the datapaths it installed
./target/release/vpn-broker status          # installed: true / reachable: true

# 3. Run the app. It starts charon through the helper on the first connect.
#    (cargo tauri must run in the crate; the bundle lands in the workspace target/)
(cd crates/vpn-desktop && cargo tauri build --bundles app)
open "target/release/bundle/macos/VPN Client.app"
```

The app sets the helper up on **first launch** — one authorization prompt, once
— so it is the default rather than something to discover, the way the Windows
installer registers the broker service. Declining is remembered; the strip under
the titlebar and the sidebar row offer it again whenever you want. Once
installed, launchd loads it at boot and it starts charon with it, so the backend
is simply always running in the background.

Without the helper everything still works, but each connect and disconnect
raises an authorization prompt — charon needs root for utun, the virtual IP and
routes, and so does `/etc/resolver`. To drive it by hand instead:

```bash
sudo scripts/run-charon-macos.sh            # foreground; --stop to signal one

# ...and from another shell (sudo too — the vici socket is root-owned):
cargo build -p vpn-agent
sudo ./target/debug/vpn-agent --socket /var/run/ipsec-vpn/charon.vici status
```

#### Where things live, and why they are not in the app bundle

The helper installs to `/Library/PrivilegedHelperTools`, its launchd plist to
`/Library/LaunchDaemons`, and **copies charon and openvpn** to
`/Library/Application Support/dev.jackolix.ipsecvpn/`. That copy is the point:
launchd runs the helper as root and the helper execs both binaries as root, so
neither may live anywhere an unprivileged user can write — and an app bundle
sitting in `~/Applications` or `~/Downloads` is exactly that.

`sudo ./target/release/vpn-broker uninstall` removes all of it, plus
`/var/run/ipsec-vpn`, `/var/log/ipsec-vpn-helper.log` and any `/etc/resolver`
file a tunnel left behind. It stops charon and our openvpn processes *before*
the launchd bootout, since afterwards nothing is left that can undo their
routes and utun devices.

#### Uninstalling

Dragging the bundle to the Trash is macOS' uninstall, and here it is not
enough: the LaunchDaemon, the root-owned charon and openvpn, and any
`/etc/resolver` file survive it and need root to remove. So the app uninstalls
itself — **Uninstall VPN Client** at the bottom of the sidebar (macOS only). It
disconnects, runs the helper's own `uninstall` behind one authorization prompt,
deletes this user's profiles, keychain entries and WebView state, and moves the
bundle to the Trash; then the window reports what happened and quits.

By hand, the same thing is:

```bash
sudo "/Library/PrivilegedHelperTools/dev.jackolix.ipsecvpn.helper" uninstall
rm -rf ~/.config/ipsec-vpn \
       ~/Library/{Caches,WebKit,HTTPStorages}/dev.jackolix.ipsecvpn \
       "~/Library/Saved Application State/dev.jackolix.ipsecvpn.savedState"
security delete-generic-password -s dev.jackolix.ipsecvpn   # once per profile
rm -rf "/Applications/VPN Client.app"
```

#### Who may drive the daemon

charon `chown`s its vici socket to its own configured gid immediately after
binding, so the group of the containing directory does **not** decide this —
`charon.group` in `macos/strongswan.conf` does. It is set to `staff`; narrowing
it to `admin` makes the VPN administrators-only, at the cost of standard users
not being able to use the app at all.

The helper's own socket is `0660 root:staff` and refuses uids below 500 via
`LOCAL_PEERCRED`. That identifies the *user*, not the program — proving which
binary is calling needs the peer's code signature, which needs a Developer ID.
Until then the real boundary is the shape of the request surface: `CharonStart`
takes no arguments (so no request can name the binary root executes), DNS
servers are re-parsed and the split-DNS domain re-validated helper-side, and
nothing goes through a shell.

#### DNS

macOS has no single NRPT equivalent, so two mechanisms cover it, chosen from
the tunnel's own remote subnets:

| Tunnel | DNS |
|---|---|
| Names a DNS domain | `/etc/resolver/<domain>` — only that suffix resolves over the tunnel |
| Split tunnel, no domain | **System DNS left alone** |
| Real `0.0.0.0/0` tunnel | Catch-all on the primary service via `networksetup` |

The middle row is a deliberate divergence from Windows. An NRPT rule for `.` is
Windows' only way to say "no namespace", so it has to take the catch-all;
macOS doesn't, and a tunnel carrying one `/24` should not quietly become the
resolver for every name on the machine. Set a DNS domain on the profile (it is
an editable field) to resolve internal names over the tunnel.

#### Gotchas

* **Rebuilding the bundle does not replace a running app.** Closing the window
  hides it to the tray, so the old binary stays alive and reopening from the
  tray gives you the *old* build. Quit it properly first
  (`pkill -f "VPN Client.app"`).
* **Changing helper code needs a reinstall** — `sudo ./target/release/vpn-broker
  install`. The running daemon is the copy under `/Library`, not your build.
* `scripts/diagnose-macos.sh` dumps the routing table, utun addresses, DNS and
  the relevant charon log lines for a live tunnel. `knl = 2` in
  `macos/strongswan.conf` is what makes route installation visible; at level 1
  strongSwan logs it at DBG2 and you see nothing.
* **Cross-check Windows from macOS** whenever shared code changes:
  `cargo check --target x86_64-pc-windows-msvc -p vpn-broker --all-targets`.

### Releases / shipping

Push a `v*` tag and `.github/workflows/release.yml` builds everything and
attaches it to a GitHub Release. Four jobs: the Windows daemon is cross-built
on Linux and handed to a `windows` job; a `macos` job builds its own daemons
natively on Apple Silicon; and a `release` job composes `latest.json` from both
and publishes. The manifest cannot belong to either build job — it names an
artifact from each, and whichever wrote it would clobber the other's entry.

**macOS** ships a `.dmg` plus the `.app.tar.gz` the updater consumes (the `.dmg`
is *not* an update channel). The job re-signs charon, openvpn and the helper
with the Developer ID **before** the bundle is assembled: Tauri signs the `.app`
it builds, but those are plain `resources` copied in carrying only the ad-hoc
signature the build scripts gave them, and notarisation rejects a bundle whose
nested Mach-O files are not all signed the same way. Secrets:
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`,
plus an App Store Connect API key for notarising: `APPLE_API_ISSUER`,
`APPLE_API_KEY` (the Key ID) and `APPLE_API_KEY_P8` (the `.p8`, base64-encoded).

Signing and notarising need different credentials because they are different
operations: signing is offline cryptography, while notarising uploads the build
to Apple and is an authenticated API call. An API key is used rather than an
Apple ID and app-specific password because it belongs to the team rather than a
person — revocable on its own, and it does not stop working when someone changes
their password or leaves.

Notarising is also not the last step. The ticket it issues has to be **stapled**
to the app and the dmg, or Gatekeeper has to reach Apple on first launch and an
offline user still sees "cannot be opened" for a perfectly notarised build. The
job staples both and then runs `spctl --assess` — the same verdict a user's Mac
reaches — so a release that would warn users fails in CI instead.

The dmg gets a background image, the icon positions and the Applications drop
link from `bundle.macOS.dmg` in `tauri.macos.conf.json`. Two things about that
are worth knowing before touching it:

* Tauri passes create-dmg `--skip-jenkins` whenever `CI` is set, which skips the
  whole AppleScript that applies *all* of it. A locally built dmg would be
  themed and every released one plain, silently. The build step sets
  `TAURI_BUNDLER_DMG_IGNORE_CI=true` to opt out, and carries a
  `timeout-minutes` because that AppleScript waits for Finder to write a
  `.DS_Store` in a loop with no timeout of its own.
* The background is a **multi-resolution TIFF**, not a PNG. Finder draws it at
  natural pixel size, so a 660x400 PNG is soft on every Retina display;
  `tiffutil -cathidpicheck` packs a 1x and a 2x image into one file and Finder
  picks per display. `scripts/make-dmg-background.sh` regenerates
  `crates/vpn-desktop/dmg/background.tiff` from a CoreGraphics drawing; the
  output is committed, so a release never depends on redrawing it (and cannot
  change because a system font did).

**Windows** gets an **installer** (NSIS `*-setup.exe`
and an MSI) that bundles the app, `charon-svc.exe` + its DLLs (installed to
`<app>\charon\`) **and** the privileged broker (`vpn-broker.exe`), plus the
standalone `vpn-agent.exe` / `vpn-cli.exe`. The NSIS installer registers the
broker as an auto-start LocalSystem service (and removes it on uninstall), so
**connecting never raises a UAC prompt** — the broker starts charon and applies
DNS on the app's behalf over an ACL'd named pipe. (The MSI doesn't run that hook;
MSI users run `vpn-broker install` once by hand.) No TAP/WinTUN driver is
installed — IPsec runs in-kernel via WFP, and the gateway-assigned virtual IP is
placed on an existing interface. The installer is **unsigned** (SmartScreen will
warn) until a code-signing cert is added. DPD/auto-reconnect is on by default
(probe every 30s; charon re-establishes the tunnel after a dead peer or link
flap).

### Updating the app

The desktop app updates itself. Eight seconds after launch it fetches
`latest.json` from the newest GitHub Release, and if that names a newer version
than the running build, a strip appears under the titlebar offering it; the
sidebar also carries the running version and a manual **Check for updates**.
Accepting downloads that release's NSIS installer and runs it — which means an
update replaces *everything* the product ships at once (GUI, broker, charon,
OpenVPN), so the unelevated app and the privileged service it talks to can never
end up on different versions. Two consequences the UI states up front: the
installer's PREINSTALL hook stops the broker, so **a live tunnel drops**, and
the bundle is per-machine, so **Windows raises a UAC prompt**. The app closes
and the installer reopens it.

Trust rests on the signature, not on the transport. `latest.json` carries a
minisign signature for the installer, and the updater verifies it against the
public key pinned in `tauri.conf.json` before executing anything — so whoever
serves the release cannot get code run on a client without the private key.

That private key lives only in the repository's Actions secrets, and the
release build **fails without it** (the bundle sets `createUpdaterArtifacts`):

| secret | value |
| --- | --- |
| `TAURI_SIGNING_PRIVATE_KEY` | the contents of the private key file |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | the key's password; empty if it has none |

A fresh pair comes from `cargo tauri signer generate -w <path>`; the public half
then replaces `plugins.updater.pubkey` in `crates/vpn-desktop/tauri.conf.json`.
Lose the private key and no already-installed client will accept an update
again — they pin the old public key — so every user would have to reinstall by
hand. Back it up.

Clients only reach the updater once they are *on* a build that has it: anyone on
v0.2.2 or earlier installs the next version manually, once.

### Upgrading across the product rename

That one manual install crosses a **product rename**: up to v0.2.2 the app was
called *IPsec VPN Client*. Tauri's NSIS installer keys the Add/Remove entry, the
recorded install directory and its "a previous version is installed" page on the
**product name**, not on the bundle identifier — and v0.2.2 additionally moved
those keys from `HKCU` to `HKLM` by switching from a per-user to a per-machine
install. Left alone, the current installer would not see such an install at all:
it lands in `C:\Program Files\VPN Client` *beside* `C:\Program Files\IPsec VPN
Client`, leaves a second Add/Remove entry, and — the part that actually breaks —
the `ipsec-vpn-broker` service, keyed by service *name* and so untouched by any
of this, keeps running the OLD directory's `vpn-broker.exe` underneath the new
GUI.

The installer migrates instead. Its PREINSTALL hook looks for an install
registered under the old name, in both registry contexts, and runs that
install's own `uninstall.exe /S _?=<dir>` first — silent, and waited on, because
`_?=` is what stops an NSIS uninstaller from relaunching itself out of `%TEMP%`.
App data is left alone (that checkbox defaults to off), so profiles and saved
credentials survive; the old directory, registry keys and shortcuts are then
cleared. Should the old uninstaller fail, its Add/Remove entry is deliberately
kept — it is the only remaining handle for removing that install by hand — and
setup continues.

Registering the broker is idempotent to match: `vpn-broker install` over a
service that already exists now rewrites the service's binary path to the
directory it was run from (stopping the old process first, so the change takes
effect without a reboot). A machine whose old uninstall failed, or an MSI
upgrade — the MSI has no installer hooks — therefore still ends up with the
service pointing at the current install rather than a stale one.

The responder side (test gateway) must accept: IKEv2, PSK, the profile's
identity, IKE `aes256-sha256-prfsha256-modp3072`, ESP `aes256-sha256` with
PFS group 15 (modp3072), and assign a virtual IP.

## Sophos profiles

A Sophos firewall hands out three files, all of them plaintext:

| File | What it is | Status |
|---|---|---|
| `.scx` | Sophos Connect. JSON; since Sophos Connect is itself built on strongSwan it is close to a serialised swanctl connection, proposals and all. | Imports. |
| `.tgb` | Legacy Cyberoam/TheGreenBow client profile. Ini-shaped, IKEv1. | Imports. |
| `.pro` | Provisioning pointer: names a user portal to sign in to, from which the real `.scx` is downloaded. | Recognised, and the app says which portal. Fetching the profile is **not** implemented — it needs an authenticated HTTPS session against the customer's portal. |

**A Sophos tunnel has been carried end to end.** Against a real SFOS gateway
(with its owner's authorization), a `.tgb` profile imported, authenticated
with XAuth, took a mode-config virtual IP, established a CHILD_SA and passed
bidirectional traffic into the remote LAN. What that run settled:

- **The gateway wanted IKEv1 + XAuth, not IKEv2.** Its `.scx` describes IKEv2
  and every IKEv2 proposal we offered — five different algorithm sets — came
  back `NO_PROPOSAL_CHOSEN`, which is what a strongSwan responder says when
  no connection policy matches at all, version included. The `.tgb` from the
  same firewall negotiated first time.
- **`Xauth = 0` in a `.tgb` cannot be trusted.** That gateway advertises the
  XAuth vendor ID and rejects phase 1 with `AUTHENTICATION_FAILED` unless
  XAuth is actually offered — so the IKE version and the user-auth round are
  both editable in the UI, and the `.tgb` importer warns when it sees
  `Xauth = 0`.
- **A `.tgb` must request a mode-config address.** Without it the gateway
  answers quick mode with `INVALID_ID_INFORMATION`, because the client
  proposes its own LAN address as the phase 2 selector instead of the one the
  gateway assigned.

- **A profile's own proposal cannot be trusted.** The SFOS 21.0 gateway
  states `aes256-sha2_256-modp2048` in its `.scx` and accepts only SHA2-512;
  the mismatch surfaces as a bare `NO_PROPOSAL_CHOSEN` that names nothing, and
  it took a twelve-combination sweep to find what it wanted. Connections now
  offer the profile's proposal first and then stronger variants of it, so the
  gateway picks — that unmodified profile negotiates on its own. The
  alternatives only ever raise the hash and the DH group and never touch the
  cipher, so this cannot be used to negotiate anything weaker than the profile
  asked for.
- **Every remote subnet needs its own CHILD_SA under IKEv1.** Quick mode
  negotiates one traffic-selector pair per SA, so a child offering three
  subnets is narrowed by the gateway to the first and the rest are silently
  unreachable. The bridge now emits one child per subnet (`<conn>-1`,
  `<conn>-2`, …) and initiates each; verified with three subnets up at once on
  one virtual IP, two of them passing traffic. IKEv2 carries all selectors in
  a single CHILD_SA and is left alone.

Remaining gaps for that path:

- **Gateway-assigned DNS is dropped.** charon logs `handling INTERNAL_IP4_DNS
  attribute failed` — the servers arrive over mode config, but the DNS path
  only applies servers named in the profile.
- **The exported gateway address is the internal one**, every time; it has to
  be replaced with the public address before the profile will connect from
  outside. The importer warns and the field is editable.

Before the first connect on any machine, two things still need checking:

- **The daemon needs the plugins, so it must be rebuilt and re-shipped.**
  `docker/strongswan-windows/Dockerfile` builds charon with
  `--disable-defaults`, so it could do IKEv2 and nothing else.
  `--enable-ikev1`, `--enable-xauth-generic` and `--enable-eap-mschapv2`
  (plus the built-in md4/des, which OpenSSL 3 has moved to its legacy
  provider) are now in the list. The cross-build succeeds and the plugins are
  in the result — `ikev1`, `xauth-generic` and `eap-mschapv2` all appear in
  the new `libcharon-0.dll` and in none of the old one — but **the currently
  shipped `charon-svc.exe` predates this**, and until it is replaced a `.tgb`
  or any user-auth profile fails at negotiation.
- **XAuth under IKEv1 is confirmed; EAP under IKEv2 is not.** The IKEv1 half
  authenticated against a real gateway. On a second, newer gateway (SFOS
  21.0) the IKEv2 IKE_SA_INIT succeeds but IKE_AUTH is refused with
  `AUTHENTICATION_FAILED` — with the profile's PSK, with no identity, with
  the username as an RFC822 or FQDN identity, and with EAP-only client auth
  (a well-formed `IDi` and no `AUTH` payload). The gateway rejects before the
  username is ever exchanged, so this is its policy or a stale key rather
  than the client's config. `eap-mschapv2` therefore remains the unverified
  guess for what carries the round, and such profiles import with a warning.

**The two gateways want opposite IKE versions**, which is why the version is
an editable field. The SFOS 18.5 firewall carries a tunnel over IKEv1 and
answers IKEv2 with `NO_PROPOSAL_CHOSEN`; the SFOS 21.0 one never answers
IKEv1 at all (six retransmits, nothing back) and negotiates IKEv2 happily.
So the firmware generation decides, and neither export says which.

Collecting those credentials *is* wired up. A profile whose gateway wants a
login prompts for one on connect (`login-overlay` in the UI), and the
username and password go to charon as a `load-shared` of type `XAUTH`/`EAP`
with its own credential id, never through `ConnectionConfig` and never into
the profile file. "Remember" puts both in the OS keychain under a
`<id>#userauth` entry, separate from the PSK entry, so forgetting one leaves
the other; deleting a profile removes both. A gateway that says its
credentials may not be saved — or that expects a one-time code — is not
offered the checkbox, and the backend refuses to store them even if asked.
Without a password, a connect is refused before any socket is opened rather
than failing deep in the exchange.

Drive it headlessly with
`vpn-desktop --dev connect <id> <user> <password> [save]`,
`--dev set-user-login <id> <user> <password>`, `--dev needs-user-login <id>`
and `--dev forget-user-login <id>`; `vpn-agent connect --username U` prompts
for the password without echoing it.

Two things the real exports taught us, both encoded in the importers. The
identity these profiles tell the client to present is the *gateway's own
public address* — the `.scx` and the `.tgb` state it independently and agree.
And a `.tgb` is generated against whichever interface the admin exported it
from, so its gateway may be a private address that will never answer from
outside; the import warns rather than leaving the user with a connection that
only times out.

## Importing from the web (`itmvpn://` links)

The config-download website can hand a profile straight to the client instead of
leaving a file in `Downloads`. The installer registers the `itmvpn://` scheme;
a link carries the profile inside it, base64url-encoded:

```
itmvpn://import?data=<base64url>&ext=<ini|scx|tgb|mobileconfig|ovpn|pro>&name=<display name>
```

`ext` and `name` are optional (`ini` and the profile's own name). Formats are
still dispatched on content, so `ext` only decides what the file is called on
disk. A `.pro` in the link opens the portal sign-in rather than importing
anything. The full contract the website is built against — encoding, sizes, the
button, what it cannot detect — is in
[`docs/website-deeplink-integration.md`](docs/website-deeplink-integration.md).

**Nothing a link brings reaches disk on its own.** Any page can open an
`itmvpn://` link, so the payload is decoded and parsed in memory
(`backend::stage_link_import`) and held there until the user confirms a dialog
naming the gateway, the networks and what happens to a profile already installed
under that name. The confirmation carries a token identifying the staging, so a
second link arriving while the dialog is open cannot slip its own profile past a
confirmation meant for another. The client never connects on its own.

Only the inline form is implemented. A `url=` form — the client downloading from
a short-lived one-time link, which keeps a profile's pre-shared key off the
Windows command line, where EDR agents and event 4688 record it — is specified
in the same document and is the intended next step.

Drive the whole path headlessly, without a window or the browser:

```powershell
# Stage a link and print what the confirmation dialog would show:
$d = [Convert]::ToBase64String([IO.File]::ReadAllBytes("ITM-TEST01.ini")).Replace('+','-').Replace('/','_').TrimEnd('=')
cargo run -p vpn-desktop -- --dev link "itmvpn://import?data=$d&ext=ini&name=Test"
# …and again with `import` appended to actually land the profile.
```

A dev build is not installed and so owns no scheme. Set `VPN_REGISTER_SCHEME=1`
to have it claim `itmvpn://` for the current user at startup — deliberately
opt-in, because that registration lives in the user hive and *shadows* an
installed client's. Undo it by deleting `HKCU\Software\Classes\itmvpn`.

## Code-mapping caveat

The NCP format is proprietary; every numeric-code interpretation in
`crates/ncp-profile/src/codes.rs` is documented with a confidence level and
surfaces as an import warning until confirmed against a real NCP client or
gateway. Unknown codes for anything security-relevant are a hard import
error — the importer never guesses silently. The Sophos formats are
undocumented too and follow the same rule.
