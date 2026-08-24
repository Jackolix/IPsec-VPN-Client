# cross-platform-vpn

Desktop IPsec VPN client wrapping strongSwan. Imports NCP-style `.ini`
profiles and Sophos `.scx` / `.tgb` exports. See
`ipsec-vpn-client-plan.md` for the full build plan;
this repo is at **Phase 2** — a Tauri desktop app whose Rust backend parses
profiles natively and drives charon over the vici control protocol
(connect / status / disconnect). Verified end-to-end against a LANCOM
vRouter, including from a native Windows build over a TCP vici socket.

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
| `crates/vpn-broker` | Privileged LocalSystem Windows **service** that removes the per-connect UAC prompts: it supervises `charon-svc.exe` and applies/reverts the NRPT DNS rule for the unelevated GUI over an ACL'd named pipe (`src/ipc.rs`). The shared `protocol` + a pipe `client` are a thin lib the desktop links against. Registered by the installer; the GUI falls back to the elevated path when it isn't installed. |
| `crates/vpn-agent` | CLI agent over `vpn-control`: imports a profile and drives charon (`connect` / `status` / `disconnect`). The PSK is pushed via `load-shared` in memory — no swanctl.conf with the secret is written to disk. |
| `crates/vpn-cli` | Phase 0 CLI: `show` (redacted interpretation) and `generate` (writes swanctl.conf). Kept for inspection/debugging. |
| `docker/vici-tcp` | Dev backend: charon with its vici socket published on `127.0.0.1:45022` so a host desktop build can drive it. |
| `docker/strongswan-windows` | MinGW cross-build of strongSwan's **native** Windows daemon `charon-svc.exe` (kernel-wfp / kernel-iph / socket-win / vici, monolithic, OpenSSL). The tunnel terminates on the Windows host via the Windows Filtering Platform - no container. Built + exported by `scripts/build-strongswan-windows.ps1`, launched (elevated) by `scripts/run-charon-windows.ps1`; vici on `127.0.0.1:4502`. |
| `docker/agent` | Multi-stage image running `vpn-agent` beside charon (Linux client during development). |
| `docker/initiator` | Legacy Phase 0 container that shells out to `swanctl`. |

## Quickstart

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

The tunnel can terminate on the Windows host itself, via strongSwan's native
`charon-svc.exe` on the Windows Filtering Platform. This is needed because
Windows' built-in IKEv2 client can't negotiate the profile's suite (PSK auth +
DH group 15 / modp3072).

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
virtual IP and route installed on a host adapter (WFP + IP Helper), ESP data
plane live.

If the app icons are ever regenerated: `powershell.exe -File scripts\gen-icons.ps1`.

### Releases / shipping

Push a `v*` tag and `.github/workflows/release.yml` builds everything and
attaches it to a GitHub Release: a Windows **installer** (NSIS `*-setup.exe`
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

## Code-mapping caveat

The NCP format is proprietary; every numeric-code interpretation in
`crates/ncp-profile/src/codes.rs` is documented with a confidence level and
surfaces as an import warning until confirmed against a real NCP client or
gateway. Unknown codes for anything security-relevant are a hard import
error — the importer never guesses silently. The Sophos formats are
undocumented too and follow the same rule.
