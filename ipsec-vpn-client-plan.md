# Cross-Platform IPsec VPN Desktop Client — Build Plan

## 0. Goal

Build a desktop VPN client (Windows, macOS, Linux) that:
1. Imports NCP-style `.ini` VPN profiles (like the sample `ACME_SITE_01.ini`) and converts them into a working connection config.
2. Establishes an IKEv2/IPsec tunnel to the specified gateway using PSK auth.
3. Provides a minimal GUI: profile list, connect/disconnect, status, logs.

We are **not** writing an IKE/ESP stack from scratch. We wrap a proven backend (strongSwan) and drive it per-platform.

## 1. Source format: NCP Secure Entry/Enterprise Client `.ini` profile

Proprietary export format, no public schema. Field meanings are inferred and
tracked with explicit confidence levels in `crates/ncp-profile/src/codes.rs`
(the authoritative, code-level version of the original mapping table).
Unconfirmed mappings surface as import warnings; unknown security-relevant
codes are hard errors. Observations from the sample profile:

- Policy names (`WIZ-AES256-SHA256`) corroborate the algorithm codes.
- DH-group codes (15) match IANA group numbers directly.
- `Ikev2PRF=5` / `Ikev2IntAlgo=12` match IANA IKEv2 transform IDs for SHA-256.
- `IpsecAuth` uses a *different* code space than `Ikev2IntAlgo`.

## 2. Architecture

One internal config model (`vpn-core`), decoupled from the NCP ini format;
the ini parser (`ncp-profile`) is just one importer. GUI (Tauri, later) →
core service (Rust) → per-platform adapter (strongSwan/vici on Linux,
NEVPNManager or embedded strongSwan on macOS, RAS API or strongSwan on
Windows).

## 3. Phases

- **Phase 0 (current)**: ini parser → config model → swanctl.conf; tunnel
  from a strongSwan Docker container against the local test firewall
  (192.168.100.10). Exit criteria: CLI generates the config and the container
  establishes IKE + CHILD SAs.
- **Phase 1 (done 2026-07-03)**: hand-rolled `vici` crate (message codec +
  packet framing + blocking request/event client) and a `vpn-agent` that
  imports a profile and drives charon over vici with
  `connect`/`status`/`disconnect`. Verified against the LANCOM: SA up,
  virtual IP assigned, ESP counters move, clean teardown. The PSK is pushed
  via `load-shared` in memory — no swanctl.conf secret on disk.
  **Still open for Phase 1.5**: move PSK storage to the OS keychain (`keyring`
  crate) on the real desktop OS; auto-reconnect/DPD config. (Live handshake
  progress via the `log` event landed in Phase 2.)
- **Phase 2 (done 2026-07-03)**: Tauri v2 desktop app (`crates/vpn-desktop`).
  Rust backend interprets profiles natively (works on Windows) and drives
  charon via the shared `vpn-control` crate; the web UI drives it through
  `invoke`. Profile list, connect/disconnect, live status tiles + throughput
  sparkline, import-trust warnings, charon log console. Verified: the desktop
  backend brings up and reports the LANCOM tunnel from a native Windows build
  over a TCP vici socket (`docker/vici-tcp`, published on 127.0.0.1:45022).
  **Live handshake log done**: connect registers for charon's `log` event
  around `initiate` and returns the captured transcript (`vpn-control`'s
  `connect_logged` → `ConnectOutcome`), so the GUI console shows the real
  `IKE_SA_INIT` / auth / `CHILD_SA` lines (and the failure reason on a
  declined handshake) instead of canned text; the CLI prints them too.
  **Phase 2.5 done 2026-07-03**: gateway-override dialog (locked/production
  profiles prompt for a lab responder IP before connecting; the production
  gateway is never contacted) and PSK storage in the OS keychain (Windows
  Credential Manager / macOS Keychain / Secret Service via the `keyring`
  crate, in `vpn-desktop/src/creds.rs`). A saved PSK takes precedence over
  the plaintext `.ini` on connect. Verified live: a wrong keychain PSK makes
  auth fail (proving the keychain key is used), forgetting it falls back to
  the `.ini` and the tunnel comes up; a locked profile connects only via an
  explicit override and the production FQDN never reaches the log. Headless
  `vpn-desktop --dev <connect|disconnect|save-creds|forget-creds|set-creds>`
  drives the same backend path for verification.
  Still open: strongSwan on the eventual Linux/macOS desktop needs the
  matching `keyring` backend at runtime (Secret Service daemon on Linux).
- **Phase 3**: macOS — start with `NEVPNProtocolIKEv2`; fall back to embedded
  strongSwan Network Extension only on cipher/feature gaps. Apple Developer
  account + Network Extension entitlement lead time.
- **Phase 4 (native daemon done 2026-07-04)**: Windows — native RAS was ruled
  out empirically (its IKEv2 client can't do DH group 15 / modp3072 or IKEv2
  PSK), so we bundle strongSwan. `docker/strongswan-windows/Dockerfile`
  cross-builds the native `charon-svc.exe` (kernel-wfp + kernel-iph +
  socket-win + vici, `--enable-monolithic`, OpenSSL) via MinGW-w64;
  `scripts/build-strongswan-windows.ps1` exports a flat artifact tree to
  `out/strongswan-windows`. `scripts/run-charon-windows.ps1` launches it
  elevated (WFP needs Administrator) with vici on `127.0.0.1:4502`; the
  existing `Transport::Tcp` path drives it unchanged. Verified live against the
  LANCOM: IKEv2/PSK/modp3072 negotiated, virtual IP + route installed on a host
  adapter via WFP/IP-Helper (not a container), ESP data plane moved (out
  counter). The Tauri app now spawns/stops charon-svc itself over UAC
  (`vpn-desktop/src/daemon.rs` + `start_daemon`/`stop_daemon` commands; the
  sidebar Start/Stop button and a connect auto-start the backend), driving it
  over loopback vici while the GUI stays unelevated; `run-desktop-native.ps1`
  launches the app in native mode. `charon-svc.exe` + its DLLs ship as bundled
  app resources (`tauri.conf.json` `bundle.resources` -> `charon/`), so the app
  elevates the bundled `charon-svc.exe` directly (no config file needed - it
  runs on defaults) and is self-contained; `daemon.rs` resolves it from the
  bundle next to the exe, falling back to `out/strongswan-windows` for dev.
  Build the daemon (`build-strongswan-windows.ps1`) before `tauri build`.
- **DPD / auto-reconnect (done 2026-07-04)**: `vpn-core::DpdConfig` (default:
  probe every 30s, auto-reconnect on) rides on `ConnectionConfig`; the vici
  bridge emits `dpd_delay` on the IKE_SA and `dpd_action`/`close_action =
  restart` on the CHILD_SA, so charon re-establishes the tunnel by itself after
  a dead peer, reboot or link flap. Verified live vs the LANCOM: blocking the
  gateway dropped the SA at ~t+36s (DPD), and unblocking it reconnected within
  seconds with no app involvement.
- Release automation: `.github/workflows/release.yml` builds everything on a
  `v*` tag — a Linux job cross-builds charon-svc (Docker/MinGW) and a Windows
  job bundles it into the Tauri installer and publishes the installer + CLIs to
  a GitHub Release. Still open: a *signed* installer (avoids SmartScreen).
- **Phase 5**: hardening — DPD/reconnect, network roaming, split vs full
  tunnel, log redaction layer, auto-update, signing/notarization, interop
  matrix.

## 4. Tech stack

Rust core (confirmed 2026-07-02) · strongSwan via vici · Tauri GUI ·
OS keychain via `keyring` crate.

## 5. Testing

- Test responder: local firewall at **192.168.100.10** (user-owned,
  authorized). Configure it to match: IKEv2, PSK, AES-256/SHA-256/PRF-SHA-256,
  DH group 15 (modp3072), PFS 15, virtual-IP assignment, protected subnet
  10.0.15.0/24.
- Fixture test (`crates/ncp-profile/tests/import_fixture.rs`) pins the
  ini → model → swanctl mapping.
- **Never** test against the profile's production gateway
  (`gateway.example.test`) without explicit authorization; the
  tooling requires `--gateway-override` to make the target an explicit choice.

## 6. Security invariants

- `*.ini` and generated `*.swanctl.conf` are gitignored; the PSK is never
  logged (the `Secret` type redacts Debug/Display) and never committed.
- The sample PSK was exposed in a conversation — rotate it before real use.
- ini parser treats input as hostile (size cap, strict grammar, gateway
  charset validation, sanitized swanctl section names).
- Elevated-privilege code paths stay minimal and separately reviewed.

## 7. Open questions

1. ~~Authorized test gateway?~~ → local firewall 192.168.100.10.
2. Distribution model (store vs sideload) — still open; affects Phase 3/4
   signing timeline.
3. Other NCP profile variants (IKEv1, cert auth)? — assumed out of scope
   until a sample shows up.
