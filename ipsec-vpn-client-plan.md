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
  crate) on the real desktop OS; add `control-log` event streaming so
  connect shows live handshake progress; auto-reconnect/DPD config.
- **Phase 2 (done 2026-07-03)**: Tauri v2 desktop app (`crates/vpn-desktop`).
  Rust backend interprets profiles natively (works on Windows) and drives
  charon via the shared `vpn-control` crate; the web UI drives it through
  `invoke`. Profile list, connect/disconnect, live status tiles + throughput
  sparkline, import-trust warnings, charon log console. Verified: the desktop
  backend brings up and reports the LANCOM tunnel from a native Windows build
  over a TCP vici socket (`docker/vici-tcp`, published on 127.0.0.1:45022).
  Still open: `control-log` event streaming for live handshake lines in the
  GUI; a gateway-override dialog for locked/production profiles; keychain.
- **Phase 3**: macOS — start with `NEVPNProtocolIKEv2`; fall back to embedded
  strongSwan Network Extension only on cipher/feature gaps. Apple Developer
  account + Network Extension entitlement lead time.
- **Phase 4**: Windows — try native RAS/`Add-VpnConnection` first, bundle
  strongSwan if the crypto suite isn't supported natively. Plan the UAC UX
  early.
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
