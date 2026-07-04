# cross-platform-vpn

Desktop IPsec (IKEv2) VPN client wrapping strongSwan. Imports NCP-style
`.ini` profiles. See `ipsec-vpn-client-plan.md` for the full build plan;
this repo is at **Phase 2** — a Tauri desktop app whose Rust backend parses
profiles natively and drives charon over the vici control protocol
(connect / status / disconnect). Verified end-to-end against a LANCOM
vRouter, including from a native Windows build over a TCP vici socket.

## Security rules (read first)

- NCP `.ini` profile exports contain a **live pre-shared key in plaintext**.
  `*.ini` is gitignored; never commit one, never log the `Secret` value.
  The only exception is the redacted test fixture
  (`crates/ncp-profile/tests/fixtures/*.redacted.ini`).
- Generated `*.swanctl.conf` files (in `out/`) contain the PSK too and are
  gitignored as well.
- Never connect to a profile's production gateway without authorization.
  The tooling forces an explicit `--gateway-override` / `-Gateway` choice.

## Layout

| Crate | Purpose |
|---|---|
| `crates/vpn-core` | Internal config model (importer-independent) + `swanctl.conf` rendering. `Secret` type redacts itself in all Debug/Display output. |
| `crates/ncp-profile` | NCP ini parser + the documented numeric code tables (`src/codes.rs`, each mapping carries a confidence level) + importer that warns on every unconfirmed mapping. |
| `crates/vici` | Hand-rolled client for strongSwan's vici control protocol: a cross-platform message codec plus packet framing and a blocking request/event client (Unix and TCP transports). |
| `crates/vpn-control` | Shared connection logic used by both the CLI and the GUI: the config→vici bridge, `list-sa` status parsing, and the connect/status/disconnect flows over a `Transport` (Unix socket or TCP). `connect_logged` registers for charon's `log` event around `initiate` and returns the captured handshake transcript. |
| `crates/vpn-desktop` | Tauri desktop app. Rust backend interprets profiles natively and calls `vpn-control`; the web UI (`ui/`) drives it via `invoke`. Gateway-override dialog for locked/production profiles; PSK saved in the OS keychain (`src/creds.rs`, `keyring` crate) takes precedence over the plaintext `.ini`. Run headlessly with `--selftest`; drive the backend flows with `--dev <cmd>`. |
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
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 connect --profile .\TEST-1.ini --gateway-override 192.168.100.10
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 status
cargo run -p vpn-agent -- --tcp 127.0.0.1:45022 disconnect --name vRouter-TEST-1

# Inspect how a profile is interpreted (secret stays redacted):
cargo run -p vpn-cli -- show .\TEST-1.ini

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

# 2. Launch the daemon ELEVATED (WFP needs Administrator). vici on 127.0.0.1:4502:
.\scripts\run-charon-windows.ps1        # accepts -Install / -Uninstall for a service

# 3. Drive it from a normal (non-elevated) shell - loopback vici needs no elevation:
cargo run -p vpn-agent -- --tcp 127.0.0.1:4502 connect --profile .\TEST-1.ini --gateway-override 192.168.100.10
cargo run -p vpn-agent -- --tcp 127.0.0.1:4502 status
```

Verified against the LANCOM: IKEv2/PSK/modp3072 negotiated, virtual IP and
route installed on a host adapter (WFP + IP Helper), ESP data plane live.

If the app icons are ever regenerated: `powershell.exe -File scripts\gen-icons.ps1`.

The responder side (test gateway) must accept: IKEv2, PSK, the profile's
identity, IKE `aes256-sha256-prfsha256-modp3072`, ESP `aes256-sha256` with
PFS group 15 (modp3072), and assign a virtual IP.

## Code-mapping caveat

The NCP format is proprietary; every numeric-code interpretation in
`crates/ncp-profile/src/codes.rs` is documented with a confidence level and
surfaces as an import warning until confirmed against a real NCP client or
gateway. Unknown codes for anything security-relevant are a hard import
error — the importer never guesses silently.
