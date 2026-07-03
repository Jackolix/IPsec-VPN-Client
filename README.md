# cross-platform-vpn

Desktop IPsec (IKEv2) VPN client wrapping strongSwan. Imports NCP-style
`.ini` profiles. See `ipsec-vpn-client-plan.md` for the full build plan;
this repo is at **Phase 1** — a Rust agent drives charon over the vici
control protocol (connect / status / disconnect), verified end-to-end
against a LANCOM vRouter.

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
| `crates/vici` | Hand-rolled client for strongSwan's vici control protocol: a cross-platform message codec plus packet framing and a blocking request/event client (Unix-socket transport). |
| `crates/vpn-agent` | Phase 1 Linux agent: imports a profile and drives charon over vici (`connect` / `status` / `disconnect`). The PSK is pushed via `load-shared` in memory — no swanctl.conf with the secret is written to disk. |
| `crates/vpn-cli` | Phase 0 CLI: `show` (redacted interpretation) and `generate` (writes swanctl.conf). Kept for inspection/debugging. |
| `docker/agent` | Multi-stage image: compiles `vpn-agent` for Linux and runs it beside charon — the "Linux client" while developing on Windows. |
| `docker/initiator` | Legacy Phase 0 container that shells out to `swanctl`; superseded by `docker/agent`. |

## Phase 1 quickstart

```powershell
# Inspect how a profile is interpreted (secret stays redacted):
cargo run -p vpn-cli -- show .\TEST-1.ini

# Build the agent image and bring up the tunnel over vici (needs Docker Desktop):
.\scripts\connect-docker.ps1 -Profile .\TEST-1.ini -Gateway 192.168.100.10

# While it runs, from another shell:
docker exec vpn-agent vpn-agent status
docker exec vpn-agent vpn-agent disconnect --name vRouter-TEST-1

# Tests (run on any platform; the vici codec is cross-platform):
cargo test --workspace
```

The responder side (test gateway) must accept: IKEv2, PSK, the profile's
identity, IKE `aes256-sha256-prfsha256-modp3072`, ESP `aes256-sha256` with
PFS group 15 (modp3072), and assign a virtual IP.

## Code-mapping caveat

The NCP format is proprietary; every numeric-code interpretation in
`crates/ncp-profile/src/codes.rs` is documented with a confidence level and
surfaces as an import warning until confirmed against a real NCP client or
gateway. Unknown codes for anything security-relevant are a hard import
error — the importer never guesses silently.
