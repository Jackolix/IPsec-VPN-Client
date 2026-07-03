# cross-platform-vpn

Desktop IPsec (IKEv2) VPN client wrapping strongSwan. Imports NCP-style
`.ini` profiles. See `ipsec-vpn-client-plan.md` for the full build plan;
this repo is currently at **Phase 0** (Linux-container proof of concept).

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
| `crates/vpn-cli` | Phase 0 CLI: `show` (redacted interpretation) and `generate` (writes swanctl.conf). |
| `docker/initiator` | Alpine strongSwan container that loads a generated config and initiates the tunnel — the "Linux client" while developing on Windows. |

## Phase 0 quickstart

```powershell
# 1. Inspect how a profile is interpreted (secret stays redacted):
cargo run -p vpn-cli -- show .\ACME_SITE_01.ini

# 2. Bring up a tunnel against the test responder (requires Docker Desktop):
.\scripts\connect-docker.ps1 -Profile .\ACME_SITE_01.ini -Gateway 192.168.100.10

# Tests:
cargo test --workspace
```

The responder side (test firewall) must accept: IKEv2, PSK, identity
`acme_site_01`, IKE `aes256-sha256-prfsha256-modp3072`,
ESP `aes256-sha256` with PFS group 15 (modp3072), and assign a virtual IP.

## Code-mapping caveat

The NCP format is proprietary; every numeric-code interpretation in
`crates/ncp-profile/src/codes.rs` is documented with a confidence level and
surfaces as an import warning until confirmed against a real NCP client or
gateway. Unknown codes for anything security-relevant are a hard import
error — the importer never guesses silently.
