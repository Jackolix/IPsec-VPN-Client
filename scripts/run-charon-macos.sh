#!/usr/bin/env bash
# Launch the native macOS strongSwan daemon in the foreground, the way the
# desktop app launches it behind the authorization prompt.
#
# charon needs root: it opens a utun device, installs the virtual IP and adds
# routes. Run this with sudo in one terminal and drive it from another with
# vpn-agent (also under sudo — the vici socket is root-owned):
#
#     sudo scripts/run-charon-macos.sh
#     sudo ./target/debug/vpn-agent --socket /var/run/ipsec-vpn/charon.vici status
#
# This is the counterpart of scripts/run-charon-windows.ps1. It has no
# -Install/-Uninstall: the macOS equivalent is a LaunchDaemon, which belongs
# with the privileged helper rather than here.
#
#   --stop   signal a running daemon instead of starting one

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${VPN_CHARON_DIR:-$REPO_ROOT/out/strongswan-macos}"
# Keep in sync with daemon::NATIVE_VICI_SOCKET and macos/strongswan.conf.
RUN_DIR=/var/run/ipsec-vpn
SOCKET="$RUN_DIR/charon.vici"

if [ "${1:-}" = "--stop" ]; then
    [ "$(id -u)" = "0" ] || { echo "error: --stop needs root (sudo)" >&2; exit 1; }
    pid="$(/usr/sbin/lsof -t "$SOCKET" 2>/dev/null | head -1 || true)"
    if [ -z "$pid" ]; then
        echo "nothing is holding $SOCKET"
        exit 0
    fi
    # SIGTERM, so charon tears down its SAs, routes and utun on the way out.
    echo "stopping charon (pid $pid)"
    kill -TERM "$pid"
    exit 0
fi

if [ "$(id -u)" != "0" ]; then
    echo "error: charon needs root — re-run as: sudo $0" >&2
    exit 1
fi

CHARON="$DIST/charon"
CONF="$DIST/etc/strongswan.conf"
for f in "$CHARON" "$CONF"; do
    [ -f "$f" ] || {
        echo "error: $f not found — build it first with scripts/build-strongswan-macos.sh" >&2
        exit 1
    }
done

# charon does not create this itself and would fail to bind the vici socket. It
# also holds the resolve plugin's captured DNS and charon.log.
#
# The group here only controls who may TRAVERSE the directory to reach the
# socket and read the resolve plugin's captured DNS. It does NOT decide who may
# drive charon: charon chown()s its vici socket to its own configured gid right
# after binding, overriding the group a new file would otherwise inherit from
# its directory. That is set by `charon.group` in strongswan.conf — see the
# comment there.
mkdir -p "$RUN_DIR"
chown root:staff "$RUN_DIR"
chmod 750 "$RUN_DIR"

# A stale socket from a daemon that crashed rather than shut down: charon will
# not bind over it, and the app reads an existing-but-refused socket as "not
# running", so clearing it here keeps the two consistent.
if [ -S "$SOCKET" ] && ! /usr/sbin/lsof -t "$SOCKET" >/dev/null 2>&1; then
    echo "removing stale $SOCKET"
    rm -f "$SOCKET"
fi

# STRONGSWAN_CONF is mandatory, not a convenience: charon cannot derive the conf
# path once the dist tree is relocated out of its build prefix, and without it
# it comes up on the built-in default vici socket that every other strongSwan
# client also uses — where this app would never look for it.
echo "starting $CHARON"
echo "  conf:   $CONF"
echo "  vici:   $SOCKET"
echo
exec env STRONGSWAN_CONF="$CONF" "$CHARON"
