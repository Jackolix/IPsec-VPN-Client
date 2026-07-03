#!/bin/sh
# Start charon, load the mounted swanctl config, and initiate the tunnel.
# Expects /config/<name>.swanctl.conf mounted read-only.
set -eu

CONF=$(ls /config/*.swanctl.conf 2>/dev/null | head -n1) || true
if [ -z "${CONF:-}" ]; then
    echo "ERROR: no /config/*.swanctl.conf mounted" >&2
    exit 1
fi

mkdir -p /etc/swanctl
cp "$CONF" /etc/swanctl/swanctl.conf

/usr/lib/strongswan/charon &
CHARON_PID=$!

# Wait for the vici socket.
for _ in $(seq 1 50); do
    [ -S /var/run/charon.vici ] && break
    sleep 0.2
done
if [ ! -S /var/run/charon.vici ]; then
    echo "ERROR: charon did not come up" >&2
    exit 1
fi

swanctl --load-all

# vpn-cli names the file after the (sanitized) connection name.
CONN=$(basename "$CONF" .swanctl.conf)
echo "Initiating connection: $CONN"
swanctl --initiate --child "$CONN" || {
    echo "Initiation failed; charon log follows (Ctrl-C to stop)." >&2
}

echo "--- SAs ---"
swanctl --list-sas

# Keep the container alive for inspection (docker exec ... swanctl --list-sas).
wait $CHARON_PID
