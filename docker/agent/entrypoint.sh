#!/bin/sh
# Start charon, wait for its vici socket, then let vpn-agent import the
# bind-mounted profile and bring up the tunnel. No swanctl.conf / ipsec.secrets
# are written — the connection and PSK are pushed to charon over vici.
set -eu

: "${PROFILE:?bind-mount a profile and set PROFILE=/path/to/profile.ini}"

/usr/lib/strongswan/charon >/tmp/charon.log 2>&1 &

for _ in $(seq 1 50); do
    [ -S /var/run/charon.vici ] && break
    sleep 0.2
done
if [ ! -S /var/run/charon.vici ]; then
    echo "ERROR: charon vici socket did not appear" >&2
    cat /tmp/charon.log >&2
    exit 1
fi

if [ -n "${GATEWAY_OVERRIDE:-}" ]; then
    vpn-agent connect --profile "$PROFILE" --gateway-override "$GATEWAY_OVERRIDE"
else
    vpn-agent connect --profile "$PROFILE"
fi

echo
vpn-agent status

echo
echo "Agent idle. Inspect with: docker exec <container> vpn-agent status"
echo "Disconnect with:          docker exec <container> vpn-agent disconnect --name <name>"
tail -f /dev/null
