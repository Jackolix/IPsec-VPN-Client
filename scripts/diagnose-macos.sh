#!/usr/bin/env bash
# Capture the routing/DNS state of a live tunnel, for diagnosing a tunnel that
# carries more or less traffic than its traffic selectors say it should.
# Run it WHILE CONNECTED; no root needed.
set -uo pipefail

echo "===== IPv4 routing table ====="
# A full tunnel shows up either as a default via utun, or — because BSD cannot
# replace the system default directly — as the 0.0.0.0/1 + 128.0.0.0/1 pair
# strongSwan installs instead (kernel_pfroute_net.c manage_route).
netstat -rn -f inet

echo
echo "===== utun interfaces ====="
ifconfig | awk '/^utun/{n=$1} n && /inet |flags=/{print n": "$0}' | sed 's/:.*flags/ flags/'
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
    addr=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2" -> "$4" netmask "$6}')
    [ -n "$addr" ] && echo "$i: $addr"
done

echo
echo "===== DNS ====="
scutil --dns | sed -n '1,20p'
echo "--- /etc/resolver ---"; ls -la /etc/resolver/ 2>&1 | head

echo
echo "===== charon: routes, addresses, traffic selectors ====="
grep -aE 'installing route|installing new virtual IP|TUN device|interface .* activated|TS |exclude route|error' \
    /var/run/ipsec-vpn/charon.log 2>/dev/null | tail -40
