# Dev "VPN backend": strongSwan charon with its vici control socket exposed
# over TCP, so the desktop app on the host can drive it. No profile or secret
# is baked in — the desktop app pushes the connection and PSK over vici.
FROM alpine:3.20

RUN apk add --no-cache strongswan

COPY docker/vici-tcp/strongswan.conf /etc/strongswan.conf
COPY docker/vici-tcp/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 45022
ENTRYPOINT ["/entrypoint.sh"]
