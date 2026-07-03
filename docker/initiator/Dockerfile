# strongSwan initiator for Phase 0 testing on a Windows/macOS dev box.
# The generated swanctl.conf (contains the PSK) is bind-mounted at runtime,
# never baked into the image.
FROM alpine:3.20

RUN apk add --no-cache strongswan

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
