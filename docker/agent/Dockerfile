# Phase 1 image: compiles vpn-agent for Linux (musl static) and runs it
# alongside charon. The agent drives charon over the vici socket; no profile
# or secret is baked in — the profile is bind-mounted at runtime.
#
# Build context is the repo root (so the whole workspace is available):
#   docker build -f docker/agent/Dockerfile -t vpn-agent .

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release -p vpn-agent

FROM alpine:3.20
RUN apk add --no-cache strongswan
COPY --from=build /src/target/release/vpn-agent /usr/local/bin/vpn-agent
COPY docker/agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
