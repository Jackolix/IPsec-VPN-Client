# Cross-compile strongSwan's native Windows daemon (charon-svc.exe), so the IPsec
# tunnel terminates on the Windows host itself — no container, no WSL. The build
# runs on Linux via the MinGW-w64 toolchain; the output is a directory of Windows
# .exe/.dll artifacts exported to the host.
#
# The datapath is ESP in userland over a Wintun adapter. It does NOT use Windows'
# own IPsec engine (kernel-wfp), which drops UDP-encapsulated ESP in tunnel mode
# with STATUS_INTERNAL_ERROR (0xc00000e5) — a limitation strongSwan documents and
# has no workaround for. Behind NAT, UDP encapsulation is not optional, so
# kernel-wfp cannot carry a road-warrior tunnel at all. Userland ESP over a
# virtual adapter is also what every other strongSwan-based Windows client ships
# (Sophos Connect does libipsec + a TAP adapter).
#
#   kernel-libipsec  ESP in userland; the Windows IPsec engine is not involved.
#   wintun           the TUN device (see 0002). The plugin LoadLibrary's
#                    wintun.dll at runtime and that DLL carries its own signed
#                    driver, so there is nothing to install. Wintun is layer 3,
#                    so unlike TAP there is no Ethernet/ARP emulation to write.
#   kernel-iph       the networking backend (addresses + routes), patched to
#                    install virtual IPs — the address lands on the Wintun
#                    adapter, and the routes follow it there.
#
# Crypto comes from OpenSSL (cross-built for MinGW) so we keep the profile's
# exact suite: AES-256-CBC / SHA-256 / PRF-SHA-256 / modp3072 (DH group 15),
# which the Windows built-in IKEv2 client cannot negotiate.
#
# Build + export the artifacts to ./out on the host:
#   docker build -t ss-win -f docker/strongswan-windows/Dockerfile .
#   docker create --name ss-win-x ss-win
#   docker cp ss-win-x:/dist ./out/strongswan-windows
#   docker rm ss-win-x
# (scripts/build-strongswan-windows.ps1 wraps this.)

FROM debian:bookworm AS build

ARG MINGW=x86_64-w64-mingw32
ARG OPENSSL_VER=3.0.16
ARG STRONGSWAN_VER=5.9.14
ARG WINTUN_VER=0.14.1
ENV PREFIX=/opt/win

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 mingw-w64-tools \
        build-essential wget ca-certificates perl pkg-config file bzip2 xz-utils \
        patch unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# ---- OpenSSL (MinGW cross build) ----
RUN wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" \
    && tar xf "openssl-${OPENSSL_VER}.tar.gz"
RUN cd "openssl-${OPENSSL_VER}" \
    && ./Configure mingw64 shared no-asm no-tests \
        --prefix="${PREFIX}" --libdir=lib --cross-compile-prefix="${MINGW}-" \
    && make -j"$(nproc)" \
    && make install_sw

# ---- Wintun: header to build against, DLL to ship ----
# wintun.dll is loaded at runtime by the plugin (LoadLibraryExW), so the header
# is all the build needs; the DLL goes into /dist next to charon-svc.exe.
RUN wget -q "https://www.wintun.net/builds/wintun-${WINTUN_VER}.zip" \
    && unzip -q "wintun-${WINTUN_VER}.zip" \
    && cp wintun/include/wintun.h "${PREFIX}/include/" \
    && mkdir -p /dist && cp wintun/bin/amd64/wintun.dll /dist/

# ---- strongSwan ----
RUN wget -q "https://download.strongswan.org/strongswan-${STRONGSWAN_VER}.tar.bz2" \
    && tar xf "strongswan-${STRONGSWAN_VER}.tar.bz2"

# 0001: kernel-iph can't install virtual IPs upstream (NOT_SUPPORTED stubs).
# 0002: the Wintun TUN device plugin. The plugin scaffolding (a TUN device
#       registry on lib->tun, so a plugin can supply the device) comes from
#       upstream's `wintun` branch; the device itself is ours — upstream's has
#       never been compiled, and its packet I/O is empty stubs returning TRUE.
COPY docker/strongswan-windows/0001-kernel-iph-install-virtual-ips.patch /src/
COPY docker/strongswan-windows/0002-wintun-tun-device-plugin.patch /src/
RUN cd "strongswan-${STRONGSWAN_VER}" \
    && patch -p1 --fuzz=0 < /src/0001-kernel-iph-install-virtual-ips.patch \
    && patch -p1 --fuzz=0 < /src/0002-wintun-tun-device-plugin.patch

# The wintun patch touches configure.ac/Makefile.am, so regenerate the build
# system (the release tarball ships pre-generated ones).
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool gettext \
    && rm -rf /var/lib/apt/lists/*
RUN cd "strongswan-${STRONGSWAN_VER}" && autoreconf -fi

RUN cd "strongswan-${STRONGSWAN_VER}" \
    && ./configure --host="${MINGW}" --prefix="${PREFIX}" \
        --disable-defaults \
        --enable-monolithic \
        --enable-svc \
        --enable-ikev2 \
        --enable-socket-win --enable-kernel-iph --enable-winhttp \
        --enable-libipsec --enable-kernel-libipsec --enable-wintun \
        --enable-openssl \
        --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-pubkey --enable-x509 \
        --enable-constraints --enable-revocation \
        --enable-nonce --enable-hmac --enable-kdf \
        --enable-vici --enable-updown \
        openssl_CFLAGS="-I${PREFIX}/include" \
        openssl_LIBS="-L${PREFIX}/lib -lssl -lcrypto" \
        CFLAGS="-I${PREFIX}/include -O2" \
        LDFLAGS="-L${PREFIX}/lib" \
    && sed -i 's|^\(ipseclib_LTLIBRARIES *=\).*|\1|' src/libcharon/plugins/vici/Makefile \
    && make -j"$(nproc)" \
    && make install

# ---- flat dist tree (charon-svc.exe loads DLLs from its own directory) ----
# NOTE: libipsec-0.dll is new compared to the kernel-wfp build — userland ESP
# lives there, and charon-svc.exe won't start without it.
RUN cp "${PREFIX}/bin/charon-svc.exe" /dist/ \
    && find "${PREFIX}" \( -name 'libcharon-*.dll' -o -name 'libstrongswan-*.dll' \
                           -o -name 'libipsec-*.dll' \) \
         | xargs -r -I{} cp {} /dist/ \
    && cp "${PREFIX}"/bin/libcrypto-*.dll "${PREFIX}"/bin/libssl-*.dll /dist/ \
    && for dll in libgcc_s_seh-1.dll libwinpthread-1.dll libstdc++-6.dll; do \
         find /usr/lib/gcc/${MINGW} /usr/${MINGW} -name "$dll" -exec cp {} /dist/ \; 2>/dev/null || true; \
       done \
    && ls -1 /dist

# strongswan.conf belongs to the dist tree, not just to the local build script:
# charon-svc cannot find it on Windows by itself (STRONGSWAN_CONF points at it),
# and it is what puts vici on our own port. Ship it with the daemon so every
# consumer — the release workflow included — gets it, instead of charon silently
# falling back to its built-in defaults on the shared default port.
COPY docker/strongswan-windows/strongswan.conf /dist/etc/strongswan.conf
