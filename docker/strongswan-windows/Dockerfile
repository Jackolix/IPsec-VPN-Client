# Cross-compile strongSwan's native Windows daemon (charon-svc.exe) with the
# Windows Filtering Platform (kernel-wfp) and IP Helper (kernel-iph) plugins,
# so the IPsec tunnel terminates on the Windows host itself — no container,
# no WSL. The build runs on Linux via the MinGW-w64 toolchain; the output is
# a directory of Windows .exe/.dll artifacts exported to the host.
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
ENV PREFIX=/opt/win

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 mingw-w64-tools \
        build-essential wget ca-certificates perl pkg-config file bzip2 xz-utils \
        patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# ---- OpenSSL (MinGW cross build; shared libs, no asm to avoid nasm dep) ----
RUN wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" \
    && tar xf "openssl-${OPENSSL_VER}.tar.gz"
RUN cd "openssl-${OPENSSL_VER}" \
    && ./Configure mingw64 shared no-asm no-tests \
        --prefix="${PREFIX}" --libdir=lib --cross-compile-prefix="${MINGW}-" \
    && make -j"$(nproc)" \
    && make install_sw

# ---- strongSwan (native Windows daemon) ----
RUN wget -q "https://download.strongswan.org/strongswan-${STRONGSWAN_VER}.tar.bz2" \
    && tar xf "strongswan-${STRONGSWAN_VER}.tar.bz2"

# Teach kernel-iph to install virtual IPs. Upstream ships add_ip/del_ip as
# NOT_SUPPORTED stubs, which makes the Windows port unusable as a road-warrior
# client: the gateway assigns a virtual IP, charon fails to install it, discards
# it, and the peer then rejects the traffic selectors. See the patch header.
COPY docker/strongswan-windows/0001-kernel-iph-install-virtual-ips.patch /src/
RUN cd "strongswan-${STRONGSWAN_VER}" \
    && patch -p1 --fuzz=0 < /src/0001-kernel-iph-install-virtual-ips.patch

RUN cd "strongswan-${STRONGSWAN_VER}" \
    && ./configure --host="${MINGW}" --prefix="${PREFIX}" \
        --disable-defaults \
        --enable-monolithic \
        --enable-svc \
        --enable-ikev2 \
        --enable-socket-win --enable-kernel-wfp --enable-kernel-iph --enable-winhttp \
        --enable-openssl \
        --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-pubkey --enable-x509 \
        --enable-constraints --enable-revocation \
        --enable-nonce --enable-hmac --enable-kdf \
        --enable-vici --enable-updown \
        openssl_CFLAGS="-I${PREFIX}/include" \
        openssl_LIBS="-L${PREFIX}/lib -lssl -lcrypto" \
        CFLAGS="-I${PREFIX}/include -O2" \
        LDFLAGS="-L${PREFIX}/lib" \
    # Drop the standalone libvici.la client library from the build: MinGW
    # libtool refuses to link it as a DLL (its Makefile has no -no-undefined),
    # and we don't need it — the vici *plugin* is compiled into charon under
    # --enable-monolithic, and our own Rust client speaks vici over TCP. Only
    # this one Makefile's ipseclib target references libvici; the core
    # libstrongswan.la / libcharon.la install via their own Makefiles.
    && sed -i 's|^\(ipseclib_LTLIBRARIES *=\).*|\1|' src/libcharon/plugins/vici/Makefile \
    && make -j"$(nproc)" \
    && make install

# ---- collect a FLAT, self-contained dist tree ----
# charon-svc.exe uses same-directory DLL loading on Windows, but `make install`
# scatters its DLLs across bin/ (charon-svc, libcrypto, libssl) and lib/bin/
# (libcharon-0, libstrongswan-0). Put charon-svc.exe and every DLL it needs at
# load time into ONE directory so it runs without a PATH dance.
RUN mkdir -p /dist \
    && cp "${PREFIX}/bin/charon-svc.exe" /dist/ \
    # core strongSwan DLLs (libtool installs these under lib/bin)
    && find "${PREFIX}" -name 'libcharon-*.dll' -o -name 'libstrongswan-*.dll' \
         | xargs -r -I{} cp {} /dist/ \
    # OpenSSL runtime DLLs
    && cp "${PREFIX}"/bin/libcrypto-*.dll "${PREFIX}"/bin/libssl-*.dll /dist/ \
    # MinGW C/pthread runtime DLLs charon-svc.exe links against
    && for dll in libgcc_s_seh-1.dll libwinpthread-1.dll libstdc++-6.dll; do \
         find /usr/lib/gcc/${MINGW} /usr/${MINGW} -name "$dll" -exec cp {} /dist/ \; 2>/dev/null || true; \
       done \
    && ls -1 /dist
