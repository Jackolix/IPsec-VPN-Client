#!/usr/bin/env bash
# Build strongSwan's native macOS daemon (charon), so the IPsec tunnel
# terminates on the Mac itself — no container, no VM.
#
# This is the macOS counterpart of docker/strongswan-windows/Dockerfile, but it
# builds NATIVELY: there is no cross-toolchain to stage, and Darwin needs no
# out-of-tree patches at all. The three the Windows build carries exist because
# Windows has no TUN device (0002 adds a Wintun plugin, 0003 gives each tunnel
# its own adapter) and because kernel-iph cannot install virtual IPs (0001).
# Darwin has utun in the kernel, strongSwan's tun_device drives it directly and
# opens a fresh utun per instance, and kernel-pfroute installs virtual IPs
# upstream. So: same datapath, none of the patches.
#
#   kernel-libipsec  ESP in userland; the macOS IPsec engine is not involved.
#   tun_device       utun, built into libstrongswan on Darwin (not a plugin).
#   kernel-pfroute   the networking backend (addresses + routes) via PF_ROUTE.
#   socket-default   IKE UDP on the standard ports.
#
# Crypto comes from OpenSSL, built from source and pinned here rather than taken
# from Homebrew: the dylibs ship inside the app bundle, so they must not depend
# on whatever a build machine happens to have installed. macOS ships only
# LibreSSL headers, which are not a substitute.
#
# Output: a flat, relocatable dist tree in out/strongswan-macos, staged the same
# way as out/strongswan-windows so the Tauri bundler and the app's dev fallback
# can treat the two identically.
#
# Usage:
#   scripts/build-strongswan-macos.sh              # build for the host arch
#   ARCH=x86_64 scripts/build-strongswan-macos.sh  # cross-build (needs Rosetta)
#   CLEAN=1 scripts/build-strongswan-macos.sh      # discard the build tree first
#
# A universal (arm64 + x86_64) bundle is NOT produced here: it needs this whole
# build run once per arch into separate prefixes and then `lipo -create` over
# every Mach-O in the dist tree. Single-arch first — it is what proves the port.

set -euo pipefail

OPENSSL_VER="${OPENSSL_VER:-3.0.16}"
STRONGSWAN_VER="${STRONGSWAN_VER:-5.9.14}"
ARCH="${ARCH:-$(uname -m)}"
# The oldest macOS the bundle claims to support. Keep in sync with
# bundle.macOS.minimumSystemVersion in the Tauri config.
MACOS_MIN="${MACOS_MIN:-11.0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO_ROOT/build/strongswan-macos/$ARCH"
PREFIX="$BUILD/prefix"
DIST="$REPO_ROOT/out/strongswan-macos"
JOBS="$(sysctl -n hw.ncpu)"

if [ "${CLEAN:-0}" = "1" ]; then
    rm -rf "$BUILD"
fi
mkdir -p "$BUILD/src" "$PREFIX"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ---- prerequisites --------------------------------------------------------
for tool in cc make curl tar install_name_tool codesign otool; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool not found (install the Xcode Command Line Tools)" >&2
        exit 1
    }
done

export MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN"
ARCHFLAGS="-arch $ARCH"

# ---- fetch ----------------------------------------------------------------
fetch() { # url, filename
    if [ ! -f "$BUILD/src/$2" ]; then
        say "fetching $2"
        curl -fsSL --retry 3 -o "$BUILD/src/$2.part" "$1"
        mv "$BUILD/src/$2.part" "$BUILD/src/$2"
    fi
}

fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" \
      "openssl-${OPENSSL_VER}.tar.gz"
fetch "https://download.strongswan.org/strongswan-${STRONGSWAN_VER}.tar.bz2" \
      "strongswan-${STRONGSWAN_VER}.tar.bz2"

# ---- OpenSSL --------------------------------------------------------------
if [ ! -f "$PREFIX/lib/libcrypto.dylib" ]; then
    say "building OpenSSL ${OPENSSL_VER} ($ARCH)"
    rm -rf "$BUILD/openssl-${OPENSSL_VER}"
    tar xf "$BUILD/src/openssl-${OPENSSL_VER}.tar.gz" -C "$BUILD"
    case "$ARCH" in
        arm64)  OSSL_TARGET=darwin64-arm64-cc ;;
        x86_64) OSSL_TARGET=darwin64-x86_64-cc ;;
        *) echo "error: unsupported ARCH=$ARCH" >&2; exit 1 ;;
    esac
    (
        cd "$BUILD/openssl-${OPENSSL_VER}"
        ./Configure "$OSSL_TARGET" shared no-tests \
            --prefix="$PREFIX" --libdir=lib
        make -j"$JOBS"
        # install_sw only: no man pages, and nothing outside the prefix.
        make install_sw
    )
else
    say "OpenSSL ${OPENSSL_VER} already built — skipping"
fi

# ---- strongSwan -----------------------------------------------------------
say "building strongSwan ${STRONGSWAN_VER} ($ARCH)"
rm -rf "$BUILD/strongswan-${STRONGSWAN_VER}"
tar xf "$BUILD/src/strongswan-${STRONGSWAN_VER}.tar.bz2" -C "$BUILD"

# `--disable-defaults` means every plugin the daemon needs is listed here, so
# what is missing from this list is a feature the daemon simply cannot do. The
# list mirrors the Windows build's, because it is driven by the same profiles:
# a legacy Sophos .tgb is IKEv1 (main + quick mode), and both Sophos formats put
# an interactive round on top of the PSK — XAuth under IKEv1, EAP under IKEv2.
# eap-mschapv2 wants MD4 and DES, which OpenSSL 3 moved to its legacy provider,
# so the built-in implementations are enabled rather than relying on the openssl
# plugin to still offer them.
#
# --enable-monolithic links every plugin into libcharon/libstrongswan, so the
# dist tree has no plugin dylibs to relocate and sign — a large simplification
# for an app bundle.
#
# resolve: without an attribute handler charon receives the gateway's
# INTERNAL_IP4_DNS and discards it. The plugin writes the servers to the file
# named in strongswan.conf; the app reads that file and applies them itself.
(
    cd "$BUILD/strongswan-${STRONGSWAN_VER}"
    ./configure \
        --prefix="$PREFIX" \
        --sysconfdir="$PREFIX/etc" \
        --disable-defaults \
        --enable-monolithic \
        --enable-charon \
        --enable-ikev1 --enable-ikev2 \
        --enable-nonce --enable-hmac --enable-kdf --enable-random \
        --enable-openssl \
        --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-pubkey --enable-x509 \
        --enable-constraints --enable-revocation \
        --enable-xauth-generic --enable-eap-identity --enable-eap-mschapv2 \
        --enable-md4 --enable-md5 --enable-des --enable-sha1 \
        --enable-vici --enable-updown --enable-resolve \
        --enable-socket-default \
        --enable-kernel-pfroute \
        --enable-libipsec --enable-kernel-libipsec \
        openssl_CFLAGS="-I$PREFIX/include" \
        openssl_LIBS="-L$PREFIX/lib -lssl -lcrypto" \
        CFLAGS="$ARCHFLAGS -I$PREFIX/include -O2" \
        LDFLAGS="$ARCHFLAGS -L$PREFIX/lib"
    make -j"$JOBS"
    make install
)

# ---- flat dist tree -------------------------------------------------------
# charon loads its dylibs from its own directory (see the install-name rewrite
# below), mirroring the Windows tree where charon-svc.exe loads sibling DLLs.
say "staging $DIST"
rm -rf "$DIST"
mkdir -p "$DIST/etc"

CHARON="$(find "$PREFIX" -type f -name charon -perm -u+x | head -1)"
[ -n "$CHARON" ] || { echo "error: charon binary not found under $PREFIX" >&2; exit 1; }
cp "$CHARON" "$DIST/charon"
chmod u+w "$DIST/charon"

# Copy charon plus every library it transitively loads out of the build prefix.
#
# This walks `otool -L` rather than globbing a directory, because globbing gets
# it wrong in three separate ways: strongSwan installs its libraries under
# lib/ipsec/ and not lib/, the filenames are versioned (libcharon.0.dylib), and
# the prefix also holds things the daemon never loads — libvici, the C client
# library, which this app has no use for because it speaks vici from Rust. The
# walk ships exactly what the binary opens and nothing else.
#
# -L resolves the unversioned symlinks (libcrypto.dylib -> libcrypto.3.dylib) so
# the dist tree holds real files; the recursion is bounded by the "already
# staged" check, which uses the filesystem as its visited set.
stage_deps() {
    otool -L "$1" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        case "$dep" in
            "$PREFIX"/*)
                base="$(basename "$dep")"
                if [ ! -f "$DIST/$base" ]; then
                    cp -L "$dep" "$DIST/$base"
                    chmod u+w "$DIST/$base"
                    stage_deps "$DIST/$base"
                fi
                ;;
        esac
    done
}
stage_deps "$DIST/charon"

# NOTE: libexec/ipsec/_updown is deliberately not staged. The updown plugin only
# runs a script when a connection config names one, and `vpn-control`'s bridge
# never does — so shipping it would add a shell script with build-prefix paths
# baked in that nothing ever executes.

cp "$REPO_ROOT/macos/strongswan.conf" "$DIST/etc/strongswan.conf"

# ---- make it relocatable --------------------------------------------------
# Everything above is linked against absolute paths inside $PREFIX, which will
# not exist on a user's Mac. Rewrite each dependency to @rpath and give every
# Mach-O an rpath pointing at its own directory.
#
# IMPORTANT: install_name_tool invalidates a Mach-O's code signature, and on
# Apple Silicon the kernel REFUSES to execute an arm64 binary whose signature is
# broken ("killed: 9", with no useful diagnostic). Every file must therefore be
# re-signed after being rewritten — ad-hoc here; the release build re-signs the
# whole bundle with the Developer ID identity.
say "rewriting install names + re-signing"
for f in "$DIST"/*.dylib "$DIST/charon"; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"

    if [ "$base" != "charon" ]; then
        install_name_tool -id "@rpath/$base" "$f"
    fi

    # Repoint every dependency that still names the build prefix.
    otool -L "$f" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        case "$dep" in
            "$PREFIX"/*)
                install_name_tool -change "$dep" "@rpath/$(basename "$dep")" "$f"
                ;;
        esac
    done

    if [ "$base" = "charon" ]; then
        install_name_tool -add_rpath "@executable_path" "$f" 2>/dev/null || true
    else
        install_name_tool -add_rpath "@loader_path" "$f" 2>/dev/null || true
    fi

    codesign --force --sign - --timestamp=none "$f"
done

# ---- verify ---------------------------------------------------------------
say "verifying the staged daemon"
fail=0

# Every file the daemon cannot start without. Checked by name before anything
# else, because a staging bug that drops a dylib otherwise sails through the
# plugin grep below — an unmatched glob is not a failed match.
for required in charon libstrongswan.0.dylib libcharon.0.dylib libipsec.0.dylib \
                libcrypto.3.dylib etc/strongswan.conf; do
    if [ -f "$DIST/$required" ]; then
        printf '  ok      %s\n' "$required"
    else
        printf '  MISSING %s\n' "$required"; fail=1
    fi
done

# The same contract build.rs enforces for the Windows tree. With
# --disable-defaults a plugin left off the configure line is simply absent from
# the binary, so its name is absent from the strings too.
MACHO=()
for f in "$DIST/charon" "$DIST"/*.dylib; do [ -f "$f" ] && MACHO+=("$f"); done
if [ "${#MACHO[@]}" -eq 0 ]; then
    echo "  MISSING nothing was staged at all"; fail=1
else
    for plugin in xauth-generic eap-mschapv2 eap-identity kernel-libipsec kernel-pfroute vici resolve; do
        if grep -qa -- "$plugin" "${MACHO[@]}"; then
            printf '  ok      %s\n' "$plugin"
        else
            printf '  MISSING %s\n' "$plugin"; fail=1
        fi
    done
fi

# Nothing in the tree may still reference the build prefix, or it breaks the
# moment the bundle lands on another machine.
if otool -L "$DIST"/* 2>/dev/null | grep -q "$PREFIX"; then
    echo "  MISSING relocation: some binaries still reference $PREFIX"; fail=1
else
    printf '  ok      no absolute build paths remain\n'
fi

for f in "$DIST"/*.dylib "$DIST/charon"; do
    [ -f "$f" ] || continue
    codesign --verify "$f" 2>/dev/null || { echo "  MISSING signature on $(basename "$f")"; fail=1; }
done
[ "$fail" = 0 ] && printf '  ok      all Mach-O files signed\n'

echo
ls -la "$DIST"
echo
if [ "$fail" != 0 ]; then
    echo "BUILD INCOMPLETE — see MISSING above" >&2
    exit 1
fi

cat <<EOF

Staged $DIST ($ARCH).

Run it (charon needs root for utun, routes and the virtual IP):

    sudo mkdir -p /var/run/ipsec-vpn
    sudo STRONGSWAN_CONF="$DIST/etc/strongswan.conf" "$DIST/charon"

and drive it from another shell:

    sudo ./target/debug/vpn-agent --socket /var/run/ipsec-vpn/charon.vici status
EOF
