#!/usr/bin/env bash
# Build OpenVPN for macOS, for the Sophos SSL VPN datapath.
#
# The Windows side vendors the official community MSI
# (scripts/fetch-openvpn-windows.ps1). There is no equivalent binary
# distribution for macOS -- Homebrew's is not redistributable inside an app
# bundle and would tie the build to whatever a machine happens to have -- so
# this builds from source and pins the version to the same 2.6.22 Windows
# ships, against an OpenSSL we build ourselves.
#
# macOS needs none of the adapter machinery Windows does. openvpn opens a utun
# directly, so there is no tapctl, no driver to install, and no pre-created
# adapter to manage: the whole reason the Windows datapath needs a privileged
# helper for *adapters* simply does not exist here. The helper is still needed,
# but only because openvpn must run as root to install routes.
#
# LZO is built in because the official Windows binaries have it, and a Sophos
# gateway is free to push `comp-lzo`; without it such a tunnel negotiates and
# then silently carries nothing.
#
# Output: a relocatable dist tree in out/openvpn-macos, staged like
# out/strongswan-macos so the Tauri bundler treats them the same way.
#
# ARM64 ONLY, matching scripts/build-strongswan-macos.sh -- see the note there.
# Intel Macs are not a target, so nothing here is lipo'd into a fat binary.
#
# Usage:
#   scripts/build-openvpn-macos.sh                                  # arm64
#   OPENSSL_PREFIX=/path/to/prefix scripts/build-openvpn-macos.sh   # reuse a build
#   CLEAN=1 scripts/build-openvpn-macos.sh

set -euo pipefail

OPENVPN_VER="${OPENVPN_VER:-2.6.22}"
LZO_VER="${LZO_VER:-2.10}"
OPENSSL_VER="${OPENSSL_VER:-3.0.16}"
ARCH="${ARCH:-$(uname -m)}"
MACOS_MIN="${MACOS_MIN:-11.0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$REPO_ROOT/build/openvpn-macos/$ARCH"
PREFIX="$BUILD/prefix"
DIST="$REPO_ROOT/out/openvpn-macos"
JOBS="$(sysctl -n hw.ncpu)"

# Reuse an OpenSSL that is already built (the strongSwan tree has one) rather
# than spending ten minutes on a second identical copy. Explicit, not magic:
# override it, or leave it unset to build one here.
OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"

[ "${CLEAN:-0}" = "1" ] && rm -rf "$BUILD"
mkdir -p "$BUILD/src" "$PREFIX"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

for tool in cc make curl tar install_name_tool codesign otool; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool not found (install the Xcode Command Line Tools)" >&2
        exit 1
    }
done

export MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN"
ARCHFLAGS="-arch $ARCH"

fetch() { # url, filename
    if [ ! -f "$BUILD/src/$2" ]; then
        say "fetching $2"
        curl -fsSL --retry 3 -o "$BUILD/src/$2.part" "$1"
        mv "$BUILD/src/$2.part" "$BUILD/src/$2"
    fi
}

# ---- OpenSSL (only if we were not handed one) -----------------------------
if [ -z "$OPENSSL_PREFIX" ]; then
    OPENSSL_PREFIX="$PREFIX"
    if [ ! -f "$PREFIX/lib/libcrypto.dylib" ]; then
        fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz" \
              "openssl-${OPENSSL_VER}.tar.gz"
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
            ./Configure "$OSSL_TARGET" shared no-tests --prefix="$PREFIX" --libdir=lib
            make -j"$JOBS"
            make install_sw
        )
    fi
else
    say "reusing OpenSSL at $OPENSSL_PREFIX"
    [ -f "$OPENSSL_PREFIX/lib/libcrypto.dylib" ] || {
        echo "error: no libcrypto.dylib under $OPENSSL_PREFIX" >&2
        exit 1
    }
fi

# ---- LZO ------------------------------------------------------------------
if [ ! -f "$PREFIX/lib/liblzo2.dylib" ]; then
    fetch "https://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VER}.tar.gz" \
          "lzo-${LZO_VER}.tar.gz"
    say "building lzo ${LZO_VER} ($ARCH)"
    rm -rf "$BUILD/lzo-${LZO_VER}"
    tar xf "$BUILD/src/lzo-${LZO_VER}.tar.gz" -C "$BUILD"
    (
        cd "$BUILD/lzo-${LZO_VER}"
        ./configure --prefix="$PREFIX" --enable-shared --disable-static \
            CFLAGS="$ARCHFLAGS -O2" LDFLAGS="$ARCHFLAGS"
        make -j"$JOBS"
        make install
    )
fi

# ---- OpenVPN --------------------------------------------------------------
fetch "https://swupdate.openvpn.org/community/releases/openvpn-${OPENVPN_VER}.tar.gz" \
      "openvpn-${OPENVPN_VER}.tar.gz"
say "building OpenVPN ${OPENVPN_VER} ($ARCH)"
rm -rf "$BUILD/openvpn-${OPENVPN_VER}"
tar xf "$BUILD/src/openvpn-${OPENVPN_VER}.tar.gz" -C "$BUILD"

# --disable-lz4: one compression library is enough, and LZO is the one the
#   Windows binaries carry, so the two platforms negotiate the same set.
# --disable-plugin-*: the helper runs openvpn as root and refuses configs that
#   name plugins (see vpn-broker's sanitize); not building the loaders at all
#   means a config that slips through still has nothing to load.
# --enable-iproute2 is Linux-only; DCO is Linux/Windows-only. Neither applies.
(
    cd "$BUILD/openvpn-${OPENVPN_VER}"
    ./configure \
        --prefix="$PREFIX" \
        --disable-lz4 \
        --enable-lzo \
        --disable-plugin-auth-pam \
        --disable-plugin-down-root \
        --disable-debug \
        --with-crypto-library=openssl \
        OPENSSL_CFLAGS="-I$OPENSSL_PREFIX/include" \
        OPENSSL_LIBS="-L$OPENSSL_PREFIX/lib -lssl -lcrypto" \
        LZO_CFLAGS="-I$PREFIX/include" \
        LZO_LIBS="-L$PREFIX/lib -llzo2" \
        CFLAGS="$ARCHFLAGS -I$OPENSSL_PREFIX/include -I$PREFIX/include -O2" \
        LDFLAGS="$ARCHFLAGS -L$OPENSSL_PREFIX/lib -L$PREFIX/lib"
    make -j"$JOBS"
    make install
)

# ---- flat dist tree -------------------------------------------------------
say "staging $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

OPENVPN_BIN="$(find "$PREFIX" -type f -name openvpn -perm -u+x | head -1)"
[ -n "$OPENVPN_BIN" ] || { echo "error: openvpn binary not found under $PREFIX" >&2; exit 1; }
cp "$OPENVPN_BIN" "$DIST/openvpn"
chmod u+w "$DIST/openvpn"

# Walk otool -L rather than globbing, for the same reasons as the strongSwan
# build: versioned names, and libraries that live where the glob would not look.
stage_deps() {
    otool -L "$1" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        case "$dep" in
            "$PREFIX"/*|"$OPENSSL_PREFIX"/*)
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
stage_deps "$DIST/openvpn"

# ---- make it relocatable --------------------------------------------------
# install_name_tool breaks the signature, and Apple Silicon will not execute an
# arm64 binary whose signature is broken -- so every file is re-signed. Same
# rule as the strongSwan build.
say "rewriting install names + re-signing"
for f in "$DIST"/*.dylib "$DIST/openvpn"; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    [ "$base" != "openvpn" ] && install_name_tool -id "@rpath/$base" "$f"
    otool -L "$f" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        case "$dep" in
            "$PREFIX"/*|"$OPENSSL_PREFIX"/*)
                install_name_tool -change "$dep" "@rpath/$(basename "$dep")" "$f" ;;
        esac
    done
    if [ "$base" = "openvpn" ]; then
        install_name_tool -add_rpath "@executable_path" "$f" 2>/dev/null || true
    else
        install_name_tool -add_rpath "@loader_path" "$f" 2>/dev/null || true
    fi
    codesign --force --sign - --timestamp=none "$f"
done

# ---- verify ---------------------------------------------------------------
say "verifying the staged openvpn"
fail=0
[ -f "$DIST/openvpn" ] || { echo "  MISSING openvpn"; fail=1; }

if otool -L "$DIST"/* 2>/dev/null | grep -qE "$PREFIX|$OPENSSL_PREFIX"; then
    echo "  MISSING relocation: binaries still reference the build prefix"; fail=1
else
    printf '  ok      no absolute build paths remain\n'
fi

for f in "$DIST"/*.dylib "$DIST/openvpn"; do
    [ -f "$f" ] || continue
    if ! lipo -archs "$f" 2>/dev/null | grep -qw "$ARCH"; then
        echo "  MISSING $(basename "$f") is not $ARCH (got: $(lipo -archs "$f" 2>/dev/null))"
        fail=1
    fi
done
[ "$fail" = 0 ] && printf '  ok      every Mach-O is %s\n' "$ARCH"

# --version proves the whole tree loads: rpath resolution, signature validity
# and the linked crypto library all have to be right for this to print.
if ver="$("$DIST/openvpn" --version 2>&1 | head -1)"; then
    printf '  ok      %s\n' "$ver"
else
    echo "  MISSING openvpn --version failed"; fail=1
fi
for want in LZO OpenSSL; do
    if "$DIST/openvpn" --version 2>&1 | grep -q "$want"; then
        printf '  ok      %s linked\n' "$want"
    else
        printf '  MISSING %s not linked\n' "$want"; fail=1
    fi
done

echo
ls -la "$DIST"
[ "$fail" = 0 ] || { echo; echo "BUILD INCOMPLETE -- see MISSING above" >&2; exit 1; }
echo
echo "Staged $DIST ($ARCH)."
