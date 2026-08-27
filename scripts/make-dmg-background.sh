#!/usr/bin/env bash
# Regenerate crates/vpn-desktop/dmg/background.tiff from the Swift drawing.
#
# The result is committed. This is not part of the build: the release runs on a
# machine that has the repo, not one that redraws art, and a background that
# changed because a system font shipped a new version would be a surprise in a
# signed artifact.
#
# Why a TIFF and not a PNG. Finder draws a dmg background at its natural pixel
# size, so a 660x400 PNG is visibly soft on every Mac sold in the last decade.
# The Apple-sanctioned fix is a multi-representation TIFF holding a 1x and a 2x
# image, which `tiffutil -cathidpicheck` builds; Finder then picks per display.
set -euo pipefail

cd "$(dirname "$0")/.."
out="crates/vpn-desktop/dmg/background.tiff"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> drawing"
swift scripts/make-dmg-background.swift "$tmp/background.png" "$tmp/background@2x.png"

echo "==> combining into a hidpi TIFF"
mkdir -p "$(dirname "$out")"
tiffutil -cathidpicheck "$tmp/background.png" "$tmp/background@2x.png" -out "$out"

echo
sips -g pixelWidth -g pixelHeight "$tmp/background.png" | tail -2
ls -lh "$out"
