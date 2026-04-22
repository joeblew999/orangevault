#!/usr/bin/env bash
# Downloads a pre-built Bitwarden web vault from dani-garcia/bw_web_builds
# (the vaultwarden-patched variant) and extracts it to ./web-vault/.
# That directory is the static-assets source referenced by [assets] in wrangler.toml.
#
# Usage:
#   scripts/fetch-web-vault.sh            # latest release
#   scripts/fetch-web-vault.sh v2026.2.0  # specific tag

set -euo pipefail

REPO="dani-garcia/bw_web_builds"
VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | awk -F'"' '/"tag_name":/ {print $4; exit}')
fi

ASSET="bw_web_${VERSION}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Fetching ${ASSET} and checksum..."
curl -fsSL "$URL" -o "$TMP/$ASSET" &
curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/sha256sums.txt" -o "$TMP/sha256sums.txt" &
wait

echo "Verifying checksum..."
(cd "$TMP" && grep " ${ASSET}\$" sha256sums.txt | shasum -a 256 -c -)

echo "Extracting..."
tar -xzf "$TMP/$ASSET" -C "$TMP"

# Source maps aren't needed at runtime and some are >25 MiB, which exceeds
# the Cloudflare Workers Assets per-file limit.
find "$TMP/web-vault" -name '*.map' -delete

# Swap into place only after extraction succeeds, so a failed run leaves
# any existing web-vault intact.
rm -rf "$REPO_ROOT/web-vault"
mv "$TMP/web-vault" "$REPO_ROOT/web-vault"

VERSION_FILE="$REPO_ROOT/web-vault/vw-version.json"
if [[ -f "$VERSION_FILE" ]]; then
    echo "Installed web vault $(cat "$VERSION_FILE")"
else
    echo "Installed web vault ${VERSION} to ${REPO_ROOT}/web-vault"
fi
