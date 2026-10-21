#!/bin/sh
set -eu

COSIGN_VERSION=3.1.3
COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71

destination=${1:-.bin}
mkdir -p "$destination"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
url="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
curl --fail --location --silent --show-error "$url" --output "$temporary/cosign"
printf '%s  %s\n' "$COSIGN_SHA256" "$temporary/cosign" | sha256sum --check --status
install -m 0755 "$temporary/cosign" "$destination/cosign"
"$destination/cosign" version
