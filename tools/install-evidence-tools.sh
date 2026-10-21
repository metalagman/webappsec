#!/bin/sh
set -eu

SYFT_VERSION=1.55.0
SYFT_SHA256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
GRYPE_VERSION=0.121.0
GRYPE_SHA256=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519

destination=${1:-.bin}
mkdir -p "$destination"

install_tool() {
  name=$1
  version=$2
  expected=$3
  archive="${name}_${version}_linux_amd64.tar.gz"
  url="https://github.com/anchore/${name}/releases/download/v${version}/${archive}"
  temporary=$(mktemp -d)
  trap 'rm -rf "$temporary"' EXIT HUP INT TERM
  curl --fail --location --silent --show-error "$url" --output "$temporary/$archive"
  printf '%s  %s\n' "$expected" "$temporary/$archive" | sha256sum --check --status
  tar -xzf "$temporary/$archive" -C "$temporary" "$name"
  install -m 0755 "$temporary/$name" "$destination/$name"
  rm -rf "$temporary"
  trap - EXIT HUP INT TERM
}

install_tool syft "$SYFT_VERSION" "$SYFT_SHA256"
install_tool grype "$GRYPE_VERSION" "$GRYPE_SHA256"

"$destination/syft" version
"$destination/grype" version
