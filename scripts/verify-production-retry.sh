#!/bin/bash
set -euo pipefail

manifest=${1:-}
release_digest=${2:-}
version_id=${3:-}
output=${4:-}
if [[ ! -f $manifest || ! $release_digest =~ ^[a-f0-9]{64}$ || ! $version_id =~ ^[a-f0-9-]{36}$ || -z $output ]]; then
  echo "invalid production retry invocation" >&2
  exit 2
fi

for attempt in {1..30}; do
  set +e
  node scripts/verify-production.mjs --manifest "$manifest" \
    --expected-release "$release_digest" --expected-version "$version_id" --noindex false --json > "$output"
  code=$?
  set -e
  if [[ $code == 0 ]]; then exit 0; fi
  if [[ $code != 3 ]]; then
    cat "$output" >&2
    exit "$code"
  fi
  if [[ $attempt == 30 ]]; then
    cat "$output" >&2
    exit 3
  fi
  sleep 10
done
