#!/bin/bash
set -euo pipefail

release_tag=${1:-}
input_directory=${2:-}
if [[ ${GITHUB_REPOSITORY:-} != metalagman/webappsec || ${GITHUB_REF:-} != refs/heads/main \
  || ! ${GITHUB_SHA:-} =~ ^[a-f0-9]{40}$ || ! ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ \
  || ! $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ \
  || ! -f $input_directory/verification-report.json ]]; then
  echo "verification publication requires trusted main and an explicit passing report" >&2
  exit 2
fi

report=$input_directory/verification-report.json
manifest_digest=$(jq -er '.manifestDigest | select(test("^[a-f0-9]{64}$"))' "$report")
verified_at=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
rm -rf .artifacts/verification-evidence
mkdir -p .artifacts
jq -cn \
  --arg tag "$release_tag" --arg manifest "$manifest_digest" --arg revision "$GITHUB_SHA" \
  --arg run "https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" --arg verifiedAt "$verified_at" \
  '{schema:"https://webappsec.metalagman.dev/schema/verification-record-v1",version:1,
    sourceRelease:{tag:$tag,manifestDigest:$manifest,url:("https://github.com/metalagman/webappsec/releases/tag/"+$tag)},
    github:{repository:"metalagman/webappsec",workflow:".github/workflows/verify-production.yml",ref:"refs/heads/main",revision:$revision,runUrl:$run},
    production:{origin:"https://webappsec.metalagman.dev",verifiedAt:$verifiedAt},result:"verified"}' \
  > .artifacts/verification-record-input.json
node scripts/verification-evidence.mjs build --record .artifacts/verification-record-input.json \
  --report "$report" --output .artifacts/verification-evidence > /dev/null

identity="https://github.com/metalagman/webappsec/.github/workflows/verify-production.yml@refs/heads/main"
sign_file() {
  local subject=$1 bundle=$2
  .bin/cosign sign-blob --yes --bundle ".artifacts/verification-evidence/$bundle" ".artifacts/verification-evidence/$subject"
  .bin/cosign verify-blob --bundle ".artifacts/verification-evidence/$bundle" \
    --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ".artifacts/verification-evidence/$subject"
}
sign_file verification-index.json verification-index.sigstore.json
sign_file verification-record.json verification-record.sigstore.json
sign_file verification-report.json verification-report.sigstore.json
sign_file verification-report.txt verification-report.txt.sigstore.json
node scripts/verification-evidence.mjs verify --directory .artifacts/verification-evidence --signed > /dev/null

verification_release="verification-$release_tag-$GITHUB_RUN_ID"
if gh release view "$verification_release" --repo metalagman/webappsec >/dev/null 2>&1; then
  echo "refusing to replace existing verification release $verification_release" >&2
  exit 1
fi
gh release create "$verification_release" --repo metalagman/webappsec --target "$GITHUB_SHA" --draft \
  --title "Production verification: $release_tag" \
  --notes "Signed full-chain production verification for $release_tag, manifest $manifest_digest." \
  .artifacts/verification-evidence/*
gh release edit "$verification_release" --repo metalagman/webappsec --draft=false

printf '### Signed production verification\n- source release: `%s`\n- manifest: `%s`\n- signed record: `%s`\n' \
  "$release_tag" "$manifest_digest" "$verification_release" >> "$GITHUB_STEP_SUMMARY"
