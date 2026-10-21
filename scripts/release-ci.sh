#!/bin/bash
set -euo pipefail

if [[ ${GITHUB_REPOSITORY:-} != metalagman/webappsec ]]; then
  echo "release must run in metalagman/webappsec" >&2
  exit 2
fi
if [[ ! ${GITHUB_REF:-} =~ ^refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$ ]]; then
  echo "release requires an immutable SemVer tag" >&2
  exit 2
fi
tag=${BASH_REMATCH[1]}
if [[ ${GITHUB_REF_NAME:-} != "$tag" || ! ${GITHUB_SHA:-} =~ ^[a-f0-9]{40}$ ]]; then
  echo "inconsistent GitHub release identity" >&2
  exit 2
fi
if [[ ! ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ || ! ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]]; then
  echo "missing GitHub invocation identity" >&2
  exit 2
fi

rm -rf .artifacts/release-a .artifacts/release-b .artifacts/evidence .artifacts/publish
common=(
  --revision "$GITHUB_SHA"
  --tag "$tag"
  --workflow .github/workflows/release.yml
  --input worker:lib/content-addressing.mjs=lib/content-addressing.mjs
  --input worker:worker/index.js=worker/index.js
  --input configuration:wrangler.jsonc=wrangler.jsonc
)
node scripts/release-artifact.mjs build --output .artifacts/release-a "${common[@]}" > .artifacts/release-a.json
node scripts/release-artifact.mjs build --output .artifacts/release-b "${common[@]}" > .artifacts/release-b.json

manifest_digest=$(jq -er .digest .artifacts/release-a.json)
second_digest=$(jq -er .digest .artifacts/release-b.json)
[[ $manifest_digest == "$second_digest" ]]
cmp ".artifacts/release-a/$manifest_digest/manifest.json" ".artifacts/release-b/$manifest_digest/manifest.json"
cmp ".artifacts/release-a/$manifest_digest.tar" ".artifacts/release-b/$manifest_digest.tar"

node scripts/generate-evidence.mjs \
  --release ".artifacts/release-a/$manifest_digest" \
  --output .artifacts/evidence

invocation_id="https://github.com/metalagman/webappsec/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT"
node scripts/assemble-release.mjs build \
  --release ".artifacts/release-a/$manifest_digest" \
  --tar ".artifacts/release-a/$manifest_digest.tar" \
  --evidence .artifacts/evidence \
  --output .artifacts/publish \
  --invocation-id "$invocation_id"
node scripts/assemble-release.mjs verify .artifacts/publish

identity="https://github.com/metalagman/webappsec/.github/workflows/release.yml@$GITHUB_REF"
issuer=https://token.actions.githubusercontent.com
sign_blob() {
  local file=$1 bundle=$2
  .bin/cosign sign-blob --yes --bundle "$bundle" "$file"
  .bin/cosign verify-blob --bundle "$bundle" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$file"
}
attest_blob() {
  local subject=$1 predicate=$2 type=$3 bundle=$4
  .bin/cosign attest-blob --yes --predicate "$predicate" --type "$type" --bundle "$bundle" "$subject"
  .bin/cosign verify-blob-attestation --bundle "$bundle" --type "$type" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$subject"
}

sign_blob .artifacts/publish/manifest.json .artifacts/publish/manifest.sigstore.json
release_tar=".artifacts/publish/$manifest_digest.tar"
sign_blob "$release_tar" .artifacts/publish/release.sigstore.json
sign_blob .artifacts/publish/evidence-index.json .artifacts/publish/evidence-index.sigstore.json
attest_blob .artifacts/publish/manifest.json .artifacts/publish/provenance.slsa.json slsaprovenance1 .artifacts/publish/provenance.manifest.intoto.sigstore.json
attest_blob "$release_tar" .artifacts/publish/provenance.slsa.json slsaprovenance1 .artifacts/publish/provenance.release.intoto.sigstore.json
attest_blob "$release_tar" .artifacts/publish/runtime.cdx.json cyclonedx .artifacts/publish/runtime-cyclonedx.intoto.sigstore.json
attest_blob "$release_tar" .artifacts/publish/build.cdx.json cyclonedx .artifacts/publish/build-cyclonedx.intoto.sigstore.json

cat > .artifacts/release-notes.md <<EOF
Canonical manifest SHA-256: \`$manifest_digest\`

This immutable evidence set was built from \`$GITHUB_SHA\` by
\`.github/workflows/release.yml\`. Verify it with the pinned policy and commands
documented in the repository README.
EOF

if gh release view "$tag" >/dev/null 2>&1; then
  echo "refusing to replace existing release $tag" >&2
  exit 1
fi
gh release create "$tag" .artifacts/publish/* \
  --draft \
  --verify-tag \
  --title "$tag — $manifest_digest" \
  --notes-file .artifacts/release-notes.md
gh release edit "$tag" --draft=false
