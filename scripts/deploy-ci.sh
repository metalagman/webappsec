#!/bin/bash
set -euo pipefail

mode=${1:-}
release_tag=${2:-}
if [[ ${GITHUB_REPOSITORY:-} != metalagman/webappsec || ! $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ \
  || ${GITHUB_REF:-} != "refs/tags/$release_tag" || ! $mode =~ ^(bootstrap|deploy)$ ]]; then
  echo "deploy requires an explicit release tag ref and bootstrap|deploy mode" >&2
  exit 2
fi

rm -rf .artifacts/deploy-release .artifacts/deploy-workspace .artifacts/deployment-evidence
mkdir -p .artifacts/deploy-release .artifacts/deploy-workspace
gh release download "$release_tag" --repo metalagman/webappsec --dir .artifacts/deploy-release
node scripts/prepare-deployment.mjs \
  --evidence .artifacts/deploy-release --source . --release "$release_tag" \
  --output .artifacts/deploy-workspace > .artifacts/deployment-input.json
manifest_digest=$(jq -er .manifestDigest .artifacts/deployment-input.json)
revision=$(jq -er .revision .artifacts/deployment-input.json)
config=.artifacts/deploy-workspace/wrangler.jsonc
export XDG_CONFIG_HOME="$RUNNER_TEMP/wrangler-config"
export WRANGLER_SEND_METRICS=false
mkdir -p "$XDG_CONFIG_HOME"

preview_url=null
preview_report=null
preview_browser=null
if [[ $mode == bootstrap ]]; then
  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-bootstrap.jsonl"
  npx wrangler deploy --config "$config" --tag "$manifest_digest" \
    --message "Bootstrap signed release $release_tag ($manifest_digest)"
  version_id=$(jq -ers 'map(select(.type == "deploy")) | last.version_id' "$WRANGLER_OUTPUT_FILE_PATH")
else
  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-upload.jsonl"
  npx wrangler versions upload --config "$config" --tag "$manifest_digest" \
    --message "Upload signed release $release_tag ($manifest_digest)"
  version_id=$(jq -ers 'map(select(.type == "version-upload")) | last.version_id' "$WRANGLER_OUTPUT_FILE_PATH")
  preview_url=$(jq -ers 'map(select(.type == "version-upload")) | last.preview_url' "$WRANGLER_OUTPUT_FILE_PATH")
  [[ $preview_url == https://*-webappsec.*.workers.dev ]]
  node scripts/verify-production.mjs --manifest .artifacts/deploy-workspace/manifest.json \
    --origin "$preview_url" --expected-release "$manifest_digest" --expected-version "$version_id" --noindex true --json \
    > .artifacts/preview-report.json
  node scripts/verify-live-browser.mjs --origin "$preview_url" > .artifacts/preview-browser.json
  preview_report=$(cat .artifacts/preview-report.json)
  preview_browser=$(cat .artifacts/preview-browser.json)
  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-promote.jsonl"
  npx wrangler versions deploy --config "$config" --version-id "$version_id" --percentage 100 --yes \
    --message "Promote verified release $release_tag ($manifest_digest)"
fi

[[ $version_id =~ ^[a-f0-9-]{36}$ ]]
npx wrangler deployments status --config "$config" --json > .artifacts/deployment-status.json
deployment_id=$(jq -er --arg version "$version_id" 'select(any(.versions[]; .version_id == $version and .percentage == 100)) | .id' .artifacts/deployment-status.json)
[[ $deployment_id =~ ^[a-f0-9-]{36}$ ]]

node scripts/verify-production.mjs --manifest .artifacts/deploy-workspace/manifest.json \
  --expected-release "$manifest_digest" --expected-version "$version_id" --noindex false --json \
  > .artifacts/production-report-base.json
node scripts/verify-live-browser.mjs --origin https://webappsec.metalagman.dev > .artifacts/production-browser.json
production_browser=$(cat .artifacts/production-browser.json)
jq -c --argjson previewReport "$preview_report" --argjson previewBrowser "$preview_browser" --argjson productionBrowser "$production_browser" \
  '. + {deploymentChecks:{preview:$previewReport,previewBrowser:$previewBrowser,productionBrowser:$productionBrowser}}' \
  .artifacts/production-report-base.json > .artifacts/production-report.json

verified_at=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
jq -cn \
  --arg action "$mode" --arg tag "$release_tag" --arg revision "$revision" --arg manifest "$manifest_digest" \
  --arg workflow .github/workflows/deploy.yml --arg ref "$GITHUB_REF" --arg run "https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
  --arg version "$version_id" --arg deployment "$deployment_id" --argjson versionUrl "$preview_url" --arg verifiedAt "$verified_at" \
  '{schema:"https://webappsec.metalagman.dev/schema/deployment-record-v1",version:1,action:$action,
    sourceRelease:{tag:$tag,revision:$revision,manifestDigest:$manifest,url:("https://github.com/metalagman/webappsec/releases/tag/"+$tag)},
    github:{repository:"metalagman/webappsec",workflow:$workflow,ref:$ref,runUrl:$run},
    cloudflare:{workerName:"webappsec",wranglerVersion:"4.151.3",versionId:$version,deploymentId:$deployment,versionUrl:$versionUrl},
    production:{origin:"https://webappsec.metalagman.dev",verifiedAt:$verifiedAt}}' > .artifacts/deployment-record-input.json
node scripts/deployment-evidence.mjs build --record .artifacts/deployment-record-input.json \
  --report .artifacts/production-report.json --output .artifacts/deployment-evidence > /dev/null

identity="https://github.com/metalagman/webappsec/.github/workflows/deploy.yml@$GITHUB_REF"
for subject in deployment-index deployment-record verification-report; do
  .bin/cosign sign-blob --yes --bundle ".artifacts/deployment-evidence/$subject.sigstore.json" ".artifacts/deployment-evidence/$subject.json"
  .bin/cosign verify-blob --bundle ".artifacts/deployment-evidence/$subject.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ".artifacts/deployment-evidence/$subject.json"
done

deployment_release="deployment-$mode-$release_tag-$GITHUB_RUN_ID"
if gh release view "$deployment_release" --repo metalagman/webappsec >/dev/null 2>&1; then
  echo "refusing to replace existing deployment release $deployment_release" >&2
  exit 1
fi
gh release create "$deployment_release" --repo metalagman/webappsec --target "$GITHUB_SHA" --draft \
  --title "Deployment: $mode $release_tag" --notes "Signed deployment record for $release_tag, manifest $manifest_digest, Worker version $version_id." \
  .artifacts/deployment-evidence/*
gh release edit "$deployment_release" --repo metalagman/webappsec --draft=false

{
  echo "manifest_digest=$manifest_digest"
  echo "version_id=$version_id"
  echo "deployment_id=$deployment_id"
  echo "deployment_release=$deployment_release"
} >> "$GITHUB_OUTPUT"
printf '### Verified deployment\n- source release: `%s`\n- manifest: `%s`\n- Worker version: `%s`\n- deployment: `%s`\n- signed record: `%s`\n' \
  "$release_tag" "$manifest_digest" "$version_id" "$deployment_id" "$deployment_release" >> "$GITHUB_STEP_SUMMARY"
