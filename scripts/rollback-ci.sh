#!/bin/bash
set -euo pipefail

action=${1:-}
release_tag=${2:-}
manifest_digest=${3:-}
version_id=${4:-}
target_deployment_release=${5:-}
if [[ ${GITHUB_REPOSITORY:-} != metalagman/webappsec || ! $action =~ ^(rollback|restore)$ \
  || ! ${GITHUB_REF:-} =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ \
  || ! $release_tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ \
  || ! $manifest_digest =~ ^[a-f0-9]{64}$ || ! $version_id =~ ^[a-f0-9-]{36}$ \
  || ! $target_deployment_release =~ ^deployment-(bootstrap|deploy)-v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?-[0-9]+$ ]]; then
  echo "rollback requires an explicit signed deployment target" >&2
  exit 2
fi

rm -rf .artifacts/target-deployment .artifacts/deploy-release .artifacts/deploy-workspace .artifacts/deployment-evidence
mkdir -p .artifacts/target-deployment .artifacts/deploy-release .artifacts/deploy-workspace
gh release download "$target_deployment_release" --repo metalagman/webappsec --dir .artifacts/target-deployment
node scripts/deployment-evidence.mjs verify --directory .artifacts/target-deployment \
  --release "$release_tag" --manifest "$manifest_digest" --version "$version_id" \
  --workflow .github/workflows/deploy.yml --ref "refs/tags/$release_tag" > .artifacts/target-record.json

gh release download "$release_tag" --repo metalagman/webappsec --dir .artifacts/deploy-release
node scripts/prepare-deployment.mjs --evidence .artifacts/deploy-release --source release-source \
  --release "$release_tag" --output .artifacts/deploy-workspace > .artifacts/deployment-input.json
[[ $(jq -er .manifestDigest .artifacts/deployment-input.json) == "$manifest_digest" ]]
revision=$(jq -er .revision .artifacts/deployment-input.json)
version_url=$(jq -c .cloudflare.versionUrl .artifacts/target-record.json)

config=.artifacts/deploy-workspace/wrangler.jsonc
export XDG_CONFIG_HOME="$RUNNER_TEMP/wrangler-config"
export WRANGLER_SEND_METRICS=false
export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-$action.jsonl"
mkdir -p "$XDG_CONFIG_HOME"
npx wrangler versions view "$version_id" --config "$config" --json > .artifacts/version.json
[[ $(jq -er .id .artifacts/version.json) == "$version_id" ]]
[[ $(jq -er '.annotations["workers/tag"]' .artifacts/version.json) == "$manifest_digest" ]]
npx wrangler versions deploy --config "$config" --version-id "$version_id" --percentage 100 --yes \
  --message "$action to verified release $release_tag ($manifest_digest)"
npx wrangler deployments status --config "$config" --json > .artifacts/deployment-status.json
deployment_id=$(jq -er --arg version "$version_id" 'select(any(.versions[]; .version_id == $version and .percentage == 100)) | .id' .artifacts/deployment-status.json)
[[ $deployment_id =~ ^[a-f0-9-]{36}$ ]]

node scripts/verify-production.mjs --manifest .artifacts/deploy-workspace/manifest.json \
  --expected-release "$manifest_digest" --expected-version "$version_id" --noindex false --json \
  > .artifacts/production-report-base.json
node scripts/verify-live-browser.mjs --origin https://webappsec.metalagman.dev > .artifacts/production-browser.json
production_browser=$(cat .artifacts/production-browser.json)
jq -c --arg target "$target_deployment_release" --argjson productionBrowser "$production_browser" \
  '. + {deploymentChecks:{verifiedTargetDeploymentRelease:$target,productionBrowser:$productionBrowser}}' \
  .artifacts/production-report-base.json > .artifacts/production-report.json

verified_at=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
jq -cn \
  --arg action "$action" --arg tag "$release_tag" --arg revision "$revision" --arg manifest "$manifest_digest" \
  --arg ref "$GITHUB_REF" --arg run "https://github.com/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
  --arg version "$version_id" --arg deployment "$deployment_id" --argjson versionUrl "$version_url" --arg verifiedAt "$verified_at" \
  '{schema:"https://webappsec.metalagman.dev/schema/deployment-record-v1",version:1,action:$action,
    sourceRelease:{tag:$tag,revision:$revision,manifestDigest:$manifest,url:("https://github.com/metalagman/webappsec/releases/tag/"+$tag)},
    github:{repository:"metalagman/webappsec",workflow:".github/workflows/rollback.yml",ref:$ref,runUrl:$run},
    cloudflare:{workerName:"webappsec",wranglerVersion:"4.151.3",versionId:$version,deploymentId:$deployment,versionUrl:$versionUrl},
    production:{origin:"https://webappsec.metalagman.dev",verifiedAt:$verifiedAt}}' > .artifacts/deployment-record-input.json
node scripts/deployment-evidence.mjs build --record .artifacts/deployment-record-input.json \
  --report .artifacts/production-report.json --output .artifacts/deployment-evidence > /dev/null

identity="https://github.com/metalagman/webappsec/.github/workflows/rollback.yml@$GITHUB_REF"
for subject in deployment-index deployment-record verification-report; do
  .bin/cosign sign-blob --yes --bundle ".artifacts/deployment-evidence/$subject.sigstore.json" ".artifacts/deployment-evidence/$subject.json"
  .bin/cosign verify-blob --bundle ".artifacts/deployment-evidence/$subject.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ".artifacts/deployment-evidence/$subject.json"
done

deployment_release="deployment-$action-$release_tag-$GITHUB_RUN_ID"
if gh release view "$deployment_release" --repo metalagman/webappsec >/dev/null 2>&1; then
  echo "refusing to replace existing deployment release $deployment_release" >&2
  exit 1
fi
gh release create "$deployment_release" --repo metalagman/webappsec --target "$GITHUB_SHA" --draft \
  --title "Deployment: $action $release_tag" --notes "Signed $action record for $release_tag, manifest $manifest_digest, Worker version $version_id." \
  .artifacts/deployment-evidence/*
gh release edit "$deployment_release" --repo metalagman/webappsec --draft=false

printf '### Verified %s\n- source release: `%s`\n- manifest: `%s`\n- Worker version: `%s`\n- deployment: `%s`\n- signed record: `%s`\n' \
  "$action" "$release_tag" "$manifest_digest" "$version_id" "$deployment_id" "$deployment_release" >> "$GITHUB_STEP_SUMMARY"
