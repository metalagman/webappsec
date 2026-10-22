#!/bin/bash
set -euo pipefail

mode=${1:-}
upstream_run=${2:-}
if [[ ${GITHUB_REPOSITORY:-} != metalagman/webappsec || ! $mode =~ ^(bootstrap|deploy)$ \
  || ! $upstream_run =~ ^[1-9][0-9]*$ || ! ${UPSTREAM_HEAD_SHA:-} =~ ^[a-f0-9]{40}$ \
  || $(git rev-parse HEAD) != "$UPSTREAM_HEAD_SHA" ]]; then
  echo "verifier deploy requires the exact trusted upstream run and revision" >&2
  exit 2
fi
for file in dist-verifier/current-verification.json dist-verifier/release-manifest.json; do
  [[ -f $file && ! -L $file ]] || { echo "missing verifier publication file: $file" >&2; exit 2; }
done

rm -rf .artifacts/verifier-deploy
mkdir -p .artifacts/verifier-deploy
manifest_digest=$(jq -er '.target.manifestDigest | select(test("^[a-f0-9]{64}$"))' dist-verifier/current-verification.json)
release_tag=$(jq -er '.sourceRelease.tag | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$"))' dist-verifier/current-verification.json)
config=wrangler.verifier.jsonc
export XDG_CONFIG_HOME="$RUNNER_TEMP/wrangler-verifier-config"
export WRANGLER_SEND_METRICS=false
mkdir -p "$XDG_CONFIG_HOME"

retry_check() {
  local output=$1
  shift
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if "$@" > "$output"; then
      return 0
    fi
    if [[ $attempt == 6 ]]; then
      echo "verification did not converge after $attempt attempts" >&2
      return 1
    fi
    sleep 10
  done
}

preview_url=
if [[ $mode == bootstrap ]]; then
  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-verifier-bootstrap.jsonl"
  npx wrangler deploy --config "$config" --tag "$manifest_digest" \
    --message "Bootstrap online verifier for $release_tag ($manifest_digest)"
  version_id=$(jq -ers 'map(select(.type == "deploy")) | last.version_id' "$WRANGLER_OUTPUT_FILE_PATH")
else
  npx wrangler deployments status --config "$config" --json > .artifacts/verifier-deploy/prior-status.json
  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-verifier-upload.jsonl"
  npx wrangler versions upload --config "$config" --tag "$manifest_digest" \
    --message "Upload online verifier for $release_tag ($manifest_digest)"
  version_id=$(jq -ers 'map(select(.type == "version-upload")) | last.version_id' "$WRANGLER_OUTPUT_FILE_PATH")
  preview_url=$(jq -ers 'map(select(.type == "version-upload")) | last.preview_url' "$WRANGLER_OUTPUT_FILE_PATH")
  [[ $version_id =~ ^[a-f0-9-]{36}$ && $preview_url == https://*-webappsec-verifier.*.workers.dev ]]

  # The preview proves the exact package, headers, snapshot binding, and SRI before promotion.
  # Its random origin cannot run the production CORS browser check; that check follows promotion.
  retry_check .artifacts/verifier-deploy/preview-static.json \
    node scripts/verify-verifier-static.mjs \
    --origin "$preview_url" --expected-version "$version_id" --preview

  export WRANGLER_OUTPUT_FILE_PATH="$RUNNER_TEMP/wrangler-verifier-promote.jsonl"
  npx wrangler versions deploy --config "$config" --version-id "$version_id" --percentage 100 --yes \
    --message "Promote verified online verifier for $release_tag ($manifest_digest)"
fi

[[ $version_id =~ ^[a-f0-9-]{36}$ ]]
npx wrangler deployments status --config "$config" --json > .artifacts/verifier-deploy/status.json
deployment_id=$(jq -er --arg version "$version_id" \
  'select(any(.versions[]; .version_id == $version and .percentage == 100)) | .id' \
  .artifacts/verifier-deploy/status.json)
[[ $deployment_id =~ ^[a-f0-9-]{36}$ ]]

retry_check .artifacts/verifier-deploy/production-static.json \
  node scripts/verify-verifier-static.mjs \
  --origin https://verify.webappsec.metalagman.dev --expected-version "$version_id"
retry_check .artifacts/verifier-deploy/hosted-browser.json \
  node scripts/verify-online-verifier.mjs \
  --verifier https://verify.webappsec.metalagman.dev \
  --production https://webappsec.metalagman.dev

checked_at=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
jq -cn \
  --arg mode "$mode" --arg run "$upstream_run" --arg revision "$UPSTREAM_HEAD_SHA" \
  --arg release "$release_tag" --arg manifest "$manifest_digest" --arg version "$version_id" \
  --arg deployment "$deployment_id" --arg checkedAt "$checked_at" \
  '{schema:"https://verify.webappsec.metalagman.dev/schema/verifier-deployment-v1",version:1,mode:$mode,
    upstream:{runId:$run,headSha:$revision},source:{release:$release,manifestDigest:$manifest},
    verifier:{origin:"https://verify.webappsec.metalagman.dev",versionId:$version,deploymentId:$deployment},checkedAt:$checkedAt}' \
  > .artifacts/verifier-deploy/deployment.json

{
  echo "version_id=$version_id"
  echo "deployment_id=$deployment_id"
} >> "$GITHUB_OUTPUT"
printf '### Online verifier deployed\n- source release: `%s`\n- manifest: `%s`\n- Worker version: `%s`\n- deployment: `%s`\n- upstream verification run: `%s`\n' \
  "$release_tag" "$manifest_digest" "$version_id" "$deployment_id" "$upstream_run" >> "$GITHUB_STEP_SUMMARY"
