import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = path.resolve(new URL("..", import.meta.url).pathname);

test("privileged verifier workflow is bound to one successful trusted main run", async () => {
  const workflow = await readFile(path.join(root, ".github/workflows/deploy-verifier.yml"), "utf8");
  assert.match(workflow, /workflow_run:\s*\n\s+workflows: \["Verify production"\]\s*\n\s+types: \[completed\]/);
  assert.match(workflow, /github\.repository == 'metalagman\/webappsec'/);
  assert.match(workflow, /github\.event\.workflow_run\.repository\.full_name == 'metalagman\/webappsec'/);
  assert.match(workflow, /github\.event\.workflow_run\.name == 'Verify production'/);
  assert.match(workflow, /github\.event\.workflow_run\.path == '\.github\/workflows\/verify-production\.yml'/);
  assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
  assert.match(workflow, /github\.event\.workflow_run\.head_branch == 'main'/);
  assert.match(workflow, /github\.event\.workflow_run\.event == 'workflow_dispatch' \|\| github\.event\.workflow_run\.event == 'schedule'/);
  assert.match(workflow, /ref: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/);
  assert.match(workflow, /RUN_ID: \$\{\{ github\.event\.workflow_run\.id \}\}/);
  assert.doesNotMatch(workflow, /download-artifact[\s\S]+run-id:/);
});

test("workflow keeps secrets in serialized deployment after validation", async () => {
  const workflow = await readFile(path.join(root, ".github/workflows/deploy-verifier.yml"), "utf8");
  const validateStart = workflow.indexOf("  validate:");
  const deployStart = workflow.indexOf("  deploy:");
  assert.ok(validateStart > 0 && deployStart > validateStart);
  const validation = workflow.slice(validateStart, deployStart);
  const deployment = workflow.slice(deployStart);
  assert.doesNotMatch(validation, /secrets\./);
  assert.match(deployment, /needs: validate/);
  assert.match(deployment, /environment: production/);
  assert.match(deployment, /CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_API_TOKEN \}\}/);
  assert.match(deployment, /CLOUDFLARE_ACCOUNT_ID: \$\{\{ secrets\.CLOUDFLARE_ACCOUNT_ID \}\}/);
  assert.match(workflow, /group: production-webappsec-verifier/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /permissions:\s*\n\s+contents: read/);
  assert.doesNotMatch(workflow, /id-token: write|contents: write/);
});

test("workflow builds exact snapshot, validates package, and runs hosted browser smoke", async () => {
  const workflow = await readFile(path.join(root, ".github/workflows/deploy-verifier.yml"), "utf8");
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm run tools:signing/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /npm run test:browser/);
  assert.match(workflow, /npm run deploy:verifier:validate/);
  assert.match(workflow, /resolve-online-verifier\.mjs --run "\$RUN_ID"/);
  assert.match(workflow, /current-verification\.json/);
  assert.match(workflow, /release-manifest\.json/);
  assert.match(workflow, /verifier-deploy-ci\.sh/);
  assert.match(workflow, /upload-artifact@[a-f0-9]{40}/);
  assert.doesNotMatch(workflow, /terraform|terragrunt/i);
});

test("deployment does not rebuild away the resolved publication", async () => {
  const workflow = await readFile(path.join(root, ".github/workflows/deploy-verifier.yml"), "utf8");
  const deployment = workflow.slice(workflow.indexOf("  deploy:"));
  const build = deployment.indexOf("npm run build:verifier");
  const publication = deployment.indexOf("install -m 0644 .artifacts/verifier-publication/current-verification.json");
  const dryRun = deployment.indexOf("npm run deploy:verifier:package:validate");
  const deploy = deployment.indexOf("scripts/verifier-deploy-ci.sh");
  assert.ok(build > 0 && publication > build && dryRun > publication && deploy > dryRun);
  assert.doesNotMatch(deployment.slice(publication, deploy), /npm run (?:build:verifier|deploy:verifier:validate)/);

  const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.doesNotMatch(packageJson.scripts["deploy:verifier:package:validate"], /build|rm /);
  assert.match(packageJson.scripts["deploy:verifier:package:validate"], /wrangler deploy --dry-run --config wrangler\.verifier\.jsonc/);
});

test("verifier deployment validates preview before promotion and live site afterward", async () => {
  const script = await readFile(path.join(root, "scripts/verifier-deploy-ci.sh"), "utf8");
  const preview = script.indexOf("verify-verifier-static.mjs");
  const promote = script.indexOf("versions deploy");
  const hosted = script.indexOf("verify-online-verifier.mjs");
  assert.ok(preview > 0 && promote > preview && hosted > promote);
  assert.match(script, /wrangler deploy/);
  assert.match(script, /versions upload/);
  assert.match(script, /deployments status/);
  assert.match(script, /verify\.webappsec\.metalagman\.dev/);
  assert.match(script, /webappsec\.metalagman\.dev/);
});
