import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createDeploymentEvidence,
  deploymentBundleNames,
  deploymentSchema,
  verifyDeploymentEvidence,
  verifySignedDeploymentEvidence,
} from "../lib/deployment-evidence.mjs";

const manifestDigest = "a".repeat(64);
const versionId = "4f117518-6f75-4ef5-a4d7-19f08ba1181d";

function record() {
  return {
    schema: deploymentSchema,
    version: 1,
    action: "deploy",
    sourceRelease: {
      tag: "v0.2.0",
      revision: "1".repeat(40),
      manifestDigest,
      url: "https://github.com/metalagman/webappsec/releases/tag/v0.2.0",
    },
    github: {
      repository: "metalagman/webappsec",
      workflow: ".github/workflows/deploy.yml",
      ref: "refs/tags/v0.2.0",
      runUrl: "https://github.com/metalagman/webappsec/actions/runs/123",
    },
    cloudflare: {
      workerName: "webappsec",
      wranglerVersion: "4.151.3",
      versionId,
      deploymentId: "9a117518-6f75-4ef5-a4d7-19f08ba1181d",
      versionUrl: "https://4f117518-webappsec.demo-account.workers.dev",
    },
    production: { origin: "https://webappsec.metalagman.dev", verifiedAt: "2026-10-22T00:00:00.000Z" },
    transition: {
      fromVersionId: "5f117518-6f75-4ef5-a4d7-19f08ba1181d",
      fromDeploymentId: "6f117518-6f75-4ef5-a4d7-19f08ba1181d",
      targetDeploymentRelease: null,
    },
  };
}

function coreReport(origin, noindex, release = manifestDigest) {
  return {
    ok: true,
    result: "verified",
    exitCode: 0,
    manifestDigest,
    layers: ["manifest", "production-bytes", "response-headers", "sri"].map((name) => ({ name, state: "pass", detail: "checked" })),
    target: { origin, expectedHeaders: { release, versionId, noindex } },
  };
}

function browser(origin) {
  return { ok: true, origin, title: "Proof of Deploy", sriResources: 2 };
}

function report() {
  const production = coreReport("https://webappsec.metalagman.dev", false);
  return {
    ...production,
    deploymentChecks: {
      preview: coreReport("https://4f117518-webappsec.demo-account.workers.dev", true, "unknown"),
      previewBrowser: browser("https://4f117518-webappsec.demo-account.workers.dev"),
      productionBrowser: browser("https://webappsec.metalagman.dev"),
    },
  };
}

test("deployment evidence canonically binds a passing production report to one Worker version", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-deployment-evidence-"));
  await createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: report() });
  const verified = await verifyDeploymentEvidence(directory);
  assert.equal(verified.record.cloudflare.versionId, versionId);
  assert.deepEqual(verified.index.files.map(({ name }) => name), ["deployment-record.json", "verification-report.json"]);
});

test("signed deployment verification pins the original workflow identity and explicit rollback target", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-signed-deployment-"));
  await createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: report() });
  for (const name of deploymentBundleNames) await writeFile(path.join(directory, name), "{}\n");
  const calls = [];
  const verified = await verifySignedDeploymentEvidence({
    directory,
    expected: { releaseTag: "v0.2.0", manifestDigest, versionId, workflow: ".github/workflows/deploy.yml", ref: "refs/tags/v0.2.0" },
    commandRunner: async (command, args) => { calls.push([command, args]); return { stdout: "", stderr: "" }; },
  });
  assert.equal(verified.record.sourceRelease.manifestDigest, manifestDigest);
  assert.equal(calls.length, 3);
  assert.ok(calls.every(([, args]) => args.includes("https://github.com/metalagman/webappsec/.github/workflows/deploy.yml@refs/tags/v0.2.0")));

  await assert.rejects(() => verifySignedDeploymentEvidence({
    directory,
    expected: { releaseTag: "v0.2.0", manifestDigest: "b".repeat(64), versionId, workflow: ".github/workflows/deploy.yml", ref: "refs/tags/v0.2.0" },
    commandRunner: async () => ({ stdout: "", stderr: "" }),
  }), /explicit rollback target/);
});

test("deployment evidence rejects failed reports and record tampering", async () => {
  const failedDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-failed-deployment-"));
  const failed = report();
  failed.ok = false;
  await assert.rejects(() => createDeploymentEvidence({ outputDirectory: failedDirectory, record: record(), verificationReport: failed }), /did not pass/);

  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-tampered-deployment-"));
  await createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: report() });
  const candidate = JSON.parse(await readFile(path.join(directory, "deployment-record.json"), "utf8"));
  candidate.cloudflare.versionId = "00000000-0000-4000-8000-000000000000";
  await writeFile(path.join(directory, "deployment-record.json"), `${JSON.stringify(candidate)}\n`);
  await assert.rejects(() => verifyDeploymentEvidence(directory), /canonical|index file mismatch/);
});

test("deployment evidence rejects missing preview, browser, header layers, and no-op transitions", async (t) => {
  await t.test("missing preview", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-missing-preview-"));
    const candidate = report();
    candidate.deploymentChecks.preview = null;
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: candidate }), /object|preview/);
  });
  await t.test("missing header layer", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-missing-header-"));
    const candidate = report();
    candidate.layers.splice(2, 1);
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: candidate }), /incomplete layers/);
  });
  await t.test("wrong browser origin", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-browser-origin-"));
    const candidate = report();
    candidate.deploymentChecks.previewBrowser.origin = "https://attacker.example";
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: candidate }), /browser verification/);
  });
  await t.test("wrong verified Worker version", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-wrong-report-version-"));
    const candidate = report();
    candidate.target.expectedHeaders.versionId = "7f117518-6f75-4ef5-a4d7-19f08ba1181d";
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: candidate }), /target mismatch/);
  });
  await t.test("preview cannot claim another release", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-wrong-preview-release-"));
    const candidate = report();
    candidate.deploymentChecks.preview.target.expectedHeaders.release = "b".repeat(64);
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: record(), verificationReport: candidate }), /target mismatch/);
  });
  await t.test("same source and target version", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-noop-transition-"));
    const candidate = record();
    candidate.transition.fromVersionId = candidate.cloudflare.versionId;
    await assert.rejects(() => createDeploymentEvidence({ outputDirectory: directory, record: candidate, verificationReport: report() }), /must change/);
  });
});

test("deployment workflows are tag-bound, environment-protected, and promote an explicit version", async () => {
  const root = path.resolve(new URL("..", import.meta.url).pathname);
  const deployWorkflow = await readFile(path.join(root, ".github/workflows/deploy.yml"), "utf8");
  const rollbackWorkflow = await readFile(path.join(root, ".github/workflows/rollback.yml"), "utf8");
  const deployScript = await readFile(path.join(root, "scripts/deploy-ci.sh"), "utf8");
  const rollbackScript = await readFile(path.join(root, "scripts/rollback-ci.sh"), "utf8");
  for (const workflow of [deployWorkflow, rollbackWorkflow]) {
    assert.match(workflow, /environment: production/);
    assert.match(workflow, /github\.ref_type == 'tag'/);
    assert.match(workflow, /CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_API_TOKEN \}\}/);
    assert.match(workflow, /CLOUDFLARE_ACCOUNT_ID: \$\{\{ secrets\.CLOUDFLARE_ACCOUNT_ID \}\}/);
    assert.doesNotMatch(workflow, /pull_request:|schedule:/);
    assert.doesNotMatch(workflow.split("    steps:", 1)[0], /secrets\.|GH_TOKEN|CLOUDFLARE_/);
    for (const line of workflow.split("\n").filter((candidate) => candidate.trimStart().startsWith("run:"))) {
      assert.doesNotMatch(line, /\$\{\{\s*inputs\./);
    }
    for (const line of workflow.split("\n").filter((candidate) => candidate.includes("uses:"))) {
      assert.match(line, /uses: [A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}(?:\s+#\s+v[0-9.]+)?$/);
    }
  }
  assert.ok(deployScript.indexOf("versions upload") < deployScript.indexOf("verify-production.mjs"));
  assert.ok(deployScript.indexOf("verify-production.mjs") < deployScript.indexOf("versions deploy"));
  assert.match(deployScript, /--version-id "\$version_id" --percentage 100/);
  assert.match(deployScript, /WRANGLER_OUTPUT_FILE_PATH/);
  assert.match(deployScript, /--expected-release unknown --expected-version "\$version_id" --noindex true --preview/);
  assert.match(deployScript, /verify-production-retry\.sh/);
  assert.match(rollbackScript, /deployment-evidence\.mjs verify/);
  assert.match(rollbackScript, /versions deploy --config "\$config" --version-id "\$version_id" --percentage 100/);
  assert.match(rollbackScript, /verify-production-retry\.sh/);
  assert.doesNotMatch(rollbackScript, /wrangler rollback/);
});
