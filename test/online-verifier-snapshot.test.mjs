import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../lib/canonical-json.mjs";
import {
  resolveTrustedVerifierSnapshot,
  writeVerifierPublication,
} from "../lib/online-verifier-snapshot.mjs";

const runId = "39690026014";
const releaseTag = "v0.2.7";
const revision = "1".repeat(40);
const verifierRevision = "2".repeat(40);
const workerVersion = "39600c79-f529-4ead-8df8-5b61acbe8ee4";
const deploymentId = "49600c79-f529-4ead-8df8-5b61acbe8ee4";
const deploymentRunId = "39689851057";
const verificationRelease = `verification-${releaseTag}-${runId}`;
const deploymentRelease = `deployment-deploy-${releaseTag}-${deploymentRunId}`;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const layerNames = [
  "release-resolution", "evidence-inventory", "signatures", "attestations", "sbom",
  "vulnerability-evidence", "reproducible-build", "production-bytes", "sri",
];

function manifest() {
  return {
    schema: "https://webappsec.metalagman.dev/schema/deployment-manifest-v1",
    version: 1,
    origin: "https://webappsec.metalagman.dev",
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision,
      tag: releaseTag,
      workflow: ".github/workflows/release.yml",
    },
    worker: { name: "webappsec" },
    inputs: [
      { path: "worker/index.js", role: "worker", size: 123, sha256: "a".repeat(64) },
      { path: "wrangler.jsonc", role: "configuration", size: 456, sha256: "b".repeat(64) },
    ],
    files: [
      { path: "assets/app/app.abc123.js", urlPath: "/app/app.abc123.js", mediaType: "text/javascript; charset=utf-8", size: 10, sha256: "c".repeat(64) },
      { path: "assets/app/site.abc123.css", urlPath: "/app/site.abc123.css", mediaType: "text/css; charset=utf-8", size: 11, sha256: "d".repeat(64) },
      { path: "assets/index.html", urlPath: "/", mediaType: "text/html; charset=utf-8", size: 12, sha256: "e".repeat(64) },
    ],
  };
}

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-online-snapshot-"));
  const manifestPath = path.join(root, "manifest.json");
  const manifestBytes = Buffer.from(canonicalJson(manifest()));
  await writeFile(manifestPath, manifestBytes);
  const manifestDigest = sha256(manifestBytes);
  const workflowRun = {
    repository: "metalagman/webappsec",
    id: runId,
    name: "Verify production",
    workflowPath: ".github/workflows/verify-production.yml",
    conclusion: "success",
    headBranch: "main",
    headSha: verifierRevision,
    event: "workflow_dispatch",
    htmlUrl: `https://github.com/metalagman/webappsec/actions/runs/${runId}`,
  };
  const verification = {
    record: {
      sourceRelease: {
        tag: releaseTag,
        manifestDigest,
        url: `https://github.com/metalagman/webappsec/releases/tag/${releaseTag}`,
      },
      github: {
        repository: "metalagman/webappsec",
        workflow: ".github/workflows/verify-production.yml",
        ref: "refs/heads/main",
        revision: verifierRevision,
        runUrl: workflowRun.htmlUrl,
      },
      production: { origin: "https://webappsec.metalagman.dev", verifiedAt: "2026-10-22T03:20:00.000Z" },
      result: "verified",
    },
    report: {
      ok: true,
      result: "verified",
      exitCode: 0,
      manifestDigest,
      layers: layerNames.map((name) => ({
        name,
        state: "pass",
        detail: name === "release-resolution"
          ? "/home/runner/work/webappsec/.artifacts/verification-release"
          : `${name} checked`,
      })),
    },
  };
  const source = {
    tag: releaseTag,
    revision,
    manifestDigest,
    manifestPath,
    checks: ["evidence-inventory", "signatures", "attestations", "sbom", "vulnerability-evidence"]
      .map((name) => ({ name, state: "pass", detail: `${name} checked` })),
  };
  const deployment = {
    record: {
      action: "deploy",
      sourceRelease: {
        tag: releaseTag,
        revision,
        manifestDigest,
        url: `https://github.com/metalagman/webappsec/releases/tag/${releaseTag}`,
      },
      github: {
        repository: "metalagman/webappsec",
        workflow: ".github/workflows/deploy.yml",
        ref: `refs/tags/${releaseTag}`,
        runUrl: `https://github.com/metalagman/webappsec/actions/runs/${deploymentRunId}`,
      },
      cloudflare: { workerName: "webappsec", versionId: workerVersion, deploymentId },
    },
  };
  return {
    root,
    manifestBytes,
    manifestDigest,
    workflowRun,
    verification,
    source,
    deployment,
    verificationCandidates: [{ release: verificationRelease, directory: path.join(root, "verification") }],
    sourceCandidates: [{ release: releaseTag, directory: path.join(root, "source") }],
    deploymentCandidates: [{ release: deploymentRelease, directory: path.join(root, "deployment") }],
    currentDeployment: {
      cloudflareStatus: { deploymentId, versions: [{ versionId: workerVersion, percentage: 100 }] },
      productionIdentity: { manifestDigest, workerVersion },
    },
  };
}

function boundaries(data, overrides = {}) {
  return {
    verifyVerificationEvidence: async () => structuredClone(data.verification),
    verifyReleaseEvidence: async () => structuredClone(data.source),
    inspectDeploymentEvidence: async () => structuredClone(data.deployment),
    verifyDeploymentEvidence: async () => structuredClone(data.deployment),
    ...overrides,
  };
}

async function resolve(data, overrides = {}, boundaryOverrides = {}) {
  const { currentDeployment = data.currentDeployment, ...options } = overrides;
  return resolveTrustedVerifierSnapshot({
    workflowRun: data.workflowRun,
    verificationCandidates: data.verificationCandidates,
    sourceCandidates: data.sourceCandidates,
    deploymentCandidates: data.deploymentCandidates,
    readCurrentDeployment: async () => structuredClone(currentDeployment),
    ...boundaries(data, boundaryOverrides),
    ...options,
  });
}

test("trusted resolver emits deterministic canonical snapshot and exact manifest bytes", async () => {
  const data = await fixture();
  const first = await resolve(data);
  const second = await resolve(data);

  assert.deepEqual(first, second);
  assert.deepEqual(first.manifestBytes, data.manifestBytes);
  assert.equal(first.snapshot.target.manifestDigest, data.manifestDigest);
  assert.equal(first.snapshot.target.workerVersion, workerVersion);
  assert.equal(first.snapshot.target.deploymentId, deploymentId);
  assert.equal(first.snapshot.verificationEvidence.release, verificationRelease);
  assert.equal(first.snapshot.deploymentEvidence.release, deploymentRelease);
  assert.deepEqual(first.snapshot.proofs.map(({ name }) => name), [
    "release-signatures", "deployment-signatures", "verification-signatures",
  ]);
  assert.equal(first.snapshotBytes.toString("utf8"), canonicalJson(first.snapshot));
  assert.equal(first.snapshot.verificationEvidence.layers[0].detail, releaseTag);
  assert.equal(first.snapshot.verificationEvidence.layers[2].detail, "signatures checked");
  assert.doesNotMatch(first.snapshotBytes.toString("utf8"), /home\/runner|CLOUDFLARE|GITHUB_TOKEN/);

  const outputDirectory = path.join(data.root, "output");
  await writeVerifierPublication({ outputDirectory, publication: first });
  assert.deepEqual(await readFile(path.join(outputDirectory, "current-verification.json")), first.snapshotBytes);
  assert.deepEqual(await readFile(path.join(outputDirectory, "release-manifest.json")), data.manifestBytes);
});

test("workflow run and immutable release selection fail closed", async (t) => {
  const data = await fixture();
  for (const [field, value] of [
    ["repository", "attacker/fork"],
    ["id", "not-numeric"],
    ["name", "Build pull request"],
    ["workflowPath", ".github/workflows/pr.yml"],
    ["conclusion", "failure"],
    ["headBranch", "feature"],
    ["headSha", "bad"],
    ["event", "pull_request"],
    ["htmlUrl", "https://attacker.example/run"],
  ]) {
    await t.test(`rejects workflow ${field}`, async () => {
      await assert.rejects(() => resolve(data, { workflowRun: { ...data.workflowRun, [field]: value } }), /workflow run/);
    });
  }
  await assert.rejects(() => resolve(data, { verificationCandidates: [] }), /exactly one verification release/);
  await assert.rejects(() => resolve(data, {
    verificationCandidates: [...data.verificationCandidates, { ...data.verificationCandidates[0], directory: `${data.root}/duplicate` }],
  }), /exactly one verification release/);
  await assert.rejects(() => resolve(data, { sourceCandidates: [] }), /exactly one source release/);
});

test("signature, evidence layer, and release identity failures are rejected", async (t) => {
  const data = await fixture();
  await assert.rejects(() => resolve(data, {}, {
    verifyVerificationEvidence: async () => { throw new Error("cosign signature invalid"); },
  }), /signature invalid/);

  const nonPass = structuredClone(data.verification);
  nonPass.report.layers[2].state = "fail";
  await assert.rejects(() => resolve(data, {}, {
    verifyVerificationEvidence: async () => nonPass,
  }), /CI layer/);

  const wrongRun = structuredClone(data.verification);
  wrongRun.record.github.runUrl = "https://github.com/metalagman/webappsec/actions/runs/1";
  await assert.rejects(() => resolve(data, {}, {
    verifyVerificationEvidence: async () => wrongRun,
  }), /workflow run identity/);

  const wrongSource = structuredClone(data.source);
  wrongSource.revision = "3".repeat(40);
  await assert.rejects(() => resolve(data, {}, {
    verifyReleaseEvidence: async () => wrongSource,
  }), /source release identity/);
});

test("Cloudflare drift and deployment ambiguity are rejected before publication", async () => {
  const data = await fixture();
  await assert.rejects(() => resolve(data, {
    currentDeployment: {
      cloudflareStatus: { deploymentId, versions: [
        { versionId: workerVersion, percentage: 50 },
        { versionId: "59600c79-f529-4ead-8df8-5b61acbe8ee4", percentage: 50 },
      ] },
      productionIdentity: { manifestDigest: data.manifestDigest, workerVersion },
    },
  }), /Cloudflare.*unambiguous/);

  await assert.rejects(() => resolve(data, {
    currentDeployment: {
      cloudflareStatus: { deploymentId: "59600c79-f529-4ead-8df8-5b61acbe8ee4", versions: [{ versionId: workerVersion, percentage: 100 }] },
      productionIdentity: { manifestDigest: data.manifestDigest, workerVersion },
    },
  }), /exactly one matching deployment release/);

  await assert.rejects(() => resolve(data, {
    deploymentCandidates: [...data.deploymentCandidates, { ...data.deploymentCandidates[0], directory: `${data.root}/duplicate-deployment` }],
  }), /exactly one matching deployment release/);
});

test("resolver rejects mid-run deployment drift and live-header disagreement", async () => {
  const data = await fixture();
  let reads = 0;
  await assert.rejects(() => resolve(data, {}, {
    readCurrentDeployment: async () => {
      reads += 1;
      if (reads === 1) return structuredClone(data.currentDeployment);
      return {
        cloudflareStatus: {
          deploymentId: "59600c79-f529-4ead-8df8-5b61acbe8ee4",
          versions: [{ versionId: workerVersion, percentage: 100 }],
        },
        productionIdentity: { manifestDigest: data.manifestDigest, workerVersion },
      };
    },
  }), /deployment changed during resolution/);
  assert.equal(reads, 2);

  await assert.rejects(() => resolve(data, {
    currentDeployment: {
      cloudflareStatus: data.currentDeployment.cloudflareStatus,
      productionIdentity: {
        manifestDigest: data.manifestDigest,
        workerVersion: "59600c79-f529-4ead-8df8-5b61acbe8ee4",
      },
    },
  }), /production identity.*Cloudflare/);
});

test("resolver binds deployment release action/run and enforces publication bounds", async () => {
  const data = await fixture();
  await assert.rejects(() => resolve(data, {
    deploymentCandidates: [{ ...data.deploymentCandidates[0], release: `deployment-rollback-${releaseTag}-${deploymentRunId}` }],
  }), /exactly one matching deployment release/);

  const huge = structuredClone(data.verification);
  huge.report.layers[0].detail = "x".repeat(2 * 1024 * 1024);
  await assert.rejects(() => resolve(data, {}, {
    verifyVerificationEvidence: async () => huge,
  }), /snapshot.*limit|layer detail.*limit/);
});
