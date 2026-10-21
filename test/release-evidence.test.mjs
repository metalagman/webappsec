import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { createRelease } from "../lib/artifact.mjs";
import { canonicalJson } from "../lib/canonical-json.mjs";
import {
  assembleReleaseEvidence,
  validateEvidenceIndex,
  validateProvenance,
  verifyEvidenceDirectory,
} from "../lib/release-evidence.mjs";

const repositoryRoot = path.resolve(new URL("..", import.meta.url).pathname);
const revision = "0123456789abcdef0123456789abcdef01234567";
const invocationId = "https://github.com/metalagman/webappsec/actions/runs/123/attempts/1";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-release-evidence-"));
  const release = await createRelease({
    outputRoot: path.join(root, "release"),
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision,
      tag: "v0.1.0",
      workflow: ".github/workflows/release.yml",
    },
    deployInputs: [
      { source: path.join(repositoryRoot, "worker/index.js"), path: "worker/index.js", role: "worker" },
      { source: path.join(repositoryRoot, "wrangler.jsonc"), path: "wrangler.jsonc", role: "configuration" },
    ],
  });
  const evidenceDirectory = path.join(root, "evidence");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(evidenceDirectory));
  for (const name of [
    "runtime.spdx.json",
    "runtime.cdx.json",
    "build.cdx.json",
    "runtime.vulnerabilities.json",
    "build.vulnerabilities.json",
  ]) await writeFile(path.join(evidenceDirectory, name), `${JSON.stringify({ fixture: name, manifestSha256: release.digest })}\n`);
  return { root, release, evidenceDirectory };
}

test("release evidence index and SLSA predicate are deterministic and cover every object", async () => {
  const { root, release, evidenceDirectory } = await fixture();
  const outputs = [path.join(root, "publish-a"), path.join(root, "publish-b")];
  for (const outputDirectory of outputs) {
    const result = await assembleReleaseEvidence({
      releaseDirectory: release.directory,
      tarPath: release.tarPath,
      evidenceDirectory,
      outputDirectory,
      repositoryRoot,
      invocationId,
    });
    assert.equal(result.manifestDigest, release.digest);
    assert.deepEqual(await verifyEvidenceDirectory(outputDirectory), { manifestDigest: release.digest, files: 9 });
  }
  const namesA = (await readdir(outputs[0])).sort();
  const namesB = (await readdir(outputs[1])).sort();
  assert.deepEqual(namesA, namesB);
  for (const name of namesA) assert.deepEqual(await readFile(path.join(outputs[0], name)), await readFile(path.join(outputs[1], name)));

  const indexBytes = await readFile(path.join(outputs[0], "evidence-index.json"));
  const index = JSON.parse(indexBytes);
  assert.deepEqual(indexBytes, Buffer.from(canonicalJson(index)));
  assert.equal(index.files.length, 8);
  assert.ok(index.files.some((entry) => entry.name === "manifest.json" && entry.sha256 === release.digest));
  assert.ok(index.files.some((entry) => entry.name === `${release.digest}.tar`));
  assert.ok(index.files.some((entry) => entry.name === "runtime.spdx.json"));
  assert.ok(index.files.some((entry) => entry.name === "runtime.vulnerabilities.json"));
  assert.ok(index.files.some((entry) => entry.name === "provenance.slsa.json"));
});

test("evidence verification and provenance policy reject tampering and mixed identities", async (t) => {
  const { root, release, evidenceDirectory } = await fixture();
  const outputDirectory = path.join(root, "publish");
  await assembleReleaseEvidence({
    releaseDirectory: release.directory,
    tarPath: release.tarPath,
    evidenceDirectory,
    outputDirectory,
    repositoryRoot,
    invocationId,
  });
  const index = JSON.parse(await readFile(path.join(outputDirectory, "evidence-index.json")));
  const provenance = JSON.parse(await readFile(path.join(outputDirectory, "provenance.slsa.json")));
  const manifest = JSON.parse(await readFile(path.join(outputDirectory, "manifest.json")));
  const lockDigest = sha256(await readFile(path.join(repositoryRoot, "package-lock.json")));
  const tarDigest = sha256(await readFile(path.join(outputDirectory, `${release.digest}.tar`)));
  const expected = { manifest, manifestDigest: release.digest, tarDigest, lockDigest, invocationId };

  await t.test("changed indexed bytes", async () => {
    await writeFile(path.join(outputDirectory, "runtime.spdx.json"), "changed\n");
    await assert.rejects(() => verifyEvidenceDirectory(outputDirectory), /index mismatch/);
  });

  await t.test("wrong workflow identity", () => {
    const candidate = structuredClone(provenance);
    candidate.runDetails.builder.id = "https://github.com/attacker/repo/.github/workflows/release.yml@refs/tags/v0.1.0";
    assert.throws(() => validateProvenance(candidate, expected), /builder identity/);
  });

  await t.test("wrong provenance subject", () => {
    const candidate = structuredClone(provenance);
    candidate.runDetails.byproducts.find((entry) => entry.name === `${release.digest}.tar`).digest.sha256 = "0".repeat(64);
    assert.throws(() => validateProvenance(candidate, expected), /subject mismatch/);
  });

  await t.test("duplicate evidence entry", () => {
    const candidate = structuredClone(index);
    candidate.files[1] = structuredClone(candidate.files[0]);
    assert.throws(() => validateEvidenceIndex(candidate, index.files), /duplicate|mismatch/);
  });
});

test("evidence directory policy is independent from the index and rejects symlinks", async (t) => {
  async function assembled() {
    const { root, release, evidenceDirectory } = await fixture();
    const outputDirectory = path.join(root, "publish");
    await assembleReleaseEvidence({
      releaseDirectory: release.directory,
      tarPath: release.tarPath,
      evidenceDirectory,
      outputDirectory,
      repositoryRoot,
      invocationId,
    });
    return { root, release, outputDirectory };
  }

  await t.test("mandatory SBOM removed from both directory and index", async () => {
    const { outputDirectory } = await assembled();
    const indexPath = path.join(outputDirectory, "evidence-index.json");
    const index = JSON.parse(await readFile(indexPath));
    index.files = index.files.filter((entry) => entry.name !== "runtime.spdx.json");
    await rm(path.join(outputDirectory, "runtime.spdx.json"));
    await writeFile(indexPath, canonicalJson(index));
    await assert.rejects(() => verifyEvidenceDirectory(outputDirectory), /coverage mismatch/);
  });

  await t.test("forged release identity", async () => {
    const { outputDirectory } = await assembled();
    const indexPath = path.join(outputDirectory, "evidence-index.json");
    const index = JSON.parse(await readFile(indexPath));
    index.release.revision = "f".repeat(40);
    index.release.tag = "v9.9.9";
    await writeFile(indexPath, canonicalJson(index));
    await assert.rejects(() => verifyEvidenceDirectory(outputDirectory), /release identity mismatch/);
  });

  await t.test("external symlink at a mandatory filename", async () => {
    const { root, outputDirectory } = await assembled();
    const filename = path.join(outputDirectory, "runtime.spdx.json");
    const external = path.join(root, "external.json");
    await writeFile(external, await readFile(filename));
    await rm(filename);
    await symlink(external, filename);
    await assert.rejects(() => verifyEvidenceDirectory(outputDirectory), /regular file/);
  });

  await t.test("external symlink at evidence-index.json", async () => {
    const { root, outputDirectory } = await assembled();
    const filename = path.join(outputDirectory, "evidence-index.json");
    const external = path.join(root, "external-index.json");
    await writeFile(external, await readFile(filename));
    await rm(filename);
    await symlink(external, filename);
    await assert.rejects(() => verifyEvidenceDirectory(outputDirectory), /index must be a regular file/);
  });
});

test("workflows keep verification read-only and signing isolated to the SHA-pinned tag job", async () => {
  const verifyWorkflow = await readFile(path.join(repositoryRoot, ".github/workflows/verify.yml"), "utf8");
  const releaseWorkflow = await readFile(path.join(repositoryRoot, ".github/workflows/release.yml"), "utf8");
  const releaseScript = await readFile(path.join(repositoryRoot, "scripts/release-ci.sh"), "utf8");
  const signingInstaller = await readFile(path.join(repositoryRoot, "tools/install-cosign.sh"), "utf8");

  assert.match(verifyWorkflow, /permissions:\n  contents: read/);
  assert.doesNotMatch(verifyWorkflow, /id-token: write|contents: write|secrets\./);
  assert.match(releaseWorkflow, /tags: \["v\*"\]/);
  assert.match(releaseWorkflow, /contents: write\n      id-token: write/);
  assert.doesNotMatch(releaseWorkflow, /pull_request:/);
  for (const workflow of [verifyWorkflow, releaseWorkflow]) {
    for (const line of workflow.split("\n").filter((candidate) => candidate.includes("uses:"))) {
      assert.match(line, /uses: [A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}(?:\s+#\s+v[0-9.]+)?$/);
    }
  }
  assert.match(signingInstaller, /COSIGN_VERSION=3\.1\.3/);
  assert.match(signingInstaller, /COSIGN_SHA256=[a-f0-9]{64}/);
  assert.match(releaseScript, /sign-blob --yes --bundle/);
  assert.match(releaseScript, /cosign attest-blob --yes --predicate/);
  assert.match(releaseScript, /attest_blob .*provenance\.slsa\.json slsaprovenance1/);
  assert.match(releaseScript, /attest_blob .*\.cdx\.json cyclonedx/);
  assert.match(releaseScript, /certificate-identity/);
  assert.match(releaseScript, /refusing to replace existing release/);
  assert.match(releaseScript, /gh release create[\s\S]+--draft[\s\S]+gh release edit "\$tag" --draft=false/);
});
