import { createHash } from "node:crypto";
import { copyFile, lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { validateManifest, verifyRelease, verifyReleaseTar } from "./artifact.mjs";
import { canonicalJson } from "./canonical-json.mjs";

export const evidenceIndexSchema = "https://webappsec.metalagman.dev/schema/evidence-index-v1";
export const slsaPredicateType = "https://slsa.dev/provenance/v1";
export const cycloneDxPredicateType = "https://cyclonedx.org/bom";
export const releaseWorkflow = ".github/workflows/release.yml";
export const authenticationBundleNames = [
  "build-cyclonedx.intoto.sigstore.json",
  "evidence-index.sigstore.json",
  "manifest.sigstore.json",
  "provenance.manifest.intoto.sigstore.json",
  "provenance.release.intoto.sigstore.json",
  "release.sigstore.json",
  "runtime-cyclonedx.intoto.sigstore.json",
];

const evidenceFiles = [
  ["runtime.spdx.json", "sbom", "spdx-2.3"],
  ["runtime.cdx.json", "sbom", "cyclonedx-1.7-runtime"],
  ["build.cdx.json", "sbom", "cyclonedx-1.7-build"],
  ["runtime.vulnerabilities.json", "vulnerability-report", "runtime"],
  ["build.vulnerabilities.json", "vulnerability-report", "build"],
];
const maxIndexSize = 2 * 1024 * 1024;
const maxEvidenceFileSize = 100 * 1024 * 1024;

function buildType(revision) {
  return `https://github.com/metalagman/webappsec/blob/${revision}/docs/build-type.md`;
}

function requiredFilePolicy(manifestDigest) {
  return [
    { name: "manifest.json", role: "deployment-manifest", format: "canonical-json" },
    { name: `${manifestDigest}.tar`, role: "release-artifact", format: "ustar" },
    { name: "provenance.slsa.json", role: "provenance-predicate", format: slsaPredicateType },
    ...evidenceFiles.map(([name, role, format]) => ({ name, role, format })),
  ].sort((a, b) => a.name.localeCompare(b.name, "en"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fileDescriptor(filename, role, format) {
  const bytes = await readFile(filename);
  return {
    name: path.basename(filename),
    role,
    format,
    size: bytes.length,
    sha256: sha256(bytes),
  };
}

function assertDigest(value, label) {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error(`invalid ${label}`);
}

function assertTag(tag) {
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(tag)) throw new Error("release tag must be immutable semver");
}

export function validateProvenance(predicate, { manifest, manifestDigest, tarDigest, lockDigest, invocationId }) {
  const definition = predicate?.buildDefinition;
  const details = predicate?.runDetails;
  if (definition?.buildType !== buildType(manifest.release.revision)) {
    throw new Error("unexpected provenance build type");
  }
  if (definition.externalParameters?.repository !== manifest.release.repository
    || definition.externalParameters?.revision !== manifest.release.revision
    || definition.externalParameters?.tag !== manifest.release.tag
    || definition.externalParameters?.workflow !== manifest.release.workflow
    || definition.externalParameters?.origin !== manifest.origin) {
    throw new Error("provenance external parameters mismatch");
  }
  const dependencies = new Map((definition.resolvedDependencies ?? []).map((entry) => [entry.name, entry]));
  if (dependencies.get("source")?.digest?.gitCommit !== manifest.release.revision
    || dependencies.get("package-lock.json")?.digest?.sha256 !== lockDigest) {
    throw new Error("provenance materials mismatch");
  }
  const byproducts = new Map((details?.byproducts ?? []).map((entry) => [entry.name, entry]));
  if (byproducts.get("manifest.json")?.digest?.sha256 !== manifestDigest
    || byproducts.get(`${manifestDigest}.tar`)?.digest?.sha256 !== tarDigest) {
    throw new Error("provenance subject mismatch");
  }
  const expectedBuilder = `https://github.com/metalagman/webappsec/${releaseWorkflow}@refs/tags/${manifest.release.tag}`;
  if (details?.builder?.id !== expectedBuilder || details?.metadata?.invocationId !== invocationId) {
    throw new Error("provenance builder identity mismatch");
  }
}

export function validateEvidenceIndex(index, expectedFiles) {
  if (index?.schema !== evidenceIndexSchema || index?.version !== 1) throw new Error("invalid evidence index envelope");
  assertDigest(index.release?.manifestSha256, "index manifest digest");
  if (index.release?.repository !== "https://github.com/metalagman/webappsec"
    || index.release?.workflow !== releaseWorkflow) throw new Error("invalid evidence index release identity");
  if (!/^[a-f0-9]{40}$/.test(index.release?.revision ?? "")) throw new Error("invalid evidence index revision");
  assertTag(index.release?.tag);
  const policy = requiredFilePolicy(index.release.manifestSha256);
  if (!Array.isArray(index.files) || index.files.length !== policy.length) throw new Error("evidence index coverage mismatch");
  const sorted = [...index.files].sort((a, b) => a.name.localeCompare(b.name, "en"));
  if (JSON.stringify(index.files) !== JSON.stringify(sorted)) throw new Error("evidence index is not sorted");
  const names = new Set();
  for (let indexPosition = 0; indexPosition < index.files.length; indexPosition += 1) {
    const entry = index.files[indexPosition];
    const required = policy[indexPosition];
    if (names.has(entry.name) || path.basename(entry.name) !== entry.name) throw new Error("unsafe or duplicate evidence filename");
    names.add(entry.name);
    if (entry.name !== required.name || entry.role !== required.role || entry.format !== required.format) {
      throw new Error(`evidence index policy mismatch: ${entry.name}`);
    }
    if (canonicalJson(Object.keys(entry).sort()) !== canonicalJson(["format", "name", "role", "sha256", "size"])) {
      throw new Error(`unexpected evidence index fields: ${entry.name}`);
    }
    assertDigest(entry.sha256, `digest for ${entry.name}`);
    if (!Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > maxEvidenceFileSize) throw new Error(`invalid size for ${entry.name}`);
  }
  if (expectedFiles) {
    if (expectedFiles.length !== policy.length) throw new Error("actual evidence coverage mismatch");
    for (const expected of expectedFiles) {
      const actual = index.files.find((entry) => entry.name === expected.name);
      if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`evidence index mismatch: ${expected.name}`);
    }
  }
}

export async function assembleReleaseEvidence({
  releaseDirectory,
  tarPath,
  evidenceDirectory,
  outputDirectory,
  repositoryRoot,
  invocationId,
}) {
  if (!invocationId || !/^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/[0-9]+\/attempts\/[0-9]+$/.test(invocationId)) {
    throw new Error("invalid GitHub Actions invocation ID");
  }
  const releaseResult = await verifyRelease(releaseDirectory);
  const tarResult = await verifyReleaseTar(tarPath);
  if (releaseResult.digest !== tarResult.digest) throw new Error("release directory and tar disagree");
  const manifestBytes = await readFile(path.join(releaseDirectory, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  assertTag(manifest.release.tag);
  if (manifest.release.workflow !== releaseWorkflow) throw new Error("manifest has unexpected release workflow");
  const tarBytes = await readFile(tarPath);
  const tarDigest = sha256(tarBytes);
  const releaseTarName = `${releaseResult.digest}.tar`;
  const lockBytes = await readFile(path.join(repositoryRoot, "package-lock.json"));
  const lockDigest = sha256(lockBytes);

  const provenance = {
    buildDefinition: {
      buildType: buildType(manifest.release.revision),
      externalParameters: {
        origin: manifest.origin,
        repository: manifest.release.repository,
        revision: manifest.release.revision,
        tag: manifest.release.tag,
        workflow: manifest.release.workflow,
      },
      internalParameters: {
        nodeVersion: "22.23.1",
        runner: "ubuntu-24.04",
      },
      resolvedDependencies: [
        {
          name: "package-lock.json",
          uri: `${manifest.release.repository}/blob/${manifest.release.revision}/package-lock.json`,
          digest: { sha256: lockDigest },
        },
        {
          name: "source",
          uri: `git+${manifest.release.repository}@refs/tags/${manifest.release.tag}`,
          digest: { gitCommit: manifest.release.revision },
        },
      ],
    },
    runDetails: {
      builder: {
        id: `https://github.com/metalagman/webappsec/${releaseWorkflow}@refs/tags/${manifest.release.tag}`,
      },
      metadata: { invocationId },
      byproducts: [
        { name: "manifest.json", digest: { sha256: releaseResult.digest } },
        { name: releaseTarName, digest: { sha256: tarDigest } },
      ],
    },
  };
  validateProvenance(provenance, {
    manifest,
    manifestDigest: releaseResult.digest,
    tarDigest,
    lockDigest,
    invocationId,
  });

  await rm(outputDirectory, { recursive: true, force: true });
  await mkdir(outputDirectory, { recursive: true });
  await Promise.all([
    writeFile(path.join(outputDirectory, "manifest.json"), manifestBytes),
    writeFile(path.join(outputDirectory, releaseTarName), tarBytes),
    writeFile(path.join(outputDirectory, "provenance.slsa.json"), canonicalJson(provenance)),
    ...evidenceFiles.map(([name]) => copyFile(path.join(evidenceDirectory, name), path.join(outputDirectory, name))),
  ]);

  const descriptors = await Promise.all([
    fileDescriptor(path.join(outputDirectory, "manifest.json"), "deployment-manifest", "canonical-json"),
    fileDescriptor(path.join(outputDirectory, releaseTarName), "release-artifact", "ustar"),
    fileDescriptor(path.join(outputDirectory, "provenance.slsa.json"), "provenance-predicate", slsaPredicateType),
    ...evidenceFiles.map(([name, role, format]) => fileDescriptor(path.join(outputDirectory, name), role, format)),
  ]);
  descriptors.sort((a, b) => a.name.localeCompare(b.name, "en"));
  const index = {
    schema: evidenceIndexSchema,
    version: 1,
    release: {
      repository: manifest.release.repository,
      revision: manifest.release.revision,
      tag: manifest.release.tag,
      workflow: manifest.release.workflow,
      manifestSha256: releaseResult.digest,
    },
    files: descriptors,
  };
  validateEvidenceIndex(index, descriptors);
  await writeFile(path.join(outputDirectory, "evidence-index.json"), canonicalJson(index));
  return { manifestDigest: releaseResult.digest, tarDigest, files: descriptors.length + 1 };
}

export async function verifyEvidenceDirectory(directory, repositoryRoot = path.resolve("."), { authenticationFiles = [] } = {}) {
  const indexPath = path.join(directory, "evidence-index.json");
  const indexMetadata = await lstat(indexPath);
  if (indexMetadata.isSymbolicLink() || !indexMetadata.isFile()) throw new Error("evidence index must be a regular file");
  if (indexMetadata.size > maxIndexSize) throw new Error("evidence index exceeds size limit");
  const indexBytes = await readFile(indexPath);
  const index = JSON.parse(indexBytes);
  if (!indexBytes.equals(Buffer.from(canonicalJson(index)))) throw new Error("evidence index is not canonical");
  validateEvidenceIndex(index);
  for (const name of authenticationFiles) {
    if (!authenticationBundleNames.includes(name)) throw new Error(`unexpected authentication filename: ${name}`);
  }
  const allowed = new Set(["evidence-index.json", ...index.files.map((entry) => entry.name), ...authenticationFiles]);
  const actualNames = await readdir(directory);
  for (const name of actualNames) if (!allowed.has(name)) throw new Error(`unexpected evidence file: ${name}`);
  if (actualNames.length !== allowed.size) throw new Error("evidence directory inventory is incomplete");

  const expected = [];
  for (const entry of index.files) {
    const filename = path.join(directory, entry.name);
    const metadata = await lstat(filename);
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`evidence must be a regular file: ${entry.name}`);
    if (metadata.size > maxEvidenceFileSize) throw new Error(`evidence exceeds size limit: ${entry.name}`);
    const descriptor = await fileDescriptor(filename, entry.role, entry.format);
    expected.push(descriptor);
  }
  validateEvidenceIndex(index, expected);

  const manifestBytes = await readFile(path.join(directory, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  if (!manifestBytes.equals(Buffer.from(canonicalJson(manifest)))) throw new Error("indexed manifest is not canonical");
  validateManifest(manifest);
  const manifestDigest = sha256(manifestBytes);
  if (manifestDigest !== index.release.manifestSha256
    || manifest.release.repository !== index.release.repository
    || manifest.release.revision !== index.release.revision
    || manifest.release.tag !== index.release.tag
    || manifest.release.workflow !== index.release.workflow) {
    throw new Error("manifest and evidence index release identity mismatch");
  }
  const tarPath = path.join(directory, `${manifestDigest}.tar`);
  const tarResult = await verifyReleaseTar(tarPath);
  if (tarResult.digest !== manifestDigest) throw new Error("release tar subject mismatch");
  const tarDigest = sha256(await readFile(tarPath));
  const lockDigest = sha256(await readFile(path.join(repositoryRoot, "package-lock.json")));
  const provenanceBytes = await readFile(path.join(directory, "provenance.slsa.json"));
  const provenance = JSON.parse(provenanceBytes);
  if (!provenanceBytes.equals(Buffer.from(canonicalJson(provenance)))) throw new Error("provenance predicate is not canonical");
  validateProvenance(provenance, {
    manifest,
    manifestDigest,
    tarDigest,
    lockDigest,
    invocationId: provenance.runDetails?.metadata?.invocationId,
  });
  return { manifestDigest: index.release.manifestSha256, files: allowed.size };
}
