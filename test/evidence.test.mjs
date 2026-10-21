import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  grypeVersion,
  lockInventory,
  syftVersion,
  unavailableVulnerabilityReport,
  validateCycloneDx,
  validateSpdx,
  validateVulnerabilityReport,
  scanVulnerabilitySbom,
  vulnerabilityReport,
} from "../lib/evidence.mjs";

const manifestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const manifest = {
  release: { tag: "v0.1.0" },
  files: [{ path: "assets/index.html", sha256: "a".repeat(64), urlPath: "/", size: 1 }],
  inputs: [
    { path: "worker/index.js", role: "worker", sha256: "b".repeat(64), size: 1 },
    { path: "wrangler.jsonc", role: "configuration", sha256: "c".repeat(64), size: 1 },
  ],
};

function spdxDocument() {
  const expectedFiles = [
    ["assets/index.html", "a".repeat(64)],
    ["inputs/worker/index.js", "b".repeat(64)],
    ["inputs/wrangler.jsonc", "c".repeat(64)],
    ["manifest.json", manifestDigest],
  ];
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `webappsec-runtime-${manifestDigest}`,
    documentNamespace: `https://github.com/metalagman/webappsec/releases/v0.1.0/sbom/runtime/${manifestDigest}`,
    creationInfo: { created: "2026-10-21T12:34:56Z", creators: [`Tool: syft-${syftVersion}`] },
    documentDescribes: ["SPDXRef-Package-webappsec-runtime"],
    packages: [{
      SPDXID: "SPDXRef-Package-webappsec-runtime",
      name: "webappsec-runtime",
      versionInfo: manifestDigest,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: true,
      packageVerificationCode: { packageVerificationCodeValue: "0".repeat(40) },
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: `pkg:generic/webappsec-runtime@${manifestDigest}` }],
    }],
    files: expectedFiles.map(([fileName, sha256], index) => ({
      fileName: `./${fileName}`,
      SPDXID: `SPDXRef-File-${index + 1}`,
      checksums: [{ algorithm: "SHA1", checksumValue: String(index).padStart(40, "0") }, { algorithm: "SHA256", checksumValue: sha256 }],
      licenseConcluded: "NOASSERTION",
      copyrightText: "NOASSERTION",
    })),
    relationships: expectedFiles.map((_, index) => ({
      spdxElementId: "SPDXRef-Package-webappsec-runtime",
      relationshipType: "CONTAINS",
      relatedSpdxElement: `SPDXRef-File-${index + 1}`,
    })),
  };
}

const buildLock = {
  packages: {
    "": { devDependencies: { "@playwright/test": "1.64.1", ajv: "8.20.0", wrangler: "4.151.3" } },
    "node_modules/@playwright/test": { version: "1.64.1", dev: true },
    "node_modules/ajv": { version: "8.20.0", dev: true, dependencies: { "ajv-formats": "3.0.1" } },
    "node_modules/ajv-formats": { version: "3.0.1", dev: true },
    "node_modules/wrangler": { version: "4.151.3", dev: true },
  },
};

function buildCycloneDx() {
  const inventory = lockInventory(buildLock);
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    version: 1,
    metadata: {
      timestamp: "2026-10-21T12:34:56Z",
      tools: { components: [{ type: "application", name: "syft", version: syftVersion }] },
      component: {
        type: "application",
        "bom-ref": "pkg:generic/webappsec-build",
        name: "webappsec-build",
        version: manifestDigest,
        properties: [
          { name: "dev.metalagman.webappsec:scope", value: "build" },
          { name: "dev.metalagman.webappsec:manifest-sha256", value: manifestDigest },
        ],
      },
    },
    components: inventory.components,
    dependencies: inventory.dependencies,
  };
}

function runtimeCycloneDx() {
  const files = [
    ["assets/index.html", "a".repeat(64), "public-asset"],
    ["inputs/worker/index.js", "b".repeat(64), "worker-runtime"],
    ["inputs/wrangler.jsonc", "c".repeat(64), "deployment-configuration"],
    ["manifest.json", manifestDigest, "deployment-manifest"],
  ];
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    version: 1,
    metadata: {
      component: {
        type: "application",
        "bom-ref": `pkg:generic/webappsec-runtime@${manifestDigest}`,
        name: "webappsec-runtime",
        version: manifestDigest,
        properties: [
          { name: "dev.metalagman.webappsec:scope", value: "runtime" },
          { name: "dev.metalagman.webappsec:manifest-sha256", value: manifestDigest },
        ],
      },
    },
    components: files.map(([name, hash, category]) => ({
      type: "file",
      "bom-ref": `file:${name}`,
      name,
      hashes: [{ alg: "SHA-256", content: hash }],
      properties: [{ name: "dev.metalagman.webappsec:category", value: category }],
    })),
  };
}

test("SBOM validation rejects release subject and build inventory tampering", () => {
  const spdx = spdxDocument();
  validateSpdx(spdx, manifest, manifestDigest);
  const wrongSubject = structuredClone(spdx);
  wrongSubject.packages[0].versionInfo = "f".repeat(64);
  assert.throws(() => validateSpdx(wrongSubject, manifest, manifestDigest), /subject mismatch/);
  const missingRuntimeFile = structuredClone(spdx);
  missingRuntimeFile.files.pop();
  assert.throws(() => validateSpdx(missingRuntimeFile, manifest, manifestDigest), /coverage mismatch/);

  const build = buildCycloneDx();
  validateCycloneDx(build, manifestDigest, "build", manifest, buildLock);
  const wrongBuildSubject = structuredClone(build);
  wrongBuildSubject.metadata.component = {
    ...wrongBuildSubject.metadata.component,
    type: "library",
    name: "unrelated-product",
    "bom-ref": "pkg:generic/unrelated-product",
  };
  assert.throws(() => validateCycloneDx(wrongBuildSubject, manifestDigest, "build", manifest, buildLock), /build subject mismatch/);
  const missingTransitive = structuredClone(build);
  missingTransitive.components = missingTransitive.components.filter((entry) => entry.name !== "ajv-formats");
  assert.throws(() => validateCycloneDx(missingTransitive, manifestDigest, "build", manifest, buildLock), /does not match package-lock/);
  const missingGraph = structuredClone(build);
  delete missingGraph.dependencies;
  assert.throws(() => validateCycloneDx(missingGraph, manifestDigest, "build", manifest, buildLock), /dependency graph/);

  const runtime = runtimeCycloneDx();
  validateCycloneDx(runtime, manifestDigest, "runtime", manifest);
  const wrongRuntimeSubject = structuredClone(runtime);
  wrongRuntimeSubject.metadata.component.name = "unrelated-runtime";
  assert.throws(() => validateCycloneDx(wrongRuntimeSubject, manifestDigest, "runtime", manifest), /runtime subject mismatch/);
  const duplicateRuntime = structuredClone(runtime);
  duplicateRuntime.components.push({ ...duplicateRuntime.components[0], "bom-ref": "file:duplicate" });
  assert.throws(() => validateCycloneDx(duplicateRuntime, manifestDigest, "runtime", manifest), /coverage mismatch|duplicate/);
});

test("vulnerability evidence distinguishes zero findings, findings, and unavailable scans", () => {
  const descriptor = {
    version: grypeVersion,
    timestamp: "2026-10-21T12:34:56Z",
    db: {
      status: {
        built: "2026-10-20T00:00:00Z",
        schemaVersion: "v6.1.3",
        checksum: "sha256:0123456789abcdef",
      },
    },
  };
  const clean = vulnerabilityReport({ scope: "runtime", manifestDigest, grype: { descriptor, matches: [], ignoredMatches: [] } });
  assert.equal(clean.status, "complete");
  assert.equal(clean.result, "no-known-vulnerabilities");
  assert.equal(clean.findingsCount, 0);
  assert.deepEqual(clean.findings, []);
  assert.deepEqual(clean.scanner.database, descriptor.db);
  assert.equal(clean.scanner.scanTimestamp, descriptor.timestamp);
  assert.equal(clean.ignoredFindingsCount, 0);

  const finding = { vulnerability: { id: "CVE-2099-0001", severity: "High" }, artifact: { name: "fixture", version: "1.0.0" } };
  const affected = vulnerabilityReport({ scope: "build", manifestDigest, grype: { descriptor, matches: [finding], ignoredMatches: [finding] } });
  assert.equal(affected.result, "findings");
  assert.equal(affected.findingsCount, 1);
  assert.deepEqual(affected.findings, [finding]);
  assert.equal(affected.ignoredFindingsCount, 1);
  assert.deepEqual(affected.ignoredFindings, [finding]);

  const ignoredOnly = vulnerabilityReport({ scope: "runtime", manifestDigest, grype: { descriptor, matches: [], ignoredMatches: [finding] } });
  assert.equal(ignoredOnly.result, "findings");
  assert.equal(ignoredOnly.findingsCount, 0);
  assert.equal(ignoredOnly.ignoredFindingsCount, 1);

  assert.throws(() => vulnerabilityReport({
    scope: "runtime",
    manifestDigest,
    grype: { descriptor: { ...descriptor, version: "0.120.0" }, matches: [] },
  }), /schema validation|scanner metadata/);
  assert.throws(() => vulnerabilityReport({
    scope: "runtime",
    manifestDigest,
    grype: { descriptor: { ...descriptor, db: {} }, matches: [] },
  }), /schema validation|scanner metadata/);

  const inconsistentCounts = structuredClone(clean);
  inconsistentCounts.findingsCount = 999;
  assert.throws(() => validateVulnerabilityReport(inconsistentCounts), /count mismatch/);

  const unavailable = unavailableVulnerabilityReport({ scope: "runtime", manifestDigest, reason: "database unavailable" });
  assert.equal(unavailable.status, "unavailable");
  assert.equal(unavailable.result, "not-scanned");
  assert.equal(unavailable.findingsCount, null);
  assert.equal(unavailable.ignoredFindingsCount, null);
  assert.equal("findings" in unavailable, false);
  assert.throws(() => unavailableVulnerabilityReport({ scope: "runtime", manifestDigest, reason: "" }), /requires a reason/);
});

test("tool acquisition pins versions and upstream archive checksums", async () => {
  const installer = await readFile(new URL("../tools/install-evidence-tools.sh", import.meta.url), "utf8");
  assert.match(installer, /SYFT_VERSION=1\.55\.0/);
  assert.match(installer, /SYFT_SHA256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d/);
  assert.match(installer, /GRYPE_VERSION=0\.121\.0/);
  assert.match(installer, /GRYPE_SHA256=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519/);
  assert.match(installer, /sha256sum --check --status/);
});

test("scanner failure writes unavailable evidence and rejects the generation gate", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-grype-failure-"));
  const scanner = path.join(directory, "grype");
  const outputPath = path.join(directory, "runtime.vulnerabilities.json");
  await writeFile(scanner, "#!/bin/sh\necho 'database unavailable' >&2\nexit 9\n");
  await chmod(scanner, 0o755);
  await assert.rejects(() => scanVulnerabilitySbom({
    grypePath: scanner,
    sbomPath: path.join(directory, "runtime.cdx.json"),
    scope: "runtime",
    manifestDigest,
    outputPath,
  }), /scan unavailable.*exited 9/i);
  const report = JSON.parse(await readFile(outputPath, "utf8"));
  assert.equal(report.status, "unavailable");
  assert.equal(report.result, "not-scanned");
  assert.equal(report.findingsCount, null);
  assert.match(report.reason, /database unavailable/);
});
