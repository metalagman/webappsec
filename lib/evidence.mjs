import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import Ajv from "ajv";
import Ajv2019 from "ajv/dist/2019.js";
import Ajv2020 from "ajv/dist/2020.js";

import { verifyRelease } from "./artifact.mjs";

export const evidenceSchema = "https://webappsec.metalagman.dev/schema/vulnerability-report-v1";
export const syftVersion = "1.55.0";
export const grypeVersion = "0.121.0";

const [cycloneDxSchema, cycloneDxSpdxSchema, jsfSchema, cryptographySchema, spdxSchema, vulnerabilitySchema] = await Promise.all([
  readFile(new URL("../schemas/cyclonedx-1.7.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("../schemas/spdx.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("../schemas/jsf-0.82.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("../schemas/cryptography-defs.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("../schemas/spdx-2.3.schema.json", import.meta.url), "utf8").then(JSON.parse),
  readFile(new URL("../schemas/vulnerability-report-v1.schema.json", import.meta.url), "utf8").then(JSON.parse),
]);
const cycloneDxAjv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
cycloneDxAjv.addSchema(cycloneDxSpdxSchema).addSchema(jsfSchema).addSchema(cryptographySchema);
const validateCycloneDxSchema = cycloneDxAjv.compile(cycloneDxSchema);
const validateSpdxSchema = new Ajv2019({ allErrors: true, strict: false, validateFormats: false }).compile(spdxSchema);
const validateVulnerabilitySchema = new Ajv2020({ allErrors: true, strict: false, validateFormats: false }).compile(vulnerabilitySchema);

function assertSchema(validate, document, label) {
  if (!validate(document)) throw new Error(`${label} schema validation failed: ${JSON.stringify(validate.errors)}`);
}

function digest(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest("hex");
}

async function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => {
      const output = Buffer.concat(stdout).toString("utf8");
      const errorOutput = Buffer.concat(stderr).toString("utf8");
      if (code === 0) resolve({ stdout: output, stderr: errorOutput });
      else reject(new Error(`${path.basename(command)} exited ${code}: ${errorOutput.trim() || output.trim()}`));
    });
  });
}

function property(name, value) {
  return { name: `dev.metalagman.webappsec:${name}`, value };
}

function expectedReleaseFiles(manifest, manifestDigest) {
  return [
    ...manifest.files.map((entry) => ({ ...entry, category: "public-asset", urlPath: entry.urlPath })),
    ...manifest.inputs.map((entry) => ({
      path: `inputs/${entry.path}`,
      size: entry.size,
      sha256: entry.sha256,
      category: entry.role === "worker" ? "worker-runtime" : "deployment-configuration",
    })),
    { path: "manifest.json", size: null, sha256: manifestDigest, category: "deployment-manifest" },
  ].sort((a, b) => a.path.localeCompare(b.path, "en"));
}

async function runtimeFiles(releaseDirectory, manifest, manifestDigest) {
  return Promise.all(expectedReleaseFiles(manifest, manifestDigest).map(async (entry, index) => {
    const bytes = await readFile(path.join(releaseDirectory, entry.path));
    if (digest("sha256", bytes) !== entry.sha256) throw new Error(`manifest digest mismatch: ${entry.path}`);
    return {
      entry,
      sha1: digest("sha1", bytes),
      spdxId: `SPDXRef-File-${index + 1}`,
      bomRef: `file:${entry.path}`,
    };
  }));
}

function enrichSpdx(document, manifest, manifestDigest, files) {
  document.name = `webappsec-runtime-${manifestDigest}`;
  document.documentNamespace = `https://github.com/metalagman/webappsec/releases/${manifest.release.tag}/sbom/runtime/${manifestDigest}`;
  document.documentDescribes = ["SPDXRef-Package-webappsec-runtime"];
  document.packages = [{
    SPDXID: "SPDXRef-Package-webappsec-runtime",
    name: "webappsec-runtime",
    versionInfo: manifestDigest,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: true,
    packageVerificationCode: {
      packageVerificationCodeValue: digest("sha1", Buffer.from(files.map((file) => file.sha1).sort().join(""))),
    },
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    externalRefs: [{
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: `pkg:generic/webappsec-runtime@${manifestDigest}`,
    }],
  }];
  document.files = files.map(({ entry, sha1, spdxId }) => ({
    fileName: `./${entry.path}`,
    SPDXID: spdxId,
    checksums: [
      { algorithm: "SHA1", checksumValue: sha1 },
      { algorithm: "SHA256", checksumValue: entry.sha256 },
    ],
    licenseConcluded: "NOASSERTION",
    copyrightText: "NOASSERTION",
  }));
  document.relationships = [
    { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package-webappsec-runtime" },
    ...files.map(({ spdxId }) => ({
      spdxElementId: "SPDXRef-Package-webappsec-runtime",
      relationshipType: "CONTAINS",
      relatedSpdxElement: spdxId,
    })),
  ];
  return document;
}

function enrichRuntimeCycloneDx(document, manifestDigest, files) {
  document.metadata.component = {
    type: "application",
    "bom-ref": `pkg:generic/webappsec-runtime@${manifestDigest}`,
    name: "webappsec-runtime",
    version: manifestDigest,
    properties: [property("scope", "runtime"), property("manifest-sha256", manifestDigest)],
  };
  document.components = files.map(({ entry, bomRef }) => ({
    type: "file",
    "bom-ref": bomRef,
    name: entry.path,
    hashes: [{ alg: "SHA-256", content: entry.sha256 }],
    properties: [
      property("category", entry.category),
      ...(entry.urlPath ? [property("url-path", entry.urlPath)] : []),
    ],
  }));
  return document;
}

function npmName(packagePath) {
  return packagePath.slice(packagePath.lastIndexOf("node_modules/") + "node_modules/".length);
}

function npmPurl(name, version) {
  const escapedName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${escapedName}@${version}`;
}

export function lockInventory(lock) {
  const records = Object.entries(lock.packages ?? {}).filter(([packagePath, entry]) => packagePath && entry?.version);
  const byPath = new Map(records.map(([packagePath, entry]) => [packagePath, {
    type: "library",
    "bom-ref": `lock:${packagePath}`,
    name: npmName(packagePath),
    version: entry.version,
    purl: npmPurl(npmName(packagePath), entry.version),
    properties: [
      property("lock-path", packagePath),
      property("development", String(Boolean(entry.dev))),
    ],
  }]));
  const resolve = (parentPath, dependency) => {
    const nested = `${parentPath}/node_modules/${dependency}`;
    if (byPath.has(nested)) return nested;
    const root = `node_modules/${dependency}`;
    return byPath.has(root) ? root : null;
  };
  const rootRef = "pkg:generic/webappsec-build";
  const rootDependencies = Object.keys({
    ...(lock.packages?.[""]?.dependencies ?? {}),
    ...(lock.packages?.[""]?.devDependencies ?? {}),
  }).map((name) => resolve("", name)).filter(Boolean).map((packagePath) => byPath.get(packagePath)["bom-ref"]);
  const dependencies = [{ ref: rootRef, dependsOn: [...new Set(rootDependencies)].sort() }];
  for (const [packagePath, entry] of records) {
    const names = Object.keys({ ...(entry.dependencies ?? {}), ...(entry.optionalDependencies ?? {}) });
    dependencies.push({
      ref: byPath.get(packagePath)["bom-ref"],
      dependsOn: [...new Set(names.map((name) => resolve(packagePath, name)).filter(Boolean).map((resolved) => byPath.get(resolved)["bom-ref"]))].sort(),
    });
  }
  return { components: [...byPath.values()].sort((a, b) => a["bom-ref"].localeCompare(b["bom-ref"], "en")), dependencies, rootRef };
}

function enrichBuildCycloneDx(document, manifestDigest, lock) {
  const inventory = lockInventory(lock);
  document.metadata.component = {
    type: "application",
    "bom-ref": inventory.rootRef,
    name: "webappsec-build",
    version: manifestDigest,
    properties: [property("scope", "build"), property("manifest-sha256", manifestDigest)],
  };
  document.components = inventory.components;
  document.dependencies = inventory.dependencies;
  return document;
}

export function validateSpdx(document, manifest, manifestDigest) {
  assertSchema(validateSpdxSchema, document, "SPDX 2.3");
  if (document.spdxVersion !== "SPDX-2.3" || document.dataLicense !== "CC0-1.0" || document.SPDXID !== "SPDXRef-DOCUMENT") {
    throw new Error("invalid SPDX 2.3 document envelope");
  }
  const expectedName = `webappsec-runtime-${manifestDigest}`;
  const expectedNamespace = `https://github.com/metalagman/webappsec/releases/${manifest.release.tag}/sbom/runtime/${manifestDigest}`;
  const subject = document.packages?.find((entry) => entry.SPDXID === "SPDXRef-Package-webappsec-runtime");
  const subjectPurl = subject?.externalRefs?.find((entry) => entry.referenceType === "purl")?.referenceLocator;
  if (document.name !== expectedName || document.documentNamespace !== expectedNamespace
    || JSON.stringify(document.documentDescribes) !== JSON.stringify(["SPDXRef-Package-webappsec-runtime"])
    || subject?.name !== "webappsec-runtime" || subject?.versionInfo !== manifestDigest
    || subjectPurl !== `pkg:generic/webappsec-runtime@${manifestDigest}`) {
    throw new Error("SPDX subject mismatch");
  }
  const expectedFiles = expectedReleaseFiles(manifest, manifestDigest);
  if (!Array.isArray(document.files) || document.files.length !== expectedFiles.length) throw new Error("SPDX runtime file coverage mismatch");
  const expected = new Map(expectedFiles.map((entry) => [`./${entry.path}`, entry.sha256]));
  for (const file of document.files) {
    const sha256 = file.checksums?.find((checksum) => checksum.algorithm === "SHA256")?.checksumValue;
    if (expected.get(file.fileName) !== sha256) throw new Error(`SPDX file digest mismatch: ${file.fileName}`);
    expected.delete(file.fileName);
  }
  if (expected.size) throw new Error("SPDX is missing runtime files");
}

export function validateCycloneDx(document, manifestDigest, scope, manifest, buildLock) {
  assertSchema(validateCycloneDxSchema, document, "CycloneDX 1.7");
  if (document.bomFormat !== "CycloneDX" || document.specVersion !== "1.7" || document.version !== 1) {
    throw new Error("invalid CycloneDX 1.7 document envelope");
  }
  const properties = new Map(document.metadata?.component?.properties?.map((entry) => [entry.name, entry.value]));
  const subject = document.metadata?.component;
  if (subject?.version !== manifestDigest
    || properties.get("dev.metalagman.webappsec:scope") !== scope
    || properties.get("dev.metalagman.webappsec:manifest-sha256") !== manifestDigest) {
    throw new Error("CycloneDX subject mismatch");
  }
  if (scope === "runtime") {
    if (subject.type !== "application" || subject.name !== "webappsec-runtime"
      || subject["bom-ref"] !== `pkg:generic/webappsec-runtime@${manifestDigest}`) {
      throw new Error("CycloneDX runtime subject mismatch");
    }
    const expectedFiles = expectedReleaseFiles(manifest, manifestDigest);
    if (!Array.isArray(document.components) || document.components.length !== expectedFiles.length) {
      throw new Error("CycloneDX runtime file coverage mismatch");
    }
    const components = new Map();
    const references = new Set();
    for (const component of document.components) {
      if (components.has(component.name) || references.has(component["bom-ref"])) throw new Error("duplicate runtime component identity");
      components.set(component.name, component);
      references.add(component["bom-ref"]);
    }
    for (const file of expectedFiles) {
      const name = file.path;
      const component = components.get(name);
      const sha256 = component?.hashes?.find((hash) => hash.alg === "SHA-256")?.content;
      const category = component?.properties?.find((entry) => entry.name === "dev.metalagman.webappsec:category")?.value;
      if (component?.type !== "file" || component?.["bom-ref"] !== `file:${file.path}` || category !== file.category || sha256 !== file.sha256) {
        throw new Error(`CycloneDX file identity mismatch: ${name}`);
      }
    }
  } else {
    if (!buildLock) throw new Error("build lock is required for SBOM validation");
    const expected = lockInventory(buildLock);
    if (subject.type !== "application" || subject.name !== "webappsec-build" || subject["bom-ref"] !== expected.rootRef) {
      throw new Error("CycloneDX build subject mismatch");
    }
    if (!Array.isArray(document.components) || document.components.length !== expected.components.length || document.components.length === 0) {
      throw new Error("build CycloneDX inventory does not match package-lock");
    }
    const components = new Map(document.components.map((entry) => [entry["bom-ref"], entry]));
    if (components.size !== document.components.length) throw new Error("duplicate build component reference");
    for (const expectedComponent of expected.components) {
      const actual = components.get(expectedComponent["bom-ref"]);
      if (actual?.name !== expectedComponent.name || actual?.version !== expectedComponent.version || actual?.purl !== expectedComponent.purl) {
        throw new Error(`build SBOM component mismatch: ${expectedComponent["bom-ref"]}`);
      }
    }
    const tools = document.metadata?.tools?.components ?? [];
    if (!tools.some((tool) => tool.name === "syft" && tool.version === syftVersion)) throw new Error("build SBOM is missing pinned Syft identity");
    if (!Array.isArray(document.dependencies) || document.dependencies.length !== expected.dependencies.length) {
      throw new Error("build SBOM dependency graph does not match package-lock");
    }
    const dependencies = new Map(document.dependencies.map((entry) => [entry.ref, entry.dependsOn ?? []]));
    if (dependencies.size !== document.dependencies.length) throw new Error("duplicate build dependency node");
    for (const expectedDependency of expected.dependencies) {
      const actual = dependencies.get(expectedDependency.ref);
      if (!actual || JSON.stringify([...actual].sort()) !== JSON.stringify(expectedDependency.dependsOn)) {
        throw new Error(`build SBOM dependency mismatch: ${expectedDependency.ref}`);
      }
    }
  }
}

export function validateVulnerabilityReport(report) {
  assertSchema(validateVulnerabilitySchema, report, "vulnerability report");
  if (report.status === "complete") {
    const status = report.scanner.database?.status;
    if (report.scanner.version !== grypeVersion || !Number.isFinite(Date.parse(report.scanner.scanTimestamp))
      || !Number.isFinite(Date.parse(status?.built))
      || !(Number.isSafeInteger(status?.schemaVersion) && status.schemaVersion > 0
        || typeof status?.schemaVersion === "string" && /^v?[0-9]+(?:\.[0-9]+)*$/.test(status.schemaVersion))
      || typeof status?.checksum !== "string" || status.checksum.length < 8) {
      throw new Error("complete vulnerability report has invalid scanner metadata");
    }
    if (report.findingsCount !== report.findings.length || report.ignoredFindingsCount !== report.ignoredFindings.length) {
      throw new Error("vulnerability report count mismatch");
    }
    const expectedResult = report.findings.length === 0 && report.ignoredFindings.length === 0
      ? "no-known-vulnerabilities"
      : "findings";
    if (report.result !== expectedResult) throw new Error("vulnerability report result mismatch");
  } else if (report.result !== "not-scanned" || report.findingsCount !== null || report.ignoredFindingsCount !== null
    || report.scanner.version !== null || report.scanner.scanTimestamp !== null || report.scanner.database !== null) {
    throw new Error("unavailable vulnerability report is inconsistent");
  }
}

export function vulnerabilityReport({ scope, manifestDigest, grype }) {
  if (!grype || !Array.isArray(grype.matches)) throw new Error("malformed Grype result");
  const ignoredMatches = grype.ignoredMatches ?? [];
  if (!Array.isArray(ignoredMatches)) throw new Error("malformed Grype ignored matches");
  const version = grype.descriptor?.version;
  const database = grype.descriptor?.db;
  const scanTimestamp = grype.descriptor?.timestamp;
  const report = {
    schema: evidenceSchema,
    version: 1,
    status: "complete",
    result: grype.matches.length === 0 && ignoredMatches.length === 0 ? "no-known-vulnerabilities" : "findings",
    subject: { scope, manifestSha256: manifestDigest },
    scanner: { name: "grype", version, scanTimestamp, database },
    findingsCount: grype.matches.length,
    findings: grype.matches,
    ignoredFindingsCount: ignoredMatches.length,
    ignoredFindings: ignoredMatches,
  };
  validateVulnerabilityReport(report);
  return report;
}

export function unavailableVulnerabilityReport({ scope, manifestDigest, reason }) {
  if (!reason) throw new Error("unavailable report requires a reason");
  const report = {
    schema: evidenceSchema,
    version: 1,
    status: "unavailable",
    result: "not-scanned",
    subject: { scope, manifestSha256: manifestDigest },
    scanner: { name: "grype", version: null, scanTimestamp: null, database: null },
    findingsCount: null,
    ignoredFindingsCount: null,
    reason,
  };
  validateVulnerabilityReport(report);
  return report;
}

export async function scanVulnerabilitySbom({ grypePath, sbomPath, scope, manifestDigest, outputPath, environment = process.env }) {
  try {
    const { stdout } = await run(grypePath, [`sbom:${sbomPath}`, "--output", "json"], { env: environment });
    const report = vulnerabilityReport({ scope, manifestDigest, grype: JSON.parse(stdout) });
    await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    const report = unavailableVulnerabilityReport({ scope, manifestDigest, reason: error.message.slice(0, 2000) });
    await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
    throw new Error(`${scope} vulnerability scan unavailable: ${error.message}`);
  }
}

export async function generateEvidence({ releaseDirectory, repositoryRoot, outputDirectory, syftPath, grypePath }) {
  const { digest: manifestDigest } = await verifyRelease(releaseDirectory);
  const manifest = JSON.parse(await readFile(path.join(releaseDirectory, "manifest.json"), "utf8"));
  const files = await runtimeFiles(releaseDirectory, manifest, manifestDigest);
  const packageLock = JSON.parse(await readFile(path.join(repositoryRoot, "package-lock.json"), "utf8"));
  await mkdir(outputDirectory, { recursive: true });
  const runtimeSpdxPath = path.join(outputDirectory, "runtime.spdx.json");
  const runtimeCycloneDxPath = path.join(outputDirectory, "runtime.cdx.json");
  const buildCycloneDxPath = path.join(outputDirectory, "build.cdx.json");
  const environment = {
    ...process.env,
    XDG_CACHE_HOME: path.join(outputDirectory, ".cache"),
    SYFT_CHECK_FOR_APP_UPDATE: "false",
    GRYPE_CHECK_FOR_APP_UPDATE: "false",
  };

  await run(syftPath, [
    "scan", `dir:${releaseDirectory}`,
    "--source-name", "webappsec-runtime", "--source-version", manifestDigest,
    "--output", `spdx-json=${runtimeSpdxPath}`,
    "--output", `cyclonedx-json=${runtimeCycloneDxPath}`,
  ], { env: environment });
  await run(syftPath, [
    "scan", `dir:${repositoryRoot}`,
    "--source-name", "webappsec-build", "--source-version", manifestDigest,
    "--exclude", "./.git/**", "--exclude", "./.artifacts/**", "--exclude", "./dist/**",
    "--output", `cyclonedx-json=${buildCycloneDxPath}`,
  ], { env: environment });

  const spdx = enrichSpdx(JSON.parse(await readFile(runtimeSpdxPath, "utf8")), manifest, manifestDigest, files);
  const runtimeCycloneDx = enrichRuntimeCycloneDx(JSON.parse(await readFile(runtimeCycloneDxPath, "utf8")), manifestDigest, files);
  const buildCycloneDx = enrichBuildCycloneDx(JSON.parse(await readFile(buildCycloneDxPath, "utf8")), manifestDigest, packageLock);
  validateSpdx(spdx, manifest, manifestDigest);
  validateCycloneDx(runtimeCycloneDx, manifestDigest, "runtime", manifest);
  validateCycloneDx(buildCycloneDx, manifestDigest, "build", manifest, packageLock);
  await Promise.all([
    writeFile(runtimeSpdxPath, `${JSON.stringify(spdx, null, 2)}\n`),
    writeFile(runtimeCycloneDxPath, `${JSON.stringify(runtimeCycloneDx, null, 2)}\n`),
    writeFile(buildCycloneDxPath, `${JSON.stringify(buildCycloneDx, null, 2)}\n`),
  ]);

  await scanVulnerabilitySbom({ grypePath, sbomPath: runtimeCycloneDxPath, scope: "runtime", manifestDigest, outputPath: path.join(outputDirectory, "runtime.vulnerabilities.json"), environment });
  await scanVulnerabilitySbom({ grypePath, sbomPath: buildCycloneDxPath, scope: "build", manifestDigest, outputPath: path.join(outputDirectory, "build.vulnerabilities.json"), environment });
  return { manifestDigest, outputDirectory };
}
