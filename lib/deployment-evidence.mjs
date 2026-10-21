import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { canonicalJson } from "./canonical-json.mjs";
import { runCommand, sigstoreIssuer } from "./signed-verifier.mjs";

export const deploymentSchema = "https://webappsec.metalagman.dev/schema/deployment-record-v1";
export const deploymentIndexSchema = "https://webappsec.metalagman.dev/schema/deployment-evidence-v1";
export const deploymentBundleNames = [
  "deployment-index.sigstore.json",
  "deployment-record.sigstore.json",
  "verification-report.sigstore.json",
];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const semver = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields mismatch`);
}

export function validateDeploymentRecord(record) {
  exactKeys(record, ["schema", "version", "action", "sourceRelease", "github", "cloudflare", "production", "transition"], "deployment record");
  if (record.schema !== deploymentSchema || record.version !== 1) throw new Error("unsupported deployment record schema");
  if (!["bootstrap", "deploy", "rollback", "restore"].includes(record.action)) throw new Error("unsupported deployment action");
  exactKeys(record.sourceRelease, ["tag", "revision", "manifestDigest", "url"], "source release");
  if (!semver.test(record.sourceRelease.tag) || !/^[a-f0-9]{40}$/.test(record.sourceRelease.revision)
    || !/^[a-f0-9]{64}$/.test(record.sourceRelease.manifestDigest)
    || record.sourceRelease.url !== `https://github.com/metalagman/webappsec/releases/tag/${record.sourceRelease.tag}`) {
    throw new Error("invalid source release identity");
  }
  exactKeys(record.github, ["repository", "workflow", "ref", "runUrl"], "GitHub invocation");
  const expectedWorkflow = ["bootstrap", "deploy"].includes(record.action) ? ".github/workflows/deploy.yml" : ".github/workflows/rollback.yml";
  if (record.github.repository !== "metalagman/webappsec" || record.github.workflow !== expectedWorkflow
    || !/^refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(record.github.ref)
    || !/^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/[0-9]+$/.test(record.github.runUrl)) {
    throw new Error("invalid GitHub deployment identity");
  }
  exactKeys(record.cloudflare, ["workerName", "wranglerVersion", "versionId", "deploymentId", "versionUrl"], "Cloudflare result");
  if (record.cloudflare.workerName !== "webappsec" || record.cloudflare.wranglerVersion !== "4.151.3"
    || !uuid.test(record.cloudflare.versionId) || !uuid.test(record.cloudflare.deploymentId)
    || (record.cloudflare.versionUrl !== null && !/^https:\/\/[a-z0-9-]+-webappsec\.[a-z0-9-]+\.workers\.dev$/.test(record.cloudflare.versionUrl))) {
    throw new Error("invalid Cloudflare deployment result");
  }
  exactKeys(record.production, ["origin", "verifiedAt"], "production result");
  if (record.production.origin !== "https://webappsec.metalagman.dev" || Number.isNaN(Date.parse(record.production.verifiedAt))) {
    throw new Error("invalid production verification result");
  }
  exactKeys(record.transition, ["fromVersionId", "fromDeploymentId", "targetDeploymentRelease"], "deployment transition");
  const transitionIds = [record.transition.fromVersionId, record.transition.fromDeploymentId];
  if (record.action === "bootstrap") {
    if (transitionIds.some((value) => value !== null) || record.transition.targetDeploymentRelease !== null) throw new Error("bootstrap must have no prior deployment");
  } else {
    if (!transitionIds.every((value) => uuid.test(value ?? "")) || record.transition.fromVersionId === record.cloudflare.versionId) {
      throw new Error("deployment transition must change the Worker version");
    }
    if (["rollback", "restore"].includes(record.action)) {
      if (!/^deployment-(?:bootstrap|deploy)-v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?-[0-9]+$/.test(record.transition.targetDeploymentRelease ?? "")) {
        throw new Error("rollback transition requires an explicit original deployment release");
      }
    } else if (record.transition.targetDeploymentRelease !== null) throw new Error("ordinary deploy must not name a rollback target");
  }
  return record;
}

function validateCoreReport(report, record, { origin, noindex, composite }) {
  const keys = ["ok", "result", "exitCode", "manifestDigest", "layers", "target", ...(composite ? ["deploymentChecks"] : [])];
  exactKeys(report, keys, "production verification report");
  if (!report.ok || report.result !== "verified" || report.exitCode !== 0 || report.manifestDigest !== record.sourceRelease.manifestDigest) {
    throw new Error("deployment verification report did not pass for this manifest");
  }
  if (!Array.isArray(report.layers) || report.layers.length !== 4) throw new Error("deployment verification report has incomplete layers");
  const requiredLayers = ["manifest", "production-bytes", "response-headers", "sri"];
  for (const [index, layer] of report.layers.entries()) {
    exactKeys(layer, ["name", "state", "detail"], "verification layer");
    if (layer.name !== requiredLayers[index] || layer.state !== "pass" || typeof layer.detail !== "string" || !layer.detail) {
      throw new Error("deployment verification report has incomplete layers");
    }
  }
  exactKeys(report.target, ["origin", "expectedHeaders"], "verification target");
  exactKeys(report.target.expectedHeaders, ["release", "versionId", "noindex"], "verification header policy");
  if (report.target.origin !== origin || report.target.expectedHeaders.release !== record.sourceRelease.manifestDigest
    || report.target.expectedHeaders.versionId !== record.cloudflare.versionId || report.target.expectedHeaders.noindex !== noindex) {
    throw new Error("deployment verification target mismatch");
  }
}

function validateBrowser(result, origin) {
  exactKeys(result, ["ok", "origin", "title", "sriResources"], "browser verification result");
  if (result.ok !== true || result.origin !== origin || typeof result.title !== "string" || !result.title
    || !Number.isSafeInteger(result.sriResources) || result.sriResources < 2) throw new Error("browser verification result mismatch");
}

function validateReport(report, record) {
  validateCoreReport(report, record, { origin: record.production.origin, noindex: false, composite: true });
  const checks = report.deploymentChecks;
  if (["bootstrap", "deploy"].includes(record.action)) {
    exactKeys(checks, ["preview", "previewBrowser", "productionBrowser"], "deployment checks");
    validateBrowser(checks.productionBrowser, record.production.origin);
    if (record.action === "bootstrap") {
      if (checks.preview !== null || checks.previewBrowser !== null || record.cloudflare.versionUrl !== null) throw new Error("bootstrap must not claim preview verification");
    } else {
      if (!record.cloudflare.versionUrl) throw new Error("deploy requires a Version URL");
      validateCoreReport(checks.preview, record, { origin: record.cloudflare.versionUrl, noindex: true, composite: false });
      validateBrowser(checks.previewBrowser, record.cloudflare.versionUrl);
    }
  } else {
    exactKeys(checks, ["verifiedTargetDeploymentRelease", "productionBrowser"], "rollback checks");
    if (checks.verifiedTargetDeploymentRelease !== record.transition.targetDeploymentRelease) throw new Error("rollback target release mismatch");
    validateBrowser(checks.productionBrowser, record.production.origin);
  }
}

async function regularBytes(directory, name) {
  const filename = path.join(directory, name);
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size < 1 || metadata.size > 10 * 1024 * 1024) {
    throw new Error(`invalid deployment evidence file: ${name}`);
  }
  return readFile(filename);
}

export async function createDeploymentEvidence({ outputDirectory, record, verificationReport }) {
  validateDeploymentRecord(record);
  validateReport(verificationReport, record);
  await mkdir(outputDirectory, { recursive: true });
  if ((await readdir(outputDirectory)).length !== 0) throw new Error("deployment evidence output must be empty");
  const recordBytes = Buffer.from(canonicalJson(record));
  const reportBytes = Buffer.from(canonicalJson(verificationReport));
  await writeFile(path.join(outputDirectory, "deployment-record.json"), recordBytes);
  await writeFile(path.join(outputDirectory, "verification-report.json"), reportBytes);
  const index = {
    schema: deploymentIndexSchema,
    version: 1,
    sourceRelease: { ...record.sourceRelease },
    files: [
      { name: "deployment-record.json", size: recordBytes.length, sha256: sha256(recordBytes) },
      { name: "verification-report.json", size: reportBytes.length, sha256: sha256(reportBytes) },
    ],
  };
  await writeFile(path.join(outputDirectory, "deployment-index.json"), canonicalJson(index));
  return index;
}

export async function verifyDeploymentEvidence(directory) {
  const allowed = new Set(["deployment-index.json", "deployment-record.json", "verification-report.json", ...deploymentBundleNames]);
  const names = await readdir(directory);
  for (const name of names) if (!allowed.has(name)) throw new Error(`unexpected deployment evidence file: ${name}`);
  for (const name of ["deployment-index.json", "deployment-record.json", "verification-report.json"]) if (!names.includes(name)) throw new Error(`missing deployment evidence file: ${name}`);
  const indexBytes = await regularBytes(directory, "deployment-index.json");
  const recordBytes = await regularBytes(directory, "deployment-record.json");
  const reportBytes = await regularBytes(directory, "verification-report.json");
  const index = JSON.parse(indexBytes);
  const record = validateDeploymentRecord(JSON.parse(recordBytes));
  const report = JSON.parse(reportBytes);
  if (!indexBytes.equals(Buffer.from(canonicalJson(index))) || !recordBytes.equals(Buffer.from(canonicalJson(record)))
    || !reportBytes.equals(Buffer.from(canonicalJson(report)))) throw new Error("deployment evidence must be canonical JSON");
  exactKeys(index, ["schema", "version", "sourceRelease", "files"], "deployment index");
  if (index.schema !== deploymentIndexSchema || index.version !== 1 || canonicalJson(index.sourceRelease) !== canonicalJson(record.sourceRelease)) {
    throw new Error("deployment index identity mismatch");
  }
  const expected = [
    { name: "deployment-record.json", size: recordBytes.length, sha256: sha256(recordBytes) },
    { name: "verification-report.json", size: reportBytes.length, sha256: sha256(reportBytes) },
  ];
  if (canonicalJson(index.files) !== canonicalJson(expected)) throw new Error("deployment index file mismatch");
  validateReport(report, record);
  return { index, record, report };
}

export async function verifySignedDeploymentEvidence({ directory, expected, cosignPath = ".bin/cosign", commandRunner = runCommand }) {
  for (const name of deploymentBundleNames) await regularBytes(directory, name);
  const verified = await verifyDeploymentEvidence(directory);
  const { record } = verified;
  if (record.sourceRelease.tag !== expected.releaseTag || record.sourceRelease.manifestDigest !== expected.manifestDigest
    || record.cloudflare.versionId !== expected.versionId || record.github.workflow !== expected.workflow
    || record.github.ref !== expected.ref) throw new Error("deployment evidence does not match explicit rollback target");
  const identity = `https://github.com/metalagman/webappsec/${expected.workflow}@${expected.ref}`;
  for (const [subject, bundle] of [
    ["deployment-index.json", "deployment-index.sigstore.json"],
    ["deployment-record.json", "deployment-record.sigstore.json"],
    ["verification-report.json", "verification-report.sigstore.json"],
  ]) {
    await commandRunner(cosignPath, ["verify-blob", "--bundle", path.join(directory, bundle), "--certificate-identity", identity,
      "--certificate-oidc-issuer", sigstoreIssuer, path.join(directory, subject)]);
  }
  return verified;
}
