import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { canonicalJson } from "./canonical-json.mjs";
import { runCommand, sigstoreIssuer } from "./signed-verifier.mjs";

export const verificationSchema = "https://webappsec.metalagman.dev/schema/verification-record-v1";
export const verificationIndexSchema = "https://webappsec.metalagman.dev/schema/verification-evidence-v1";
export const verificationBundleNames = [
  "verification-index.sigstore.json",
  "verification-record.sigstore.json",
  "verification-report.sigstore.json",
  "verification-report.txt.sigstore.json",
];

const layerNames = [
  "release-resolution",
  "evidence-inventory",
  "signatures",
  "attestations",
  "sbom",
  "vulnerability-evidence",
  "reproducible-build",
  "production-bytes",
  "sri",
];
const semver = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields mismatch`);
}

export function validateVerificationRecord(record) {
  exactKeys(record, ["schema", "version", "sourceRelease", "github", "production", "result"], "verification record");
  if (record.schema !== verificationSchema || record.version !== 1 || record.result !== "verified") {
    throw new Error("unsupported verification record");
  }
  exactKeys(record.sourceRelease, ["tag", "manifestDigest", "url"], "source release");
  if (!semver.test(record.sourceRelease.tag) || !/^[a-f0-9]{64}$/.test(record.sourceRelease.manifestDigest)
    || record.sourceRelease.url !== `https://github.com/metalagman/webappsec/releases/tag/${record.sourceRelease.tag}`) {
    throw new Error("invalid source release identity");
  }
  exactKeys(record.github, ["repository", "workflow", "ref", "revision", "runUrl"], "GitHub invocation");
  if (record.github.repository !== "metalagman/webappsec"
    || record.github.workflow !== ".github/workflows/verify-production.yml"
    || record.github.ref !== "refs/heads/main"
    || !/^[a-f0-9]{40}$/.test(record.github.revision)
    || !/^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/[0-9]+$/.test(record.github.runUrl)) {
    throw new Error("invalid GitHub verification identity");
  }
  exactKeys(record.production, ["origin", "verifiedAt"], "production verification");
  if (record.production.origin !== "https://webappsec.metalagman.dev"
    || Number.isNaN(Date.parse(record.production.verifiedAt))) throw new Error("invalid production verification target");
  return record;
}

export function validateFullVerificationReport(report, record) {
  exactKeys(report, ["ok", "result", "exitCode", "manifestDigest", "layers"], "verification report");
  if (report.ok !== true || report.result !== "verified" || report.exitCode !== 0
    || report.manifestDigest !== record.sourceRelease.manifestDigest) {
    throw new Error("verification report did not pass for this manifest");
  }
  if (!Array.isArray(report.layers) || report.layers.length !== layerNames.length) {
    throw new Error("verification report must contain complete ordered layers");
  }
  for (const [index, layer] of report.layers.entries()) {
    exactKeys(layer, ["name", "state", "detail"], "verification layer");
    if (layer.name !== layerNames[index] || layer.state !== "pass" || typeof layer.detail !== "string" || !layer.detail) {
      throw new Error("verification report must contain complete ordered layers");
    }
  }
  const releaseIdentity = `https://github.com/metalagman/webappsec/.github/workflows/release.yml@refs/tags/${record.sourceRelease.tag}`;
  if (!report.layers[2].detail.includes(releaseIdentity)) throw new Error("release signature identity mismatch");
  if (report.layers[6].detail !== record.sourceRelease.manifestDigest) throw new Error("reproducible build digest mismatch");
  return report;
}

function humanReport(record, report) {
  const lines = [
    `Release: ${record.sourceRelease.tag}`,
    `Manifest SHA-256: ${record.sourceRelease.manifestDigest}`,
    `Production: ${record.production.origin}`,
    `Verified at: ${record.production.verifiedAt}`,
    `Workflow run: ${record.github.runUrl}`,
    "",
    ...report.layers.map((layer) => `${layer.state.toUpperCase().padEnd(9)} ${layer.name}: ${layer.detail}`),
    "PASS deployment verified",
  ];
  return `${lines.join("\n")}\n`;
}

async function regularBytes(directory, name) {
  const filename = path.join(directory, name);
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size < 1 || metadata.size > 10 * 1024 * 1024) {
    throw new Error(`invalid verification evidence file: ${name}`);
  }
  return readFile(filename);
}

export async function createVerificationEvidence({ outputDirectory, record, verificationReportBytes }) {
  validateVerificationRecord(record);
  if (!Buffer.isBuffer(verificationReportBytes) || verificationReportBytes.length < 1 || verificationReportBytes.length > 10 * 1024 * 1024) {
    throw new Error("verification report bytes are invalid");
  }
  const report = validateFullVerificationReport(JSON.parse(verificationReportBytes), record);
  await mkdir(outputDirectory, { recursive: true });
  if ((await readdir(outputDirectory)).length !== 0) throw new Error("verification evidence output must be empty");

  const recordBytes = Buffer.from(canonicalJson(record));
  const humanBytes = Buffer.from(humanReport(record, report));
  await writeFile(path.join(outputDirectory, "verification-record.json"), recordBytes);
  await writeFile(path.join(outputDirectory, "verification-report.json"), verificationReportBytes);
  await writeFile(path.join(outputDirectory, "verification-report.txt"), humanBytes);
  const index = {
    schema: verificationIndexSchema,
    version: 1,
    sourceRelease: { ...record.sourceRelease },
    files: [
      { name: "verification-record.json", size: recordBytes.length, sha256: sha256(recordBytes) },
      { name: "verification-report.json", size: verificationReportBytes.length, sha256: sha256(verificationReportBytes) },
      { name: "verification-report.txt", size: humanBytes.length, sha256: sha256(humanBytes) },
    ],
  };
  await writeFile(path.join(outputDirectory, "verification-index.json"), canonicalJson(index));
  return index;
}

export async function verifyVerificationEvidence(directory) {
  const dataNames = ["verification-index.json", "verification-record.json", "verification-report.json", "verification-report.txt"];
  const allowed = new Set([...dataNames, ...verificationBundleNames]);
  const names = await readdir(directory);
  for (const name of names) if (!allowed.has(name)) throw new Error(`unexpected verification evidence file: ${name}`);
  for (const name of dataNames) if (!names.includes(name)) throw new Error(`missing verification evidence file: ${name}`);

  const [indexBytes, recordBytes, reportBytes, humanBytes] = await Promise.all(dataNames.map((name) => regularBytes(directory, name)));
  const index = JSON.parse(indexBytes);
  const record = validateVerificationRecord(JSON.parse(recordBytes));
  const report = validateFullVerificationReport(JSON.parse(reportBytes), record);
  if (!indexBytes.equals(Buffer.from(canonicalJson(index))) || !recordBytes.equals(Buffer.from(canonicalJson(record)))) {
    throw new Error("verification index and record must be canonical JSON");
  }
  exactKeys(index, ["schema", "version", "sourceRelease", "files"], "verification index");
  if (index.schema !== verificationIndexSchema || index.version !== 1
    || canonicalJson(index.sourceRelease) !== canonicalJson(record.sourceRelease)) throw new Error("verification index identity mismatch");
  const expected = [
    { name: "verification-record.json", size: recordBytes.length, sha256: sha256(recordBytes) },
    { name: "verification-report.json", size: reportBytes.length, sha256: sha256(reportBytes) },
    { name: "verification-report.txt", size: humanBytes.length, sha256: sha256(humanBytes) },
  ];
  if (canonicalJson(index.files) !== canonicalJson(expected)) throw new Error("verification index file mismatch");
  if (!humanBytes.equals(Buffer.from(humanReport(record, report)))) throw new Error("human report mismatch");
  return { index, record, report };
}

export async function verifySignedVerificationEvidence({ directory, cosignPath = ".bin/cosign", commandRunner = runCommand }) {
  for (const name of verificationBundleNames) await regularBytes(directory, name);
  const verified = await verifyVerificationEvidence(directory);
  const identity = "https://github.com/metalagman/webappsec/.github/workflows/verify-production.yml@refs/heads/main";
  for (const [subject, bundle] of [
    ["verification-index.json", "verification-index.sigstore.json"],
    ["verification-record.json", "verification-record.sigstore.json"],
    ["verification-report.json", "verification-report.sigstore.json"],
    ["verification-report.txt", "verification-report.txt.sigstore.json"],
  ]) {
    await commandRunner(cosignPath, ["verify-blob", "--bundle", path.join(directory, bundle), "--certificate-identity", identity,
      "--certificate-oidc-issuer", sigstoreIssuer, path.join(directory, subject)]);
  }
  return verified;
}
