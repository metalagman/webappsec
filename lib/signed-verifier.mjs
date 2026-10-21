import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { createRelease } from "./artifact.mjs";
import { canonicalJson } from "./canonical-json.mjs";
import { validateCycloneDx, validateSpdx, validateVulnerabilityReport } from "./evidence.mjs";
import {
  authenticationBundleNames,
  cycloneDxPredicateType,
  slsaPredicateType,
  verifyEvidenceDirectory,
} from "./release-evidence.mjs";

export const sigstoreIssuer = "https://token.actions.githubusercontent.com";
const repository = "metalagman/webappsec";
const maximumBundleSize = 10 * 1024 * 1024;

export class VerificationUnavailableError extends Error {}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertTag(tag) {
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? "")) throw new Error("release tag must be explicit immutable SemVer");
}

export function signerIdentity(tag) {
  assertTag(tag);
  return `https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${tag}`;
}

export async function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);
    child.once("close", (code) => {
      const result = { stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") };
      if (code === 0) resolve(result);
      else {
        const error = new Error(`${path.basename(command)} exited ${code}: ${(result.stderr || result.stdout).trim()}`);
        error.exitCode = code;
        reject(error);
      }
    });
  });
}

function classifyToolError(error) {
  if (/timeout|timed out|connection|network|dns|lookup|socket: operation not permitted|no such host|temporary failure|service unavailable|failed to (?:fetch|download)|tuf.*(?:download|update|fetch)/i.test(error.message)) {
    return new VerificationUnavailableError(error.message);
  }
  return error;
}

export function classifyResolutionError(error) {
  if (/timeout|timed out|connection reset|connection refused|failed to connect|couldn't connect|error connecting|internet connection|network is unreachable|could not resolve|lookup|socket: operation not permitted|no such host|temporary failure|rate limit|HTTP (?:429|5[0-9]{2})|error: (?:429|5[0-9]{2})|service unavailable/i.test(error.message)) {
    return new VerificationUnavailableError(error.message);
  }
  return error;
}

async function regularBundle(directory, name) {
  const filename = path.join(directory, name);
  const metadata = await lstat(filename);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`Sigstore bundle must be a regular file: ${name}`);
  if (metadata.size < 1 || metadata.size > maximumBundleSize) throw new Error(`invalid Sigstore bundle size: ${name}`);
  return filename;
}

async function cosignVerify(cosignPath, args, commandRunner) {
  try {
    await commandRunner(cosignPath, args);
  } catch (error) {
    throw classifyToolError(error);
  }
}

function statementFromBundle(bundle) {
  const encoded = bundle?.dsseEnvelope?.payload;
  if (typeof encoded !== "string" || encoded.length > maximumBundleSize * 2) throw new Error("Sigstore bundle has no bounded DSSE payload");
  let statement;
  try {
    statement = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  } catch (error) {
    throw new Error(`malformed in-toto statement: ${error.message}`);
  }
  return statement;
}

async function verifyAttestationStatement({ directory, bundleName, subjectName, subjectDigest, predicateName, predicateType }) {
  const bundle = JSON.parse(await readFile(path.join(directory, bundleName), "utf8"));
  const statement = statementFromBundle(bundle);
  if (!["https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"].includes(statement._type)) {
    throw new Error(`unexpected in-toto statement type: ${bundleName}`);
  }
  if (statement.predicateType !== predicateType || !Array.isArray(statement.subject) || statement.subject.length !== 1
    || statement.subject[0].name !== subjectName || statement.subject[0].digest?.sha256 !== subjectDigest) {
    throw new Error(`in-toto subject or predicate type mismatch: ${bundleName}`);
  }
  const expectedPredicate = JSON.parse(await readFile(path.join(directory, predicateName), "utf8"));
  if (canonicalJson(statement.predicate) !== canonicalJson(expectedPredicate)) throw new Error(`in-toto predicate mismatch: ${bundleName}`);
}

export async function resolveExplicitEvidence({ releaseTag, evidenceDirectory, downloadDirectory, commandRunner = runCommand }) {
  if (Boolean(releaseTag) === Boolean(evidenceDirectory)) throw new Error("choose exactly one explicit release tag or local evidence directory");
  if (evidenceDirectory) return path.resolve(evidenceDirectory);
  assertTag(releaseTag);
  if (!downloadDirectory) throw new Error("download directory is required for GitHub release resolution");
  const existing = await readdir(downloadDirectory);
  if (existing.length !== 0) throw new Error("release download directory must be empty");
  try {
    await commandRunner("gh", ["release", "download", releaseTag, "--repo", repository, "--dir", downloadDirectory]);
  } catch (error) {
    throw classifyResolutionError(error);
  }
  return downloadDirectory;
}

export async function verifySignedEvidence({ directory, repositoryRoot = path.resolve("."), cosignPath = ".bin/cosign", commandRunner = runCommand, expectedTag }) {
  const checks = [];
  let currentStage = "evidence-inventory";
  try {
    for (const name of authenticationBundleNames) await regularBundle(directory, name);
    const structural = await verifyEvidenceDirectory(directory, repositoryRoot, { authenticationFiles: authenticationBundleNames });
    const index = JSON.parse(await readFile(path.join(directory, "evidence-index.json"), "utf8"));
    const tag = index.release.tag;
    if (expectedTag !== undefined && tag !== expectedTag) throw new Error(`downloaded release tag mismatch: expected ${expectedTag}, got ${tag}`);
    const identity = signerIdentity(tag);
    const tarName = `${structural.manifestDigest}.tar`;
    const tarBytes = await readFile(path.join(directory, tarName));
    const tarDigest = digest(tarBytes);
    checks.push({ name: currentStage, state: "pass", detail: `${index.files.length} indexed objects` });

    currentStage = "signatures";
    const direct = [
      ["evidence-index.json", "evidence-index.sigstore.json"],
      ["manifest.json", "manifest.sigstore.json"],
      [tarName, "release.sigstore.json"],
    ];
    for (const [subject, bundle] of direct) {
      await cosignVerify(cosignPath, ["verify-blob", "--bundle", path.join(directory, bundle), "--certificate-identity", identity, "--certificate-oidc-issuer", sigstoreIssuer, path.join(directory, subject)], commandRunner);
    }
    checks.push({ name: currentStage, state: "pass", detail: `3 keyless bundles; ${identity}` });

    currentStage = "attestations";
    const attestations = [
      ["manifest.json", "provenance.slsa.json", "slsaprovenance1", "provenance.manifest.intoto.sigstore.json", slsaPredicateType],
      [tarName, "provenance.slsa.json", "slsaprovenance1", "provenance.release.intoto.sigstore.json", slsaPredicateType],
      [tarName, "runtime.cdx.json", "cyclonedx", "runtime-cyclonedx.intoto.sigstore.json", cycloneDxPredicateType],
      [tarName, "build.cdx.json", "cyclonedx", "build-cyclonedx.intoto.sigstore.json", cycloneDxPredicateType],
    ];
    for (const [subject, , type, bundle] of attestations) {
      await cosignVerify(cosignPath, ["verify-blob-attestation", "--bundle", path.join(directory, bundle), "--type", type, "--certificate-identity", identity, "--certificate-oidc-issuer", sigstoreIssuer, path.join(directory, subject)], commandRunner);
    }
    const manifestBytes = await readFile(path.join(directory, "manifest.json"));
    for (const [subject, predicateName, , bundleName, predicateType] of attestations) {
      await verifyAttestationStatement({
        directory,
        bundleName,
        subjectName: subject,
        subjectDigest: subject === "manifest.json" ? digest(manifestBytes) : tarDigest,
        predicateName,
        predicateType,
      });
    }
    checks.push({ name: currentStage, state: "pass", detail: "SLSA manifest/tar and CycloneDX runtime/build subjects" });

    currentStage = "sbom";
    const manifest = JSON.parse(manifestBytes);
    const lock = JSON.parse(await readFile(path.join(repositoryRoot, "package-lock.json"), "utf8"));
    const spdx = JSON.parse(await readFile(path.join(directory, "runtime.spdx.json"), "utf8"));
    const runtimeCdx = JSON.parse(await readFile(path.join(directory, "runtime.cdx.json"), "utf8"));
    const buildCdx = JSON.parse(await readFile(path.join(directory, "build.cdx.json"), "utf8"));
    validateSpdx(spdx, manifest, structural.manifestDigest);
    validateCycloneDx(runtimeCdx, structural.manifestDigest, "runtime", manifest);
    validateCycloneDx(buildCdx, structural.manifestDigest, "build", manifest, lock);
    checks.push({ name: currentStage, state: "pass", detail: "SPDX runtime and CycloneDX runtime/build" });

    currentStage = "vulnerability-evidence";
    for (const scope of ["runtime", "build"]) {
      const report = JSON.parse(await readFile(path.join(directory, `${scope}.vulnerabilities.json`), "utf8"));
      validateVulnerabilityReport(report);
      if (report.subject.scope !== scope || report.subject.manifestSha256 !== structural.manifestDigest) throw new Error(`${scope} vulnerability subject mismatch`);
      if (report.status !== "complete") throw new Error(`${scope} vulnerability scan was unavailable at release time`);
    }
    checks.push({ name: currentStage, state: "pass", detail: "runtime and build scans complete" });
    return {
      directory,
      tag,
      revision: index.release.revision,
      manifestDigest: structural.manifestDigest,
      manifestPath: path.join(directory, "manifest.json"),
      tarPath: path.join(directory, tarName),
      checks,
    };
  } catch (error) {
    error.verificationLayer ??= currentStage;
    error.completedChecks ??= checks;
    throw error;
  }
}

export async function reproduceRelease({ verified, releaseSourceRoot = path.resolve("."), commandRunner = runCommand }) {
  const head = (await commandRunner("git", ["rev-parse", "HEAD"], { cwd: releaseSourceRoot })).stdout.trim();
  if (head !== verified.revision) throw new Error(`clean rebuild requires checkout ${verified.revision}`);
  const dirty = (await commandRunner("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: releaseSourceRoot })).stdout.trim();
  if (dirty) throw new Error("clean rebuild requires an unmodified tracked checkout");
  const manifest = JSON.parse(await readFile(verified.manifestPath, "utf8"));
  const temporary = await mkdtemp(path.join(tmpdir(), "webappsec-rebuild-"));
  try {
    const rebuilt = await createRelease({
      outputRoot: temporary,
      release: manifest.release,
      sourceDirectory: path.join(releaseSourceRoot, "site"),
      deployInputs: [
        { source: path.join(releaseSourceRoot, "lib/content-addressing.mjs"), path: "lib/content-addressing.mjs", role: "worker" },
        { source: path.join(releaseSourceRoot, "worker/index.js"), path: "worker/index.js", role: "worker" },
        { source: path.join(releaseSourceRoot, "wrangler.jsonc"), path: "wrangler.jsonc", role: "configuration" },
      ],
    });
    if (!Buffer.from(await readFile(rebuilt.manifestPath)).equals(await readFile(verified.manifestPath))) throw new Error("rebuilt manifest differs from signed release");
    if (!Buffer.from(await readFile(rebuilt.tarPath)).equals(await readFile(verified.tarPath))) throw new Error("rebuilt tar differs from signed release");
    return { manifestDigest: rebuilt.digest };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
