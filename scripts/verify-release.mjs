#!/usr/bin/env node
import { writeSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  reproduceRelease,
  resolveExplicitEvidence,
  VerificationUnavailableError,
  verifySignedEvidence,
} from "../lib/signed-verifier.mjs";
import { humanReport, verifyProduction } from "../lib/verifier.mjs";

function usage() {
  writeSync(2, `Usage:
  node scripts/verify-release.mjs --release <vX.Y.Z> [--origin <url>] [--rebuild] [--json]
  node scripts/verify-release.mjs --evidence <directory> [--expected-tag <vX.Y.Z>] [--source <tag-checkout>] [--origin <url>] [--rebuild] [--json]
Exit: 0 verified, 1 authenticity/evidence/content failure, 2 invalid invocation, 3 required service unavailable.
`);
  process.exit(2);
}

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (["--json", "--rebuild"].includes(argument)) options[argument.slice(2)] = true;
  else if (["--release", "--evidence", "--expected-tag", "--source", "--origin", "--cosign"].includes(argument)
    && args[index + 1] && !args[index + 1].startsWith("--")) options[argument.slice(2)] = args[++index];
  else usage();
}
if (Boolean(options.release) === Boolean(options.evidence)) usage();
if (options.release && !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(options.release)) usage();
if (options["expected-tag"] && !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(options["expected-tag"])) usage();
if (options.release && options["expected-tag"]) usage();
if (options.origin) {
  try {
    const parsed = new URL(options.origin);
    if (!(["http:", "https:"].includes(parsed.protocol)) || parsed.username || parsed.password) usage();
    options.origin = parsed.origin;
  } catch {
    usage();
  }
}

const layers = [];
const releaseSourceRoot = path.resolve(options.source ?? ".");
let result = "verification-failed";
let exitCode = 1;
let manifestDigest = null;
let downloadDirectory;
try {
  if (options.release) downloadDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-release-download-"));
  let evidenceDirectory;
  try {
    evidenceDirectory = await resolveExplicitEvidence({
      releaseTag: options.release,
      evidenceDirectory: options.evidence,
      downloadDirectory,
    });
    layers.push({ name: "release-resolution", state: "pass", detail: options.release ?? path.resolve(options.evidence) });
  } catch (error) {
    layers.push({ name: "release-resolution", state: error instanceof VerificationUnavailableError ? "unavailable" : "fail", detail: error.message });
    throw error;
  }

  let verified;
  try {
    verified = await verifySignedEvidence({
      directory: evidenceDirectory,
      repositoryRoot: releaseSourceRoot,
      cosignPath: path.resolve(options.cosign ?? ".bin/cosign"),
      expectedTag: options.release ?? options["expected-tag"],
    });
    manifestDigest = verified.manifestDigest;
    layers.push(...verified.checks);
  } catch (error) {
    layers.push(...(error.completedChecks ?? []));
    layers.push({ name: error.verificationLayer ?? "signed-evidence", state: error instanceof VerificationUnavailableError ? "unavailable" : "fail", detail: error.message });
    throw error;
  }

  if (options.rebuild) {
    try {
      await reproduceRelease({ verified, releaseSourceRoot });
      layers.push({ name: "reproducible-build", state: "pass", detail: verified.manifestDigest });
    } catch (error) {
      layers.push({ name: "reproducible-build", state: error instanceof VerificationUnavailableError ? "unavailable" : "fail", detail: error.message });
      throw error;
    }
  } else {
    layers.push({ name: "reproducible-build", state: "skipped", detail: "optional; pass --rebuild to execute" });
  }

  const production = await verifyProduction({ manifestPath: verified.manifestPath, origin: options.origin });
  layers.push(...production.layers.filter((layer) => layer.name !== "manifest"));
  manifestDigest = production.manifestDigest;
  if (!production.ok) {
    if (production.exitCode === 3) throw new VerificationUnavailableError("production verification unavailable");
    throw new Error("production byte or SRI verification failed");
  }
  result = "verified";
  exitCode = 0;
} catch (error) {
  const unavailable = error instanceof VerificationUnavailableError || layers.some((layer) => layer.state === "unavailable");
  result = unavailable ? "service-unavailable" : "verification-failed";
  exitCode = unavailable ? 3 : 1;
} finally {
  if (downloadDirectory) await rm(downloadDirectory, { recursive: true, force: true });
}

const report = { ok: exitCode === 0, result, exitCode, manifestDigest, layers };
writeSync(1, options.json ? `${JSON.stringify(report)}\n` : humanReport(report));
process.exitCode = exitCode;
