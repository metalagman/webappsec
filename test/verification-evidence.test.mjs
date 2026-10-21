import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createVerificationEvidence,
  verificationBundleNames,
  verificationSchema,
  verifySignedVerificationEvidence,
  verifyVerificationEvidence,
} from "../lib/verification-evidence.mjs";

const manifestDigest = "a".repeat(64);
const releaseTag = "v0.2.7";

function record() {
  return {
    schema: verificationSchema,
    version: 1,
    sourceRelease: {
      tag: releaseTag,
      manifestDigest,
      url: `https://github.com/metalagman/webappsec/releases/tag/${releaseTag}`,
    },
    github: {
      repository: "metalagman/webappsec",
      workflow: ".github/workflows/verify-production.yml",
      ref: "refs/heads/main",
      revision: "1".repeat(40),
      runUrl: "https://github.com/metalagman/webappsec/actions/runs/123",
    },
    production: {
      origin: "https://webappsec.metalagman.dev",
      verifiedAt: "2026-10-22T12:34:56.000Z",
    },
    result: "verified",
  };
}

function report() {
  const identity = `https://github.com/metalagman/webappsec/.github/workflows/release.yml@refs/tags/${releaseTag}`;
  const details = [
    releaseTag,
    "8 indexed evidence files",
    `3 keyless signatures from ${identity}`,
    "4 authenticated attestations",
    "SPDX and CycloneDX validated",
    "runtime and build scans passed",
    manifestDigest,
    "4 exact responses",
    "3 HTML references",
  ];
  const names = [
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
  return {
    ok: true,
    result: "verified",
    exitCode: 0,
    manifestDigest,
    layers: names.map((name, index) => ({ name, state: "pass", detail: details[index] })),
  };
}

test("verification evidence preserves the exact JSON report and binds a deterministic human report", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-verification-evidence-"));
  const reportBytes = Buffer.from(`${JSON.stringify(report(), null, 2)}\n`);
  await createVerificationEvidence({ outputDirectory: directory, record: record(), verificationReportBytes: reportBytes });
  const verified = await verifyVerificationEvidence(directory);
  assert.deepEqual(await readFile(path.join(directory, "verification-report.json")), reportBytes);
  assert.equal(verified.record.sourceRelease.tag, releaseTag);
  assert.match(await readFile(path.join(directory, "verification-report.txt"), "utf8"), /PASS deployment verified/);
  assert.deepEqual(verified.index.files.map(({ name }) => name), [
    "verification-record.json",
    "verification-report.json",
    "verification-report.txt",
  ]);
});

test("signed verification evidence authenticates every retained representation", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-signed-verification-"));
  await createVerificationEvidence({
    outputDirectory: directory,
    record: record(),
    verificationReportBytes: Buffer.from(`${JSON.stringify(report())}\n`),
  });
  for (const name of verificationBundleNames) await writeFile(path.join(directory, name), "{}\n");
  const calls = [];
  await verifySignedVerificationEvidence({
    directory,
    commandRunner: async (command, args) => { calls.push([command, args]); return { stdout: "", stderr: "" }; },
  });
  assert.equal(calls.length, 4);
  assert.ok(calls.every(([, args]) => args.includes(
    "https://github.com/metalagman/webappsec/.github/workflows/verify-production.yml@refs/heads/main",
  )));
});

test("verification evidence rejects missing layers, false success, and altered retained bytes", async (t) => {
  await t.test("missing layer", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-verification-missing-"));
    const candidate = report();
    candidate.layers.pop();
    await assert.rejects(() => createVerificationEvidence({
      outputDirectory: directory,
      record: record(),
      verificationReportBytes: Buffer.from(JSON.stringify(candidate)),
    }), /complete ordered layers/);
  });

  await t.test("false success", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-verification-failed-"));
    const candidate = report();
    candidate.ok = false;
    await assert.rejects(() => createVerificationEvidence({
      outputDirectory: directory,
      record: record(),
      verificationReportBytes: Buffer.from(JSON.stringify(candidate)),
    }), /did not pass/);
  });

  await t.test("altered human report", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-verification-tampered-"));
    await createVerificationEvidence({
      outputDirectory: directory,
      record: record(),
      verificationReportBytes: Buffer.from(JSON.stringify(report())),
    });
    await writeFile(path.join(directory, "verification-report.txt"), "PASS forged\n");
    await assert.rejects(() => verifyVerificationEvidence(directory), /index file mismatch|human report mismatch/);
  });
});
