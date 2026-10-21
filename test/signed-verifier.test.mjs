import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createRelease } from "../lib/artifact.mjs";
import { canonicalJson } from "../lib/canonical-json.mjs";
import { grypeVersion, lockInventory, syftVersion, unavailableVulnerabilityReport, vulnerabilityReport } from "../lib/evidence.mjs";
import { assembleReleaseEvidence, authenticationBundleNames, cycloneDxPredicateType, slsaPredicateType } from "../lib/release-evidence.mjs";
import {
  classifyResolutionError,
  reproduceRelease,
  resolveExplicitEvidence,
  signerIdentity,
  sigstoreIssuer,
  VerificationUnavailableError,
  verifySignedEvidence,
} from "../lib/signed-verifier.mjs";

const repositoryRoot = path.resolve(new URL("..", import.meta.url).pathname);
const revision = "0123456789abcdef0123456789abcdef01234567";
const execFile = promisify(execFileCallback);
const sha = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");
const property = (name, value) => ({ name: `dev.metalagman.webappsec:${name}`, value });

async function evidenceFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-signed-"));
  const release = await createRelease({
    outputRoot: path.join(root, "release"),
    release: { repository: "https://github.com/metalagman/webappsec", revision, tag: "v0.1.0", workflow: ".github/workflows/release.yml" },
    deployInputs: [
      { source: path.join(repositoryRoot, "lib/content-addressing.mjs"), path: "lib/content-addressing.mjs", role: "worker" },
      { source: path.join(repositoryRoot, "worker/index.js"), path: "worker/index.js", role: "worker" },
      { source: path.join(repositoryRoot, "wrangler.jsonc"), path: "wrangler.jsonc", role: "configuration" },
    ],
  });
  const manifest = JSON.parse(await readFile(release.manifestPath, "utf8"));
  const runtimeFiles = [
    ...manifest.files.map((entry) => ({ path: entry.path, sha256: entry.sha256, category: "public-asset", urlPath: entry.urlPath })),
    ...manifest.inputs.map((entry) => ({ path: `inputs/${entry.path}`, sha256: entry.sha256, category: entry.role === "worker" ? "worker-runtime" : "deployment-configuration" })),
    { path: "manifest.json", sha256: release.digest, category: "deployment-manifest" },
  ].sort((a, b) => a.path.localeCompare(b.path, "en"));
  const evidenceDirectory = path.join(root, "evidence");
  await mkdir(evidenceDirectory);
  const spdx = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `webappsec-runtime-${release.digest}`,
    documentNamespace: `https://github.com/metalagman/webappsec/releases/v0.1.0/sbom/runtime/${release.digest}`,
    creationInfo: { created: "2026-10-21T12:34:56Z", creators: [`Tool: syft-${syftVersion}`] },
    documentDescribes: ["SPDXRef-Package-webappsec-runtime"],
    packages: [{
      SPDXID: "SPDXRef-Package-webappsec-runtime",
      name: "webappsec-runtime",
      versionInfo: release.digest,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: true,
      packageVerificationCode: { packageVerificationCodeValue: "0".repeat(40) },
      licenseConcluded: "NOASSERTION",
      licenseDeclared: "NOASSERTION",
      copyrightText: "NOASSERTION",
      externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: `pkg:generic/webappsec-runtime@${release.digest}` }],
    }],
    files: await Promise.all(runtimeFiles.map(async (entry, index) => ({
      fileName: `./${entry.path}`,
      SPDXID: `SPDXRef-File-${index + 1}`,
      checksums: [
        { algorithm: "SHA1", checksumValue: sha("sha1", await readFile(path.join(release.directory, entry.path))) },
        { algorithm: "SHA256", checksumValue: entry.sha256 },
      ],
      licenseConcluded: "NOASSERTION",
      copyrightText: "NOASSERTION",
    }))),
    relationships: [
      { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package-webappsec-runtime" },
      ...runtimeFiles.map((_, index) => ({ spdxElementId: "SPDXRef-Package-webappsec-runtime", relationshipType: "CONTAINS", relatedSpdxElement: `SPDXRef-File-${index + 1}` })),
    ],
  };
  const runtimeCdx = {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    version: 1,
    metadata: {
      component: {
        type: "application", "bom-ref": `pkg:generic/webappsec-runtime@${release.digest}`,
        name: "webappsec-runtime", version: release.digest,
        properties: [property("scope", "runtime"), property("manifest-sha256", release.digest)],
      },
    },
    components: runtimeFiles.map((entry) => ({
      type: "file", "bom-ref": `file:${entry.path}`, name: entry.path,
      hashes: [{ alg: "SHA-256", content: entry.sha256 }],
      properties: [property("category", entry.category), ...(entry.urlPath ? [property("url-path", entry.urlPath)] : [])],
    })),
  };
  const lock = JSON.parse(await readFile(path.join(repositoryRoot, "package-lock.json"), "utf8"));
  const inventory = lockInventory(lock);
  const buildCdx = {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: "urn:uuid:8c0c39e7-a087-40a9-9da6-2a91b476fc8f",
    version: 1,
    metadata: {
      tools: { components: [{ type: "application", name: "syft", version: syftVersion }] },
      component: {
        type: "application", "bom-ref": inventory.rootRef, name: "webappsec-build", version: release.digest,
        properties: [property("scope", "build"), property("manifest-sha256", release.digest)],
      },
    },
    components: inventory.components,
    dependencies: inventory.dependencies,
  };
  const descriptor = {
    version: grypeVersion,
    timestamp: "2026-10-21T12:34:56Z",
    db: { status: {
      built: "2026-10-20T00:00:00Z",
      schemaVersion: "v6.1.3",
      from: "https://grype.anchore.io/databases/v6/vulnerability-db.tar.zst",
      path: "/tmp/grype/vulnerability.db",
      valid: true,
    } },
  };
  const documents = {
    "runtime.spdx.json": spdx,
    "runtime.cdx.json": runtimeCdx,
    "build.cdx.json": buildCdx,
    "runtime.vulnerabilities.json": vulnerabilityReport({ scope: "runtime", manifestDigest: release.digest, grype: { descriptor, matches: [], ignoredMatches: [] } }),
    "build.vulnerabilities.json": vulnerabilityReport({ scope: "build", manifestDigest: release.digest, grype: { descriptor, matches: [], ignoredMatches: [] } }),
  };
  for (const [name, document] of Object.entries(documents)) await writeFile(path.join(evidenceDirectory, name), `${JSON.stringify(document)}\n`);
  const publish = path.join(root, "publish");
  await assembleReleaseEvidence({
    releaseDirectory: release.directory,
    tarPath: release.tarPath,
    evidenceDirectory,
    outputDirectory: publish,
    repositoryRoot,
    invocationId: "https://github.com/metalagman/webappsec/actions/runs/123/attempts/1",
  });
  await writeBundles(publish, release.digest);
  return { root, release, publish };
}

async function writeBundles(directory, manifestDigest) {
  const identity = signerIdentity("v0.1.0");
  const direct = {
    "evidence-index.sigstore.json": "evidence-index.json",
    "manifest.sigstore.json": "manifest.json",
    "release.sigstore.json": `${manifestDigest}.tar`,
  };
  for (const [bundle, subject] of Object.entries(direct)) {
    await writeFile(path.join(directory, bundle), JSON.stringify({ identity, issuer: sigstoreIssuer, subjectSha256: sha("sha256", await readFile(path.join(directory, subject))) }));
  }
  const statements = [
    ["provenance.manifest.intoto.sigstore.json", "manifest.json", "provenance.slsa.json", slsaPredicateType],
    ["provenance.release.intoto.sigstore.json", `${manifestDigest}.tar`, "provenance.slsa.json", slsaPredicateType],
    ["runtime-cyclonedx.intoto.sigstore.json", `${manifestDigest}.tar`, "runtime.cdx.json", cycloneDxPredicateType],
    ["build-cyclonedx.intoto.sigstore.json", `${manifestDigest}.tar`, "build.cdx.json", cycloneDxPredicateType],
  ];
  for (const [bundle, subject, predicate, predicateType] of statements) {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: subject, digest: { sha256: sha("sha256", await readFile(path.join(directory, subject))) } }],
      predicateType,
      predicate: JSON.parse(await readFile(path.join(directory, predicate), "utf8")),
    };
    await writeFile(path.join(directory, bundle), JSON.stringify({
      identity,
      issuer: sigstoreIssuer,
      dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString("base64"), signatures: [{ sig: "fixture" }] },
    }));
  }
  assert.deepEqual((await Promise.all(authenticationBundleNames.map(async (name) => [name, await readFile(path.join(directory, name))]))).map(([name]) => name).sort(), [...authenticationBundleNames].sort());
}

async function fakeCosign(_command, args) {
  const bundle = JSON.parse(await readFile(args[args.indexOf("--bundle") + 1], "utf8"));
  const identity = args[args.indexOf("--certificate-identity") + 1];
  const issuer = args[args.indexOf("--certificate-oidc-issuer") + 1];
  if (bundle.identity !== identity || bundle.issuer !== issuer) throw new Error("certificate identity or issuer mismatch");
  if (args[0] === "verify-blob") {
    const subject = args.at(-1);
    if (bundle.subjectSha256 !== sha("sha256", await readFile(subject))) throw new Error("signature payload mismatch");
  }
  return { stdout: "Verified OK\n", stderr: "" };
}

test("signed verifier authenticates exact identity, statements, SBOMs, and scan subjects", async () => {
  const fixture = await evidenceFixture();
  const result = await verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: fakeCosign, expectedTag: "v0.1.0" });
  assert.equal(result.manifestDigest, fixture.release.digest);
  assert.equal(result.tag, "v0.1.0");
  assert.deepEqual(result.checks.map((entry) => entry.name), ["evidence-inventory", "signatures", "attestations", "sbom", "vulnerability-evidence"]);
  const rebuilt = await reproduceRelease({
    verified: result,
    releaseSourceRoot: repositoryRoot,
    commandRunner: async (_command, args) => ({ stdout: args[0] === "rev-parse" ? `${revision}\n` : "", stderr: "" }),
  });
  assert.equal(rebuilt.manifestDigest, fixture.release.digest);
});

test("signed verifier rejects wrong signer, statement subject, indexed bytes, and unavailable trust service", async (t) => {
  await t.test("wrong signer identity", async () => {
    const fixture = await evidenceFixture();
    const filename = path.join(fixture.publish, "manifest.sigstore.json");
    const bundle = JSON.parse(await readFile(filename));
    bundle.identity = "https://github.com/attacker/repo/.github/workflows/release.yml@refs/tags/v0.1.0";
    await writeFile(filename, JSON.stringify(bundle));
    await assert.rejects(() => verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: fakeCosign }), (error) => error.verificationLayer === "signatures" && /identity/.test(error.message));
  });

  await t.test("wrong provenance subject", async () => {
    const fixture = await evidenceFixture();
    const filename = path.join(fixture.publish, "provenance.release.intoto.sigstore.json");
    const bundle = JSON.parse(await readFile(filename));
    const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64"));
    statement.subject[0].digest.sha256 = "0".repeat(64);
    bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
    await writeFile(filename, JSON.stringify(bundle));
    await assert.rejects(() => verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: fakeCosign }), (error) => error.verificationLayer === "attestations" && /subject/.test(error.message));
  });

  await t.test("altered indexed SBOM", async () => {
    const fixture = await evidenceFixture();
    await writeFile(path.join(fixture.publish, "runtime.spdx.json"), "{}\n");
    await assert.rejects(() => verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: fakeCosign }), (error) => error.verificationLayer === "evidence-inventory" && /index mismatch/.test(error.message));
  });

  await t.test("Sigstore trust service unavailable", async () => {
    const fixture = await evidenceFixture();
    const unavailable = async () => { throw new Error("network connection timed out while fetching TUF root"); };
    await assert.rejects(() => verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: unavailable }), (error) => error instanceof VerificationUnavailableError && error.verificationLayer === "signatures");
  });

  await t.test("historical unavailable scan is a permanent evidence failure", async () => {
    const fixture = await evidenceFixture();
    const reportPath = path.join(fixture.publish, "build.vulnerabilities.json");
    await writeFile(reportPath, `${JSON.stringify(unavailableVulnerabilityReport({ scope: "build", manifestDigest: fixture.release.digest, reason: "scanner unavailable during release" }))}\n`);
    const indexPath = path.join(fixture.publish, "evidence-index.json");
    const index = JSON.parse(await readFile(indexPath));
    const entry = index.files.find((candidate) => candidate.name === "build.vulnerabilities.json");
    const reportBytes = await readFile(reportPath);
    entry.size = reportBytes.length;
    entry.sha256 = sha("sha256", reportBytes);
    await writeFile(indexPath, canonicalJson(index));
    const indexBundlePath = path.join(fixture.publish, "evidence-index.sigstore.json");
    const indexBundle = JSON.parse(await readFile(indexBundlePath));
    indexBundle.subjectSha256 = sha("sha256", await readFile(indexPath));
    await writeFile(indexBundlePath, JSON.stringify(indexBundle));
    await assert.rejects(() => verifySignedEvidence({ directory: fixture.publish, repositoryRoot, commandRunner: fakeCosign }), (error) => {
      assert.equal(error.verificationLayer, "vulnerability-evidence");
      assert.equal(error instanceof VerificationUnavailableError, false);
      return /unavailable at release time/.test(error.message);
    });
  });
});

test("GitHub resolution requires an explicit tag and never selects latest", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-download-"));
  let invocation;
  await resolveExplicitEvidence({
    releaseTag: "v0.1.0",
    downloadDirectory: directory,
    commandRunner: async (command, args) => { invocation = [command, ...args]; return { stdout: "", stderr: "" }; },
  });
  assert.deepEqual(invocation, ["gh", "release", "download", "v0.1.0", "--repo", "metalagman/webappsec", "--dir", directory]);
  assert.equal(invocation.includes("latest"), false);
  await assert.rejects(() => resolveExplicitEvidence({ releaseTag: "latest", downloadDirectory: directory }), /explicit immutable SemVer/);
});

test("GitHub 404 and 403 release errors are policy failures, not service outages", async () => {
  for (const message of ["HTTP 404 from api.github.com: release not found", "HTTP 403 from api.github.com: forbidden"]) {
    const directory = await mkdtemp(path.join(tmpdir(), "webappsec-download-error-"));
    await assert.rejects(() => resolveExplicitEvidence({
      releaseTag: "v0.1.0",
      downloadDirectory: directory,
      commandRunner: async () => { throw new Error(message); },
    }), (error) => error instanceof VerificationUnavailableError === false && error.message === message);
  }
});

test("production verification workflow retains JSON and publishes separately signed immutable evidence", async () => {
  const workflow = await readFile(path.join(repositoryRoot, ".github/workflows/verify-production.yml"), "utf8");
  const publisher = await readFile(path.join(repositoryRoot, "scripts/publish-verification.sh"), "utf8");
  assert.match(workflow, /RELEASE_TAG: \$\{\{ inputs\.release \|\| vars\.PRODUCTION_RELEASE_TAG \}\}/);
  assert.equal((workflow.match(/ref: \$\{\{ github\.sha \}\}/g) ?? []).length, 2);
  assert.match(workflow, /resolve-release\.mjs[\s\\]+--release "\$RELEASE_TAG"/);
  assert.match(workflow, /if: steps\.resolve\.outputs\.exit_code == '0'/);
  assert.match(workflow, /resolve-source\.mjs[\s\\]+--release "\$RELEASE_TAG"/);
  assert.ok(workflow.indexOf("resolve-release.mjs") < workflow.indexOf("resolve-source.mjs"));
  assert.match(workflow, /verify-release\.mjs[\s\\]+--evidence \.artifacts\/verification-release/);
  assert.match(workflow, /--source release-source/);
  assert.match(workflow, /env -u GH_TOKEN -u GITHUB_TOKEN/);
  assert.match(workflow, /actions\/upload-artifact@[a-f0-9]{40}/);
  assert.match(workflow, /actions\/download-artifact@[a-f0-9]{40}/);
  assert.match(workflow, /retention-days: 90/);
  assert.match(workflow, /steps\.verify\.outputs\.exit_code \|\| steps\.source\.outputs\.exit_code \|\| steps\.resolve\.outputs\.exit_code/);
  const readOnlyJob = workflow.slice(workflow.indexOf("  verify-production:"), workflow.indexOf("  publish-verification:"));
  const publishingJob = workflow.slice(workflow.indexOf("  publish-verification:"));
  assert.doesNotMatch(readOnlyJob, /id-token: write|contents: write|secrets\./);
  assert.match(publishingJob, /needs: verify-production/);
  assert.match(publishingJob, /contents: write\n      id-token: write/);
  assert.match(publishingJob, /publish-verification\.sh/);
  assert.doesNotMatch(publishingJob, /CLOUDFLARE_|secrets\./);
  assert.match(publisher, /verification-evidence\.mjs build/);
  assert.match(publisher, /sign-blob --yes --bundle/);
  assert.match(publisher, /verification-evidence\.mjs verify[\s\S]+--signed/);
  assert.match(publisher, /gh release create[\s\S]+--draft[\s\S]+gh release edit[\s\S]+--draft=false/);
});

test("Sigstore TUF DNS failures are classified as unavailable", async () => {
  const error = new Error("cosign exited 1: updating TUF root: lookup tuf-repo-cdn.sigstore.dev: socket: operation not permitted");
  const classified = classifyResolutionError(error);
  assert.ok(classified instanceof VerificationUnavailableError);
});

test("release resolver always emits a stable JSON report", async () => {
  const cli = path.join(repositoryRoot, "scripts/resolve-release.mjs");
  for (const scenario of [
    { message: "HTTP 404 from api.github.com: release not found", code: 1, state: "fail" },
    { message: "rate limit exceeded while contacting api.github.com", code: 3, state: "unavailable" },
    { message: "error connecting to api.github.com; check your internet connection", code: 3, state: "unavailable" },
  ]) {
    const root = await mkdtemp(path.join(tmpdir(), "webappsec-resolver-cli-"));
    const bin = path.join(root, "bin");
    const output = path.join(root, "evidence");
    await mkdir(bin);
    await mkdir(output);
    await writeFile(path.join(bin, "gh"), `#!/bin/sh\nprintf '%s\\n' '${scenario.message}' >&2\nexit 1\n`);
    await chmod(path.join(bin, "gh"), 0o755);
    await assert.rejects(
      () => execFile(process.execPath, [cli, "--release", "v0.1.0", "--output", output, "--json"], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      }),
      (error) => {
        assert.equal(error.code, scenario.code);
        const report = JSON.parse(error.stdout);
        assert.equal(report.exitCode, scenario.code);
        assert.equal(report.layers[0].name, "release-resolution");
        assert.equal(report.layers[0].state, scenario.state);
        assert.match(report.layers[0].detail, new RegExp(scenario.message.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
        return true;
      },
    );
  }

  await assert.rejects(
    () => execFile(process.execPath, [cli, "--release", "latest", "--output", "/tmp/unused", "--json"]),
    (error) => {
      assert.equal(error.code, 2);
      const report = JSON.parse(error.stdout);
      assert.equal(report.result, "invalid-invocation");
      assert.equal(report.layers[0].name, "release-resolution");
      return true;
    },
  );
});

test("release source resolver classifies missing tags and transient GitHub failures", async () => {
  const cli = path.join(repositoryRoot, "scripts/resolve-source.mjs");
  for (const scenario of [
    { message: "fatal: Remote branch v0.1.0 not found in upstream origin", code: 1, state: "fail" },
    { message: "fatal: unable to access repository: Could not resolve host: github.com", code: 3, state: "unavailable" },
    { message: "fatal: unable to access repository: Failed to connect to github.com port 443", code: 3, state: "unavailable" },
    { message: "fatal: unable to access repository: Couldn't connect to server", code: 3, state: "unavailable" },
    { message: "fatal: unable to access repository: The requested URL returned error: 503", code: 3, state: "unavailable" },
  ]) {
    const root = await mkdtemp(path.join(tmpdir(), "webappsec-source-cli-"));
    const bin = path.join(root, "bin");
    await mkdir(bin);
    await writeFile(path.join(bin, "git"), `#!/bin/sh\ncat >&2 <<'ERROR_MESSAGE'\n${scenario.message}\nERROR_MESSAGE\nexit 128\n`);
    await chmod(path.join(bin, "git"), 0o755);
    await assert.rejects(
      () => execFile(process.execPath, [cli, "--release", "v0.1.0", "--output", path.join(root, "source"), "--json"], {
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      }),
      (error) => {
        assert.equal(error.code, scenario.code);
        const report = JSON.parse(error.stdout);
        assert.equal(report.layers[0].name, "release-source-resolution");
        assert.equal(report.layers[0].state, scenario.state);
        return true;
      },
    );
  }
});

test("clean rebuild rejects a site input symlink from an untrusted checkout", async () => {
  const fixture = await evidenceFixture();
  const verified = await verifySignedEvidence({
    directory: fixture.publish,
    repositoryRoot,
    commandRunner: fakeCosign,
    expectedTag: "v0.1.0",
  });
  const sourceRoot = path.join(fixture.root, "untrusted-source");
  await mkdir(path.join(sourceRoot, "lib"), { recursive: true });
  await mkdir(path.join(sourceRoot, "worker"), { recursive: true });
  await cp(path.join(repositoryRoot, "site"), path.join(sourceRoot, "site"), { recursive: true });
  await cp(path.join(repositoryRoot, "lib/content-addressing.mjs"), path.join(sourceRoot, "lib/content-addressing.mjs"));
  await cp(path.join(repositoryRoot, "worker/index.js"), path.join(sourceRoot, "worker/index.js"));
  await cp(path.join(repositoryRoot, "wrangler.jsonc"), path.join(sourceRoot, "wrangler.jsonc"));
  const external = path.join(fixture.root, "external-styles.css");
  await writeFile(external, "body { color: red; }\n");
  await rm(path.join(sourceRoot, "site/styles.css"));
  await symlink(external, path.join(sourceRoot, "site/styles.css"));

  await assert.rejects(() => reproduceRelease({
    verified,
    releaseSourceRoot: sourceRoot,
    commandRunner: async (_command, args) => ({ stdout: args[0] === "rev-parse" ? `${revision}\n` : "", stderr: "" }),
  }), /regular file: styles\.css/);
});

test("signed verifier CLI gives stable usage status for ambiguous or mutable release selection", async () => {
  const cli = path.join(repositoryRoot, "scripts/verify-release.mjs");
  for (const args of [[], ["--release", "latest"], ["--release", "v0.1.0", "--evidence", "/tmp/evidence"]]) {
    await assert.rejects(() => execFile(process.execPath, [cli, ...args]), (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /^Usage:/);
      return true;
    });
  }
});
