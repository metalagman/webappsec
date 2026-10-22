import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";

import { validateOnlineVerifierSnapshot, validateBrowserReleaseManifest } from "./browser-verifier.mjs";
import { canonicalJson } from "./canonical-json.mjs";
import {
  verifyDeploymentEvidence as inspectSignedDeploymentDirectory,
  verifySignedDeploymentEvidence,
} from "./deployment-evidence.mjs";
import { verifySignedEvidence } from "./signed-verifier.mjs";
import { verifySignedVerificationEvidence } from "./verification-evidence.mjs";

const repository = "metalagman/webappsec";
const verificationWorkflow = ".github/workflows/verify-production.yml";
const productionOrigin = "https://webappsec.metalagman.dev";
const semverSource = "v[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?";
const sha256Pattern = /^[a-f0-9]{64}$/;
const revisionPattern = /^[a-f0-9]{40}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const releaseCheckNames = ["evidence-inventory", "signatures", "attestations", "sbom", "vulnerability-evidence"];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function exactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  if (Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) throw new Error(`${label} fields mismatch`);
}

function validateWorkflowRun(run) {
  exactKeys(run, ["repository", "id", "name", "workflowPath", "conclusion", "headBranch", "headSha", "event", "htmlUrl"], "workflow run");
  const runId = typeof run.id === "string" ? run.id : "";
  if (run.repository !== repository || !/^[1-9][0-9]*$/.test(runId)
    || run.name !== "Verify production" || run.workflowPath !== verificationWorkflow
    || run.conclusion !== "success" || run.headBranch !== "main" || !revisionPattern.test(run.headSha)
    || !["schedule", "workflow_dispatch"].includes(run.event)
    || run.htmlUrl !== `https://github.com/${repository}/actions/runs/${runId}`) {
    throw new Error("workflow run identity mismatch");
  }
  return run;
}

function validateCandidates(candidates, label, maximum = 20) {
  if (!Array.isArray(candidates) || candidates.length > maximum) throw new Error(`${label} candidate limit exceeded`);
  for (const candidate of candidates) {
    exactKeys(candidate, ["release", "directory"], `${label} candidate`);
    if (typeof candidate.release !== "string" || typeof candidate.directory !== "string" || !candidate.directory) {
      throw new Error(`invalid ${label} candidate`);
    }
  }
  return candidates;
}

function validateCloudflareStatus(status) {
  exactKeys(status, ["deploymentId", "versions"], "Cloudflare deployment status");
  if (!uuidPattern.test(status.deploymentId) || !Array.isArray(status.versions) || status.versions.length !== 1) {
    throw new Error("Cloudflare deployment must be unambiguous");
  }
  exactKeys(status.versions[0], ["versionId", "percentage"], "Cloudflare deployment version");
  if (!uuidPattern.test(status.versions[0].versionId) || status.versions[0].percentage !== 100) {
    throw new Error("Cloudflare deployment must be unambiguous");
  }
  return { deploymentId: status.deploymentId, versionId: status.versions[0].versionId };
}

function validateCurrentDeployment(state) {
  exactKeys(state, ["cloudflareStatus", "productionIdentity"], "current deployment");
  const cloudflare = validateCloudflareStatus(state.cloudflareStatus);
  exactKeys(state.productionIdentity, ["manifestDigest", "workerVersion"], "production identity");
  if (!sha256Pattern.test(state.productionIdentity.manifestDigest)
    || !uuidPattern.test(state.productionIdentity.workerVersion)) throw new Error("invalid production identity headers");
  if (state.productionIdentity.workerVersion !== cloudflare.versionId) {
    throw new Error("production identity does not match Cloudflare deployment");
  }
  return { ...cloudflare, manifestDigest: state.productionIdentity.manifestDigest };
}

function validateReleaseChecks(checks) {
  if (!Array.isArray(checks) || checks.length !== releaseCheckNames.length) throw new Error("source release verification is incomplete");
  for (const [index, check] of checks.entries()) {
    if (check?.name !== releaseCheckNames[index] || check.state !== "pass" || typeof check.detail !== "string" || !check.detail) {
      throw new Error("source release verification is incomplete");
    }
  }
}

function exactOne(candidates, message) {
  if (candidates.length !== 1) throw new Error(message);
  return candidates[0];
}

export async function resolveTrustedVerifierSnapshot({
  workflowRun,
  verificationCandidates,
  sourceCandidates,
  deploymentCandidates,
  readCurrentDeployment,
  repositoryRoot,
  cosignPath = ".bin/cosign",
  commandRunner,
  verifyVerificationEvidence = verifySignedVerificationEvidence,
  verifyReleaseEvidence = verifySignedEvidence,
  inspectDeploymentEvidence = inspectSignedDeploymentDirectory,
  verifyDeploymentEvidence = verifySignedDeploymentEvidence,
}) {
  const run = validateWorkflowRun(workflowRun);
  if (typeof readCurrentDeployment !== "function") throw new Error("current deployment reader is required");
  const initialDeployment = validateCurrentDeployment(await readCurrentDeployment());
  const verificationPattern = new RegExp(`^verification-(${semverSource})-${run.id}$`);
  const verificationCandidate = exactOne(
    validateCandidates(verificationCandidates, "verification release").filter(({ release }) => verificationPattern.test(release)),
    "expected exactly one verification release for workflow run",
  );
  const verificationMatch = verificationPattern.exec(verificationCandidate.release);
  const verifiedVerification = await verifyVerificationEvidence({
    directory: verificationCandidate.directory,
    cosignPath,
    commandRunner,
  });
  const verificationRecord = verifiedVerification?.record;
  const verificationReport = verifiedVerification?.report;
  const releaseTag = verificationMatch[1];
  if (verificationRecord?.sourceRelease?.tag !== releaseTag
    || verificationRecord?.github?.repository !== repository
    || verificationRecord?.github?.workflow !== verificationWorkflow
    || verificationRecord?.github?.ref !== "refs/heads/main"
    || verificationRecord?.github?.revision !== run.headSha
    || verificationRecord?.github?.runUrl !== run.htmlUrl
    || verificationRecord?.production?.origin !== productionOrigin
    || verificationRecord?.result !== "verified") {
    throw new Error("verification evidence does not match workflow run identity");
  }

  const sourceCandidate = exactOne(
    validateCandidates(sourceCandidates, "source release").filter(({ release }) => release === releaseTag),
    "expected exactly one source release",
  );
  const verifiedRelease = await verifyReleaseEvidence({
    directory: sourceCandidate.directory,
    repositoryRoot,
    cosignPath,
    commandRunner,
    expectedTag: releaseTag,
  });
  validateReleaseChecks(verifiedRelease?.checks);
  if (verifiedRelease.tag !== releaseTag || !revisionPattern.test(verifiedRelease.revision)
    || verifiedRelease.manifestDigest !== verificationRecord.sourceRelease.manifestDigest
    || !sha256Pattern.test(verifiedRelease.manifestDigest)) {
    throw new Error("source release identity mismatch");
  }

  const manifestBytes = await readFile(verifiedRelease.manifestPath);
  if (manifestBytes.length < 1 || manifestBytes.length > 2 * 1024 * 1024
    || sha256(manifestBytes) !== verifiedRelease.manifestDigest) throw new Error("source release manifest digest mismatch");
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes);
  } catch (error) {
    throw new Error(`source release manifest is malformed: ${error.message}`);
  }
  if (!manifestBytes.equals(Buffer.from(canonicalJson(manifest)))) throw new Error("source release manifest must be canonical JSON");
  validateBrowserReleaseManifest(manifest);
  if (manifest.release.tag !== releaseTag || manifest.release.revision !== verifiedRelease.revision) {
    throw new Error("source release identity mismatch");
  }
  if (verifiedRelease.manifestDigest !== initialDeployment.manifestDigest) {
    throw new Error("current production manifest does not match signed release");
  }

  const current = initialDeployment;
  const escapedTag = releaseTag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const deploymentPattern = new RegExp(`^deployment-(?:bootstrap|deploy|rollback|restore)-${escapedTag}-[1-9][0-9]*$`);
  const inspected = [];
  for (const candidate of validateCandidates(deploymentCandidates, "deployment release")) {
    if (!deploymentPattern.test(candidate.release)) continue;
    const evidence = await inspectDeploymentEvidence(candidate.directory);
    const record = evidence?.record;
    const deploymentRun = /^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/([1-9][0-9]*)$/.exec(record?.github?.runUrl ?? "");
    const exactRelease = deploymentRun
      ? `deployment-${record.action}-${releaseTag}-${deploymentRun[1]}`
      : null;
    if (candidate.release === exactRelease
      && record?.sourceRelease?.tag === releaseTag
      && record.sourceRelease.revision === verifiedRelease.revision
      && record.sourceRelease.manifestDigest === verifiedRelease.manifestDigest
      && record.cloudflare?.versionId === current.versionId
      && record.cloudflare?.deploymentId === current.deploymentId) {
      inspected.push({ candidate, evidence });
    }
  }
  const selected = exactOne(inspected, "expected exactly one matching deployment release");
  const expectedWorkflow = ["bootstrap", "deploy"].includes(selected.evidence.record.action)
    ? ".github/workflows/deploy.yml" : ".github/workflows/rollback.yml";
  const signedDeployment = await verifyDeploymentEvidence({
    directory: selected.candidate.directory,
    expected: {
      releaseTag,
      manifestDigest: verifiedRelease.manifestDigest,
      versionId: current.versionId,
      workflow: expectedWorkflow,
      ref: `refs/tags/${releaseTag}`,
    },
    cosignPath,
    commandRunner,
  });
  const deploymentRecord = signedDeployment?.record;
  if (deploymentRecord?.cloudflare?.deploymentId !== current.deploymentId
    || deploymentRecord?.cloudflare?.versionId !== current.versionId
    || deploymentRecord?.github?.workflow !== expectedWorkflow
    || deploymentRecord?.github?.ref !== `refs/tags/${releaseTag}`) {
    throw new Error("signed deployment evidence identity mismatch");
  }
  const signedRun = /^https:\/\/github\.com\/metalagman\/webappsec\/actions\/runs\/([1-9][0-9]*)$/.exec(deploymentRecord.github.runUrl ?? "");
  if (!signedRun || selected.candidate.release !== `deployment-${deploymentRecord.action}-${releaseTag}-${signedRun[1]}`) {
    throw new Error("signed deployment release action or run mismatch");
  }

  const finalDeployment = validateCurrentDeployment(await readCurrentDeployment());
  if (canonicalJson(finalDeployment) !== canonicalJson(initialDeployment)) {
    throw new Error("deployment changed during resolution");
  }

  for (const layer of verificationReport?.layers ?? []) {
    if (typeof layer.detail !== "string" || Buffer.byteLength(layer.detail) > 8192) {
      throw new Error("verification layer detail exceeds snapshot limit");
    }
  }

  const snapshot = {
    schema: "https://webappsec.metalagman.dev/schema/online-verifier-snapshot-v1",
    version: 1,
    target: {
      origin: productionOrigin,
      manifestDigest: verifiedRelease.manifestDigest,
      workerVersion: current.versionId,
      deploymentId: current.deploymentId,
    },
    sourceRelease: {
      tag: releaseTag,
      revision: verifiedRelease.revision,
      url: `https://github.com/${repository}/releases/tag/${releaseTag}`,
    },
    deploymentEvidence: {
      release: selected.candidate.release,
      url: `https://github.com/${repository}/releases/tag/${selected.candidate.release}`,
      runUrl: deploymentRecord.github.runUrl,
    },
    verificationEvidence: {
      release: verificationCandidate.release,
      url: `https://github.com/${repository}/releases/tag/${verificationCandidate.release}`,
      runUrl: run.htmlUrl,
      verifiedAt: verificationRecord.production.verifiedAt,
      layers: verificationReport.layers.map(({ name, state, detail }) => ({
        name,
        state,
        detail: name === "release-resolution" ? releaseTag : detail,
      })),
    },
    proofs: ["release-signatures", "deployment-signatures", "verification-signatures"]
      .map((name) => ({ name, state: "pass", source: "ci" })),
    manifest: {
      path: "release-manifest.json",
      size: manifestBytes.length,
      sha256: verifiedRelease.manifestDigest,
    },
  };
  validateOnlineVerifierSnapshot(snapshot);
  const snapshotBytes = Buffer.from(canonicalJson(snapshot));
  if (snapshotBytes.length > 2 * 1024 * 1024) throw new Error("verifier snapshot exceeds publication limit");
  return {
    snapshot,
    snapshotBytes,
    manifestBytes,
  };
}

export async function writeVerifierPublication({ outputDirectory, publication }) {
  if (!publication?.snapshotBytes?.length || !publication?.manifestBytes?.length) throw new Error("invalid verifier publication");
  if (publication.snapshotBytes.length > 2 * 1024 * 1024 || publication.manifestBytes.length > 2 * 1024 * 1024) {
    throw new Error("verifier publication exceeds byte limit");
  }
  await mkdir(outputDirectory, { recursive: true });
  if ((await readdir(outputDirectory)).length !== 0) throw new Error("verifier publication output must be empty");
  await Promise.all([
    writeFile(`${outputDirectory}/current-verification.json`, publication.snapshotBytes, { flag: "wx" }),
    writeFile(`${outputDirectory}/release-manifest.json`, publication.manifestBytes, { flag: "wx" }),
  ]);
}
