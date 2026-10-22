#!/usr/bin/env node
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  resolveTrustedVerifierSnapshot,
  writeVerifierPublication,
} from "../lib/online-verifier-snapshot.mjs";
import {
  validateAggregateReleasePlans,
  validateReleaseAssetPlan,
} from "../lib/github-release-assets.mjs";
import { runCommand } from "../lib/signed-verifier.mjs";

const repository = "metalagman/webappsec";
const usage = "Usage: node scripts/resolve-online-verifier.mjs --run <numeric-id> --output <empty-directory> [--cosign <path>] [--config <wrangler.jsonc>]";
const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (["--run", "--output", "--cosign", "--config"].includes(argument)
    && args[index + 1] && !args[index + 1].startsWith("--")) {
    options[argument.slice(2)] = args[++index];
  } else {
    process.stderr.write(`${usage}\n`);
    process.exit(2);
  }
}
if (!/^[1-9][0-9]*$/.test(options.run ?? "") || !options.output) {
  process.stderr.write(`${usage}\n`);
  process.exit(2);
}

function parseJson(stdout, label) {
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`${label} returned malformed JSON: ${error.message}`);
  }
}

async function downloadRelease(metadata, plan, directory) {
  await mkdir(directory, { recursive: false });
  const patterns = plan.names.flatMap((name) => ["--pattern", name]);
  await runCommand("gh", ["release", "download", metadata.tagName, "--repo", repository, "--dir", directory, ...patterns]);
  return { release: metadata.tagName, directory };
}

function normalizeReleaseMetadata(release) {
  return {
    tagName: release?.tag_name,
    assets: Array.isArray(release?.assets) ? release.assets.map((asset) => ({ name: asset?.name, size: asset?.size })) : null,
  };
}

function normalizeCloudflareStatus(rawStatus) {
  return {
    deploymentId: rawStatus.id,
    versions: Array.isArray(rawStatus.versions) ? rawStatus.versions.map((version) => ({
      versionId: version.version_id,
      percentage: version.percentage,
    })) : null,
  };
}

async function readLiveCurrentDeployment() {
  const wranglerPath = path.resolve("node_modules/.bin/wrangler");
  const cloudflareResponse = await runCommand(wranglerPath, [
    "deployments", "status", "--config", path.resolve(options.config ?? "wrangler.jsonc"), "--json",
  ]);
  const response = await fetch("https://webappsec.metalagman.dev/", {
    cache: "no-store",
    credentials: "omit",
    method: "HEAD",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`production identity returned HTTP ${response.status}`);
  return {
    cloudflareStatus: normalizeCloudflareStatus(parseJson(cloudflareResponse.stdout, "Cloudflare deployment status")),
    productionIdentity: {
      manifestDigest: response.headers.get("X-Webappsec-Release"),
      workerVersion: response.headers.get("X-Webappsec-Worker-Version"),
    },
  };
}

const workspace = await mkdtemp(path.join(tmpdir(), "webappsec-online-resolver-"));
try {
  const workflowResponse = await runCommand("gh", ["api", `repos/${repository}/actions/runs/${options.run}`]);
  const apiRun = parseJson(workflowResponse.stdout, "GitHub workflow run");
  const workflowRun = {
    repository: apiRun.repository?.full_name,
    id: String(apiRun.id ?? ""),
    name: apiRun.name,
    workflowPath: apiRun.path,
    conclusion: apiRun.conclusion,
    headBranch: apiRun.head_branch,
    headSha: apiRun.head_sha,
    event: apiRun.event,
    htmlUrl: apiRun.html_url,
  };

  const releasesResponse = await runCommand("gh", ["api", `repos/${repository}/releases?per_page=100`]);
  const releases = parseJson(releasesResponse.stdout, "GitHub releases");
  if (!Array.isArray(releases) || releases.length >= 100) throw new Error("GitHub release enumeration is invalid or reached its bound");
  const releaseMetadata = releases.map(normalizeReleaseMetadata);
  const verificationReleases = releaseMetadata.filter(({ tagName }) => new RegExp(`^verification-v[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?-${options.run}$`).test(tagName));
  if (verificationReleases.length !== 1) throw new Error("expected exactly one verification release for workflow run");
  const releaseTag = /^verification-(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-/.exec(verificationReleases[0].tagName)?.[1];
  if (!releaseTag) throw new Error("verification release has invalid source tag");
  const escapedTag = releaseTag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const sourceReleases = releaseMetadata.filter(({ tagName }) => tagName === releaseTag);
  if (sourceReleases.length !== 1) throw new Error("expected exactly one source release");
  const deploymentReleases = releaseMetadata.filter(({ tagName }) =>
    new RegExp(`^deployment-(?:bootstrap|deploy|rollback|restore)-${escapedTag}-[1-9][0-9]*$`).test(tagName));
  if (deploymentReleases.length < 1 || deploymentReleases.length > 20) throw new Error("deployment release candidate count is outside bounds");

  const verificationPlan = validateReleaseAssetPlan(verificationReleases[0], "verification");
  const sourcePlan = validateReleaseAssetPlan(sourceReleases[0], "source");
  const deploymentPlans = deploymentReleases.map((release) => validateReleaseAssetPlan(release, "deployment"));
  validateAggregateReleasePlans([verificationPlan, sourcePlan, ...deploymentPlans]);
  const initialDeployment = await readLiveCurrentDeployment();

  const verificationCandidate = await downloadRelease(verificationReleases[0], verificationPlan, path.join(workspace, "verification"));
  const sourceCandidate = await downloadRelease(sourceReleases[0], sourcePlan, path.join(workspace, "source-evidence"));
  const deploymentCandidates = [];
  for (const [index, release] of deploymentReleases.entries()) {
    deploymentCandidates.push(await downloadRelease(release, deploymentPlans[index], path.join(workspace, `deployment-${index}`)));
  }
  const releaseSource = path.join(workspace, "release-source");
  await runCommand("git", [
    "clone", "--depth=1", "--single-branch", "--branch", releaseTag,
    "https://github.com/metalagman/webappsec.git", releaseSource,
  ]);

  let deploymentRead = 0;
  const readCurrentDeployment = async () => {
    deploymentRead += 1;
    return deploymentRead === 1 ? initialDeployment : readLiveCurrentDeployment();
  };

  const publication = await resolveTrustedVerifierSnapshot({
    workflowRun,
    verificationCandidates: [verificationCandidate],
    sourceCandidates: [sourceCandidate],
    deploymentCandidates,
    readCurrentDeployment,
    repositoryRoot: releaseSource,
    cosignPath: path.resolve(options.cosign ?? ".bin/cosign"),
  });
  await writeVerifierPublication({ outputDirectory: path.resolve(options.output), publication });
  process.stdout.write(`${JSON.stringify({
    release: publication.snapshot.sourceRelease.tag,
    manifestDigest: publication.snapshot.target.manifestDigest,
    workerVersion: publication.snapshot.target.workerVersion,
    deploymentId: publication.snapshot.target.deploymentId,
  })}\n`);
} finally {
  await rm(workspace, { recursive: true, force: true });
}
