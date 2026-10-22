import { authenticationBundleNames } from "./release-evidence.mjs";
import { deploymentBundleNames } from "./deployment-evidence.mjs";
import { verificationBundleNames } from "./verification-evidence.mjs";

const MiB = 1024 * 1024;
const sourceStaticNames = [
  ...authenticationBundleNames,
  "build.cdx.json",
  "build.vulnerabilities.json",
  "evidence-index.json",
  "manifest.json",
  "provenance.slsa.json",
  "runtime.cdx.json",
  "runtime.spdx.json",
  "runtime.vulnerabilities.json",
];

export const verificationAssetNames = Object.freeze([
  "verification-index.json",
  "verification-record.json",
  "verification-report.json",
  "verification-report.txt",
  ...verificationBundleNames,
].sort());

export const deploymentAssetNames = Object.freeze([
  "deployment-index.json",
  "deployment-record.json",
  "verification-report.json",
  ...deploymentBundleNames,
].sort());

export function sourceAssetNames(manifestDigest) {
  if (!/^[a-f0-9]{64}$/.test(manifestDigest)) throw new Error("invalid source manifest digest");
  return Object.freeze([...sourceStaticNames, `${manifestDigest}.tar`].sort());
}

const policies = {
  source: { perAssetBytes: 100 * MiB, totalBytes: 128 * MiB },
  verification: { perAssetBytes: 10 * MiB, totalBytes: 32 * MiB },
  deployment: { perAssetBytes: 10 * MiB, totalBytes: 32 * MiB },
};

function expectedNames(release, kind) {
  if (kind === "verification") return verificationAssetNames;
  if (kind === "deployment") return deploymentAssetNames;
  const archives = release.assets.map(({ name }) => name).filter((name) => /^[a-f0-9]{64}\.tar$/.test(name));
  if (archives.length !== 1) throw new Error("source release asset inventory mismatch");
  return sourceAssetNames(archives[0].slice(0, 64));
}

export function validateReleaseAssetPlan(release, kind) {
  const policy = policies[kind];
  if (!policy) throw new Error("unknown release asset policy");
  if (!release || typeof release !== "object" || Array.isArray(release)
    || Object.keys(release).sort().join("\0") !== ["assets", "tagName"].sort().join("\0")
    || typeof release.tagName !== "string" || !Array.isArray(release.assets)) {
    throw new Error("invalid release asset metadata");
  }
  const names = [];
  let totalBytes = 0;
  for (const asset of release.assets) {
    if (!asset || typeof asset !== "object" || Array.isArray(asset)
      || Object.keys(asset).sort().join("\0") !== ["name", "size"].sort().join("\0")) {
      throw new Error("invalid release asset metadata");
    }
    if (typeof asset.name !== "string" || asset.name.length < 1 || asset.name.length > 180
      || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(asset.name)) throw new Error("unsafe release asset name");
    if (!Number.isSafeInteger(asset.size) || asset.size < 1 || asset.size > policy.perAssetBytes) {
      throw new Error(`release asset size exceeds ${kind} limit`);
    }
    names.push(asset.name);
    totalBytes += asset.size;
  }
  if (new Set(names).size !== names.length) throw new Error("duplicate release asset name");
  const expected = [...expectedNames(release, kind)].sort();
  const sorted = [...names].sort();
  if (JSON.stringify(sorted) !== JSON.stringify(expected)) throw new Error(`${kind} release asset inventory mismatch`);
  if (totalBytes > policy.totalBytes) throw new Error(`${kind} release aggregate size exceeds limit`);
  return Object.freeze({ release: release.tagName, kind, names: Object.freeze(sorted), totalBytes });
}

export function validateAggregateReleasePlans(plans, maximumBytes = 256 * MiB) {
  if (!Array.isArray(plans) || plans.length < 1 || plans.length > 22) throw new Error("release download plan count exceeds limit");
  const totalBytes = plans.reduce((total, plan) => total + plan.totalBytes, 0);
  if (!Number.isSafeInteger(totalBytes) || totalBytes > maximumBytes) throw new Error("release download aggregate size exceeds limit");
  return totalBytes;
}
