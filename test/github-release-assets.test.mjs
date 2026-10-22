import assert from "node:assert/strict";
import test from "node:test";

import {
  deploymentAssetNames,
  sourceAssetNames,
  validateAggregateReleasePlans,
  validateReleaseAssetPlan,
  verificationAssetNames,
} from "../lib/github-release-assets.mjs";

const digest = "a".repeat(64);

const release = (tagName, names, size = 1024) => ({
  tagName,
  assets: names.map((name) => ({ name, size })),
});

test("release asset preflight accepts only exact bounded inventories", () => {
  const source = validateReleaseAssetPlan(release("v0.2.7", sourceAssetNames(digest)), "source");
  const verification = validateReleaseAssetPlan(
    release("verification-v0.2.7-123", verificationAssetNames),
    "verification",
  );
  const deployment = validateReleaseAssetPlan(
    release("deployment-deploy-v0.2.7-122", deploymentAssetNames),
    "deployment",
  );
  assert.deepEqual(source.names, [...sourceAssetNames(digest)].sort());
  assert.equal(verification.totalBytes, verificationAssetNames.length * 1024);
  assert.equal(deployment.names.length, deploymentAssetNames.length);
});

test("release asset preflight rejects missing, unexpected, duplicate, unsafe, and oversized assets", () => {
  const valid = verificationAssetNames;
  assert.throws(() => validateReleaseAssetPlan(release("verification-v0.2.7-123", valid.slice(1)), "verification"), /inventory/);
  assert.throws(() => validateReleaseAssetPlan(release("verification-v0.2.7-123", [...valid, "extra.json"]), "verification"), /inventory/);
  assert.throws(() => validateReleaseAssetPlan(release("verification-v0.2.7-123", [...valid.slice(1), valid[0], valid[0]]), "verification"), /duplicate|inventory/);
  assert.throws(() => validateReleaseAssetPlan(release("verification-v0.2.7-123", [...valid.slice(1), "../secret"]), "verification"), /unsafe|inventory/);
  assert.throws(() => validateReleaseAssetPlan(release("verification-v0.2.7-123", valid, 11 * 1024 * 1024), "verification"), /size/);
  assert.throws(() => validateReleaseAssetPlan(release("v0.2.7", [...sourceAssetNames(digest), `${"b".repeat(64)}.tar`]), "source"), /inventory/);
});

test("aggregate plan is bounded before any download", () => {
  const oversized = release("v0.2.7", sourceAssetNames(digest), 10 * 1024 * 1024);
  assert.throws(() => validateReleaseAssetPlan(oversized, "source"), /aggregate size/);
  assert.throws(() => validateAggregateReleasePlans(
    Array.from({ length: 9 }, () => ({ totalBytes: 32 * 1024 * 1024 })),
  ), /aggregate size/);
});
