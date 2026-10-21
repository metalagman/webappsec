#!/usr/bin/env node
import { writeSync } from "node:fs";
import path from "node:path";

import { resolveExplicitEvidence, VerificationUnavailableError } from "../lib/signed-verifier.mjs";

const usageText = "Usage: node scripts/resolve-release.mjs --release <vX.Y.Z> --output <empty-directory> --json";
const wantsJson = process.argv.slice(2).includes("--json");

function report({ state, result, exitCode, detail }) {
  writeSync(1, `${JSON.stringify({ ok: exitCode === 0, result, exitCode, manifestDigest: null, layers: [{ name: "release-resolution", state, detail }] })}\n`);
}

function usage() {
  if (wantsJson) report({ state: "fail", result: "invalid-invocation", exitCode: 2, detail: usageText });
  else writeSync(2, `${usageText}\n`);
  process.exit(2);
}

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--json") options.json = true;
  else if (["--release", "--output"].includes(args[index]) && args[index + 1] && !args[index + 1].startsWith("--")) {
    options[args[index].slice(2)] = args[++index];
  } else usage();
}
if (!options.release || !options.output || !options.json || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(options.release)) usage();

let state = "pass";
let result = "verified";
let exitCode = 0;
let detail = options.release;
try {
  await resolveExplicitEvidence({ releaseTag: options.release, downloadDirectory: path.resolve(options.output) });
} catch (error) {
  state = error instanceof VerificationUnavailableError ? "unavailable" : "fail";
  result = state === "unavailable" ? "service-unavailable" : "verification-failed";
  exitCode = state === "unavailable" ? 3 : 1;
  detail = error.message;
}
report({ state, result, exitCode, detail });
process.exitCode = exitCode;
