#!/usr/bin/env node
import { writeSync } from "node:fs";
import path from "node:path";

import { classifyResolutionError, runCommand, VerificationUnavailableError } from "../lib/signed-verifier.mjs";

const usageText = "Usage: node scripts/resolve-source.mjs --release <vX.Y.Z> --output <absent-directory> --json";
const args = process.argv.slice(2);
const wantsJson = args.includes("--json");

function report({ state, result, exitCode, detail }) {
  writeSync(1, `${JSON.stringify({ ok: exitCode === 0, result, exitCode, manifestDigest: null, layers: [{ name: "release-source-resolution", state, detail }] })}\n`);
}

function usage() {
  if (wantsJson) report({ state: "fail", result: "invalid-invocation", exitCode: 2, detail: usageText });
  else writeSync(2, `${usageText}\n`);
  process.exit(2);
}

const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--json") options.json = true;
  else if (["--release", "--output"].includes(args[index]) && args[index + 1] && !args[index + 1].startsWith("--")) {
    options[args[index].slice(2)] = args[++index];
  } else usage();
}
if (!options.release || !options.output || !options.json || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(options.release)) usage();

let state = "pass";
let result = "resolved";
let exitCode = 0;
let detail = options.release;
try {
  await runCommand("git", [
    "clone",
    "--depth=1",
    "--single-branch",
    "--branch",
    options.release,
    "https://github.com/metalagman/webappsec.git",
    path.resolve(options.output),
  ]);
} catch (caught) {
  const error = classifyResolutionError(caught);
  state = error instanceof VerificationUnavailableError ? "unavailable" : "fail";
  result = state === "unavailable" ? "service-unavailable" : "verification-failed";
  exitCode = state === "unavailable" ? 3 : 1;
  detail = error.message;
}
report({ state, result, exitCode, detail });
process.exitCode = exitCode;
