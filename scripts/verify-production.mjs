#!/usr/bin/env node
import path from "node:path";
import { writeSync } from "node:fs";
import { humanReport, verifyProduction } from "../lib/verifier.mjs";

function usage() {
  writeSync(2, "Usage: node scripts/verify-production.mjs --manifest <manifest.json> [--origin <url>] [--expected-release <sha256|unknown> --expected-version <uuid> --noindex <true|false> [--preview]] [--json]\nExit: 0 verified, 1 content/policy failure, 2 invalid invocation, 3 required service unavailable.\n");
  process.exit(2);
}

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--json" || args[index] === "--preview") options[args[index].slice(2)] = true;
  else if (["--manifest", "--origin", "--expected-release", "--expected-version", "--noindex"].includes(args[index]) && args[index + 1] && !args[index + 1].startsWith("--")) options[args[index].slice(2)] = args[++index];
  else usage();
}
if (!options.manifest) usage();
if (options.origin) {
  try {
    const parsed = new URL(options.origin);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) usage();
    options.origin = parsed.origin;
  } catch {
    usage();
  }
}
if (options.preview) {
  const origin = new URL(options.origin ?? "https://invalid.invalid");
  if (origin.protocol !== "https:" || !/^[a-z0-9][a-z0-9-]*-webappsec\.[a-z0-9][a-z0-9-]*\.workers\.dev$/.test(origin.hostname)
    || options["expected-release"] !== "unknown" || options.noindex !== "true") usage();
}

const headerOptions = [options["expected-release"], options["expected-version"], options.noindex];
if (headerOptions.some(Boolean) && !headerOptions.every(Boolean)) usage();
let expectedHeaders;
if (headerOptions.every(Boolean)) {
  if (!(options.preview ? options["expected-release"] === "unknown" : /^[a-f0-9]{64}$/.test(options["expected-release"]))
    || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(options["expected-version"])
    || !["true", "false"].includes(options.noindex)) usage();
  expectedHeaders = { release: options["expected-release"], versionId: options["expected-version"], noindex: options.noindex === "true" };
}

const report = await verifyProduction({ manifestPath: path.resolve(options.manifest), origin: options.origin, expectedHeaders });
writeSync(1, options.json ? `${JSON.stringify(report)}\n` : humanReport(report));
process.exitCode = report.exitCode;
