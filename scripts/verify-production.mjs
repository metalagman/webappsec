#!/usr/bin/env node
import path from "node:path";
import { writeSync } from "node:fs";
import { humanReport, verifyProduction } from "../lib/verifier.mjs";

function usage() {
  writeSync(2, "Usage: node scripts/verify-production.mjs --manifest <manifest.json> [--origin <url>] [--json]\nExit: 0 verified, 1 content/policy failure, 2 invalid invocation, 3 required service unavailable.\n");
  process.exit(2);
}

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--json") options.json = true;
  else if (["--manifest", "--origin"].includes(args[index]) && args[index + 1] && !args[index + 1].startsWith("--")) options[args[index].slice(2)] = args[++index];
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

const report = await verifyProduction({ manifestPath: path.resolve(options.manifest), origin: options.origin });
writeSync(1, options.json ? `${JSON.stringify(report)}\n` : humanReport(report));
process.exitCode = report.exitCode;
