#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";

import { createVerificationEvidence, verifySignedVerificationEvidence, verifyVerificationEvidence } from "../lib/verification-evidence.mjs";

function usage() {
  process.stderr.write("Usage: verification-evidence.mjs build --record <json> --report <json> --output <dir> | verify --directory <dir> [--signed]\n");
  process.exit(2);
}

const [command, ...args] = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  const argument = args[index];
  if (argument === "--signed") options.signed = true;
  else if (argument?.startsWith("--") && args[index + 1] && !args[index + 1].startsWith("--")) options[argument.slice(2)] = args[++index];
  else usage();
}

if (command === "build" && options.record && options.report && options.output && !options.signed) {
  const index = await createVerificationEvidence({
    outputDirectory: path.resolve(options.output),
    record: JSON.parse(await readFile(options.record, "utf8")),
    verificationReportBytes: await readFile(options.report),
  });
  process.stdout.write(`${JSON.stringify(index)}\n`);
} else if (command === "verify" && options.directory && Object.keys(options).every((name) => ["directory", "signed"].includes(name))) {
  const verified = options.signed
    ? await verifySignedVerificationEvidence({ directory: path.resolve(options.directory) })
    : await verifyVerificationEvidence(path.resolve(options.directory));
  process.stdout.write(`${JSON.stringify(verified.record)}\n`);
} else usage();
