#!/usr/bin/env node
import path from "node:path";

import { assembleReleaseEvidence, verifyEvidenceDirectory } from "../lib/release-evidence.mjs";

function usage() {
  process.stderr.write(`Usage:
  node scripts/assemble-release.mjs build --release <directory> --tar <file> --evidence <directory> --output <directory> --invocation-id <url>
  node scripts/assemble-release.mjs verify <directory>
`);
  process.exit(2);
}

const [command, ...arguments_] = process.argv.slice(2);
if (command === "verify") {
  if (arguments_.length !== 1) usage();
  process.stdout.write(`${JSON.stringify(await verifyEvidenceDirectory(path.resolve(arguments_[0])))}\n`);
} else if (command === "build") {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage();
    options[key.slice(2)] = value;
  }
  if (!["release", "tar", "evidence", "output", "invocation-id"].every((key) => options[key])) usage();
  const result = await assembleReleaseEvidence({
    releaseDirectory: path.resolve(options.release),
    tarPath: path.resolve(options.tar),
    evidenceDirectory: path.resolve(options.evidence),
    outputDirectory: path.resolve(options.output),
    repositoryRoot: path.resolve("."),
    invocationId: options["invocation-id"],
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else {
  usage();
}
