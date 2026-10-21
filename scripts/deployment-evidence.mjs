#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";

import { createDeploymentEvidence, verifySignedDeploymentEvidence } from "../lib/deployment-evidence.mjs";

function usage() {
  process.stderr.write("Usage: deployment-evidence.mjs build --record <json> --report <json> --output <dir> | verify --directory <dir> --release <tag> --manifest <sha256> --version <uuid> --workflow <path> --ref <refs/tags/vX.Y.Z>\n");
  process.exit(2);
}

const [command, ...args] = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 2) {
  if (!args[index]?.startsWith("--") || !args[index + 1]) usage();
  options[args[index].slice(2)] = args[index + 1];
}

if (command === "build" && options.record && options.report && options.output) {
  const index = await createDeploymentEvidence({
    outputDirectory: path.resolve(options.output),
    record: JSON.parse(await readFile(options.record, "utf8")),
    verificationReport: JSON.parse(await readFile(options.report, "utf8")),
  });
  process.stdout.write(`${JSON.stringify(index)}\n`);
} else if (command === "verify" && ["directory", "release", "manifest", "version", "workflow", "ref"].every((name) => options[name])) {
  const verified = await verifySignedDeploymentEvidence({
    directory: path.resolve(options.directory),
    expected: { releaseTag: options.release, manifestDigest: options.manifest, versionId: options.version, workflow: options.workflow, ref: options.ref },
  });
  process.stdout.write(`${JSON.stringify(verified.record)}\n`);
} else usage();
