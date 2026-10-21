#!/usr/bin/env node
import path from "node:path";

import { generateEvidence } from "../lib/evidence.mjs";

function parse(arguments_) {
  const values = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (!key?.startsWith("--") || value === undefined) throw new Error(`invalid argument: ${key ?? ""}`);
    values[key.slice(2)] = value;
  }
  return values;
}

const options = parse(process.argv.slice(2));
if (!options.release || !options.output) {
  throw new Error("Usage: node scripts/generate-evidence.mjs --release <digest-directory> --output <directory>");
}

const result = await generateEvidence({
  releaseDirectory: path.resolve(options.release),
  repositoryRoot: path.resolve("."),
  outputDirectory: path.resolve(options.output),
  syftPath: path.resolve(options.syft ?? ".bin/syft"),
  grypePath: path.resolve(options.grype ?? ".bin/grype"),
});
process.stdout.write(`${JSON.stringify(result)}\n`);
