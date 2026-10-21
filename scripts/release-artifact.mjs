#!/usr/bin/env node
import path from "node:path";

import { createRelease, verifyRelease, verifyReleaseTar } from "../lib/artifact.mjs";

function usage(message) {
  if (message) process.stderr.write(`${message}\n\n`);
  process.stderr.write(`Usage:
  node scripts/release-artifact.mjs verify <digest-directory>
  node scripts/release-artifact.mjs verify-tar <digest>.tar
  node scripts/release-artifact.mjs build --output <dir> --revision <sha> --tag <tag> \\
    --input worker:lib/content-addressing.mjs=lib/content-addressing.mjs \\
    --input worker:worker/index.js=worker/index.js \\
    --input configuration:wrangler.jsonc=wrangler.jsonc
`);
  process.exit(2);
}

function options(arguments_) {
  const parsed = { input: [] };
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (!key?.startsWith("--") || value === undefined) usage(`invalid argument: ${key ?? ""}`);
    const name = key.slice(2);
    if (name === "input") parsed.input.push(value);
    else parsed[name] = value;
  }
  return parsed;
}

const [command, ...arguments_] = process.argv.slice(2);
if (command === "verify") {
  if (arguments_.length !== 1) usage();
  const result = await verifyRelease(path.resolve(arguments_[0]));
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else if (command === "verify-tar") {
  if (arguments_.length !== 1) usage();
  const result = await verifyReleaseTar(path.resolve(arguments_[0]));
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else if (command === "build") {
  const parsed = options(arguments_);
  if (!parsed.output || !parsed.revision || !parsed.tag || parsed.input.length === 0) usage("missing build option");
  const deployInputs = parsed.input.map((value) => {
    const match = /^(worker|configuration):([^=]+)=(.+)$/.exec(value);
    if (!match) usage(`invalid --input: ${value}`);
    return { role: match[1], path: match[2], source: path.resolve(match[3]) };
  });
  const result = await createRelease({
    outputRoot: path.resolve(parsed.output),
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision: parsed.revision,
      tag: parsed.tag,
      workflow: parsed.workflow ?? ".github/workflows/release.yml",
    },
    deployInputs,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else {
  usage(`unknown command: ${command ?? ""}`);
}
