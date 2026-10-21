#!/usr/bin/env node
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { verifyRelease } from "../lib/artifact.mjs";
import { canonicalJson } from "../lib/canonical-json.mjs";
import { reproduceRelease, verifySignedEvidence } from "../lib/signed-verifier.mjs";
import { extractNormalizedTar } from "../lib/tar.mjs";

function usage() {
  process.stderr.write("Usage: prepare-deployment.mjs --evidence <dir> --source <checkout> --release <tag> --output <empty-dir>\n");
  process.exit(2);
}
const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 2) {
  if (!args[index]?.startsWith("--") || !args[index + 1]) usage();
  options[args[index].slice(2)] = args[index + 1];
}
if (!["evidence", "source", "release", "output"].every((name) => options[name])) usage();

const output = path.resolve(options.output);
await mkdir(output, { recursive: true });
if ((await readdir(output)).length !== 0) throw new Error("deployment output must be empty");
const verified = await verifySignedEvidence({
  directory: path.resolve(options.evidence),
  repositoryRoot: path.resolve(options.source),
  expectedTag: options.release,
});
await reproduceRelease({ verified, releaseSourceRoot: path.resolve(options.source) });
const temporary = await mkdtemp(path.join(tmpdir(), "webappsec-deploy-"));
try {
  const extracted = path.join(temporary, verified.manifestDigest);
  await extractNormalizedTar(verified.tarPath, extracted);
  const unpacked = await verifyRelease(extracted);
  if (unpacked.digest !== verified.manifestDigest) throw new Error("unpacked release digest mismatch");
  await cp(path.join(extracted, "assets"), path.join(output, "dist"), { recursive: true, errorOnExist: true });
  await cp(path.join(extracted, "inputs", "worker"), path.join(output, "worker"), { recursive: true, errorOnExist: true });
  await cp(path.join(extracted, "inputs", "lib"), path.join(output, "lib"), { recursive: true, errorOnExist: true });
  await cp(path.join(extracted, "inputs", "wrangler.jsonc"), path.join(output, "wrangler.jsonc"), { errorOnExist: true });
  await cp(path.join(extracted, "manifest.json"), path.join(output, "manifest.json"), { errorOnExist: true });
  const result = { releaseTag: verified.tag, revision: verified.revision, manifestDigest: verified.manifestDigest, output };
  await writeFile(path.join(output, "deployment-input.json"), canonicalJson(result));
  process.stdout.write(`${JSON.stringify(result)}\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
