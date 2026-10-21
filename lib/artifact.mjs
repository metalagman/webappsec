import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";

import { buildSite } from "../scripts/build.mjs";
import { canonicalJson } from "./canonical-json.mjs";
import { extractNormalizedTar, writeNormalizedTar } from "./tar.mjs";

export const manifestSchema = "https://webappsec.metalagman.dev/schema/deployment-manifest-v1";
export const productionOrigin = "https://webappsec.metalagman.dev";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const maxFiles = 20_000;
const maxFileSize = 25 * 1024 * 1024;
const maxManifestSize = 2 * 1024 * 1024;
const maxEntries = maxFiles + 256;

function safeRelativePath(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 240
    && value === value.normalize("NFC")
    && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value)
    && !value.split("/").some((part) => !part || part === "." || part === ".." || part.startsWith("."))
    && path.posix.normalize(value) === value;
}

function assertSafePath(value) {
  if (!safeRelativePath(value)) throw new Error(`expected a safe relative path: ${value}`);
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.join("\0") !== wanted.join("\0")) {
    throw new Error(`${label} fields must be exactly: ${wanted.join(", ")}`);
  }
}

function assertRelease(release) {
  exactKeys(release, ["repository", "revision", "tag", "workflow"], "release");
  if (release.repository !== "https://github.com/metalagman/webappsec") throw new Error("unexpected repository");
  if (!/^[a-f0-9]{40}$/.test(release.revision)) throw new Error("revision must be a full lowercase Git SHA");
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(release.tag)) throw new Error("tag must be semver-like");
  if (!/^\.github\/workflows\/[a-zA-Z0-9._-]+\.ya?ml$/.test(release.workflow)) {
    throw new Error("workflow must identify a file under .github/workflows");
  }
}

function mediaType(filename) {
  const extension = path.extname(filename);
  if (extension === ".html") return "text/html; charset=utf-8";
  if (extension === ".css") return "text/css; charset=utf-8";
  if (extension === ".js") return "text/javascript; charset=utf-8";
  if (extension === ".json") return "application/json; charset=utf-8";
  if (extension === ".svg") return "image/svg+xml";
  return "application/octet-stream";
}

function publicUrlPath(relative) {
  if (relative === "index.html") return "/";
  return `/${relative}`;
}

async function walk(directory, prefix = "", state = { count: 0 }) {
  const output = [];
  const entries = await readdir(path.join(directory, prefix), { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, "en"))) {
    state.count += 1;
    if (state.count > maxEntries) throw new Error("release entry limit exceeded");
    const relative = path.posix.join(prefix, entry.name);
    const metadata = await lstat(path.join(directory, relative));
    if (metadata.isSymbolicLink()) throw new Error(`symlink is not allowed: ${relative}`);
    if (metadata.isDirectory()) output.push(...await walk(directory, relative, state));
    else if (metadata.isFile()) {
      if (metadata.size > maxFileSize && relative !== "manifest.json") throw new Error(`file exceeds size limit: ${relative}`);
      output.push(relative);
    }
    else throw new Error(`unsupported filesystem entry: ${relative}`);
  }
  return output.sort((a, b) => a.localeCompare(b, "en"));
}

async function sha256File(filename) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest("hex");
}

async function descriptor(directory, relative, extra = {}) {
  const filename = path.join(directory, relative);
  const metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.size > maxFileSize) throw new Error(`file exceeds size limit: ${relative}`);
  return { path: relative, mediaType: mediaType(relative), size: metadata.size, sha256: await sha256File(filename), ...extra };
}

function assertSortedUnique(values, label) {
  const sorted = [...values].sort((a, b) => a.localeCompare(b, "en"));
  if (values.some((value, index) => value !== sorted[index])) throw new Error(`${label} must be sorted`);
  if (new Set(values).size !== values.length) throw new Error(`duplicate ${label}`);
}

export function validateManifest(manifest) {
  exactKeys(manifest, ["schema", "version", "origin", "release", "worker", "inputs", "files"], "manifest");
  if (manifest.schema !== manifestSchema || manifest.version !== 1) throw new Error("unsupported manifest schema");
  if (manifest.origin !== productionOrigin) throw new Error("unexpected production origin");
  assertRelease(manifest.release);
  exactKeys(manifest.worker, ["name"], "worker");
  if (manifest.worker.name !== "webappsec") throw new Error("unexpected Worker name");
  if (!Array.isArray(manifest.inputs) || !Array.isArray(manifest.files)) throw new Error("manifest inventories must be arrays");
  if (manifest.inputs.length < 2) throw new Error("manifest must include Worker and Wrangler inputs");
  if (manifest.files.length === 0) throw new Error("manifest public file inventory must not be empty");
  if (manifest.inputs.length + manifest.files.length > maxFiles) throw new Error("manifest file limit exceeded");

  const inputPaths = manifest.inputs.map((entry) => entry.path);
  const filePaths = manifest.files.map((entry) => entry.path);
  const urlPaths = manifest.files.map((entry) => entry.urlPath);
  assertSortedUnique(inputPaths, "input paths");
  assertSortedUnique(filePaths, "file paths");
  if (new Set(urlPaths).size !== urlPaths.length) throw new Error("duplicate public URL paths");

  const requiredInputs = new Map([
    ["worker/index.js", "worker"],
    ["wrangler.jsonc", "configuration"],
  ]);
  for (const [requiredPath, requiredRole] of requiredInputs) {
    const matches = manifest.inputs.filter((entry) => entry.path === requiredPath && entry.role === requiredRole);
    if (matches.length !== 1) throw new Error(`manifest requires exactly one ${requiredPath} input with role ${requiredRole}`);
  }

  for (const entry of manifest.inputs) {
    exactKeys(entry, ["path", "role", "size", "sha256"], `input ${entry.path}`);
    assertSafePath(entry.path);
    if (!["configuration", "worker"].includes(entry.role)) throw new Error(`unsupported input role: ${entry.role}`);
    if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxFileSize) throw new Error(`invalid input size: ${entry.path}`);
    if (!/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error(`invalid input digest: ${entry.path}`);
  }

  for (const entry of manifest.files) {
    exactKeys(entry, ["path", "urlPath", "mediaType", "size", "sha256"], `file ${entry.path}`);
    assertSafePath(entry.path);
    if (!entry.path.startsWith("assets/")) throw new Error(`public file must be under assets/: ${entry.path}`);
    const expectedUrlPath = publicUrlPath(entry.path.slice("assets/".length));
    if (entry.urlPath !== expectedUrlPath) throw new Error(`public URL path mismatch for ${entry.path}`);
    if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxFileSize) throw new Error(`invalid file size: ${entry.path}`);
    if (!/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error(`invalid file digest: ${entry.path}`);
    if (entry.mediaType !== mediaType(entry.path)) throw new Error(`invalid media type: ${entry.path}`);
  }

  const homepages = manifest.files.filter((entry) => entry.path === "assets/index.html" && entry.urlPath === "/");
  if (homepages.length !== 1) throw new Error("manifest requires exactly one homepage mapping");

  for (const required of manifest.files.filter((entry) => /\.(?:html|js)$/.test(entry.path))) {
    if (!required.urlPath) throw new Error(`missing public URL mapping: ${required.path}`);
  }
}

export async function createRelease({ outputRoot, release, deployInputs, origin = productionOrigin, sourceDirectory }) {
  if (origin !== productionOrigin) throw new Error(`unexpected production origin: ${origin}`);
  assertRelease(release);
  if (!Array.isArray(deployInputs) || deployInputs.length < 2) throw new Error("deployInputs must include Worker and Wrangler configuration");
  const inputPaths = deployInputs.map((input) => input.path);
  for (const input of deployInputs) assertSafePath(input.path);
  if (new Set(inputPaths).size !== inputPaths.length) throw new Error("duplicate deploy input path");

  await mkdir(outputRoot, { recursive: true });
  const staging = await mkdtemp(path.join(outputRoot, ".staging-"));
  try {
    const assetsDirectory = path.join(staging, "assets");
    await buildSite({ outputDirectory: assetsDirectory, sourceDirectory });

    for (const input of [...deployInputs].sort((a, b) => a.path.localeCompare(b.path, "en"))) {
      if (!["configuration", "worker"].includes(input.role)) throw new Error(`unsupported input role: ${input.role}`);
      const metadata = await lstat(input.source);
      if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error(`deploy input must be a regular file: ${input.source}`);
      if (metadata.size > maxFileSize) throw new Error(`deploy input exceeds size limit: ${input.path}`);
      const destination = path.join(staging, "inputs", input.path);
      await mkdir(path.dirname(destination), { recursive: true });
      await copyFile(input.source, destination);
    }

    const assetFiles = await walk(assetsDirectory);
    const inputsDirectory = path.join(staging, "inputs");
    const files = await Promise.all(assetFiles.map((relative) =>
      descriptor(staging, `assets/${relative}`, { urlPath: publicUrlPath(relative) })
    ));
    const inputs = await Promise.all([...deployInputs]
      .sort((a, b) => a.path.localeCompare(b.path, "en"))
      .map(async (input) => {
        const filename = path.join(inputsDirectory, input.path);
        const metadata = await lstat(filename);
        return { path: input.path, role: input.role, size: metadata.size, sha256: await sha256File(filename) };
      }));

    const manifest = {
      schema: manifestSchema,
      version: 1,
      origin,
      release: { ...release },
      worker: { name: "webappsec" },
      inputs,
      files,
    };
    validateManifest(manifest);
    const manifestBytes = Buffer.from(canonicalJson(manifest));
    const digest = sha256(manifestBytes);
    await writeFile(path.join(staging, "manifest.json"), manifestBytes);

    const directory = path.join(outputRoot, digest);
    try {
      await rename(staging, directory);
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") throw error;
      await rm(staging, { recursive: true, force: true });
      const verified = await verifyRelease(directory);
      if (verified.digest !== digest) throw new Error("existing release digest mismatch");
    }
    const tarPath = path.join(outputRoot, `${digest}.tar`);
    await writeNormalizedTar(directory, tarPath);
    await verifyRelease(directory);
    await verifyReleaseTar(tarPath);
    return { digest, directory, manifestPath: path.join(directory, "manifest.json"), tarPath };
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyRelease(directory) {
  const allFiles = await walk(directory);
  if (!allFiles.includes("manifest.json")) throw new Error("manifest.json is missing");
  const manifestMetadata = await lstat(path.join(directory, "manifest.json"));
  if (manifestMetadata.size > maxManifestSize) throw new Error("manifest exceeds size limit");
  const manifestBytes = await readFile(path.join(directory, "manifest.json"));
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes);
  } catch (error) {
    throw new Error(`malformed manifest JSON: ${error.message}`);
  }
  const canonical = Buffer.from(canonicalJson(manifest));
  if (!manifestBytes.equals(canonical)) throw new Error("manifest JSON is not canonical");
  validateManifest(manifest);

  const digest = sha256(manifestBytes);
  if (path.basename(path.resolve(directory)) !== digest) throw new Error("release directory does not match manifest digest");
  const expected = new Set([
    "manifest.json",
    ...manifest.files.map((entry) => entry.path),
    ...manifest.inputs.map((entry) => `inputs/${entry.path}`),
  ]);
  for (const filename of allFiles) {
    if (!expected.has(filename)) throw new Error(`unexpected release file: ${filename}`);
  }
  if (allFiles.length !== expected.size) throw new Error("release inventory is incomplete");

  for (const entry of manifest.files) {
    const filename = path.join(directory, entry.path);
    const metadata = await lstat(filename);
    if (!metadata.isFile() || metadata.size !== entry.size) throw new Error(`size mismatch: ${entry.path}`);
    if (await sha256File(filename) !== entry.sha256) throw new Error(`digest mismatch: ${entry.path}`);
  }
  for (const entry of manifest.inputs) {
    const filename = path.join(directory, "inputs", entry.path);
    const metadata = await lstat(filename);
    if (!metadata.isFile() || metadata.size !== entry.size) throw new Error(`size mismatch: ${entry.path}`);
    if (await sha256File(filename) !== entry.sha256) throw new Error(`digest mismatch: ${entry.path}`);
  }
  return { digest, files: manifest.files.length, inputs: manifest.inputs.length };
}

export async function verifyReleaseTar(tarPath) {
  const match = /^([a-f0-9]{64})\.tar$/.exec(path.basename(tarPath));
  if (!match) throw new Error("release tar filename must be <manifest-digest>.tar");
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "webappsec-tar-"));
  const directory = path.join(temporaryRoot, match[1]);
  try {
    await extractNormalizedTar(tarPath, directory);
    return await verifyRelease(directory);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
