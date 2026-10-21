import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { copyFile, cp, mkdtemp, readFile, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";

import { createRelease, validateManifest, verifyRelease, verifyReleaseTar } from "../lib/artifact.mjs";
import { writeNormalizedTar } from "../lib/tar.mjs";

const release = {
  repository: "https://github.com/metalagman/webappsec",
  revision: "0123456789abcdef0123456789abcdef01234567",
  tag: "v0.1.0",
  workflow: ".github/workflows/release.yml",
};
const execFile = promisify(execFileCallback);
const schema = JSON.parse(await readFile(new URL("../schemas/deployment-manifest-v1.schema.json", import.meta.url), "utf8"));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

function clone(value) {
  return structuredClone(value);
}

function rewriteHeader(buffer, mutate) {
  const copy = Buffer.from(buffer);
  mutate(copy.subarray(0, 512));
  copy.fill(0x20, 148, 156);
  const checksum = [...copy.subarray(0, 512)].reduce((sum, byte) => sum + byte, 0);
  Buffer.from(`${checksum.toString(8).padStart(6, "0")}\0 `).copy(copy, 148);
  return copy;
}

async function fixture(root) {
  const worker = path.join(root, "worker.js");
  const wrangler = path.join(root, "wrangler.jsonc");
  await writeFile(worker, "export default { fetch() { return new Response('ok') } };\n");
  await writeFile(wrangler, '{"name":"webappsec"}\n');
  return [
    { source: worker, path: "worker/index.js", role: "worker" },
    { source: wrangler, path: "wrangler.jsonc", role: "configuration" },
  ];
}

test("release manifest and normalized tar are reproducible across output paths", async () => {
  const rootA = await mkdtemp(path.join(tmpdir(), "webappsec-release-a-"));
  const rootB = await mkdtemp(path.join(tmpdir(), "webappsec-release-b-"));
  const inputsA = await fixture(rootA);
  const inputsB = await fixture(rootB);

  const originalTimezone = process.env.TZ;
  const originalLocale = process.env.LANG;
  let a;
  let b;
  try {
    process.env.TZ = "UTC";
    process.env.LANG = "C";
    a = await createRelease({ outputRoot: rootA, release, deployInputs: inputsA });
    process.env.TZ = "Pacific/Chatham";
    process.env.LANG = "tr_TR.UTF-8";
    b = await createRelease({ outputRoot: rootB, release, deployInputs: inputsB });
  } finally {
    if (originalTimezone === undefined) delete process.env.TZ;
    else process.env.TZ = originalTimezone;
    if (originalLocale === undefined) delete process.env.LANG;
    else process.env.LANG = originalLocale;
  }

  assert.equal(a.digest, b.digest);
  assert.deepEqual(await readFile(a.manifestPath), await readFile(b.manifestPath));
  assert.deepEqual(await readFile(a.tarPath), await readFile(b.tarPath));
  assert.equal(path.basename(a.directory), a.digest);
  const { stdout: tarListing } = await execFile("tar", ["-tf", a.tarPath]);
  assert.match(tarListing, /^assets\/\n/m);
  assert.match(tarListing, /^inputs\/worker\/index\.js$/m);
  assert.match(tarListing, /^manifest\.json$/m);

  const manifest = JSON.parse(await readFile(a.manifestPath, "utf8"));
  assert.equal(validateSchema(manifest), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(manifest.release, release);
  assert.equal(manifest.origin, "https://webappsec.metalagman.dev");
  assert.deepEqual(manifest.inputs.map(({ path: name }) => name), [
    "worker/index.js",
    "wrangler.jsonc",
  ]);
  assert.ok(manifest.files.some((file) => file.path === "assets/index.html" && file.urlPath === "/"));
  assert.ok(manifest.files.some((file) => file.path.endsWith(".js") && file.urlPath.endsWith(".js")));
  assert.ok(manifest.files.every((file, index, files) => index === 0 || files[index - 1].path < file.path));
  const expectedVerification = { digest: a.digest, files: manifest.files.length, inputs: 2 };
  assert.deepEqual(await verifyRelease(a.directory), expectedVerification);
  assert.deepEqual(await verifyReleaseTar(a.tarPath), expectedVerification);
});

test("schema and semantic validation reject missing mandatory inventory and unsafe URLs", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-schema-"));
  const built = await createRelease({ outputRoot: root, release, deployInputs: await fixture(root) });
  const valid = JSON.parse(await readFile(built.manifestPath, "utf8"));
  const sharedInvalid = [
    { label: "empty inputs", change: (value) => { value.inputs = []; } },
    { label: "empty files", change: (value) => { value.files = []; } },
    { label: "missing worker", change: (value) => { value.inputs = value.inputs.filter((entry) => entry.path !== "worker/index.js"); } },
    { label: "missing wrangler", change: (value) => { value.inputs = value.inputs.filter((entry) => entry.path !== "wrangler.jsonc"); } },
    { label: "wrong role", change: (value) => { value.inputs.find((entry) => entry.path === "worker/index.js").role = "configuration"; } },
    { label: "network URL", change: (value) => { value.files[0].urlPath = "//attacker.example/file"; } },
    { label: "encoded traversal", change: (value) => { value.files[0].urlPath = "/%2e%2e/secret"; } },
    { label: "query", change: (value) => { value.files[0].urlPath += "?changed=1"; } },
    { label: "control character", change: (value) => { value.files[0].urlPath = "/bad\npath"; } },
  ];

  for (const fixtureCase of sharedInvalid) {
    const candidate = clone(valid);
    fixtureCase.change(candidate);
    assert.equal(validateSchema(candidate), false, `${fixtureCase.label} unexpectedly passed JSON Schema`);
    assert.throws(() => validateManifest(candidate), undefined, `${fixtureCase.label} unexpectedly passed semantic validation`);
  }

  for (const fixtureCase of [
    { label: "mismatched local URL", change: (value) => { value.files[1].urlPath = "/another.css"; } },
    { label: "duplicate canonical URL", change: (value) => { value.files[1].urlPath = value.files[0].urlPath; } },
  ]) {
    const candidate = clone(valid);
    fixtureCase.change(candidate);
    assert.throws(() => validateManifest(candidate), undefined, `${fixtureCase.label} unexpectedly passed semantic validation`);
  }
});

test("verification rejects tampering, unexpected files, symlinks, and noncanonical JSON", async (t) => {
  async function builtRelease() {
    const root = await mkdtemp(path.join(tmpdir(), "webappsec-reject-"));
    const result = await createRelease({
      outputRoot: root,
      release,
      deployInputs: await fixture(root),
    });
    return result.directory;
  }

  await t.test("changed content", async () => {
    const directory = await builtRelease();
    await writeFile(path.join(directory, "assets", "index.html"), "changed\n");
    await assert.rejects(() => verifyRelease(directory), /digest|size/i);
  });

  await t.test("unexpected content", async () => {
    const directory = await builtRelease();
    await writeFile(path.join(directory, "secret.txt"), "surprise\n");
    await assert.rejects(() => verifyRelease(directory), /unexpected/i);
  });

  await t.test("symlink", async () => {
    const directory = await builtRelease();
    await symlink("index.html", path.join(directory, "assets", "alias.html"));
    await assert.rejects(() => verifyRelease(directory), /symlink/i);
  });

  await t.test("noncanonical manifest", async () => {
    const directory = await builtRelease();
    const manifestPath = path.join(directory, "manifest.json");
    const value = JSON.parse(await readFile(manifestPath, "utf8"));
    await writeFile(manifestPath, JSON.stringify(value, null, 2));
    await assert.rejects(() => verifyRelease(directory), /canonical/i);
  });
});

test("release creation rejects unsafe or duplicate deploy input paths", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-paths-"));
  const source = path.join(root, "input.txt");
  await writeFile(source, "x");

  await assert.rejects(() => createRelease({
    outputRoot: root,
    release,
    deployInputs: [
      { source, path: "../escape", role: "worker" },
      { source, path: "wrangler.jsonc", role: "configuration" },
    ],
  }), /safe relative path/i);

  await assert.rejects(() => createRelease({
    outputRoot: root,
    release,
    deployInputs: [
      { source, path: "same", role: "worker" },
      { source, path: "same", role: "configuration" },
    ],
  }), /duplicate/i);
});

test("tar verification rejects changed payloads, truncation, extra files, traversal, and links", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-tar-reject-"));
  const built = await createRelease({ outputRoot: root, release, deployInputs: await fixture(root) });
  const original = await readFile(built.tarPath);

  async function candidate(bytes, suffix) {
    const directory = await mkdtemp(path.join(tmpdir(), `webappsec-tar-${suffix}-`));
    const filename = path.join(directory, `${built.digest}.tar`);
    await writeFile(filename, bytes);
    return filename;
  }

  await t.test("changed payload", async () => {
    const bytes = Buffer.from(original);
    const offset = bytes.indexOf(Buffer.from("<!doctype html>"));
    assert.notEqual(offset, -1);
    bytes[offset] ^= 1;
    const filename = await candidate(bytes, "payload");
    await assert.rejects(() => verifyReleaseTar(filename), /digest mismatch/i);
  });

  await t.test("truncated", async () => {
    const filename = await candidate(original.subarray(0, -512), "short");
    await assert.rejects(() => verifyReleaseTar(filename), /truncated|end marker/i);
  });

  await t.test("unexpected entry", async () => {
    const expanded = path.join(root, "expanded");
    await cp(built.directory, expanded, { recursive: true });
    await writeFile(path.join(expanded, "surprise.txt"), "unexpected\n");
    const filename = path.join(await mkdtemp(path.join(tmpdir(), "webappsec-tar-extra-")), `${built.digest}.tar`);
    await writeNormalizedTar(expanded, filename);
    await assert.rejects(() => verifyReleaseTar(filename), /unexpected/i);
  });

  await t.test("path traversal", async () => {
    const bytes = rewriteHeader(original, (header) => {
      header.fill(0, 0, 100);
      Buffer.from("../evil/").copy(header, 0);
    });
    const filename = await candidate(bytes, "traversal");
    await assert.rejects(() => verifyReleaseTar(filename), /unsafe tar path/i);
  });

  await t.test("symlink entry", async () => {
    const bytes = rewriteHeader(original, (header) => { header[156] = "2".charCodeAt(0); });
    const filename = await candidate(bytes, "link");
    await assert.rejects(() => verifyReleaseTar(filename), /unsafe tar entry type/i);
  });
});

test("size limits are enforced before oversized data is read", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "webappsec-limits-"));
  const built = await createRelease({ outputRoot: root, release, deployInputs: await fixture(root) });

  await truncate(path.join(built.directory, "manifest.json"), 2 * 1024 * 1024 + 1);
  await assert.rejects(() => verifyRelease(built.directory), /manifest exceeds size limit/i);

  const inputs = await fixture(root);
  await truncate(inputs[0].source, 25 * 1024 * 1024 + 1);
  const outputRoot = await mkdtemp(path.join(tmpdir(), "webappsec-input-limit-"));
  await assert.rejects(() => createRelease({
    outputRoot,
    release,
    deployInputs: inputs,
  }), /input exceeds size limit/i);
});
