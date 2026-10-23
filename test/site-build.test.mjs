import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { buildSite } from "../scripts/build.mjs";

const integrity = (bytes) =>
  `sha384-${createHash("sha384").update(bytes).digest("base64")}`;

async function readTree(directory, prefix = "") {
  const result = new Map();
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      for (const [name, bytes] of await readTree(directory, relative)) result.set(name, bytes);
    } else {
      result.set(relative, await readFile(path.join(directory, relative)));
    }
  }
  return result;
}

test("build emits deterministic local assets with matching SRI", async () => {
  const first = await mkdtemp(path.join(tmpdir(), "webappsec-a-"));
  const second = await mkdtemp(path.join(tmpdir(), "webappsec-b-"));

  await buildSite({ outputDirectory: first });
  await buildSite({ outputDirectory: second });

  const firstNames = (await readdir(first)).sort();
  const secondNames = (await readdir(second)).sort();
  assert.deepEqual(firstNames, secondNames);
  assert.deepEqual(firstNames, ["404.html", "app", "index.html", "security-policy.txt"]);

  const appFiles = (await readdir(path.join(first, "app"))).sort();
  assert.equal(appFiles.length, 3);
  assert.equal(appFiles.filter((name) => name.endsWith(".js")).length, 2);
  assert.equal(appFiles.filter((name) => name.endsWith(".css")).length, 1);
  for (const name of appFiles) assert.match(name, /^(?:app|interactions|site)\.[a-f0-9]{12}\.(?:js|css)$/);

  const firstHTML = await readFile(path.join(first, "index.html"), "utf8");
  const secondHTML = await readFile(path.join(second, "index.html"), "utf8");
  assert.equal(firstHTML, secondHTML);

  const firstTree = await readTree(first);
  const secondTree = await readTree(second);
  assert.deepEqual([...firstTree.keys()], [...secondTree.keys()]);
  for (const [name, bytes] of firstTree) {
    assert.deepEqual(bytes, secondTree.get(name), `${name} differs between clean builds`);
  }

  for (const assetName of appFiles.filter((name) => name.endsWith(".css") || name.startsWith("app."))) {
    const bytes = await readFile(path.join(first, "app", assetName));
    assert.match(firstHTML, new RegExp(`(?:src|href)="/app/${assetName}"`));
    assert.match(firstHTML, new RegExp(`integrity="${integrity(bytes).replaceAll("+", "\\+")}"`));
  }

  const importMapMatch = firstHTML.match(/<script type="importmap">([^<]+)<\/script>/);
  assert.ok(importMapMatch, "inline import map is present");
  const importMap = JSON.parse(importMapMatch[1]);
  const javascriptFiles = appFiles.filter((name) => name.endsWith(".js"));
  assert.deepEqual(Object.keys(importMap), ["integrity"]);
  assert.deepEqual(Object.keys(importMap.integrity), javascriptFiles.map((name) => `/app/${name}`).sort());
  for (const assetName of javascriptFiles) {
    const bytes = await readFile(path.join(first, "app", assetName));
    assert.equal(importMap.integrity[`/app/${assetName}`], integrity(bytes));
  }
  assert.ok(firstHTML.indexOf('type="importmap"') < firstHTML.indexOf('type="module"'));

  const policy = await readFile(path.join(first, "security-policy.txt"), "utf8");
  const importMapIntegrity = integrity(Buffer.from(importMapMatch[1]));
  assert.match(policy, new RegExp(`script-src 'self' '${importMapIntegrity.replaceAll("+", "\\+")}'`));
  assert.match(policy, /frame-ancestors 'none'/);
  assert.match(firstHTML, new RegExp(`script-src 'self' '${importMapIntegrity.replaceAll("+", "\\+")}'`));
});

test("page explains every evidence layer and its limits", async () => {
  const outputDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-copy-"));
  await buildSite({ outputDirectory });
  const html = await readFile(path.join(outputDirectory, "index.html"), "utf8");

  for (const phrase of [
    "SBOM",
    "CVE",
    "SLSA provenance",
    "Воспроизводимая сборка",
    "Sigstore / Cosign",
    "Подписанный manifest",
    "Внешний verifier",
    "Subresource Integrity",
    "Что доказывает",
    "Граница проверки",
    "SBOM не доказывает",
    "SRI не защищает HTML-документ",
  ]) {
    assert.match(html, new RegExp(phrase));
  }

  assert.match(html, /https:\/\/github\.com\/metalagman\/webappsec/);
  assert.match(html, /href="https:\/\/verify\.webappsec\.metalagman\.dev"/);
  assert.match(html, /Проверить текущий deployment онлайн/);
  assert.match(html, /Проверено CI/);
  assert.match(html, /Проверено сейчас в браузере/);
  assert.match(html, /SHA-256/);
  assert.match(html, /npm run verify:release -- --release/);
  assert.doesNotMatch(html, /https?:\/\/(?:fonts|cdn|unpkg|jsdelivr)\./);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /default-src 'none'/);
});
