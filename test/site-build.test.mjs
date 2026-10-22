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
  assert.deepEqual(firstNames, ["404.html", "app", "index.html"]);

  const appFiles = (await readdir(path.join(first, "app"))).sort();
  assert.equal(appFiles.length, 2);
  assert.match(appFiles[0], /^(app\.[a-f0-9]{12}\.js|site\.[a-f0-9]{12}\.css)$/);
  assert.match(appFiles[1], /^(app\.[a-f0-9]{12}\.js|site\.[a-f0-9]{12}\.css)$/);

  const firstHTML = await readFile(path.join(first, "index.html"), "utf8");
  const secondHTML = await readFile(path.join(second, "index.html"), "utf8");
  assert.equal(firstHTML, secondHTML);

  const firstTree = await readTree(first);
  const secondTree = await readTree(second);
  assert.deepEqual([...firstTree.keys()], [...secondTree.keys()]);
  for (const [name, bytes] of firstTree) {
    assert.deepEqual(bytes, secondTree.get(name), `${name} differs between clean builds`);
  }

  for (const assetName of appFiles) {
    const bytes = await readFile(path.join(first, "app", assetName));
    assert.match(firstHTML, new RegExp(`(?:src|href)="/app/${assetName}"`));
    assert.match(firstHTML, new RegExp(`integrity="${integrity(bytes).replaceAll("+", "\\+")}"`));
  }
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
