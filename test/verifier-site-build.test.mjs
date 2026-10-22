import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { buildVerifierSite } from "../scripts/build-verifier.mjs";

const sri = (algorithm, bytes) =>
  `${algorithm}-${createHash(algorithm).update(bytes).digest("base64")}`;

async function tree(directory, prefix = "") {
  const result = new Map();
  for (const entry of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const relative = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      for (const item of await tree(directory, relative)) result.set(...item);
    } else result.set(relative, await readFile(path.join(directory, relative)));
  }
  return result;
}

test("verifier build is deterministic, content-addressed, and protected by local SRI", async () => {
  const first = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-a-"));
  const second = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-b-"));
  await buildVerifierSite({ outputDirectory: first });
  await buildVerifierSite({ outputDirectory: second });

  const firstTree = await tree(first);
  const secondTree = await tree(second);
  assert.deepEqual([...firstTree.keys()], [...secondTree.keys()]);
  assert.equal(firstTree.size, 3);
  for (const [name, bytes] of firstTree) assert.deepEqual(bytes, secondTree.get(name), name);

  const names = [...firstTree.keys()];
  const style = names.find((name) => /^app\/verifier\.[a-f0-9]{12}\.css$/.test(name));
  const app = names.find((name) => /^app\/verifier\.[a-f0-9]{12}\.js$/.test(name));
  assert.ok(style);
  assert.ok(app);

  const html = firstTree.get("index.html").toString("utf8");
  assert.match(html, new RegExp(`href="/${style}" integrity="${sri("sha384", firstTree.get(style)).replaceAll("+", "\\+")}"`));
  assert.match(html, new RegExp(`src="/${app}" integrity="${sri("sha384", firstTree.get(app)).replaceAll("+", "\\+")}"`));
  assert.match(firstTree.get(app).toString("utf8"), /async function verifyOnlineDeployment/);
  assert.doesNotMatch(firstTree.get(app).toString("utf8"), /from "\.\/browser-verifier/);
  assert.match(html, /connect-src 'self' https:\/\/webappsec\.metalagman\.dev/);
  assert.doesNotMatch(html, /frame-ancestors/);
  assert.match(html, /href="https:\/\/github\.com\/metalagman\/webappsec\/actions\/workflows\/deploy-verifier\.yml"[^>]*>Deploy workflow/);
  assert.doesNotMatch(html, /https?:\/\/(?:fonts|cdn|unpkg|jsdelivr)\./);
});

test("verifier page states exact trust boundary and accessible controls", async () => {
  const outputDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-copy-"));
  await buildVerifierSite({ outputDirectory });
  const html = await readFile(path.join(outputDirectory, "index.html"), "utf8");
  const scriptName = (await readdir(path.join(outputDirectory, "app"))).find((name) => name.endsWith(".js"));
  const script = await readFile(path.join(outputDirectory, "app", scriptName), "utf8");

  for (const phrase of [
    "Проверено CI",
    "Проверено сейчас в этом браузере",
    "Повторить проверку",
    "Результат проверки",
    "Доказательства и воспроизведение",
    "Cosign и воспроизводимая сборка выполняются доверенным GitHub Actions workflow",
  ]) assert.match(html, new RegExp(phrase));

  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /data-check-id="ci:signatures"/);
  assert.match(html, /data-check-id="browser:production-bytes"/);
  assert.match(html, /<button[^>]+data-retry/);
  assert.doesNotMatch(script, /\.innerHTML\s*=/);
  assert.match(script, /textContent/);
  assert.match(script, /verifyOnlineDeployment/);
  assert.match(script, /AbortController/);
});
