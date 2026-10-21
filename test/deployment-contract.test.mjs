import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import worker from "../worker/index.js";
import { createRelease } from "../lib/artifact.mjs";
import { buildSite } from "../scripts/build.mjs";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const wranglerPath = path.join(root, "wrangler.jsonc");
const workerPath = path.join(root, "worker/index.js");
const contentAddressingPath = path.join(root, "lib/content-addressing.mjs");

function environment(body, init = {}) {
  const calls = [];
  return {
    calls,
    env: {
      CF_VERSION_METADATA: {
        id: "4f117518-6f75-4ef5-a4d7-19f08ba1181d",
        tag: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      },
      ASSETS: {
        async fetch(request) {
          calls.push(request);
          return new Response(body, init);
        },
      },
    },
  };
}

test("Wrangler declares one pinned public Worker and immutable routing contract", async () => {
  const config = JSON.parse(await readFile(wranglerPath, "utf8"));
  assert.equal(config.name, "webappsec");
  assert.equal(config.main, "./worker/index.js");
  assert.equal(config.compatibility_date, "2026-10-16");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, true);
  assert.deepEqual(config.assets, {
    directory: "./dist",
    binding: "ASSETS",
    run_worker_first: true,
    not_found_handling: "404-page",
  });
  assert.deepEqual(config.version_metadata, { binding: "CF_VERSION_METADATA" });
  assert.deepEqual(config.routes, [{ pattern: "webappsec.metalagman.dev", custom_domain: true }]);
  assert.equal("env" in config, false);

  const packageManifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.equal(packageManifest.devDependencies.wrangler, "4.151.3");
});

test("Worker delegates exact bytes and adds release, cache, and security headers", async () => {
  const bytes = Uint8Array.from([0, 1, 2, 10, 13, 127, 128, 255]);
  const { env, calls } = environment(bytes, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream", ETag: '"asset"' },
  });
  const buildDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-cache-policy-"));
  const built = await buildSite({ outputDirectory: buildDirectory });
  const scriptPath = built.files.find((filename) => filename.endsWith(".js"));
  assert.ok(scriptPath);
  const request = new Request(`https://webappsec.metalagman.dev/${scriptPath}`);
  const response = await worker.fetch(request, env);

  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
  assert.equal(calls.length, 1);
  assert.equal(calls[0], request);
  assert.equal(response.headers.get("ETag"), '"asset"');
  assert.equal(response.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  assert.equal(response.headers.get("Strict-Transport-Security"), "max-age=31536000");
  assert.match(response.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  assert.equal(response.headers.get("X-Webappsec-Release"), env.CF_VERSION_METADATA.tag);
  assert.equal(response.headers.get("X-Webappsec-Worker-Version"), env.CF_VERSION_METADATA.id);
  assert.equal(response.headers.get("X-Robots-Tag"), null);
});

test("HTML, errors, Version URLs, HTTPS, and unknown hosts follow fail-closed policy", async (t) => {
  await t.test("HTML is revalidated", async () => {
    const { env } = environment("<!doctype html>", { headers: { "Content-Type": "text/html" } });
    const response = await worker.fetch(new Request("https://webappsec.metalagman.dev/"), env);
    assert.equal(response.headers.get("Cache-Control"), "no-cache");
  });

  await t.test("errors are never cached", async () => {
    const { env } = environment("missing", { status: 404 });
    const response = await worker.fetch(new Request("https://webappsec.metalagman.dev/missing"), env);
    assert.equal(response.status, 404);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });

  await t.test("Version URL is public but noindex", async () => {
    const { env } = environment("version");
    const response = await worker.fetch(new Request("https://4f117518-webappsec.demo-account.workers.dev/"), env);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
    assert.equal(response.headers.get("Strict-Transport-Security"), "max-age=31536000");
  });

  await t.test("allowed HTTP redirects to the same URL over HTTPS", async () => {
    const { env, calls } = environment("unused");
    const response = await worker.fetch(new Request("http://webappsec.metalagman.dev/path?q=1"), env);
    assert.equal(response.status, 308);
    assert.equal(response.headers.get("Location"), "https://webappsec.metalagman.dev/path?q=1");
    assert.equal(response.headers.get("Strict-Transport-Security"), null);
    assert.equal(calls.length, 0);
  });

  await t.test("unknown hosts are rejected without reaching assets", async () => {
    const { env, calls } = environment("unused");
    const response = await worker.fetch(new Request("https://attacker.example/"), env);
    assert.equal(response.status, 421);
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex, nofollow");
    assert.equal(calls.length, 0);
  });
});

test("real Worker and Wrangler bytes are covered by the release manifest", async () => {
  const outputRoot = path.join(root, ".artifacts", "contract-test");
  const result = await createRelease({
    outputRoot,
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision: "0123456789abcdef0123456789abcdef01234567",
      tag: "v0.1.0",
      workflow: ".github/workflows/release.yml",
    },
    deployInputs: [
      { source: contentAddressingPath, path: "lib/content-addressing.mjs", role: "worker" },
      { source: workerPath, path: "worker/index.js", role: "worker" },
      { source: wranglerPath, path: "wrangler.jsonc", role: "configuration" },
    ],
  });
  const manifest = JSON.parse(await readFile(result.manifestPath, "utf8"));
  assert.deepEqual(manifest.inputs.map(({ path: inputPath }) => inputPath), [
    "lib/content-addressing.mjs",
    "worker/index.js",
    "wrangler.jsonc",
  ]);
});

test("repository contains no Terraform or populated secret files", async () => {
  const ignoredDirectories = new Set([".git", ".dolt", ".artifacts", "node_modules", "dist", "test-results", "playwright-report"]);
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(filename);
      else files.push(path.relative(root, filename));
    }
  }
  await walk(root);
  assert.deepEqual(files.filter((name) => name.endsWith(".tf") || name.endsWith(".tfstate")), []);
  assert.deepEqual(files.filter((name) => [".env", ".dev.vars"].includes(path.basename(name))), []);
});
