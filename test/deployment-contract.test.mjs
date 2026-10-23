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
const releaseContentSecurityPolicy = [
  "default-src 'none'",
  `script-src 'self' 'sha384-${"A".repeat(64)}'`,
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function environment(body, init = {}, policy = releaseContentSecurityPolicy) {
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
          if (new URL(request.url).pathname === "/security-policy.txt") {
            return new Response(policy, { status: policy ? 200 : 404 });
          }
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
    html_handling: "none",
    not_found_handling: "404-page",
  });
  assert.deepEqual(config.version_metadata, { binding: "CF_VERSION_METADATA" });
  assert.deepEqual(config.routes, [{ pattern: "webappsec.metalagman.dev", custom_domain: true }]);
  assert.equal("env" in config, false);

  const packageManifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.equal(packageManifest.devDependencies.wrangler, "4.151.3");
});

test("Worker serves root explicitly while preserving exact signed HTML paths", async () => {
  const { env, calls } = environment("html", { headers: { "Content-Type": "text/html" } });
  const rootRequest = new Request("https://webappsec.metalagman.dev/", {
    headers: { Origin: "https://verify.webappsec.metalagman.dev" },
  });
  await worker.fetch(rootRequest, env);
  assert.equal(new URL(calls[0].url).pathname, "/security-policy.txt");
  assert.equal(new URL(calls[1].url).pathname, "/index.html");
  assert.equal(calls[1].method, "GET");
  assert.equal(calls[1].headers.get("Origin"), "https://verify.webappsec.metalagman.dev");

  const notFoundPage = new Request("https://webappsec.metalagman.dev/404.html");
  await worker.fetch(notFoundPage, env);
  assert.equal(new URL(calls[2].url).pathname, "/security-policy.txt");
  assert.equal(calls[3], notFoundPage);
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
  assert.equal(calls.length, 2);
  assert.equal(new URL(calls[0].url).pathname, "/security-policy.txt");
  assert.equal(calls[1], request);
  assert.equal(response.headers.get("ETag"), '"asset"');
  assert.equal(response.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  assert.equal(response.headers.get("Strict-Transport-Security"), "max-age=31536000");
  assert.equal(response.headers.get("Content-Security-Policy"), releaseContentSecurityPolicy);
  assert.equal(response.headers.get("X-Webappsec-Release"), env.CF_VERSION_METADATA.tag);
  assert.equal(response.headers.get("X-Webappsec-Worker-Version"), env.CF_VERSION_METADATA.id);
  assert.equal(response.headers.get("X-Robots-Tag"), null);
});

test("Worker fails closed when the signed release CSP is missing or malformed", async (t) => {
  for (const [name, policy] of [["missing", ""], ["malformed", "default-src *\nX-Evil: yes"]]) {
    await t.test(name, async () => {
      const { env, calls } = environment("must not be served", {}, policy);
      const response = await worker.fetch(new Request("https://webappsec.metalagman.dev/"), env);
      assert.equal(response.status, 503);
      assert.equal(await response.text(), "Release policy unavailable\n");
      assert.equal(calls.length, 1);
      assert.equal(new URL(calls[0].url).pathname, "/security-policy.txt");
    });
  }
});

test("production responses grant narrow read-only CORS access to the online verifier", async (t) => {
  const verifierOrigin = "https://verify.webappsec.metalagman.dev";

  for (const method of ["GET", "HEAD"]) {
    await t.test(`${method} exposes only deployment identity to the verifier`, async () => {
      const { env } = environment("production", {
        headers: {
          Vary: "Accept-Encoding",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Expose-Headers": "*",
          "Access-Control-Allow-Credentials": "true",
        },
      });
      const response = await worker.fetch(
        new Request("https://webappsec.metalagman.dev/", {
          method,
          headers: { Origin: verifierOrigin },
        }),
        env,
      );

      assert.equal(response.headers.get("Access-Control-Allow-Origin"), verifierOrigin);
      assert.equal(
        response.headers.get("Access-Control-Expose-Headers"),
        "X-Webappsec-Release, X-Webappsec-Worker-Version",
      );
      assert.equal(response.headers.get("Access-Control-Allow-Credentials"), null);
      assert.deepEqual(
        response.headers.get("Vary").split(",").map((value) => value.trim()),
        ["Accept-Encoding", "Origin"],
      );
    });
  }

  for (const [name, request] of [
    ["missing Origin", new Request("https://webappsec.metalagman.dev/")],
    [
      "foreign Origin",
      new Request("https://webappsec.metalagman.dev/", {
        headers: { Origin: "https://attacker.example" },
      }),
    ],
    [
      "POST",
      new Request("https://webappsec.metalagman.dev/", {
        method: "POST",
        headers: { Origin: verifierOrigin },
      }),
    ],
    [
      "OPTIONS",
      new Request("https://webappsec.metalagman.dev/", {
        method: "OPTIONS",
        headers: { Origin: verifierOrigin },
      }),
    ],
  ]) {
    await t.test(`${name} receives no cross-origin grant`, async () => {
      const { env } = environment("production", {
        headers: {
          Vary: "Origin",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Expose-Headers": "*",
          "Access-Control-Allow-Credentials": "true",
        },
      });
      const response = await worker.fetch(request, env);

      assert.equal(response.headers.get("Access-Control-Allow-Origin"), null);
      assert.equal(response.headers.get("Access-Control-Expose-Headers"), null);
      assert.equal(response.headers.get("Access-Control-Allow-Credentials"), null);
      assert.deepEqual(response.headers.get("Vary"), "Origin");
    });
  }
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
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex");
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
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex");
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
