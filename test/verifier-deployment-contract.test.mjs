import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import verifierWorker from "../verifier-worker/index.js";
import { buildVerifierSite } from "../scripts/build-verifier.mjs";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const verifierHost = "verify.webappsec.metalagman.dev";

function environment(body, init = {}) {
  const calls = [];
  return {
    calls,
    env: {
      CF_VERSION_METADATA: { id: "4f117518-6f75-4ef5-a4d7-19f08ba1181d" },
      ASSETS: {
        async fetch(request) {
          calls.push(request);
          return new Response(body, init);
        },
      },
    },
  };
}

test("verifier Wrangler config is isolated and pins the public custom domain", async () => {
  const config = JSON.parse(await readFile(path.join(root, "wrangler.verifier.jsonc"), "utf8"));
  assert.equal(config.name, "webappsec-verifier");
  assert.equal(config.main, "./verifier-worker/index.js");
  assert.equal(config.compatibility_date, "2026-10-16");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, true);
  assert.deepEqual(config.assets, {
    directory: "./dist-verifier",
    binding: "ASSETS",
    run_worker_first: true,
  });
  assert.deepEqual(config.version_metadata, { binding: "CF_VERSION_METADATA" });
  assert.deepEqual(config.routes, [{ pattern: verifierHost, custom_domain: true }]);
  assert.equal("env" in config, false);
});

test("verifier Worker adds exact CSP, security, version, and cache headers", async (t) => {
  const buildDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-worker-"));
  const built = await buildVerifierSite({ outputDirectory: buildDirectory });
  const scriptPath = built.files.find((name) => name.endsWith(".js"));
  assert.ok(scriptPath);

  await t.test("content-addressed assets are immutable", async () => {
    const { env, calls } = environment("script", { headers: { ETag: '"asset"' } });
    const request = new Request(`https://${verifierHost}/${scriptPath}`);
    const response = await verifierWorker.fetch(request, env);
    assert.equal(calls[0], request);
    assert.equal(response.headers.get("Cache-Control"), "public, max-age=31536000, immutable");
    assert.equal(response.headers.get("ETag"), '"asset"');
    assert.equal(response.headers.get("X-Webappsec-Verifier-Version"), env.CF_VERSION_METADATA.id);
    assert.equal(response.headers.get("Strict-Transport-Security"), "max-age=31536000");
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(response.headers.get("X-Frame-Options"), "DENY");
    assert.equal(response.headers.get("Cross-Origin-Opener-Policy"), "same-origin");
    assert.equal(response.headers.get("Cross-Origin-Resource-Policy"), "same-origin");
    assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
    assert.equal(response.headers.get("Permissions-Policy"), "camera=(), geolocation=(), microphone=()");
    assert.equal(
      response.headers.get("Content-Security-Policy"),
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://webappsec.metalagman.dev; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
  });

  for (const pathname of ["/", "/index.html", "/current-verification.json", "/release-manifest.json"]) {
    await t.test(`${pathname} cannot be cached stale`, async () => {
      const { env } = environment("mutable");
      const response = await verifierWorker.fetch(new Request(`https://${verifierHost}${pathname}`), env);
      assert.equal(response.headers.get("Cache-Control"), "no-store");
    });
  }

  await t.test("errors are never cached", async () => {
    const { env } = environment("missing", { status: 404 });
    const response = await verifierWorker.fetch(new Request(`https://${verifierHost}/missing`), env);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });
});

test("verifier Worker enforces exact production/version hosts and HTTPS", async (t) => {
  await t.test("version preview is allowed and noindex", async () => {
    const { env, calls } = environment("preview");
    const response = await verifierWorker.fetch(
      new Request("https://4f117518-webappsec-verifier.demo-account.workers.dev/"),
      env,
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("X-Robots-Tag"), "noindex");
    assert.equal(calls.length, 1);
  });

  await t.test("HTTP redirects on an allowed host", async () => {
    const { env, calls } = environment("unused");
    const response = await verifierWorker.fetch(new Request(`http://${verifierHost}/path?q=1`), env);
    assert.equal(response.status, 308);
    assert.equal(response.headers.get("Location"), `https://${verifierHost}/path?q=1`);
    assert.equal(response.headers.get("Strict-Transport-Security"), null);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(calls.length, 0);
  });

  for (const hostname of ["attacker.example", "webappsec.metalagman.dev", "webappsec-verifier.workers.dev"]) {
    await t.test(`${hostname} is rejected`, async () => {
      const { env, calls } = environment("unused");
      const response = await verifierWorker.fetch(new Request(`https://${hostname}/`), env);
      assert.equal(response.status, 421);
      assert.equal(response.headers.get("Cache-Control"), "no-store");
      assert.equal(response.headers.get("X-Robots-Tag"), "noindex");
      assert.equal(calls.length, 0);
    });
  }
});

test("verifier build inventory contains only the intended page and addressed assets", async () => {
  const outputDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-inventory-"));
  await buildVerifierSite({ outputDirectory });
  const rootEntries = (await readdir(outputDirectory)).sort();
  const assetEntries = (await readdir(path.join(outputDirectory, "app"))).sort();
  assert.deepEqual(rootEntries, ["app", "index.html"]);
  assert.equal(assetEntries.length, 2);
  assert.ok(assetEntries.every((name) => /^verifier\.[a-f0-9]{12}\.(?:css|js)$/.test(name)));
});
