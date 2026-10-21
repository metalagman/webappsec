import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createRelease } from "../lib/artifact.mjs";
import { canonicalJson } from "../lib/canonical-json.mjs";
import { humanReport, verifyProduction } from "../lib/verifier.mjs";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const execFile = promisify(execFileCallback);

async function releaseFixture() {
  const outputRoot = await mkdtemp(path.join(tmpdir(), "webappsec-verifier-"));
  const built = await createRelease({
    outputRoot,
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision: "0123456789abcdef0123456789abcdef01234567",
      tag: "v0.1.0",
      workflow: ".github/workflows/release.yml",
    },
    deployInputs: [
      { source: path.join(root, "lib/content-addressing.mjs"), path: "lib/content-addressing.mjs", role: "worker" },
      { source: path.join(root, "worker/index.js"), path: "worker/index.js", role: "worker" },
      { source: path.join(root, "wrangler.jsonc"), path: "wrangler.jsonc", role: "configuration" },
    ],
  });
  const manifest = JSON.parse(await readFile(built.manifestPath, "utf8"));
  const bodies = new Map();
  for (const entry of manifest.files) bodies.set(entry.urlPath, await readFile(path.join(built.directory, entry.path)));
  return { ...built, manifest, bodies, outputRoot };
}

function fixtureFetch(fixture, transform = ({ body }) => new Response(body)) {
  return async (url, options) => {
    const body = fixture.bodies.get(url.pathname);
    return transform({ url, options, body });
  };
}

async function alterHomepage(fixture, transform, filename) {
  const html = Buffer.from(transform(fixture.bodies.get("/").toString("utf8")));
  fixture.bodies.set("/", html);
  const homepage = fixture.manifest.files.find((entry) => entry.urlPath === "/");
  homepage.size = html.length;
  homepage.sha256 = sha256(html);
  const manifestPath = path.join(fixture.outputRoot, filename);
  await writeFile(manifestPath, canonicalJson(fixture.manifest));
  return manifestPath;
}

test("verifier accepts exact local production bytes and SRI without executing code", async () => {
  const fixture = await releaseFixture();
  let identityRequests = 0;
  const fetchImplementation = fixtureFetch(fixture, ({ options, body }) => {
    if (options.headers["Accept-Encoding"] === "identity") identityRequests += 1;
    return new Response(body, { status: body ? 200 : 404, headers: { "Content-Length": body?.length ?? 0 } });
  });
  const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation });
  assert.equal(report.ok, true);
  assert.deepEqual(report.layers.map(({ state }) => state), ["pass", "pass", "pass"]);
  assert.equal(identityRequests, fixture.manifest.files.length);
  assert.match(humanReport(report), /PASS deployment verified/);
});

test("verifier enforces the selected Worker version and preview noindex headers", async () => {
  const fixture = await releaseFixture();
  const versionId = "4f117518-6f75-4ef5-a4d7-19f08ba1181d";
  const fetchImplementation = fixtureFetch(fixture, ({ body }) => new Response(body, {
    headers: {
      "Content-Length": body.length,
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
      "Strict-Transport-Security": "max-age=31536000",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-Robots-Tag": "noindex, nofollow",
      "X-Webappsec-Release": fixture.digest,
      "X-Webappsec-Worker-Version": versionId,
    },
  }));
  const report = await verifyProduction({
    manifestPath: fixture.manifestPath,
    origin: "https://4f117518-webappsec.example.workers.dev",
    expectedHeaders: { release: fixture.digest, versionId, noindex: true },
    fetchImplementation,
  });
  assert.equal(report.ok, true);
  assert.deepEqual(report.layers.map(({ name, state }) => [name, state]), [
    ["manifest", "pass"],
    ["production-bytes", "pass"],
    ["response-headers", "pass"],
    ["sri", "pass"],
  ]);

  const wrongVersion = await verifyProduction({
    manifestPath: fixture.manifestPath,
    origin: "https://4f117518-webappsec.example.workers.dev",
    expectedHeaders: { release: fixture.digest, versionId: "00000000-0000-4000-8000-000000000000", noindex: true },
    fetchImplementation,
  });
  assert.equal(wrongVersion.ok, false);
  assert.match(wrongVersion.layers.find(({ name }) => name === "response-headers").detail, /X-Webappsec-Worker-Version/);
});

test("verifier fails closed for changed bytes, off-origin redirect, timeout, and wrong SRI", async (t) => {
  await t.test("changed bytes", async () => {
    const fixture = await releaseFixture();
    const fetchImplementation = fixtureFetch(fixture, ({ url, body }) => new Response(url.pathname === "/" ? "changed" : body));
    const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation });
    assert.equal(report.ok, false);
    assert.match(report.layers[1].detail, /size|SHA-256/);
    assert.equal(report.layers[2].state, "skipped");
  });

  await t.test("off-origin redirect", async () => {
    const fixture = await releaseFixture();
    const fetchImplementation = async () => new Response(null, { status: 302, headers: { Location: "https://attacker.example/file" } });
    const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation });
    assert.equal(report.ok, false);
    assert.match(report.layers[1].detail, /off-origin/);
  });

  await t.test("oversized response", async () => {
    const fixture = await releaseFixture();
    const fetchImplementation = fixtureFetch(fixture, ({ body }) => new Response(body, { headers: { "Content-Length": String(30 * 1024 * 1024) } }));
    const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation });
    assert.equal(report.ok, false);
    assert.match(report.layers[1].detail, /size limit/);
  });

  await t.test("timeout", async () => {
    const fixture = await releaseFixture();
    const fetchImplementation = async () => { throw new DOMException("The operation was aborted due to timeout", "TimeoutError"); };
    const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", timeoutMs: 10, fetchImplementation });
    assert.equal(report.ok, false);
    assert.equal(report.result, "service-unavailable");
    assert.equal(report.exitCode, 3);
    assert.equal(report.layers[1].state, "unavailable");
    assert.match(report.layers[1].detail, /timeout/i);
  });

  await t.test("response body timeout", async () => {
    const fixture = await releaseFixture();
    const fetchImplementation = fixtureFetch(fixture, ({ body }) => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(body.subarray(0, 1));
        controller.error(new DOMException("body read timed out", "TimeoutError"));
      },
    })));
    const report = await verifyProduction({ manifestPath: fixture.manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation });
    assert.equal(report.result, "service-unavailable");
    assert.equal(report.exitCode, 3);
    assert.equal(report.layers[1].state, "unavailable");
    assert.match(report.layers[1].detail, /body timeout/i);
  });

  await t.test("wrong SRI with otherwise matching declared bytes", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html.replace(/sha384-[A-Za-z0-9+/=]+/, `sha384-${"A".repeat(64)}`), "wrong-sri.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.equal(report.layers[1].state, "pass");
    assert.match(report.layers[2].detail, /SRI mismatch/);
  });

  await t.test("data-integrity cannot impersonate integrity", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html.replaceAll(" integrity=", " data-integrity="), "data-integrity.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /missing SRI/);
  });

  await t.test("relative unquoted browser resource must be declared", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html.replace(/src="\/app\/[^"]+"/, "src=assets/undeclared.js"), "relative-resource.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /undeclared subresource: \/assets\/undeclared\.js/);
  });

  await t.test("stylesheet rel token is parsed exactly", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html
      .replace('rel="stylesheet"', 'rel="preload stylesheet"')
      .replace(/(<link[^>]+) integrity=/, "$1 data-integrity="), "rel-token.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /missing SRI/);
  });

  await t.test("a wrong stronger SRI digest cannot accompany the expected digest", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html.replaceAll(/integrity="(sha384-[^"]+)"/g, `integrity="$1 sha512-${"A".repeat(88)}"`), "stronger-sri.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /SRI mismatch/);
  });

  await t.test("script cannot reference a declared stylesheet", async () => {
    const fixture = await releaseFixture();
    const stylesheet = fixture.manifest.files.find((entry) => entry.mediaType.startsWith("text/css"));
    const integrity = `sha384-${createHash("sha384").update(fixture.bodies.get(stylesheet.urlPath)).digest("base64")}`;
    const manifestPath = await alterHomepage(fixture, (html) => html.replace(/<script type="module" src="[^"]+" integrity="[^"]+"><\/script>/, `<script type="module" src="${stylesheet.urlPath}" integrity="${integrity}"></script>`), "wrong-resource-kind.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /script has invalid media type/);
  });

  await t.test("base href is rejected", async () => {
    const fixture = await releaseFixture();
    const manifestPath = await alterHomepage(fixture, (html) => html.replace("<head>", '<head><base href="https://attacker.example/">'), "base-href.json");
    const report = await verifyProduction({ manifestPath, origin: "http://127.0.0.1:4173", fetchImplementation: fixtureFetch(fixture) });
    assert.equal(report.ok, false);
    assert.match(report.layers[2].detail, /base href is forbidden/);
  });
});

test("malformed or noncanonical manifest skips every network-dependent layer", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "webappsec-bad-manifest-"));
  const filename = path.join(directory, "manifest.json");
  await writeFile(filename, "{bad json");
  const report = await verifyProduction({ manifestPath: filename, origin: "http://127.0.0.1:1" });
  assert.equal(report.ok, false);
  assert.deepEqual(report.layers.map(({ state }) => state), ["fail", "skipped", "skipped"]);
});

test("CLI returns stable invocation and unavailable exit codes", async () => {
  const cli = path.join(root, "scripts/verify-production.mjs");
  for (const args of [["--manifest", "--json"], ["--manifest", "file", "--origin", "not-a-url"]]) {
    await assert.rejects(() => execFile(process.execPath, [cli, ...args]), (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /^Usage:/);
      assert.doesNotMatch(error.stderr, /\bat\s+file:/);
      return true;
    });
  }

  const fixture = await releaseFixture();
  await assert.rejects(() => execFile(process.execPath, [cli, "--manifest", fixture.manifestPath, "--origin", "http://127.0.0.1:1", "--json"]), (error) => {
    assert.equal(error.code, 3);
    const report = JSON.parse(error.stdout);
    assert.equal(report.result, "service-unavailable");
    assert.equal(report.layers[1].state, "unavailable");
    return true;
  });
});
