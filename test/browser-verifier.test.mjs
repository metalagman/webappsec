import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import test from "node:test";

const origin = "https://webappsec.metalagman.dev";
const manifestDigest = "a".repeat(64);
const workerVersion = "39600c79-f529-4ead-8df8-5b61acbe8ee4";
const deploymentId = "49600c79-f529-4ead-8df8-5b61acbe8ee4";
const revision = "b".repeat(40);
const layerNames = [
  "release-resolution",
  "evidence-inventory",
  "signatures",
  "attestations",
  "sbom",
  "vulnerability-evidence",
  "reproducible-build",
  "production-bytes",
  "sri",
];

function snapshot(overrides = {}) {
  return {
    schema: "https://webappsec.metalagman.dev/schema/online-verifier-snapshot-v1",
    version: 1,
    target: { origin, manifestDigest, workerVersion, deploymentId },
    sourceRelease: {
      tag: "v0.2.7",
      revision,
      url: "https://github.com/metalagman/webappsec/releases/tag/v0.2.7",
    },
    deploymentEvidence: {
      release: "deployment-deploy-v0.2.7-39689851057",
      url: "https://github.com/metalagman/webappsec/releases/tag/deployment-deploy-v0.2.7-39689851057",
      runUrl: "https://github.com/metalagman/webappsec/actions/runs/39689851057",
    },
    verificationEvidence: {
      release: "verification-v0.2.7-39690026014",
      url: "https://github.com/metalagman/webappsec/releases/tag/verification-v0.2.7-39690026014",
      runUrl: "https://github.com/metalagman/webappsec/actions/runs/39690026014",
      verifiedAt: "2026-10-22T03:20:00.000Z",
      layers: layerNames.map((name) => ({ name, state: "pass", detail: `${name} checked` })),
    },
    proofs: ["release-signatures", "deployment-signatures", "verification-signatures"]
      .map((name) => ({ name, state: "pass", source: "ci" })),
    manifest: { path: "release-manifest.json", size: 1234, sha256: manifestDigest },
    ...overrides,
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function manifest(files = [
  { path: "assets/app/app.abc123.js", urlPath: "/app/app.abc123.js", mediaType: "text/javascript; charset=utf-8", size: 18, sha256: "c".repeat(64) },
  { path: "assets/index.html", urlPath: "/", mediaType: "text/html; charset=utf-8", size: 90, sha256: "d".repeat(64) },
]) {
  return {
    schema: "https://webappsec.metalagman.dev/schema/deployment-manifest-v1",
    version: 1,
    origin,
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision,
      tag: "v0.2.7",
      workflow: ".github/workflows/release.yml",
    },
    worker: { name: "webappsec" },
    inputs: [
      { path: "worker/index.js", role: "worker", size: 100, sha256: "e".repeat(64) },
      { path: "wrangler.jsonc", role: "configuration", size: 100, sha256: "f".repeat(64) },
    ],
    files,
  };
}

function file(path, urlPath, mediaType, bytes) {
  return { path, urlPath, mediaType, size: bytes.length, sha256: sha256(bytes) };
}

function response(bytes, { release = manifestDigest, version = workerVersion, status = 200 } = {}) {
  return new Response(bytes, {
    status,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Webappsec-Release": release,
      "X-Webappsec-Worker-Version": version,
    },
  });
}

function verifierFixture() {
  const html = new TextEncoder().encode("<!doctype html>");
  const script = new TextEncoder().encode("console.log('verified');\n");
  const style = new TextEncoder().encode("body { color: green; }\n");
  const value = manifest([
    file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
    file("assets/app/site.abc123.css", "/app/site.abc123.css", "text/css; charset=utf-8", style),
    file("assets/index.html", "/", "text/html; charset=utf-8", html),
  ]);
  const manifestBytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = sha256(manifestBytes);
  const snap = snapshot();
  snap.target.manifestDigest = digest;
  snap.manifest.sha256 = digest;
  snap.manifest.size = manifestBytes.length;
  const scriptSri = `sha384-${createHash("sha384").update(script).digest("base64")}`;
  const styleSri = `sha384-${createHash("sha384").update(style).digest("base64")}`;
  const DOMParserImplementation = fixtureParser({
    scripts: [new FixtureElement({ src: "/app/app.abc123.js", integrity: scriptSri })],
    styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: styleSri })],
  });
  return { html, script, style, value, manifestBytes, digest, snap, DOMParserImplementation };
}

test("snapshot validation accepts the exact trusted proof and layer inventory", async () => {
  const { validateOnlineVerifierSnapshot } = await import("../lib/browser-verifier.mjs");
  assert.equal(validateOnlineVerifierSnapshot(snapshot()).target.workerVersion, workerVersion);
});

test("snapshot validation rejects missing, duplicate, and unknown proof groups", async () => {
  const { validateOnlineVerifierSnapshot } = await import("../lib/browser-verifier.mjs");
  for (const proofs of [
    snapshot().proofs.slice(1),
    [...snapshot().proofs, snapshot().proofs[0]],
    snapshot().proofs.map((proof, index) => index === 0 ? { ...proof, name: "browser-signatures" } : proof),
  ]) {
    assert.throws(() => validateOnlineVerifierSnapshot(snapshot({ proofs })), /proof inventory/);
  }
});

test("snapshot validation rejects reordered or non-pass CI layers", async () => {
  const { validateOnlineVerifierSnapshot } = await import("../lib/browser-verifier.mjs");
  const reordered = snapshot();
  [reordered.verificationEvidence.layers[0], reordered.verificationEvidence.layers[1]] =
    [reordered.verificationEvidence.layers[1], reordered.verificationEvidence.layers[0]];
  assert.throws(() => validateOnlineVerifierSnapshot(reordered), /layer inventory/);

  const failed = snapshot();
  failed.verificationEvidence.layers[2].state = "fail";
  assert.throws(() => validateOnlineVerifierSnapshot(failed), /layer inventory/);
});

test("manifest validation accepts bounded sorted production mappings", async () => {
  const { validateBrowserReleaseManifest } = await import("../lib/browser-verifier.mjs");
  const value = manifest();
  assert.equal(validateBrowserReleaseManifest(value).files.length, 2);
});

test("manifest validation rejects unsafe, duplicate, unsorted, and excessive mappings", async () => {
  const { validateBrowserReleaseManifest } = await import("../lib/browser-verifier.mjs");
  const unsafe = manifest();
  unsafe.files[0].path = "assets/../secret.js";
  assert.throws(() => validateBrowserReleaseManifest(unsafe), /safe relative path/);

  const duplicateUrl = manifest();
  duplicateUrl.files[0].urlPath = "/";
  assert.throws(() => validateBrowserReleaseManifest(duplicateUrl), /URL paths/);

  const unsorted = manifest([...manifest().files].reverse());
  assert.throws(() => validateBrowserReleaseManifest(unsorted), /sorted/);

  const excessive = manifest(Array.from({ length: 129 }, (_, index) => ({
    path: `assets/chunk-${String(index).padStart(3, "0")}.js`,
    urlPath: `/chunk-${String(index).padStart(3, "0")}.js`,
    mediaType: "text/javascript; charset=utf-8",
    size: 1,
    sha256: "c".repeat(64),
  })));
  assert.throws(() => validateBrowserReleaseManifest(excessive), /file limit/);
});

test("production verification streams every mapped file and checks identity, size, and SHA-256", async () => {
  const { verifyProductionFiles } = await import("../lib/browser-verifier.mjs");
  const script = new TextEncoder().encode("console.log('ok');\n");
  const html = new TextEncoder().encode("<!doctype html><script></script>");
  const value = manifest([
    file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
    file("assets/index.html", "/", "text/html; charset=utf-8", html),
  ]);
  const bodies = new Map([["/", html], ["/app/app.abc123.js", script]]);
  const requests = [];
  const result = await verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async (url, options) => {
      requests.push({ url, options });
      return response(bodies.get(new URL(url).pathname));
    },
  });

  assert.deepEqual([...result.keys()].sort(), ["/", "/app/app.abc123.js"]);
  assert.equal(requests.length, 2);
  assert.ok(requests.every(({ options }) => options.cache === "no-store"
    && options.credentials === "omit" && options.mode === "cors" && options.redirect === "error"));
});

test("production verification rejects identity drift, tampered bytes, and streamed overflow", async () => {
  const { verifyProductionFiles } = await import("../lib/browser-verifier.mjs");
  const html = new TextEncoder().encode("<!doctype html>");
  const value = manifest([file("assets/index.html", "/", "text/html; charset=utf-8", html)]);

  await assert.rejects(() => verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async () => response(html, { version: deploymentId }),
  }), /Worker version mismatch/);

  await assert.rejects(() => verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async () => response(new TextEncoder().encode("tampered")),
  }), /size mismatch/);

  const huge = new Uint8Array(8 * 1024 * 1024 + 1);
  await assert.rejects(() => verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async () => response(huge),
  }), /byte limit/);
});

class FixtureElement {
  constructor(attributes) { this.attributes = attributes; }
  getAttribute(name) { return this.attributes[name] ?? null; }
}

function fixtureParser(resources) {
  return class {
    parseFromString() {
      return {
        querySelectorAll(selector) {
          if (selector === "script[src]") return resources.scripts;
          if (selector === 'link[rel~="stylesheet"][href]') return resources.styles;
          if (selector === "base[href]") return resources.bases ?? [];
          return [];
        },
      };
    }
  };
}

test("SRI verification hashes same-origin scripts and styles without executing them", async () => {
  const { verifySriDocuments } = await import("../lib/browser-verifier.mjs");
  const html = new TextEncoder().encode("<!doctype html>");
  const script = new TextEncoder().encode("console.log('verified');\n");
  const style = new TextEncoder().encode("body { color: green; }\n");
  const scriptSri = `sha384-${createHash("sha384").update(script).digest("base64")}`;
  const styleSri = `sha384-${createHash("sha384").update(style).digest("base64")}`;
  const value = manifest([
    file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
    file("assets/app/site.abc123.css", "/app/site.abc123.css", "text/css; charset=utf-8", style),
    file("assets/index.html", "/", "text/html; charset=utf-8", html),
  ]);
  const bodies = new Map([["/", html], ["/app/app.abc123.js", script], ["/app/site.abc123.css", style]]);
  const DOMParserImplementation = fixtureParser({
    scripts: [new FixtureElement({ src: "/app/app.abc123.js", integrity: scriptSri })],
    styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: styleSri })],
  });

  const result = await verifySriDocuments({ manifest: value, bodies, DOMParserImplementation, cryptoImplementation: webcrypto });
  assert.deepEqual(result, { scripts: 1, stylesheets: 1, resources: 2 });
});

test("SRI verification rejects missing, cross-origin, and mismatched integrity metadata", async () => {
  const { verifySriDocuments } = await import("../lib/browser-verifier.mjs");
  const html = new TextEncoder().encode("<!doctype html>");
  const script = new TextEncoder().encode("console.log('verified');\n");
  const style = new TextEncoder().encode("body { color: green; }\n");
  const validStyle = `sha384-${createHash("sha384").update(style).digest("base64")}`;
  const value = manifest([
    file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
    file("assets/app/site.abc123.css", "/app/site.abc123.css", "text/css; charset=utf-8", style),
    file("assets/index.html", "/", "text/html; charset=utf-8", html),
  ]);
  const bodies = new Map([["/", html], ["/app/app.abc123.js", script], ["/app/site.abc123.css", style]]);

  for (const [attributes, pattern] of [
    [{ src: "/app/app.abc123.js" }, /missing SRI/],
    [{ src: "https://evil.example/app.js", integrity: "sha384-abc" }, /same production origin/],
    [{ src: "/app/app.abc123.js", integrity: `sha384-${"A".repeat(64)}` }, /SRI mismatch/],
  ]) {
    const DOMParserImplementation = fixtureParser({
      scripts: [new FixtureElement(attributes)],
      styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: validStyle })],
    });
    await assert.rejects(() => verifySriDocuments({
      manifest: value, bodies, DOMParserImplementation, cryptoImplementation: webcrypto,
    }), pattern);
  }
});

test("online verification joins CI proof with fresh bytes, SRI, and stable identity", async () => {
  const { verifyOnlineDeployment } = await import("../lib/browser-verifier.mjs");
  const fixture = verifierFixture();
  const updates = [];
  const bodies = new Map([
    ["/", fixture.html],
    ["/app/app.abc123.js", fixture.script],
    ["/app/site.abc123.css", fixture.style],
  ]);
  const fetchImplementation = async (url) => {
    const parsed = new URL(url);
    if (parsed.origin === "https://verify.webappsec.metalagman.dev") {
      if (parsed.pathname === "/current-verification.json") {
        return new Response(JSON.stringify(fixture.snap), { headers: { "Content-Type": "application/json" } });
      }
      if (parsed.pathname === "/release-manifest.json") {
        return new Response(fixture.manifestBytes, { headers: { "Content-Type": "application/json" } });
      }
    }
    return response(bodies.get(parsed.pathname), { release: fixture.digest });
  };

  const result = await verifyOnlineDeployment({
    verifierOrigin: "https://verify.webappsec.metalagman.dev",
    fetchImplementation,
    cryptoImplementation: webcrypto,
    DOMParserImplementation: fixture.DOMParserImplementation,
    now: () => Date.parse("2026-10-22T04:00:00.000Z"),
    onCheck: (check) => updates.push(check),
  });

  assert.equal(result.ok, true);
  assert.equal(result.stale, false);
  assert.equal(result.identity.manifestDigest, fixture.digest);
  assert.ok(result.checks.every((check) => check.state === "pass"));
  assert.ok(result.checks.some((check) => check.id === "ci:signatures" && check.group === "ci"));
  assert.ok(updates.some((check) => check.id === "browser:production-bytes" && check.state === "running"));
});

test("online verification fails closed on final identity drift and classifies network loss as unavailable", async () => {
  const { verifyOnlineDeployment } = await import("../lib/browser-verifier.mjs");
  const fixture = verifierFixture();
  const bodies = new Map([
    ["/", fixture.html],
    ["/app/app.abc123.js", fixture.script],
    ["/app/site.abc123.css", fixture.style],
  ]);
  let rootRequests = 0;
  const staticResponse = (parsed) => parsed.pathname === "/current-verification.json"
    ? new Response(JSON.stringify(fixture.snap), { headers: { "Content-Type": "application/json" } })
    : new Response(fixture.manifestBytes, { headers: { "Content-Type": "application/json" } });
  const drift = await verifyOnlineDeployment({
    verifierOrigin: "https://verify.webappsec.metalagman.dev",
    cryptoImplementation: webcrypto,
    DOMParserImplementation: fixture.DOMParserImplementation,
    fetchImplementation: async (url) => {
      const parsed = new URL(url);
      if (parsed.origin.startsWith("https://verify.")) return staticResponse(parsed);
      if (parsed.pathname === "/") rootRequests += 1;
      const version = rootRequests >= 3 ? deploymentId : workerVersion;
      return response(bodies.get(parsed.pathname), { release: fixture.digest, version });
    },
  });
  assert.equal(drift.ok, false);
  assert.equal(drift.checks.at(-1).id, "browser:stability");
  assert.equal(drift.checks.at(-1).state, "fail");
  assert.deepEqual(drift.sourceRelease, fixture.snap.sourceRelease);
  assert.deepEqual(drift.deploymentEvidence, fixture.snap.deploymentEvidence);
  assert.deepEqual(drift.verificationEvidence, fixture.snap.verificationEvidence);

  const unavailable = await verifyOnlineDeployment({
    verifierOrigin: "https://verify.webappsec.metalagman.dev",
    cryptoImplementation: webcrypto,
    DOMParserImplementation: fixture.DOMParserImplementation,
    fetchImplementation: async (url) => {
      const parsed = new URL(url);
      if (parsed.origin.startsWith("https://verify.")) return staticResponse(parsed);
      throw new TypeError("offline");
    },
  });
  assert.equal(unavailable.ok, false);
  assert.equal(unavailable.checks.at(-1).state, "unavailable");
  assert.deepEqual(unavailable.sourceRelease, fixture.snap.sourceRelease);
  assert.deepEqual(unavailable.deploymentEvidence, fixture.snap.deploymentEvidence);
  assert.deepEqual(unavailable.verificationEvidence, fixture.snap.verificationEvidence);
});

test("online verification reports stale valid CI evidence without changing pass to failure", async () => {
  const { verificationAge } = await import("../lib/browser-verifier.mjs");
  assert.deepEqual(verificationAge("2026-10-20T00:00:00.000Z", Date.parse("2026-10-22T00:00:01.000Z")), {
    stale: true,
    ageMs: 48 * 60 * 60 * 1000 + 1000,
    thresholdMs: 36 * 60 * 60 * 1000,
  });
});

test("snapshot binds deployment and verification release tags and run URLs exactly", async () => {
  const { validateOnlineVerifierSnapshot } = await import("../lib/browser-verifier.mjs");
  const wrongDeploymentTag = snapshot();
  wrongDeploymentTag.deploymentEvidence.release = "deployment-deploy-v9.9.9-39689851057";
  wrongDeploymentTag.deploymentEvidence.url = `https://github.com/metalagman/webappsec/releases/tag/${wrongDeploymentTag.deploymentEvidence.release}`;
  assert.throws(() => validateOnlineVerifierSnapshot(wrongDeploymentTag), /deployment evidence identity/);

  const wrongDeploymentRun = snapshot();
  wrongDeploymentRun.deploymentEvidence.runUrl = "https://github.com/metalagman/webappsec/actions/runs/1";
  assert.throws(() => validateOnlineVerifierSnapshot(wrongDeploymentRun), /deployment evidence identity/);

  const wrongVerificationRun = snapshot();
  wrongVerificationRun.verificationEvidence.runUrl = "https://github.com/metalagman/webappsec/actions/runs/1";
  assert.throws(() => validateOnlineVerifierSnapshot(wrongVerificationRun), /verification evidence identity/);

  const looseDate = snapshot();
  looseDate.verificationEvidence.verifiedAt = "October 22, 2026";
  assert.throws(() => validateOnlineVerifierSnapshot(looseDate), /verification timestamp/);

  const impossibleDate = snapshot();
  impossibleDate.verificationEvidence.verifiedAt = "2026-99-22T03:20:00.000Z";
  assert.throws(() => validateOnlineVerifierSnapshot(impossibleDate), /verification timestamp/);
});

test("production body transport errors are unavailable and the timeout covers streamed bytes", async () => {
  const { VerificationUnavailableError, verifyProductionFiles } = await import("../lib/browser-verifier.mjs");
  const html = new TextEncoder().encode("<!doctype html>");
  const value = manifest([file("assets/index.html", "/", "text/html; charset=utf-8", html)]);

  await assert.rejects(() => verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async () => response(new ReadableStream({
      pull() { throw new TypeError("connection reset"); },
    })),
  }), VerificationUnavailableError);

  const originalSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, milliseconds, ...args) =>
    originalSetTimeout(callback, milliseconds === 10_000 ? 10 : milliseconds, ...args);
  try {
    await assert.rejects(() => verifyProductionFiles({
      manifest: value,
      target: snapshot().target,
      cryptoImplementation: webcrypto,
      fetchImplementation: async (_url, options) => response(new ReadableStream({
        start(controller) {
          options.signal.addEventListener("abort", () => controller.error(options.signal.reason), { once: true });
          originalSetTimeout(() => controller.error(new TypeError("safety timeout")), 100);
        },
      })),
    }), (error) => error instanceof VerificationUnavailableError && /timed out/.test(error.message));
  } finally {
    globalThis.setTimeout = originalSetTimeout;
  }
});

test("a failed production resource aborts and awaits its sibling downloads", async () => {
  const { verifyProductionFiles } = await import("../lib/browser-verifier.mjs");
  const byte = new Uint8Array([1]);
  const value = manifest([
    ...Array.from({ length: 4 }, (_, index) =>
      file(`assets/chunk-${index}.js`, `/chunk-${index}.js`, "text/javascript; charset=utf-8", byte)),
    file("assets/index.html", "/", "text/html; charset=utf-8", byte),
  ]);
  let siblingAborts = 0;
  await assert.rejects(() => verifyProductionFiles({
    manifest: value,
    target: snapshot().target,
    cryptoImplementation: webcrypto,
    fetchImplementation: async (url, options) => {
      if (new URL(url).pathname === "/chunk-0.js") return response("missing", { status: 404 });
      return new Promise((resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          siblingAborts += 1;
          reject(options.signal.reason);
        }, { once: true });
      });
    },
  }), /HTTP 404/);
  assert.equal(siblingAborts, 3);
});

test("SRI follows strongest supported digest semantics and resource media types", async () => {
  const { verifySriDocuments } = await import("../lib/browser-verifier.mjs");
  const html = new TextEncoder().encode("<!doctype html>");
  const script = new TextEncoder().encode("console.log('verified');\n");
  const style = new TextEncoder().encode("body { color: green; }\n");
  const scriptSri = `sha384-${createHash("sha384").update(script).digest("base64")}`;
  const styleSri = `sha384-${createHash("sha384").update(style).digest("base64")}`;
  const value = manifest([
    file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
    file("assets/app/site.abc123.css", "/app/site.abc123.css", "text/css; charset=utf-8", style),
    file("assets/index.html", "/", "text/html; charset=utf-8", html),
  ]);
  const bodies = new Map([["/", html], ["/app/app.abc123.js", script], ["/app/site.abc123.css", style]]);

  const strongerMismatch = fixtureParser({
    scripts: [new FixtureElement({ src: "/app/app.abc123.js", integrity: `${scriptSri} sha512-${"A".repeat(86)}==` })],
    styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: styleSri })],
  });
  await assert.rejects(() => verifySriDocuments({
    manifest: value, bodies, DOMParserImplementation: strongerMismatch, cryptoImplementation: webcrypto,
  }), /SRI mismatch/);

  const wrongMediaType = fixtureParser({
    scripts: [new FixtureElement({ src: "/app/site.abc123.css", integrity: styleSri })],
    styles: [new FixtureElement({ href: "/app/app.abc123.js", integrity: scriptSri })],
  });
  await assert.rejects(() => verifySriDocuments({
    manifest: value, bodies, DOMParserImplementation: wrongMediaType, cryptoImplementation: webcrypto,
  }), /media type/);

  const baseHref = fixtureParser({
    scripts: [new FixtureElement({ src: "/app/app.abc123.js", integrity: scriptSri })],
    styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: styleSri })],
    bases: [new FixtureElement({ href: "/other/" })],
  });
  await assert.rejects(() => verifySriDocuments({
    manifest: value, bodies, DOMParserImplementation: baseHref, cryptoImplementation: webcrypto,
  }), /base href/);

  for (const integrity of [
    `sha256-${createHash("sha256").update(script).digest("base64")}`,
    `sha512-${createHash("sha512").update(script).digest("base64")}`,
  ]) {
    const withoutSha384 = fixtureParser({
      scripts: [new FixtureElement({ src: "/app/app.abc123.js", integrity })],
      styles: [new FixtureElement({ href: "/app/site.abc123.css", integrity: styleSri })],
    });
    await assert.rejects(() => verifySriDocuments({
      manifest: value, bodies, DOMParserImplementation: withoutSha384, cryptoImplementation: webcrypto,
    }), /SHA-384 is required/);
  }
});

test("missing required browser APIs returns an explicit unavailable capability result", async () => {
  const { verifyOnlineDeployment } = await import("../lib/browser-verifier.mjs");
  const result = await verifyOnlineDeployment({
    verifierOrigin: "https://verify.webappsec.metalagman.dev",
    fetchImplementation: null,
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.checks.map(({ id, state }) => ({ id, state })), [
    { id: "browser:capabilities", state: "unavailable" },
  ]);
});
