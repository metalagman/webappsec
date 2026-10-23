import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { buildVerifierSite } from "../../scripts/build-verifier.mjs";

const verifierOrigin = "https://verify.test";
const productionOrigin = "https://webappsec.metalagman.dev";
const workerVersion = "39600c79-f529-4ead-8df8-5b61acbe8ee4";
const deploymentId = "49600c79-f529-4ead-8df8-5b61acbe8ee4";
const revision = "b".repeat(40);
const releaseTag = "v0.2.7";
const runId = "39690026014";
const layerNames = [
  "release-resolution", "evidence-inventory", "signatures", "attestations", "sbom",
  "vulnerability-evidence", "reproducible-build", "production-bytes", "sri",
];
let outputDirectory;

const sha = (algorithm, bytes, encoding = "hex") =>
  createHash(algorithm).update(bytes).digest(encoding);
const file = (pathName, urlPath, mediaType, bytes) => ({
  path: pathName,
  urlPath,
  mediaType,
  size: bytes.byteLength,
  sha256: sha("sha256", bytes),
});

function fixture({ importMapMismatch = false, sriMismatch = false, stale = false } = {}) {
  const script = Buffer.from("import '/app/interactions.abc123.js';\ndocument.documentElement.dataset.production = 'never-executed';\n");
  const interactions = Buffer.from("export const loaded = true;\n");
  const style = Buffer.from("body { color: #fff; }\n");
  const scriptSri = sriMismatch ? `sha384-${"A".repeat(64)}` : `sha384-${sha("sha384", script, "base64")}`;
  const importMap = JSON.stringify({ integrity: {
    "/app/app.abc123.js": importMapMismatch ? `sha384-${"A".repeat(64)}` : `sha384-${sha("sha384", script, "base64")}`,
    "/app/interactions.abc123.js": `sha384-${sha("sha384", interactions, "base64")}`,
  } });
  const importMapSri = `sha384-${sha("sha384", Buffer.from(importMap), "base64")}`;
  const styleSri = `sha384-${sha("sha384", style, "base64")}`;
  const documentPolicy = `default-src 'none'; script-src 'self' '${importMapSri}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'`;
  const responsePolicy = Buffer.from(`${documentPolicy}; frame-ancestors 'none'`);
  const html = Buffer.from(`<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="${documentPolicy}"><link rel="stylesheet" href="/app/site.abc123.css" integrity="${styleSri}"><script type="importmap">${importMap}</script><script type="module" src="/app/app.abc123.js" integrity="${scriptSri}"></script></head><body>production</body></html>`);
  const files = new Map([
    ["/", html],
    ["/app/app.abc123.js", script],
    ["/app/interactions.abc123.js", interactions],
    ["/app/site.abc123.css", style],
    ["/security-policy.txt", responsePolicy],
  ]);
  const manifest = {
    schema: "https://webappsec.metalagman.dev/schema/deployment-manifest-v1",
    version: 1,
    origin: productionOrigin,
    release: {
      repository: "https://github.com/metalagman/webappsec",
      revision,
      tag: releaseTag,
      workflow: ".github/workflows/release.yml",
    },
    worker: { name: "webappsec" },
    inputs: [
      { path: "worker/index.js", role: "worker", size: 100, sha256: "e".repeat(64) },
      { path: "wrangler.jsonc", role: "configuration", size: 100, sha256: "f".repeat(64) },
    ],
    files: [
      file("assets/app/app.abc123.js", "/app/app.abc123.js", "text/javascript; charset=utf-8", script),
      file("assets/app/interactions.abc123.js", "/app/interactions.abc123.js", "text/javascript; charset=utf-8", interactions),
      file("assets/app/site.abc123.css", "/app/site.abc123.css", "text/css; charset=utf-8", style),
      file("assets/index.html", "/", "text/html; charset=utf-8", html),
      file("assets/security-policy.txt", "/security-policy.txt", "application/octet-stream", responsePolicy),
    ],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestDigest = sha("sha256", manifestBytes);
  const verifiedAt = new Date(Date.now() - (stale ? 40 * 60 * 60_000 : 60_000)).toISOString();
  const snapshot = {
    schema: "https://webappsec.metalagman.dev/schema/online-verifier-snapshot-v1",
    version: 1,
    target: { origin: productionOrigin, manifestDigest, workerVersion, deploymentId },
    sourceRelease: {
      tag: releaseTag,
      revision,
      url: `https://github.com/metalagman/webappsec/releases/tag/${releaseTag}`,
    },
    deploymentEvidence: {
      release: `deployment-deploy-${releaseTag}-${runId}`,
      url: `https://github.com/metalagman/webappsec/releases/tag/deployment-deploy-${releaseTag}-${runId}`,
      runUrl: `https://github.com/metalagman/webappsec/actions/runs/${runId}`,
    },
    verificationEvidence: {
      release: `verification-${releaseTag}-${runId}`,
      url: `https://github.com/metalagman/webappsec/releases/tag/verification-${releaseTag}-${runId}`,
      runUrl: `https://github.com/metalagman/webappsec/actions/runs/${runId}`,
      verifiedAt,
      layers: layerNames.map((name) => ({
        name,
        state: "pass",
        detail: name === "signatures" ? "<img src=x onerror=alert(1)> verified" : `${name} verified`,
      })),
    },
    proofs: ["release-signatures", "deployment-signatures", "verification-signatures"]
      .map((name) => ({ name, state: "pass", source: "ci" })),
    manifest: { path: "release-manifest.json", size: manifestBytes.length, sha256: manifestDigest },
  };
  return { files, manifestBytes, manifestDigest, snapshot };
}

async function routeVerifier(page, {
  tamper = false,
  unavailable = false,
  importMapMismatch = false,
  sriMismatch = false,
  stale = false,
  delayFirstSnapshot = false,
  counter = { snapshots: 0 },
} = {}) {
  const data = fixture({ importMapMismatch, sriMismatch, stale });
  let releaseFirstSnapshot;
  const firstSnapshotGate = new Promise((resolve) => { releaseFirstSnapshot = resolve; });
  await page.route(`${verifierOrigin}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/current-verification.json") {
      counter.snapshots += 1;
      const requestNumber = counter.snapshots;
      if (delayFirstSnapshot && requestNumber === 1) await firstSnapshotGate;
      const snapshot = delayFirstSnapshot && requestNumber === 1
        ? { ...data.snapshot, schema: "https://attacker.example/forged" }
        : data.snapshot;
      await route.fulfill({ json: snapshot, headers: { "cache-control": "no-store" } }).catch(() => {});
      return;
    }
    if (url.pathname === "/release-manifest.json") {
      await route.fulfill({ body: data.manifestBytes, contentType: "application/json" });
      return;
    }
    const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    try {
      const body = await readFile(path.join(outputDirectory, relative));
      await route.fulfill({ body, contentType: url.pathname.endsWith(".css") ? "text/css" : url.pathname.endsWith(".html") || url.pathname === "/" ? "text/html" : "text/javascript" });
    } catch {
      await route.fulfill({ status: 404, body: "missing" });
    }
  });
  await page.route(`${productionOrigin}/**`, async (route) => {
    if (unavailable) {
      await route.abort("connectionfailed");
      return;
    }
    const url = new URL(route.request().url());
    let body = data.files.get(url.pathname);
    if (tamper && url.pathname.endsWith(".js")) body = Buffer.from("tampered");
    await route.fulfill({
      status: body ? 200 : 404,
      body: route.request().method() === "HEAD" ? "" : body,
      headers: {
        "Access-Control-Allow-Origin": verifierOrigin,
        "Access-Control-Expose-Headers": "X-Webappsec-Release, X-Webappsec-Worker-Version",
        "Content-Type": "application/octet-stream",
        "X-Webappsec-Release": data.manifestDigest,
        "X-Webappsec-Worker-Version": workerVersion,
      },
    });
  });
  return { data, counter, releaseFirstSnapshot };
}

test.beforeAll(async () => {
  outputDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-online-verifier-"));
  await buildVerifierSite({ outputDirectory });
});

test("auto-run clearly joins CI trust with fresh browser verification", async ({ page }) => {
  const { data } = await routeVerifier(page);
  await page.goto(verifierOrigin);

  await expect(page.getByRole("heading", { name: "Deployment подтверждён" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Проверено CI" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Проверено сейчас в этом браузере" })).toBeVisible();
  await expect(page.locator('[data-check-id="ci:signatures"] [data-check-state]')).toHaveText("пройдено");
  await expect(page.locator('[data-check-id="browser:production-bytes"] [data-check-state]')).toHaveText("пройдено");
  await expect(page.locator('[data-identity="release"]')).toHaveText(releaseTag);
  await expect(page.locator('[data-identity="digest"]')).toHaveText(data.manifestDigest);
  await expect(page.locator('[data-evidence="verification"]')).toHaveAttribute("href", data.snapshot.verificationEvidence.url);
  await expect(page.locator('[data-check-id="ci:signatures"] [data-check-detail]')).toContainText("<img src=x");
  await expect(page.locator('[data-check-id="ci:signatures"] img')).toHaveCount(0);
  await expect(page.locator("html")).not.toHaveAttribute("data-production", "never-executed");
});

test("progress is restrained and retry cancels an in-flight stale run", async ({ page }) => {
  const counter = { snapshots: 0 };
  const { releaseFirstSnapshot } = await routeVerifier(page, { counter, delayFirstSnapshot: true });
  await page.goto(verifierOrigin);
  await expect.poll(() => counter.snapshots).toBe(1);
  await expect(page.getByRole("heading", { name: "Проверка выполняется" })).toBeVisible();
  await expect(page.locator("#result")).toHaveAttribute("aria-busy", "true");
  await expect(page.locator("[data-live-summary]")).toHaveText("Проверка запущена.");
  await expect(page.locator('[data-check-id="browser:snapshot"] [data-check-state]')).toHaveText("проверяется");
  await page.getByRole("button", { name: "Повторить проверку" }).click();
  await expect.poll(() => counter.snapshots).toBe(2);
  await expect(page.getByRole("heading", { name: "Deployment подтверждён" })).toBeVisible();
  releaseFirstSnapshot();
  await page.waitForTimeout(100);
  await expect(page.getByRole("heading", { name: "Deployment подтверждён" })).toBeVisible();
});

test("network loss is unavailable and tampered bytes fail closed", async ({ page }) => {
  await routeVerifier(page, { unavailable: true });
  await page.goto(verifierOrigin);
  await expect(page.getByRole("heading", { name: "Проверка недоступна" })).toBeVisible();
  await expect(page.locator("#result")).toHaveAttribute("aria-busy", "false");
  await expect(page.locator('[data-identity="release"]')).toHaveText(releaseTag);
  await expect(page.locator('[data-evidence="verification"]')).toBeVisible();

  await page.unrouteAll({ behavior: "wait" });
  await routeVerifier(page, { tamper: true });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Проверка не пройдена" })).toBeVisible();
  await expect(page.locator('[data-check-id="browser:production-bytes"] [data-check-state]')).toHaveText("ошибка");
  await expect(page.locator('[data-identity="release"]')).toHaveText(releaseTag);
  await expect(page.locator('[data-evidence="verification"]')).toBeVisible();
});

test("SRI mismatch fails closed and stale evidence is visibly warned", async ({ page }) => {
  await routeVerifier(page, { sriMismatch: true });
  await page.goto(verifierOrigin);
  await expect(page.getByRole("heading", { name: "Проверка не пройдена" })).toBeVisible();
  await expect(page.locator('[data-check-id="browser:sri"] [data-check-state]')).toHaveText("ошибка");

  await page.unrouteAll({ behavior: "wait" });
  await routeVerifier(page, { stale: true });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Deployment подтверждён" })).toBeVisible();
  await expect(page.locator("[data-stale]")).toBeVisible();
  await expect(page.locator("[data-stale]")).toContainText("старше 36 часов");
});

test("import map integrity mismatch fails closed", async ({ page }) => {
  await routeVerifier(page, { importMapMismatch: true });
  await page.goto(verifierOrigin);
  await expect(page.getByRole("heading", { name: "Проверка не пройдена" })).toBeVisible();
  await expect(page.locator('[data-check-id="browser:sri"] [data-check-state]')).toHaveText("ошибка");
  await expect(page.locator('[data-check-id="browser:sri"] [data-check-detail]')).toContainText("import map integrity mismatch");
});

test("missing Web Crypto is reported as unavailable without false PASS", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(Crypto.prototype, "subtle", { configurable: true, get: () => undefined });
  });
  await routeVerifier(page);
  await page.goto(verifierOrigin);
  await expect(page.getByRole("heading", { name: "Проверка недоступна" })).toBeVisible();
  await expect(page.locator('[data-check-id="browser:capabilities"] [data-check-state]')).toHaveText("недоступно");
  await expect(page.locator('[data-check-id="browser:capabilities"] [data-check-detail]')).toContainText("Web Crypto");
});

test("mobile, keyboard focus, and reduced motion remain usable", async ({ page }) => {
  await routeVerifier(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(verifierOrigin);
  await expect(page.getByRole("button", { name: "Повторить проверку" })).toBeVisible();
  await page.getByRole("button", { name: "Повторить проверку" }).focus();
  await expect(page.getByRole("button", { name: "Повторить проверку" })).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await page.locator("html").evaluate((element) => getComputedStyle(element).scrollBehavior)).toBe("auto");
});
