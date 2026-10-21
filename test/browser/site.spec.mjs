import { expect, test } from "@playwright/test";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { buildSite } from "../../scripts/build.mjs";

let outputDirectory;
const origin = "https://demo.test";

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
]);

async function routeBuild(page, { tamperJavaScript = false } = {}) {
  await page.route(`${origin}/**`, async (route) => {
    const url = new URL(route.request().url());
    const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    let filename = path.join(outputDirectory, relative);
    let status = 200;

    try {
      await readFile(filename);
    } catch {
      filename = path.join(outputDirectory, "404.html");
      status = 404;
    }

    let body = await readFile(filename);
    if (tamperJavaScript && path.extname(filename) === ".js") {
      body = Buffer.concat([body, Buffer.from("\n// modified in transit\n")]);
    }

    await route.fulfill({
      status,
      body,
      contentType: contentTypes.get(path.extname(filename)) ?? "application/octet-stream",
      headers: {
        "cache-control": "no-store",
      },
    });
  });
}

test.beforeAll(async () => {
  outputDirectory = await mkdtemp(path.join(tmpdir(), "webappsec-browser-"));
  await buildSite({ outputDirectory });
});

test("valid release loads with local resources and usable interactions", async ({ page }) => {
  await routeBuild(page);
  const consoleErrors = [];
  const requests = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("request", (request) => requests.push(new URL(request.url()).origin));

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(origin);

  await expect(page).toHaveTitle(/Proof of Deploy/);
  await expect(page.locator("html")).toHaveAttribute("data-enhanced", "true");
  await expect(page.getByRole("heading", { name: /От коммита до байтов/ })).toBeVisible();
  await expect(page.getByRole("link", { name: "GitHub ↗" })).toHaveAttribute(
    "href",
    "https://github.com/metalagman/webappsec",
  );

  await page.locator("body").focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "К содержанию" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(`${origin}/#content`);

  const cveToggle = page.getByRole("button", { name: /CVE correlation/ });
  await cveToggle.focus();
  await expect(cveToggle).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(cveToggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.locator("#layer-cve")).toBeVisible();

  const copy = page.locator(".copy-command");
  await copy.focus();
  await page.keyboard.press("Enter");
  await expect(copy).toHaveText(/Скопировано|Скопируйте из терминала/);

  expect(consoleErrors).toEqual([]);
  await page.evaluate(() => {
    const script = document.createElement("script");
    script.textContent = "window.__inlineExecuted = true";
    document.head.append(script);
  });
  expect(await page.evaluate(() => window.__inlineExecuted)).toBeUndefined();
  expect(consoleErrors.some((message) => /content security policy|script-src/i.test(message))).toBe(true);

  expect(new Set(requests)).toEqual(new Set([origin]));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (process.env.CAPTURE_SCREENSHOT === "1") {
    await page.screenshot({ path: "test-results/homepage.png", fullPage: true });
  }
});

test("mobile and reduced-motion layouts remain usable", async ({ page }) => {
  await routeBuild(page);
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(origin);

  await expect(page.getByRole("heading", { name: /От коммита до байтов/ })).toBeVisible();
  await expect(page.getByRole("link", { name: "Проверить deployment" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await page.locator("html").evaluate((element) => getComputedStyle(element).scrollBehavior)).toBe("smooth");
  await page.emulateMedia({ reducedMotion: "reduce" });
  expect(await page.locator("html").evaluate((element) => getComputedStyle(element).scrollBehavior)).toBe("auto");
});

test("all educational layers remain readable without JavaScript", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await routeBuild(page);
  await page.goto(origin);

  await expect(page.locator(".layer-body")).toHaveCount(8);
  for (const panel of await page.locator(".layer-body").all()) await expect(panel).toBeVisible();
  await context.close();
});

test("browser rejects a JavaScript response changed behind unchanged HTML", async ({ page }) => {
  await routeBuild(page, { tamperJavaScript: true });
  const errors = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });

  await page.goto(origin);

  await expect(page.locator("html")).not.toHaveAttribute("data-enhanced", "true");
  await expect(page.getByRole("heading", { name: /От коммита до байтов/ })).toBeVisible();
  for (const panel of await page.locator(".layer-body").all()) await expect(panel).toBeVisible();
  expect(errors.some((message) => /integrity|digest/i.test(message))).toBe(true);
});
