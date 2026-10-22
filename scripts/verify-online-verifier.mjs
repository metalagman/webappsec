#!/usr/bin/env node
import { mkdir } from "node:fs/promises";
import { chromium } from "@playwright/test";

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (["--verifier", "--production"].includes(args[index]) && args[index + 1]) options[args[index].slice(2)] = args[++index];
  else process.exitCode = 2;
}
if (process.exitCode || options.verifier !== "https://verify.webappsec.metalagman.dev"
  || options.production !== "https://webappsec.metalagman.dev") {
  throw new Error("expected exact production and verifier origins");
}

await mkdir(".artifacts", { recursive: true });
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const errors = [];
page.on("console", (message) => { if (message.type() === "error") errors.push(`console: ${message.text()}`); });
page.on("pageerror", (error) => errors.push(`page: ${error.message}`));
page.on("requestfailed", (request) => {
  const reason = request.failure()?.errorText ?? "failed";
  if (reason !== "net::ERR_ABORTED") errors.push(`request: ${request.url()} ${reason}`);
});

async function requireVerified() {
  await page.waitForFunction(
    () => document.querySelector("#result")?.getAttribute("aria-busy") === "false",
    undefined,
    { timeout: 60_000 },
  );
  const title = await page.locator("[data-result-title]").textContent();
  if (title !== "Deployment подтверждён") {
    const diagnostics = await page.locator("[data-diagnostics]").textContent();
    throw new Error(`online verifier returned ${title}: ${diagnostics}`);
  }
  const checks = page.locator("[data-check-id]");
  if (await checks.count() !== 19) throw new Error("online verifier check inventory mismatch");
  const failedChecks = page.locator('[data-check-id]:not([data-state="pass"])');
  if (await failedChecks.count() !== 0) {
    const ids = await failedChecks.evaluateAll((nodes) => nodes.map((node) => node.dataset.checkId));
    throw new Error(`online verifier contains non-PASS checks: ${ids.join(", ")}`);
  }
  if (await page.locator('[aria-busy="true"]').count() !== 0) throw new Error("online verifier remained busy");
  if (await page.locator('[data-evidence-links] a:visible').count() !== 4) throw new Error("evidence link inventory mismatch");
}

try {
  await page.goto(options.verifier, { waitUntil: "domcontentloaded", timeout: 30_000 });
  await requireVerified();
  await page.goto(options.production, { waitUntil: "domcontentloaded", timeout: 30_000 });
  const link = page.locator(`a[href="${options.verifier}"], a[href="${options.verifier}/"]`).first();
  await link.waitFor({ state: "visible", timeout: 15_000 });
  await Promise.all([page.waitForURL(`${options.verifier}/`), link.click()]);
  await requireVerified();
  if (errors.length > 0) throw new Error(errors.join("; "));
  process.stdout.write(`${JSON.stringify({ ok: true, verifier: options.verifier, production: options.production, checks: 19 })}\n`);
} catch (error) {
  await page.screenshot({ path: ".artifacts/hosted-verifier-failure.png", fullPage: true }).catch(() => {});
  throw error;
} finally {
  await browser.close();
}
