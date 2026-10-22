#!/usr/bin/env node
import { chromium } from "@playwright/test";

function usage() {
  process.stderr.write("Usage: verify-live-browser.mjs --origin <https-url>\n");
  process.exit(2);
}
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--origin") usage();
let origin;
try {
  const parsed = new URL(args[1]);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) usage();
  origin = parsed.origin;
} catch {
  usage();
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const failures = [];
  page.on("console", (message) => { if (message.type() === "error") failures.push(`console: ${message.text()}`); });
  page.on("pageerror", (error) => failures.push(`page: ${error.message}`));
  page.on("requestfailed", (request) => failures.push(`request: ${request.url()} (${request.failure()?.errorText})`));
  const response = await page.goto(`${origin}/`, { waitUntil: "networkidle", timeout: 30_000 });
  if (!response?.ok()) throw new Error(`browser received HTTP ${response?.status() ?? "none"}`);
  if ((await page.title()).trim().length === 0) throw new Error("page has no title");
  const resources = await page.locator("script[src][integrity], link[rel~='stylesheet'][href][integrity]").count();
  if (resources < 2) throw new Error("browser found fewer than two SRI-protected resources");
  const toggle = page.getByRole("button", { name: /CVE correlation/ });
  const panel = page.locator("#layer-cve");
  if (await toggle.getAttribute("aria-expanded") !== "false" || await panel.isVisible()) {
    throw new Error("accordion did not initialize with the second panel collapsed");
  }
  await toggle.locator(".toggle-icon").click();
  if (await toggle.getAttribute("aria-expanded") !== "true" || !(await panel.isVisible())) {
    throw new Error("accordion did not open from the plus control");
  }
  await toggle.click();
  if (await toggle.getAttribute("aria-expanded") !== "false" || await panel.isVisible()) {
    throw new Error("accordion did not close from the minus control");
  }
  if (failures.length) throw new Error(failures.join("; "));
  process.stdout.write(`${JSON.stringify({ ok: true, origin, title: await page.title(), sriResources: resources })}\n`);
} finally {
  await browser.close();
}
