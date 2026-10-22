import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const windowsChrome = "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe";
const requestedExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
const localExecutable = requestedExecutable || (existsSync(windowsChrome) ? windowsChrome : undefined);

export default defineConfig({
  testDir: "./test/browser",
  fullyParallel: false,
  reporter: "line",
  use: {
    browserName: "chromium",
    headless: true,
    launchOptions: localExecutable ? { executablePath: localExecutable } : {},
  },
});
