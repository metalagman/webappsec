#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const filename = process.argv[2];
if (!filename) process.exit(1);

try {
  const report = JSON.parse(await readFile(filename, "utf8"));
  const states = Object.fromEntries((report.layers ?? []).map(({ name, state }) => [name, state]));
  process.exitCode = states.manifest === "pass"
    && (states["production-bytes"] === "fail" || states["response-headers"] === "fail") ? 0 : 1;
} catch {
  process.exitCode = 1;
}
